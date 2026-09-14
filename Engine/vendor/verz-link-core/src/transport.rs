//! Stateful packet sender. Platform adapters own sockets, carrier detection and TUN I/O.
//! Session/sequence/cache lifetime is independent from the lifetime of a WAN socket.
use crate::{
    ACK, FEC, NACK, PRIMARY, Packet, RESEND, TUN, decode_nack,
    recovery::PacketCache,
    scheduler::{Config, Link, Scheduler},
};
use std::{collections::HashMap, io};

pub trait WanWriter {
    fn carrier(&self, id: u8) -> bool;
    fn send(&mut self, id: u8, wire: &[u8]) -> io::Result<()>;
}

pub struct Sender {
    session: u32,
    key: Vec<u8>,
    scheduler: Scheduler,
    sequences: HashMap<u16, u32>,
    cache: PacketCache,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Sent {
    pub sequence: u32,
    pub primary: u8,
    pub duplicate: Option<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Repair {
    pub sequence: u32,
    pub path: u8,
    pub wire_bytes: usize,
}

impl Sender {
    /// Policy changes must not reset flow sequences or retransmission state.
    pub fn set_config(&mut self, config: Config) {
        self.scheduler = Scheduler::new(config);
    }
    pub fn new(session: u32, key: Vec<u8>, config: Config) -> io::Result<Self> {
        if session == 0 || key.len() < 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "nonzero session and at least 32 key bytes required",
            ));
        }
        Ok(Self {
            session,
            key,
            scheduler: Scheduler::new(config),
            sequences: HashMap::new(),
            cache: PacketCache::new(512),
        })
    }
    fn send_one(&self, packet: &Packet, id: u8, writer: &mut impl WanWriter) -> io::Result<()> {
        if !writer.carrier(id) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "link has no carrier",
            ));
        }
        let mut packet = packet.clone();
        packet.link = id;
        let wire = packet.encode(&self.key).map_err(io::Error::other)?;
        writer.send(id, &wire)
    }
    fn send_any(
        &self,
        packet: &Packet,
        primary: u8,
        snapshot: &[Link],
        writer: &mut impl WanWriter,
    ) -> io::Result<u8> {
        let mut order = vec![primary];
        for link in snapshot {
            if !link.disabled && matches!(link.status, 1 | 2) && !order.contains(&link.id) {
                order.push(link.id);
            }
        }
        let mut last = io::Error::new(io::ErrorKind::NotConnected, "no usable WAN socket");
        for id in order {
            match self.send_one(packet, id, writer) {
                Ok(()) => return Ok(id),
                Err(error) => last = error,
            }
        }
        Err(last)
    }
    /// Metadata/classification is supplied by the ingress layer; payload is a full IP packet for TUN.
    pub fn forward(
        &mut self,
        mut packet: Packet,
        snapshot: &[Link],
        writer: &mut impl WanWriter,
    ) -> io::Result<Sent> {
        if packet.payload.len() > crate::MAX_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "payload too large",
            ));
        }
        let decision = self
            .scheduler
            .schedule(packet.class, snapshot)
            .map_err(io::Error::other)?;
        let sequence = self.sequences.entry(packet.local_port).or_default();
        packet.sequence = *sequence;
        *sequence = sequence.wrapping_add(1);
        packet.session = self.session;
        packet.flags = PRIMARY | (packet.flags & TUN);
        let primary = self.send_any(&packet, decision.primary, snapshot, writer)?;
        packet.link = primary;
        self.cache.store(packet.clone());
        let mut duplicate = None;
        if decision.fec != 0 && decision.fec != primary {
            packet.flags = FEC | (packet.flags & TUN);
            if self.send_one(&packet, decision.fec, writer).is_ok() {
                duplicate = Some(decision.fec);
            }
        }
        Ok(Sent {
            sequence: packet.sequence,
            primary,
            duplicate,
        })
    }

    /// Send through a path selected by a caller that owns a stronger scheduler.
    /// Socket failure still falls back to another healthy path, while sequence,
    /// cache, authentication and NACK repair remain owned by this Sender.
    pub fn forward_on(
        &mut self,
        packet: Packet,
        snapshot: &[Link],
        writer: &mut impl WanWriter,
        preferred: u8,
    ) -> io::Result<Sent> {
        if !snapshot
            .iter()
            .any(|link| link.id == preferred && !link.disabled && matches!(link.status, 1 | 2))
        {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "preferred WAN is not healthy",
            ));
        }
        self.forward_with_decision(packet, snapshot, writer, preferred, 0)
    }

    fn forward_with_decision(
        &mut self,
        mut packet: Packet,
        snapshot: &[Link],
        writer: &mut impl WanWriter,
        preferred: u8,
        fec: u8,
    ) -> io::Result<Sent> {
        if packet.payload.len() > crate::MAX_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "payload too large",
            ));
        }
        let sequence = self.sequences.entry(packet.local_port).or_default();
        packet.sequence = *sequence;
        *sequence = sequence.wrapping_add(1);
        packet.session = self.session;
        packet.flags = PRIMARY | (packet.flags & TUN);
        let primary = self.send_any(&packet, preferred, snapshot, writer)?;
        packet.link = primary;
        self.cache.store(packet.clone());
        let mut duplicate = None;
        if fec != 0 && fec != primary {
            packet.flags = FEC | (packet.flags & TUN);
            if self.send_one(&packet, fec, writer).is_ok() {
                duplicate = Some(fec);
            }
        }
        Ok(Sent {
            sequence: packet.sequence,
            primary,
            duplicate,
        })
    }
    /// Only authenticated control packets belonging to this session can trim or resend its cache.
    pub fn control(
        &mut self,
        wire: &[u8],
        snapshot: &[Link],
        writer: &mut impl WanWriter,
    ) -> io::Result<usize> {
        let control = Packet::decode(wire, &self.key).map_err(io::Error::other)?;
        if control.session != self.session {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "wrong session",
            ));
        }
        if control.flags == ACK {
            self.cache
                .trim_through(control.local_port, control.sequence);
            return Ok(0);
        }
        if control.flags != NACK {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "not ACK/NACK"));
        }
        let sequences = decode_nack(&control.payload).map_err(io::Error::other)?;
        let mut sent = 0;
        for sequence in sequences {
            if let Some(mut packet) = self.cache.get(control.local_port, sequence).cloned() {
                packet.flags |= RESEND;
                if self
                    .send_any(&packet, packet.link, snapshot, writer)
                    .is_ok()
                {
                    sent += 1;
                }
            }
        }
        Ok(sent)
    }

    /// Handle authenticated feedback and, for NACKs, optionally prefer the WAN
    /// that delivered the feedback. This lets a multipath owner repair around a
    /// silently failed original path without changing the legacy control path.
    pub fn control_on(
        &mut self,
        wire: &[u8],
        snapshot: &[Link],
        writer: &mut impl WanWriter,
        preferred_repair: Option<u8>,
    ) -> io::Result<Vec<Repair>> {
        let control = Packet::decode(wire, &self.key).map_err(io::Error::other)?;
        if control.session != self.session {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "wrong session",
            ));
        }
        if control.flags == ACK {
            self.cache
                .trim_through(control.local_port, control.sequence);
            return Ok(Vec::new());
        }
        if control.flags != NACK {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "not ACK/NACK"));
        }
        let sequences = decode_nack(&control.payload).map_err(io::Error::other)?;
        let mut repairs = Vec::new();
        for sequence in sequences {
            if let Some(mut packet) = self.cache.get(control.local_port, sequence).cloned() {
                packet.flags |= RESEND;
                // The authenticated control packet arriving through this socket
                // is newer reachability evidence than the heartbeat snapshot.
                // send_any still checks carrier and falls back safely.
                let preferred = preferred_repair.unwrap_or(packet.link);
                if let Ok(path) = self.send_any(&packet, preferred, snapshot, writer) {
                    repairs.push(Repair {
                        sequence,
                        path,
                        wire_bytes: packet.encode(&self.key).map_err(io::Error::other)?.len(),
                    });
                }
            }
        }
        Ok(repairs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Wans {
        up: Vec<u8>,
        fail: Vec<u8>,
        sent: Vec<Packet>,
    }
    impl WanWriter for Wans {
        fn carrier(&self, id: u8) -> bool {
            self.up.contains(&id)
        }
        fn send(&mut self, id: u8, wire: &[u8]) -> io::Result<()> {
            if self.fail.contains(&id) {
                return Err(io::Error::other("injected socket error"));
            }
            self.sent.push(Packet::decode(wire, &[7; 32]).unwrap());
            Ok(())
        }
    }
    fn links() -> Vec<Link> {
        [1, 2]
            .into_iter()
            .map(|id| Link {
                id,
                status: 1,
                disabled: false,
                probed: true,
                rtt: 10.0,
                jitter: 1.0,
                variance: 0.0,
                loss: 0.0,
                capacity: 100.0,
                uptime: 1.0,
            })
            .collect()
    }
    fn packet() -> Packet {
        Packet {
            flags: TUN,
            class: 4,
            local_port: 9000,
            payload: vec![42; 100],
            ..Default::default()
        }
    }
    #[test]
    fn unplug_and_replug_do_not_reset_sequence_or_session() {
        let mut sender = Sender::new(123, vec![7; 32], Config::default()).unwrap();
        let mut w = Wans {
            up: vec![1, 2],
            fail: vec![],
            sent: vec![],
        };
        assert_eq!(
            sender.forward(packet(), &links(), &mut w).unwrap().primary,
            2
        );
        w.up = vec![1];
        for seq in 1..9 {
            assert_eq!(
                sender.forward(packet(), &links(), &mut w).unwrap().sequence,
                seq
            );
        }
        w.up = vec![1, 2];
        assert_eq!(
            sender.forward(packet(), &links(), &mut w).unwrap().sequence,
            9
        );
        assert!(w.sent.iter().all(|p| p.session == 123));
        assert!(w.sent[1..9].iter().all(|p| p.link == 1));
    }
    #[test]
    fn socket_failure_tries_other_path_and_nack_survives_removal() {
        let mut s = Sender::new(123, vec![7; 32], Config::default()).unwrap();
        let mut w = Wans {
            up: vec![1, 2],
            fail: vec![2],
            sent: vec![],
        };
        assert_eq!(s.forward(packet(), &links(), &mut w).unwrap().primary, 1);
        w.up = vec![2];
        w.fail.clear();
        let nack = Packet {
            session: 123,
            flags: NACK,
            local_port: 9000,
            payload: crate::encode_nack(&[0]).unwrap(),
            ..Default::default()
        };
        assert_eq!(
            s.control(&nack.encode(&[7; 32]).unwrap(), &links(), &mut w)
                .unwrap(),
            1
        );
        let p = w.sent.last().unwrap();
        assert_eq!((p.sequence, p.link), (0, 2));
        assert_ne!(p.flags & RESEND, 0);
    }
    #[test]
    fn caller_selected_path_preserves_sequence_and_falls_back_on_socket_error() {
        let mut s = Sender::new(123, vec![7; 32], Config::default()).unwrap();
        let mut w = Wans {
            up: vec![1, 2],
            fail: vec![],
            sent: vec![],
        };
        let sent = s.forward_on(packet(), &links(), &mut w, 1).unwrap();
        assert_eq!((sent.sequence, sent.primary, sent.duplicate), (0, 1, None));
        w.fail.push(1);
        let sent = s.forward_on(packet(), &links(), &mut w, 1).unwrap();
        assert_eq!((sent.sequence, sent.primary, sent.duplicate), (1, 2, None));
        assert_eq!(w.sent.iter().map(|p| p.link).collect::<Vec<_>>(), [1, 2]);
    }
    #[test]
    fn caller_selected_repair_uses_feedback_path_while_legacy_keeps_original() {
        let mut s = Sender::new(123, vec![7; 32], Config::default()).unwrap();
        let mut w = Wans {
            up: vec![1, 2],
            fail: vec![],
            sent: vec![],
        };
        assert_eq!(
            s.forward_on(packet(), &links(), &mut w, 1).unwrap().primary,
            1
        );
        let nack = Packet {
            session: 123,
            flags: NACK,
            local_port: 9000,
            payload: crate::encode_nack(&[0]).unwrap(),
            ..Default::default()
        }
        .encode(&[7; 32])
        .unwrap();
        let mut stale = links();
        stale[1].status = 0;
        let repairs = s.control_on(&nack, &stale, &mut w, Some(2)).unwrap();
        assert_eq!(repairs.len(), 1);
        assert_eq!((repairs[0].sequence, repairs[0].path), (0, 2));
        assert_eq!(w.sent.last().unwrap().link, 2);
    }
    #[test]
    fn authentication_and_session_isolate_control() {
        let mut s = Sender::new(123, vec![7; 32], Config::default()).unwrap();
        let mut w = Wans {
            up: vec![1],
            fail: vec![],
            sent: vec![],
        };
        let ack = Packet {
            session: 124,
            flags: ACK,
            ..Default::default()
        };
        assert!(
            s.control(&ack.encode(&[7; 32]).unwrap(), &links(), &mut w)
                .is_err()
        );
        assert!(
            s.control(&ack.encode(&[8; 32]).unwrap(), &links(), &mut w)
                .is_err()
        );
        assert!(Sender::new(0, vec![7; 32], Config::default()).is_err());
        assert!(Sender::new(1, vec![], Config::default()).is_err());
    }
}
