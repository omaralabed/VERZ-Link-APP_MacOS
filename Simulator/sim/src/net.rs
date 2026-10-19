//! Discrete-event network: one client and one server joined by fake links.
//! Time is simulated microseconds; nothing here reads a real clock.

use crate::link::LinkSim;
use std::cmp::Ordering;
use std::collections::BinaryHeap;

/// Why an uplink packet was sent, for data-cost accounting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// First transmission of an application packet.
    Original = 0,
    /// Anything else carrying application data: copies, resends, repairs.
    Protection = 1,
    /// Liveness probes and heartbeats.
    Probe = 2,
}

pub enum Event<U, D> {
    /// Arrived at the server.
    Up { link: usize, msg: U },
    /// Arrived at the client.
    Down { link: usize, msg: D },
}

struct Queued<U, D> {
    at: u64,
    order: u64,
    event: Event<U, D>,
}

impl<U, D> PartialEq for Queued<U, D> {
    fn eq(&self, other: &Self) -> bool {
        (self.at, self.order) == (other.at, other.order)
    }
}

impl<U, D> Eq for Queued<U, D> {}

impl<U, D> PartialOrd for Queued<U, D> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<U, D> Ord for Queued<U, D> {
    /// Earliest first; ties keep send order.
    fn cmp(&self, other: &Self) -> Ordering {
        (other.at, other.order).cmp(&(self.at, self.order))
    }
}

pub struct Net<U, D> {
    pub links: Vec<LinkSim>,
    /// Uplink bytes per link, indexed by [`Kind`].
    pub up_bytes: Vec<[u64; 3]>,
    pub down_bytes: Vec<u64>,
    /// Send times of originals per link, for failure-detection timing.
    pub originals: Vec<Vec<u64>>,
    count_from: u64,
    count_until: u64,
    queue: BinaryHeap<Queued<U, D>>,
    order: u64,
}

impl<U, D> Net<U, D> {
    /// Bytes are counted only for sends inside `[count_from, count_until)`.
    pub fn new(links: Vec<LinkSim>, count_from: u64, count_until: u64) -> Self {
        let n = links.len();
        Self {
            links,
            up_bytes: vec![[0; 3]; n],
            down_bytes: vec![0; n],
            originals: vec![Vec::new(); n],
            count_from,
            count_until,
            queue: BinaryHeap::new(),
            order: 0,
        }
    }

    pub fn carrier(&self, link: usize, now: u64) -> bool {
        self.links[link].carrier_at(now)
    }

    fn counting(&self, now: u64) -> bool {
        now >= self.count_from && now < self.count_until
    }

    fn push(&mut self, at: u64, event: Event<U, D>) {
        self.order += 1;
        self.queue.push(Queued { at, order: self.order, event });
    }

    /// Client to server. Fails only when the OS reports no carrier, as a
    /// socket send would; a silent outage accepts the packet and loses it.
    pub fn up(&mut self, now: u64, link: usize, bytes: usize, kind: Kind, msg: U) -> bool {
        if !self.carrier(link, now) {
            return false;
        }
        if self.counting(now) {
            self.up_bytes[link][kind as usize] += bytes as u64;
        }
        if kind == Kind::Original {
            self.originals[link].push(now);
        }
        if let Some(at) = self.links[link].send_up(now, bytes) {
            self.push(at, Event::Up { link, msg });
        }
        true
    }

    /// Server to client. The server cannot see the client's carrier, so this
    /// always "succeeds"; the link decides whether it arrives.
    pub fn down(&mut self, now: u64, link: usize, bytes: usize, msg: D) {
        if self.counting(now) {
            self.down_bytes[link] += bytes as u64;
        }
        if let Some(at) = self.links[link].send_down(now) {
            self.push(at, Event::Down { link, msg });
        }
    }

    pub fn next_at(&self) -> Option<u64> {
        self.queue.peek().map(|q| q.at)
    }

    pub fn pop(&mut self) -> Option<(u64, Event<U, D>)> {
        self.queue.pop().map(|q| (q.at, q.event))
    }
}
