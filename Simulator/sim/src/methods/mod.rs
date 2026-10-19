//! Bonding methods under test. Each has a client half and a server half that
//! talk only through [`Net`], exactly as the real app and relay would.

pub mod coded;
pub mod shipped;

use crate::net::Net;

/// Application payload bytes per packet (a typical video datagram).
pub const PAYLOAD: usize = 1_200;
/// The same payload inside the shipped wire format.
pub const WIRE: usize = PAYLOAD + verz_link_core::HEADER + verz_link_core::TAG;

pub trait Method {
    type Up;
    type Down;

    /// The application handed the client packet `seq`.
    fn source(&mut self, now: u64, seq: u32, net: &mut Net<Self::Up, Self::Down>, log: &mut Log);
    fn at_server(&mut self, now: u64, link: usize, msg: Self::Up, net: &mut Net<Self::Up, Self::Down>, log: &mut Log);
    fn at_client(&mut self, now: u64, link: usize, msg: Self::Down, net: &mut Net<Self::Up, Self::Down>);
    /// Called every millisecond on both halves.
    fn tick(&mut self, now: u64, net: &mut Net<Self::Up, Self::Down>, log: &mut Log);

    /// Internal counters worth showing with `--verbose`.
    fn notes(&self) -> String {
        String::new()
    }

    /// Instantaneous internal state for `--timeline`.
    fn trace(&self, _now: u64) -> String {
        String::new()
    }

    /// Everything the method did for one original, for `--timeline`.
    fn story(&self, _seq: u32) -> Vec<String> {
        Vec::new()
    }

    /// What the method did in a time window, for `--timeline`.
    fn between(&self, _from_us: u64, _to_us: u64) -> Vec<String> {
        Vec::new()
    }
}

/// When each application packet was handed over and when the server
/// released it to the destination.
#[derive(Default)]
pub struct Log {
    pub sent_at: Vec<u64>,
    pub released_at: Vec<Option<u64>>,
    /// Link each original went out on, and when the original itself (not a
    /// copy or a rebuild) reached the server. Used to explain misses.
    pub sent_on: Vec<Option<u8>>,
    pub arrived_at: Vec<Option<u64>>,
}

impl Log {
    pub fn sent(&mut self, seq: u32, now: u64) {
        debug_assert_eq!(seq as usize, self.sent_at.len());
        self.sent_at.push(now);
        self.released_at.push(None);
        self.sent_on.push(None);
        self.arrived_at.push(None);
    }

    pub fn sent_on(&mut self, seq: u32, link: u8) {
        if let Some(slot) = self.sent_on.get_mut(seq as usize) {
            *slot = Some(link);
        }
    }

    pub fn arrived(&mut self, seq: u32, now: u64) {
        if let Some(slot) = self.arrived_at.get_mut(seq as usize)
            && slot.is_none()
        {
            *slot = Some(now);
        }
    }

    /// The first release counts; later duplicates are ignored, as the
    /// destination application would see only one.
    pub fn released(&mut self, seq: u32, now: u64) {
        if let Some(slot) = self.released_at.get_mut(seq as usize)
            && slot.is_none()
        {
            *slot = Some(now);
        }
    }
}
