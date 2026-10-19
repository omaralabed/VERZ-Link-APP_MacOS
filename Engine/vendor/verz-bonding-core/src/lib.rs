//! Experimental VERZ coded bonding.
//!
//! Sans-IO by design: callers pass in monotonic time and network events, and
//! receive decisions back. Nothing here opens sockets or reads clocks, so the
//! same code can run in the simulator, every client platform and the server.
//!
//! Pieces:
//! - [`gf256`]: finite-field arithmetic for repair packets.
//! - [`coding`]: sliding-window repair packets and an incremental decoder.
//! - [`health`]: probability that a link has failed, from its feedback rhythm.
//! - [`delay`]: queueing on a link, from how its echo delay exceeds its best.
//! - [`planner`]: minimum-cost repair rates that survive the failures that matter.
//! - [`sender`] / [`receiver`]: the two halves of the protocol.

pub mod coding;
pub mod delay;
pub mod gf256;
pub mod health;
pub mod planner;
pub mod receiver;
pub mod sender;
