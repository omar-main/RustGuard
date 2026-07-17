//! RustGuard TUN Interface Library
//!
//! This crate provides TUN device abstraction for Linux.
//! Windows and macOS are out of scope per project requirements.

mod linux;

pub use linux::{AsyncTun, LinuxTun, TunError};

/// TUN device interface trait.
pub trait TunDevice: Send + Sync {
    /// Read a packet from the TUN device.
    fn read(&self, buf: &mut [u8]) -> std::io::Result<usize>;

    /// Write a packet to the TUN device.
    fn write(&self, buf: &[u8]) -> std::io::Result<usize>;

    /// Get the interface name.
    fn name(&self) -> &str;

    /// Get the current MTU.
    fn mtu(&self) -> u16;
}
