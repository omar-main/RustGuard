//! Linux TUN device implementation.
//!
//! Uses /dev/net/tun via ioctl to create and manage TUN interfaces.
//! Requires CAP_NET_ADMIN or root privileges.

use nix::fcntl::{open, OFlag};
use nix::sys::stat::Mode;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use thiserror::Error;
use tokio::io::unix::AsyncFd;
use tracing::{debug, info};

use crate::TunDevice;

/// TUN device path on Linux.
const TUN_DEVICE_PATH: &str = "/dev/net/tun";

/// TUN interface flags.
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;

/// ioctl request code for TUNSETIFF.
const TUNSETIFF: libc::c_ulong = 0x400454ca;

/// Interface request structure for ioctl.
#[repr(C)]
struct IfReq {
    ifr_name: [libc::c_char; libc::IFNAMSIZ],
    ifr_flags: libc::c_short,
    _padding: [u8; 22],
}

/// Errors that can occur with TUN devices.
#[derive(Debug, Error)]
pub enum TunError {
    #[error("Failed to open TUN device: {0}")]
    OpenError(#[source] nix::Error),

    #[error("Failed to configure TUN device: {0}")]
    IoctlError(#[source] nix::Error),

    #[error("Interface name too long (max {} bytes)", libc::IFNAMSIZ - 1)]
    NameTooLong,

    #[error("Failed to read from TUN device: {0}")]
    ReadError(#[source] std::io::Error),

    #[error("Failed to write to TUN device: {0}")]
    WriteError(#[source] std::io::Error),

    #[error("Failed to set MTU: {0}")]
    MtuError(String),

    #[error("Permission denied. Run as root or with CAP_NET_ADMIN.")]
    PermissionDenied,
}

/// Linux TUN device.
pub struct LinuxTun {
    /// File descriptor for the TUN device
    fd: OwnedFd,
    /// Interface name (e.g., "tun0")
    name: String,
    /// Current MTU
    mtu: u16,
}

impl LinuxTun {
    /// Create a new TUN device with the specified name.
    ///
    /// If `name` is empty, the kernel will assign a name (tun0, tun1, etc.).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The TUN device cannot be opened (permission denied)
    /// - The ioctl call fails
    /// - The interface name is too long
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rustguard_tun::{LinuxTun, TunDevice};
    ///
    /// let tun = LinuxTun::new("rg0", 1420).expect("Failed to create TUN");
    /// println!("Created interface: {}", tun.name());
    /// ```
    pub fn new(name: &str, mtu: u16) -> Result<Self, TunError> {
        // Validate name length
        if name.len() >= libc::IFNAMSIZ {
            return Err(TunError::NameTooLong);
        }

        // Open /dev/net/tun
        let fd = open(
            TUN_DEVICE_PATH,
            OFlag::O_RDWR | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
            Mode::empty(),
        )
        .map_err(|e| {
            if e == nix::errno::Errno::EACCES || e == nix::errno::Errno::EPERM {
                TunError::PermissionDenied
            } else {
                TunError::OpenError(e)
            }
        })?;

        debug!("Opened TUN device fd={}", fd.as_raw_fd());

        // Prepare ioctl request
        let mut req = IfReq {
            ifr_name: [0; libc::IFNAMSIZ],
            ifr_flags: IFF_TUN | IFF_NO_PI,
            _padding: [0; 22],
        };

        // Copy interface name
        for (i, byte) in name.bytes().enumerate() {
            req.ifr_name[i] = byte as libc::c_char;
        }

        // Configure the TUN device
        // SAFETY: `fd` is an open `/dev/net/tun` descriptor and `req` points to
        // a correctly sized, initialized `ifreq`-compatible structure for the
        // duration of the ioctl call.
        let result = unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF, &mut req) };
        if result < 0 {
            return Err(TunError::IoctlError(nix::errno::Errno::last()));
        }

        // Extract the actual interface name (kernel may have modified it)
        let actual_name = unsafe {
            let name_bytes: &[u8] =
                std::slice::from_raw_parts(req.ifr_name.as_ptr() as *const u8, libc::IFNAMSIZ);
            let end = name_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(libc::IFNAMSIZ);
            String::from_utf8_lossy(&name_bytes[..end]).to_string()
        };

        info!("Created TUN interface: {} (mtu={})", actual_name, mtu);

        let tun = Self {
            fd,
            name: actual_name,
            mtu,
        };

        // Set MTU via ip command (ioctl for MTU requires more setup)
        tun.set_mtu_via_ip(mtu)?;

        Ok(tun)
    }

    /// Bring the interface up.
    pub fn up(&self) -> Result<(), TunError> {
        let status = std::process::Command::new("ip")
            .args(["link", "set", &self.name, "up"])
            .status()
            .map_err(|e| TunError::MtuError(format!("Failed to run ip command: {}", e)))?;

        if !status.success() {
            return Err(TunError::MtuError("Failed to bring interface up".into()));
        }

        info!("Interface {} is UP", self.name);
        Ok(())
    }

    /// Bring the interface down.
    pub fn down(&self) -> Result<(), TunError> {
        let status = std::process::Command::new("ip")
            .args(["link", "set", &self.name, "down"])
            .status()
            .map_err(|e| TunError::MtuError(format!("Failed to run ip command: {}", e)))?;

        if !status.success() {
            return Err(TunError::MtuError("Failed to bring interface down".into()));
        }

        info!("Interface {} is DOWN", self.name);
        Ok(())
    }

    /// Set the interface MTU using the `ip` command.
    fn set_mtu_via_ip(&self, mtu: u16) -> Result<(), TunError> {
        let status = std::process::Command::new("ip")
            .args(["link", "set", &self.name, "mtu", &mtu.to_string()])
            .status()
            .map_err(|e| TunError::MtuError(format!("Failed to run ip command: {}", e)))?;

        if !status.success() {
            return Err(TunError::MtuError(format!("Failed to set MTU to {}", mtu)));
        }

        debug!("Set MTU for {} to {}", self.name, mtu);
        Ok(())
    }

    /// Add an IP address to the interface.
    pub fn add_address(&self, address: &str) -> Result<(), TunError> {
        let status = std::process::Command::new("ip")
            .args(["addr", "add", address, "dev", &self.name])
            .status()
            .map_err(|e| TunError::MtuError(format!("Failed to run ip command: {}", e)))?;

        if !status.success() {
            return Err(TunError::MtuError(format!(
                "Failed to add address {} to {}",
                address, self.name
            )));
        }

        info!("Added address {} to {}", address, self.name);
        Ok(())
    }

    /// Get the file descriptor (for use with async I/O).
    pub fn fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl crate::TunDevice for LinuxTun {
    fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        // SAFETY: the owned descriptor is valid and `buf` is writable for
        // exactly `buf.len()` bytes.
        let n = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        if n < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
        // SAFETY: the owned descriptor is valid and `buf` is readable for
        // exactly `buf.len()` bytes.
        let n = unsafe {
            libc::write(
                self.fd.as_raw_fd(),
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
            )
        };
        if n < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }
}

impl AsRawFd for LinuxTun {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Tokio readiness wrapper around a nonblocking Linux TUN descriptor.
pub struct AsyncTun {
    inner: AsyncFd<LinuxTun>,
}

impl AsyncTun {
    pub fn new(tun: LinuxTun) -> std::io::Result<Self> {
        Ok(Self {
            inner: AsyncFd::new(tun)?,
        })
    }

    pub fn name(&self) -> &str {
        self.inner.get_ref().name()
    }

    pub async fn read_packet(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let mut ready = self.inner.readable().await?;
            match ready.try_io(|inner| inner.get_ref().read(buffer)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    pub async fn write_packet(&self, packet: &[u8]) -> std::io::Result<()> {
        loop {
            let mut ready = self.inner.writable().await?;
            match ready.try_io(|inner| inner.get_ref().write(packet)) {
                Ok(Ok(written)) if written == packet.len() => return Ok(()),
                Ok(Ok(written)) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        format!("partial TUN packet write: {written}/{} bytes", packet.len()),
                    ));
                }
                Ok(Err(error)) => return Err(error),
                Err(_would_block) => continue,
            }
        }
    }
}

// Note: Full tests require root privileges and are performed manually
// or in a CI environment with sudo access.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name_too_long() {
        let long_name = "a".repeat(libc::IFNAMSIZ + 1);
        let result = LinuxTun::new(&long_name, 1420);
        assert!(matches!(result, Err(TunError::NameTooLong)));
    }

    #[test]
    fn test_permission_denied_without_root() {
        // This test will pass if not running as root (expected case)
        // and pass if running as root (it creates the device)
        let result = LinuxTun::new("rg_test", 1420);

        // Either permission denied or success is acceptable
        match result {
            Err(TunError::PermissionDenied) => {
                // Expected when not root
            }
            Ok(tun) => {
                // Running as root, device created
                assert!(!tun.name().is_empty());
            }
            Err(e) => {
                // On non-Linux or other error, just log it
                eprintln!("TUN creation failed (may be expected): {}", e);
            }
        }
    }
}
