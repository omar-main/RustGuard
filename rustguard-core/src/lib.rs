//! RustGuard Core Library
//!
//! This crate provides the core functionality for RustGuard VPN:
//! - Configuration parsing and validation
//! - Permission enforcement
//! - Peer management
//! - WireGuard protocol integration (via boringtun)

pub mod config;
pub mod packet;
pub mod peer;
pub mod permissions;
pub mod runtime;
pub mod tunnel;

pub use config::{
    ClientConfig, Config, Endpoint, InterfaceConfig, LoggingConfig, PeerConfig, PublicKey,
    SecretKey, ServerConfig,
};
pub use packet::{
    parse_ipv4, validate_inbound_source, validate_outbound_destination, Ipv4Packet, PacketError,
};
pub use permissions::{check_file_permissions, PermissionError};
pub use runtime::{
    notify_systemd, recover_runtime, send_control, ControlRequest, PeerRuntimeStatus, RuntimeOwner,
    RuntimeRole, RuntimeStatus,
};
pub use tunnel::{
    Decapsulation, ServerPacketIdentity, SharedRateLimiter, TunnelError, TunnelEvent, WgTunnel,
};
