//! Configuration parsing and validation for RustGuard.
//!
//! Configuration format is TOML-based, similar to WireGuard's wg-quick format.
//! All configuration values are validated on load.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ipnet::IpNet;
use serde::{Deserialize, Deserializer};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::str::FromStr;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Errors that can occur during configuration parsing.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Failed to read config file: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Failed to parse TOML: {0}")]
    ParseError(#[from] toml::de::Error),

    #[error("Invalid private key: must be 32 bytes base64-encoded")]
    InvalidPrivateKey,

    #[error("Invalid public key: must be 32 bytes base64-encoded")]
    InvalidPublicKey,

    #[error("Invalid preshared key: must be 32 bytes base64-encoded")]
    InvalidPresharedKey,

    #[error("No peers configured")]
    NoPeers,

    #[error("Unknown field in configuration: {0}")]
    UnknownField(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Invalid MTU value: must be between 1280 and 1500")]
    InvalidMtu,

    #[error("Invalid listen port: must be between 1 and 65535")]
    InvalidPort,

    #[error("Invalid endpoint: expected an IPv4 address or hostname followed by a non-zero port")]
    InvalidEndpoint,

    #[error("Invalid {0} configuration: {1}")]
    InvalidRole(&'static str, String),

    #[error("Endpoint resolution failed for {0}: {1}")]
    Resolution(String, String),
}

/// A 32-byte key that is zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    /// Create a new SecretKey from bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes (use with caution).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material
        write!(f, "SecretKey([REDACTED])")
    }
}

/// A 32-byte public key.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// Create a new PublicKey from bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A validated endpoint name and port. Resolution is deliberately deferred
/// until client startup so hostnames are resolved before any host mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Endpoint(String);

impl Endpoint {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Resolve once at startup and select the first IPv4 result. Dynamic
    /// refresh is intentionally deferred until a reconnect policy exists.
    pub fn resolve_ipv4(&self) -> Result<SocketAddr, ConfigError> {
        self.0
            .to_socket_addrs()
            .map_err(|error| ConfigError::Resolution(self.0.clone(), error.to_string()))?
            .find(SocketAddr::is_ipv4)
            .ok_or_else(|| {
                ConfigError::Resolution(self.0.clone(), "no IPv4 address returned".into())
            })
    }
}

impl FromStr for Endpoint {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let valid = if let Ok(address) = value.parse::<SocketAddr>() {
            address.is_ipv4() && address.port() != 0
        } else if let Some((host, port)) = value.rsplit_once(':') {
            !host.is_empty()
                && !host.contains(char::is_whitespace)
                && !host.contains(':')
                && port.parse::<u16>().is_ok_and(|port| port != 0)
        } else {
            false
        };
        valid
            .then(|| Self(value.to_owned()))
            .ok_or(ConfigError::InvalidEndpoint)
    }
}

impl<'de> Deserialize<'de> for Endpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Main configuration structure.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Interface configuration
    pub interface: InterfaceConfig,

    /// Peer configurations
    #[serde(rename = "peer", default)]
    pub peers: Vec<PeerConfig>,

    /// Client-specific settings (optional)
    pub client: Option<ClientConfig>,

    /// Server-specific prerequisite policy (optional).
    pub server: Option<ServerConfig>,

    /// Logging configuration (optional)
    pub logging: Option<LoggingConfig>,
}

/// Interface configuration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceConfig {
    /// Base64-encoded private key
    #[serde(deserialize_with = "deserialize_secret_key")]
    pub private_key: SecretKey,

    /// Interface address with CIDR notation
    pub address: IpNet,

    /// Listen port (optional for clients)
    pub listen_port: Option<u16>,

    /// DNS servers to use through the tunnel
    #[serde(default)]
    pub dns: Vec<std::net::IpAddr>,

    /// MTU for the tunnel interface (default: 1420)
    #[serde(default = "default_mtu")]
    pub mtu: u16,
}

/// Peer configuration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    /// Stable human-readable label used in status output.
    pub name: Option<String>,

    /// Base64-encoded public key
    #[serde(deserialize_with = "deserialize_public_key")]
    pub public_key: PublicKey,

    /// Peer endpoint (optional for server)
    pub endpoint: Option<Endpoint>,

    /// Allowed IP ranges for this peer
    pub allowed_ips: Vec<IpNet>,

    /// Persistent keepalive interval in seconds (optional)
    pub persistent_keepalive: Option<u16>,

    /// Base64-encoded preshared key (optional)
    #[serde(default, deserialize_with = "deserialize_optional_secret_key")]
    pub preshared_key: Option<SecretKey>,
}

/// Client-specific configuration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    /// Enable kill switch
    #[serde(default)]
    pub kill_switch: bool,

    /// Enable DNS leak prevention
    #[serde(default)]
    pub dns_leak_prevention: bool,

    /// Permit direct access to common private/link-local IPv4 networks while
    /// the kill switch is active. Disabled by default to remain fail-closed.
    #[serde(default)]
    pub allow_lan: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Require IPv4 forwarding to already be enabled on the host.
    #[serde(default)]
    pub require_forwarding: bool,

    /// Require an existing nftables masquerade rule for the outbound interface.
    #[serde(default)]
    pub require_nat: bool,

    /// Physical interface used when validating an existing NAT rule.
    pub outbound_interface: Option<String>,
}

/// Logging configuration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    /// Log level: off, error, warn, info, debug, trace
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Write debug logs to file (ephemeral, /tmp)
    #[serde(default)]
    pub debug_to_file: bool,
}

fn default_mtu() -> u16 {
    1420
}

fn default_log_level() -> String {
    "info".to_string()
}

fn deserialize_secret_key<'de, D>(deserializer: D) -> Result<SecretKey, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let bytes = BASE64
        .decode(&s)
        .map_err(|_| serde::de::Error::custom("invalid base64"))?;

    if bytes.len() != 32 {
        return Err(serde::de::Error::custom("key must be 32 bytes"));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(SecretKey::new(arr))
}

fn deserialize_public_key<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let bytes = BASE64
        .decode(&s)
        .map_err(|_| serde::de::Error::custom("invalid base64"))?;

    if bytes.len() != 32 {
        return Err(serde::de::Error::custom("key must be 32 bytes"));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(PublicKey::new(arr))
}

fn deserialize_optional_secret_key<'de, D>(deserializer: D) -> Result<Option<SecretKey>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    match opt {
        None => Ok(None),
        Some(s) => {
            let bytes = BASE64
                .decode(&s)
                .map_err(|_| serde::de::Error::custom("invalid base64"))?;

            if bytes.len() != 32 {
                return Err(serde::de::Error::custom("key must be 32 bytes"));
            }

            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(Some(SecretKey::new(arr)))
        }
    }
}

impl Config {
    /// Load configuration from a TOML file.
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        Self::parse(&content)
    }

    /// Parse configuration from a TOML string.
    pub fn parse(content: &str) -> Result<Self, ConfigError> {
        let config: Config = toml::from_str(content)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration.
    fn validate(&self) -> Result<(), ConfigError> {
        // Validate MTU
        if self.interface.mtu < 1280 || self.interface.mtu > 1500 {
            return Err(ConfigError::InvalidMtu);
        }

        // Validate listen port if present
        if let Some(port) = self.interface.listen_port {
            if port == 0 {
                return Err(ConfigError::InvalidPort);
            }
        }

        // Ensure at least one peer
        if self.peers.is_empty() {
            return Err(ConfigError::NoPeers);
        }

        if !self.interface.address.addr().is_ipv4() {
            return Err(ConfigError::InvalidRole(
                "shared",
                "only IPv4 interface addresses are supported".into(),
            ));
        }

        let valid_levels = ["off", "error", "warn", "info", "debug", "trace"];
        if self
            .logging
            .as_ref()
            .is_some_and(|logging| !valid_levels.contains(&logging.level.as_str()))
        {
            return Err(ConfigError::InvalidRole(
                "shared",
                "logging.level must be off, error, warn, info, debug, or trace".into(),
            ));
        }

        Ok(())
    }

    pub fn validate_client(&self) -> Result<(), ConfigError> {
        if self.server.is_some() {
            return Err(role_error("client", "the [server] section is not allowed"));
        }
        if self.peers.len() != 1 {
            return Err(role_error(
                "client",
                "exactly one peer is currently supported",
            ));
        }
        if self.interface.listen_port.is_some() {
            return Err(role_error("client", "interface.listen_port is server-only"));
        }
        let peer = &self.peers[0];
        if peer.endpoint.is_none() {
            return Err(role_error("client", "peer.endpoint is required"));
        }
        validate_ipv4_networks("client", &peer.allowed_ips)?;
        if self.interface.dns.iter().any(|server| !server.is_ipv4()) {
            return Err(role_error("client", "only IPv4 DNS servers are supported"));
        }
        if let Some(client) = &self.client {
            if client.allow_lan && !client.kill_switch {
                return Err(role_error(
                    "client",
                    "client.allow_lan requires client.kill_switch",
                ));
            }
            if client.dns_leak_prevention {
                if self.interface.dns.is_empty() {
                    return Err(role_error(
                        "client",
                        "DNS leak prevention requires interface.dns",
                    ));
                }
                if self.interface.dns.iter().any(|server| {
                    !peer
                        .allowed_ips
                        .iter()
                        .any(|network| network.contains(server))
                }) {
                    return Err(role_error(
                        "client",
                        "protected DNS servers must be inside peer.allowed_ips",
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn validate_server(&self) -> Result<(), ConfigError> {
        if self.client.is_some() {
            return Err(role_error("server", "the [client] section is not allowed"));
        }
        if self.peers.len() > 256 {
            return Err(role_error("server", "at most 256 peers are supported"));
        }
        if self.interface.listen_port.is_none() {
            return Err(role_error("server", "interface.listen_port is required"));
        }
        if !self.interface.dns.is_empty() {
            return Err(role_error("server", "interface.dns is client-only"));
        }
        if self.server.as_ref().is_some_and(|server| {
            server.require_nat
                && (!server.require_forwarding || server.outbound_interface.is_none())
        }) {
            return Err(role_error(
                "server",
                "require_nat needs require_forwarding and outbound_interface",
            ));
        }
        if self
            .server
            .as_ref()
            .and_then(|server| server.outbound_interface.as_deref())
            .is_some_and(|name| {
                name.is_empty()
                    || name.len() > 15
                    || !name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            })
        {
            return Err(role_error("server", "outbound_interface is invalid"));
        }
        let mut names = std::collections::HashSet::new();
        let mut keys = std::collections::HashSet::new();
        for (index, peer) in self.peers.iter().enumerate() {
            if peer.endpoint.is_some() {
                return Err(role_error(
                    "server",
                    "peer.endpoint must be learned from authenticated traffic",
                ));
            }
            validate_ipv4_networks("server", &peer.allowed_ips)?;
            if peer
                .allowed_ips
                .iter()
                .any(|network| network.contains(&self.interface.address.addr()))
            {
                return Err(role_error(
                    "server",
                    "a peer allowed network contains the server interface address",
                ));
            }
            let name = peer
                .name
                .clone()
                .unwrap_or_else(|| format!("peer-{}", index + 1));
            if name.is_empty()
                || name.len() > 32
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            {
                return Err(role_error(
                    "server",
                    "peer.name must use 1-32 letters, digits, '-' or '_'",
                ));
            }
            if !names.insert(name) || !keys.insert(peer.public_key.clone()) {
                return Err(role_error(
                    "server",
                    "peer names and public keys must be unique",
                ));
            }
        }
        for (left_index, left) in self.peers.iter().enumerate() {
            for right in self.peers.iter().skip(left_index + 1) {
                for left_network in &left.allowed_ips {
                    for right_network in &right.allowed_ips {
                        if left_network.contains(&right_network.addr())
                            || right_network.contains(&left_network.addr())
                        {
                            return Err(role_error(
                                "server",
                                "allowed IP ownership overlaps between peers",
                            ));
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

fn role_error(role: &'static str, message: &str) -> ConfigError {
    ConfigError::InvalidRole(role, message.into())
}

fn validate_ipv4_networks(role: &'static str, networks: &[IpNet]) -> Result<(), ConfigError> {
    if networks.is_empty() || networks.iter().any(|network| !network.addr().is_ipv4()) {
        return Err(role_error(
            role,
            "peer.allowed_ips must contain IPv4 networks only",
        ));
    }
    for (index, left) in networks.iter().enumerate() {
        for right in networks.iter().skip(index + 1) {
            if left.contains(&right.addr()) || right.contains(&left.addr()) {
                return Err(role_error(
                    role,
                    "peer.allowed_ips contains duplicate or overlapping networks",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Valid 32-byte keys encoded as base64:
    // [0u8; 32] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    // [1u8; 32] = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
    const VALID_PRIVATE_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const VALID_PUBLIC_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

    const VALID_CONFIG: &str = r#"
[interface]
private_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
address = "10.0.0.2/24"
listen_port = 51820
dns = ["10.0.0.1"]
mtu = 1420

[[peer]]
public_key = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
endpoint = "192.168.1.1:51820"
allowed_ips = ["0.0.0.0/0"]
persistent_keepalive = 25

[client]
kill_switch = true
dns_leak_prevention = true

[logging]
level = "info"
debug_to_file = false
"#;

    #[test]
    fn test_parse_valid_config() {
        let config = Config::parse(VALID_CONFIG).expect("should parse valid config");
        assert_eq!(config.interface.mtu, 1420);
        assert_eq!(config.peers.len(), 1);
        assert!(config.client.is_some());
    }

    #[test]
    fn endpoint_accepts_hostname_and_resolves_numeric_ipv4() {
        let hostname: Endpoint = "vpn.example.com:51820".parse().unwrap();
        assert_eq!(hostname.as_str(), "vpn.example.com:51820");
        let numeric: Endpoint = "127.0.0.1:51820".parse().unwrap();
        assert_eq!(
            numeric.resolve_ipv4().unwrap(),
            "127.0.0.1:51820".parse().unwrap()
        );
    }

    #[test]
    fn shipped_examples_match_their_role_schemas() {
        let client = Config::parse(include_str!("../../examples/client.toml")).unwrap();
        client.validate_client().unwrap();
        let server = Config::parse(include_str!("../../examples/server.toml")).unwrap();
        server.validate_server().unwrap();
    }

    #[test]
    fn role_specific_fields_are_rejected_before_runtime_setup() {
        let mut client = Config::parse(VALID_CONFIG).unwrap();
        assert!(client.validate_client().is_err()); // listen_port is server-only
        client.interface.listen_port = None;
        client.validate_client().unwrap();
        assert!(client.validate_server().is_err()); // [client] is not valid for server
    }

    #[test]
    fn overlapping_routes_and_unrouted_protected_dns_are_rejected() {
        let overlapping = VALID_CONFIG.replace(
            "allowed_ips = [\"0.0.0.0/0\"]",
            "allowed_ips = [\"0.0.0.0/0\", \"10.0.0.0/8\"]",
        );
        let mut config = Config::parse(&overlapping).unwrap();
        config.interface.listen_port = None;
        assert!(config.validate_client().is_err());

        let split = VALID_CONFIG.replace(
            "allowed_ips = [\"0.0.0.0/0\"]",
            "allowed_ips = [\"192.0.2.0/24\"]",
        );
        let mut config = Config::parse(&split).unwrap();
        config.interface.listen_port = None;
        assert!(config.validate_client().is_err());
    }

    #[test]
    fn server_accepts_distinct_peers_and_rejects_ownership_overlap() {
        let config = format!(
            r#"
[interface]
private_key = "{VALID_PRIVATE_KEY}"
address = "10.50.0.1/24"
listen_port = 51820

[[peer]]
name = "laptop"
public_key = "{VALID_PUBLIC_KEY}"
allowed_ips = ["10.50.0.2/32"]

[[peer]]
name = "phone"
public_key = "{}"
allowed_ips = ["10.50.0.3/32"]
"#,
            BASE64.encode([2_u8; 32])
        );
        Config::parse(&config).unwrap().validate_server().unwrap();

        let overlap = config.replace("10.50.0.3/32", "10.50.0.2/31");
        assert!(Config::parse(&overlap).unwrap().validate_server().is_err());
    }

    #[test]
    fn test_reject_unknown_field() {
        let config = format!(
            r#"
[interface]
private_key = "{}"
address = "10.0.0.2/24"
unknown_field = "should fail"

[[peer]]
public_key = "{}"
allowed_ips = ["0.0.0.0/0"]
"#,
            VALID_PRIVATE_KEY, VALID_PUBLIC_KEY
        );
        let result = Config::parse(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_invalid_mtu() {
        let config = format!(
            r#"
[interface]
private_key = "{}"
address = "10.0.0.2/24"
mtu = 500

[[peer]]
public_key = "{}"
allowed_ips = ["0.0.0.0/0"]
"#,
            VALID_PRIVATE_KEY, VALID_PUBLIC_KEY
        );
        let result = Config::parse(&config);
        assert!(matches!(result, Err(ConfigError::InvalidMtu)));
    }

    #[test]
    fn test_reject_no_peers() {
        let config = format!(
            r#"
[interface]
private_key = "{}"
address = "10.0.0.2/24"
"#,
            VALID_PRIVATE_KEY
        );
        let result = Config::parse(&config);
        assert!(matches!(result, Err(ConfigError::NoPeers)));
    }

    #[test]
    fn test_secret_key_debug_redacted() {
        let key = SecretKey::new([0u8; 32]);
        let debug_str = format!("{:?}", key);
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains("0, 0, 0"));
    }

    #[test]
    fn test_reject_invalid_base64_key() {
        let config = format!(
            r#"
[interface]
private_key = "not-valid-base64!!!"
address = "10.0.0.2/24"

[[peer]]
public_key = "{}"
allowed_ips = ["0.0.0.0/0"]
"#,
            VALID_PUBLIC_KEY
        );
        let result = Config::parse(&config);
        assert!(result.is_err());
    }
}
