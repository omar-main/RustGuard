//! Peer state management.
//!
//! This module handles peer state tracking and allowed-IPs matching.

use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use crate::config::{PeerConfig, PublicKey, SecretKey};

/// Represents a configured peer.
#[derive(Debug)]
pub struct Peer {
    /// Peer's public key
    pub public_key: PublicKey,

    /// Allowed IP ranges for this peer
    pub allowed_ips: Vec<IpNet>,

    /// Peer's endpoint (may be learned dynamically)
    pub endpoint: Option<SocketAddr>,

    /// Persistent keepalive interval in seconds
    pub persistent_keepalive: Option<u16>,

    /// Optional preshared key
    pub preshared_key: Option<SecretKey>,

    /// Active session state (if established)
    session: Option<Session>,
}

/// Active session with a peer.
#[derive(Debug)]
pub struct Session {
    /// When the session was established
    pub created_at: Instant,

    /// Bytes sent through this session
    pub bytes_sent: u64,

    /// Bytes received through this session
    pub bytes_recv: u64,
}

impl Peer {
    /// Create a new peer from configuration.
    pub fn from_config(config: PeerConfig) -> Self {
        Self {
            public_key: config.public_key,
            allowed_ips: config.allowed_ips,
            endpoint: None,
            persistent_keepalive: config.persistent_keepalive,
            preshared_key: config.preshared_key,
            session: None,
        }
    }

    /// Check if an IP address is allowed for this peer.
    pub fn is_ip_allowed(&self, addr: IpAddr) -> bool {
        self.allowed_ips.iter().any(|net| net.contains(&addr))
    }

    /// Update the peer's endpoint.
    pub fn update_endpoint(&mut self, endpoint: SocketAddr) {
        self.endpoint = Some(endpoint);
    }

    /// Check if a session is active.
    pub fn has_session(&self) -> bool {
        self.session.is_some()
    }

    /// Get session statistics (bytes sent, bytes received).
    pub fn session_stats(&self) -> Option<(u64, u64)> {
        self.session.as_ref().map(|s| (s.bytes_sent, s.bytes_recv))
    }

    /// Record bytes sent through the session.
    pub fn add_bytes_sent(&mut self, bytes: u64) {
        if let Some(ref mut session) = self.session {
            session.bytes_sent = session.bytes_sent.saturating_add(bytes);
        }
    }

    /// Record bytes received through the session.
    pub fn add_bytes_recv(&mut self, bytes: u64) {
        if let Some(ref mut session) = self.session {
            session.bytes_recv = session.bytes_recv.saturating_add(bytes);
        }
    }

    /// Start a new session.
    pub fn start_session(&mut self) {
        self.session = Some(Session {
            created_at: Instant::now(),
            bytes_sent: 0,
            bytes_recv: 0,
        });
    }

    /// End the current session.
    pub fn end_session(&mut self) {
        self.session = None;
    }
}

/// Find the peer that should handle traffic for a given destination IP.
pub fn find_peer_for_ip(peers: &[Peer], dest: IpAddr) -> Option<&Peer> {
    // Find the peer with the most specific matching allowed-IP
    let mut best_match: Option<(&Peer, u8)> = None;

    for peer in peers {
        for net in &peer.allowed_ips {
            if net.contains(&dest) {
                let prefix_len = net.prefix_len();
                if best_match.is_none_or(|(_, len)| prefix_len > len) {
                    best_match = Some((peer, prefix_len));
                }
            }
        }
    }

    best_match.map(|(peer, _)| peer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn make_test_peer(allowed_ips: &[&str]) -> Peer {
        Peer {
            public_key: PublicKey::new([0u8; 32]),
            allowed_ips: allowed_ips
                .iter()
                .map(|s| IpNet::from_str(s).unwrap())
                .collect(),
            endpoint: None,
            persistent_keepalive: None,
            preshared_key: None,
            session: None,
        }
    }

    #[test]
    fn test_ip_allowed() {
        let peer = make_test_peer(&["10.0.0.0/24", "192.168.1.0/24"]);

        assert!(peer.is_ip_allowed(IpAddr::from_str("10.0.0.1").unwrap()));
        assert!(peer.is_ip_allowed(IpAddr::from_str("10.0.0.255").unwrap()));
        assert!(peer.is_ip_allowed(IpAddr::from_str("192.168.1.100").unwrap()));
        assert!(!peer.is_ip_allowed(IpAddr::from_str("10.0.1.1").unwrap()));
        assert!(!peer.is_ip_allowed(IpAddr::from_str("8.8.8.8").unwrap()));
    }

    #[test]
    fn test_find_peer_most_specific() {
        let peer1 = make_test_peer(&["0.0.0.0/0"]); // Default route
        let peer2 = make_test_peer(&["10.0.0.0/8"]); // More specific
        let peer3 = make_test_peer(&["10.0.0.0/24"]); // Most specific

        let peers = vec![peer1, peer2, peer3];
        let dest = IpAddr::from_str("10.0.0.5").unwrap();

        let found = find_peer_for_ip(&peers, dest).unwrap();
        // Should match the most specific (10.0.0.0/24)
        assert!(found.allowed_ips.iter().any(|n| n.prefix_len() == 24));
    }

    #[test]
    fn test_session_stats() {
        let mut peer = make_test_peer(&["10.0.0.0/24"]);

        assert!(!peer.has_session());
        assert!(peer.session_stats().is_none());

        peer.start_session();
        assert!(peer.has_session());

        peer.add_bytes_sent(1000);
        peer.add_bytes_recv(500);

        let (sent, recv) = peer.session_stats().unwrap();
        assert_eq!(sent, 1000);
        assert_eq!(recv, 500);

        peer.end_session();
        assert!(!peer.has_session());
    }
}
