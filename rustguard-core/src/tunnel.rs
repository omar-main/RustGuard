//! Owned, single-peer WireGuard tunnel adapter.
//!
//! `boringtun` returns slices backed by the destination buffer supplied to each
//! call. This adapter copies those slices into owned events and drains every
//! queued decapsulation result before returning to the event loop.

use crate::config::{PublicKey, SecretKey};
use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::noise::{Packet, Tunn, TunnResult};
use boringtun::x25519::{PublicKey as X25519Public, StaticSecret};
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;

const SCRATCH_BUFFER_SIZE: usize = 65_536;
const MAX_DRAIN_EVENTS: usize = 256;

/// Errors produced by the WireGuard adapter.
#[derive(Debug, Error)]
pub enum TunnelError {
    #[error("failed to create tunnel: {0}")]
    Creation(String),

    #[error("encapsulation failed: {0}")]
    Encapsulation(String),

    #[error("decapsulation failed: {0}")]
    Decapsulation(String),

    #[error("timer processing failed: {0}")]
    Timer(String),

    #[error("protocol engine produced too many queued events")]
    DrainLimitExceeded,

    #[error("protocol engine returned an unexpected result for {0}")]
    UnexpectedResult(&'static str),
}

/// An owned action produced while processing an encrypted UDP datagram.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TunnelEvent {
    /// Send an encrypted WireGuard datagram over UDP.
    WriteToNetwork(Vec<u8>),
    /// Write a decrypted IPv4 packet to the TUN interface.
    WriteToTunnelV4(Vec<u8>),
    /// A decrypted IPv6 packet. IPv6 transport is not enabled in this milestone.
    WriteToTunnelV6(Vec<u8>),
}

/// Result of a server-side pre-authentication dispatch check.
#[derive(Debug, Eq, PartialEq)]
pub enum ServerPacketIdentity {
    /// A handshake initiation decrypted to this configured static public key.
    PeerKey([u8; 32]),
    /// Established packets carry the peer number in the high index bits.
    PeerIndex(u32),
    /// The shared limiter requires a cookie response before more work is done.
    CookieReply(Vec<u8>),
}

/// One limiter shared by every peer on a server listener.
#[derive(Clone)]
pub struct SharedRateLimiter(Arc<RateLimiter>);

impl SharedRateLimiter {
    pub fn for_server(private_key: &SecretKey, handshakes_per_second: u64) -> Self {
        let private = StaticSecret::from(*private_key.as_bytes());
        let public = X25519Public::from(&private);
        Self(Arc::new(RateLimiter::new(&public, handshakes_per_second)))
    }

    pub fn classify(
        &self,
        private_key: &SecretKey,
        source: std::net::IpAddr,
        datagram: &[u8],
    ) -> Result<ServerPacketIdentity, TunnelError> {
        // A WireGuard cookie reply is exactly 64 bytes; avoid a per-datagram
        // heap allocation on the unauthenticated listener path.
        let mut response = [0_u8; 64];
        let packet = match self.0.verify_packet(Some(source), datagram, &mut response) {
            Ok(packet) => packet,
            Err(TunnResult::WriteToNetwork(cookie)) => {
                return Ok(ServerPacketIdentity::CookieReply(cookie.to_vec()));
            }
            Err(TunnResult::Err(error)) => {
                return Err(TunnelError::Decapsulation(format!("{error:?}")));
            }
            Err(_) => {
                return Err(TunnelError::UnexpectedResult(
                    "server packet classification",
                ))
            }
        };
        match packet {
            Packet::HandshakeInit(handshake) => {
                let private = StaticSecret::from(*private_key.as_bytes());
                let public = X25519Public::from(&private);
                let half = parse_handshake_anon(&private, &public, &handshake)
                    .map_err(|error| TunnelError::Decapsulation(format!("{error:?}")))?;
                Ok(ServerPacketIdentity::PeerKey(half.peer_static_public))
            }
            Packet::HandshakeResponse(packet) => {
                Ok(ServerPacketIdentity::PeerIndex(packet.receiver_idx >> 8))
            }
            Packet::PacketCookieReply(packet) => {
                Ok(ServerPacketIdentity::PeerIndex(packet.receiver_idx >> 8))
            }
            Packet::PacketData(packet) => {
                Ok(ServerPacketIdentity::PeerIndex(packet.receiver_idx >> 8))
            }
        }
    }
}

/// Owned decapsulation results plus whether the packet passed the selected
/// peer's cryptographic state machine (including an empty authenticated keepalive).
pub struct Decapsulation {
    pub events: Vec<TunnelEvent>,
    pub authenticated: bool,
}

/// WireGuard protocol state for one configured peer.
pub struct WgTunnel {
    tunn: Tunn,
    /// Current UDP endpoint for this peer.
    pub endpoint: Option<SocketAddr>,
    scratch: Vec<u8>,
}

impl WgTunnel {
    /// Create one peer tunnel.
    pub fn new(
        private_key: &SecretKey,
        peer_public_key: &PublicKey,
        preshared_key: Option<&[u8; 32]>,
        persistent_keepalive: Option<u16>,
        index: u32,
    ) -> Result<Self, TunnelError> {
        Self::new_with_rate_limiter(
            private_key,
            peer_public_key,
            preshared_key,
            persistent_keepalive,
            index,
            None,
        )
    }

    pub fn new_with_rate_limiter(
        private_key: &SecretKey,
        peer_public_key: &PublicKey,
        preshared_key: Option<&[u8; 32]>,
        persistent_keepalive: Option<u16>,
        index: u32,
        rate_limiter: Option<&SharedRateLimiter>,
    ) -> Result<Self, TunnelError> {
        let static_private = StaticSecret::from(*private_key.as_bytes());
        let peer_static_public = X25519Public::from(*peer_public_key.as_bytes());

        let tunn = Tunn::new(
            static_private,
            peer_static_public,
            preshared_key.copied(),
            persistent_keepalive,
            index,
            rate_limiter.map(|limiter| Arc::clone(&limiter.0)),
        );

        Ok(Self {
            tunn,
            endpoint: None,
            scratch: vec![0; SCRATCH_BUFFER_SIZE],
        })
    }

    /// Set or update the peer's UDP endpoint.
    pub fn set_endpoint(&mut self, endpoint: SocketAddr) {
        self.endpoint = Some(endpoint);
    }

    /// Encrypt one IP packet for the peer.
    pub fn encapsulate(&mut self, packet: &[u8]) -> Result<Option<Vec<u8>>, TunnelError> {
        match self.tunn.encapsulate(packet, &mut self.scratch) {
            TunnResult::Done => Ok(None),
            TunnResult::WriteToNetwork(data) => Ok(Some(data.to_vec())),
            TunnResult::Err(error) => Err(TunnelError::Encapsulation(format!("{error:?}"))),
            TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                Err(TunnelError::UnexpectedResult("encapsulation"))
            }
        }
    }

    /// Process one UDP datagram and drain all queued protocol-engine outputs.
    ///
    /// The first call receives `datagram` and its source IP. Every subsequent
    /// call uses an empty datagram, as required by `boringtun`, until `Done`.
    pub fn decapsulate(
        &mut self,
        source: std::net::IpAddr,
        datagram: &[u8],
    ) -> Result<Vec<TunnelEvent>, TunnelError> {
        Ok(self.decapsulate_authenticated(source, datagram)?.events)
    }

    pub fn decapsulate_authenticated(
        &mut self,
        source: std::net::IpAddr,
        datagram: &[u8],
    ) -> Result<Decapsulation, TunnelError> {
        let mut events = Vec::new();
        let mut input = datagram;
        let mut source_ip = Some(source);

        for _ in 0..MAX_DRAIN_EVENTS {
            let result = self.tunn.decapsulate(source_ip, input, &mut self.scratch);

            match result {
                TunnResult::Done => {
                    return Ok(Decapsulation {
                        events,
                        authenticated: true,
                    });
                }
                TunnResult::WriteToNetwork(data) => {
                    events.push(TunnelEvent::WriteToNetwork(data.to_vec()));
                }
                TunnResult::WriteToTunnelV4(data, _) => {
                    events.push(TunnelEvent::WriteToTunnelV4(data.to_vec()));
                }
                TunnResult::WriteToTunnelV6(data, _) => {
                    events.push(TunnelEvent::WriteToTunnelV6(data.to_vec()));
                }
                TunnResult::Err(error) => {
                    return Err(TunnelError::Decapsulation(format!("{error:?}")));
                }
            }

            input = &[];
            source_ip = None;
        }

        Err(TunnelError::DrainLimitExceeded)
    }

    /// Process handshake retry, keepalive, and rekey timers.
    pub fn update_timers(&mut self) -> Result<Option<Vec<u8>>, TunnelError> {
        match self.tunn.update_timers(&mut self.scratch) {
            TunnResult::Done => Ok(None),
            TunnResult::WriteToNetwork(data) => Ok(Some(data.to_vec())),
            TunnResult::Err(error) => Err(TunnelError::Timer(format!("{error:?}"))),
            TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                Err(TunnelError::UnexpectedResult("timer processing"))
            }
        }
    }

    /// Time since this peer's most recent authenticated handshake.
    pub fn time_since_last_handshake(&self) -> Option<std::time::Duration> {
        self.tunn.time_since_last_handshake()
    }

    /// Whether the current protocol session is expired.
    pub fn is_expired(&self) -> bool {
        self.tunn.is_expired()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{PublicKey as DalekPublicKey, StaticSecret as DalekSecret};

    const CLIENT_IP: std::net::IpAddr =
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 10));
    const SERVER_IP: std::net::IpAddr =
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 20));

    fn make_pair() -> (WgTunnel, WgTunnel) {
        let client_private = SecretKey::new([7; 32]);
        let server_private = SecretKey::new([9; 32]);
        let client_public = PublicKey::new(
            *DalekPublicKey::from(&DalekSecret::from(*client_private.as_bytes())).as_bytes(),
        );
        let server_public = PublicKey::new(
            *DalekPublicKey::from(&DalekSecret::from(*server_private.as_bytes())).as_bytes(),
        );

        let client = WgTunnel::new(&client_private, &server_public, None, None, 1).unwrap();
        let server = WgTunnel::new(&server_private, &client_public, None, None, 2).unwrap();
        (client, server)
    }

    fn ipv4_packet(source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
        vec![
            0x45,
            0,
            0,
            20,
            0,
            0,
            0,
            0,
            64,
            0,
            0,
            0,
            source[0],
            source[1],
            source[2],
            source[3],
            destination[0],
            destination[1],
            destination[2],
            destination[3],
        ]
    }

    fn deliver(
        recipient: &mut WgTunnel,
        source: std::net::IpAddr,
        datagrams: impl IntoIterator<Item = Vec<u8>>,
    ) -> Vec<TunnelEvent> {
        datagrams
            .into_iter()
            .flat_map(|datagram| recipient.decapsulate(source, &datagram).unwrap())
            .collect()
    }

    fn network_events(events: &[TunnelEvent]) -> Vec<Vec<u8>> {
        events
            .iter()
            .filter_map(|event| match event {
                TunnelEvent::WriteToNetwork(data) => Some(data.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn handshake_drains_queued_packet_from_the_supplied_buffer() {
        let (mut client, mut server) = make_pair();
        let packet = ipv4_packet([10, 0, 0, 2], [10, 0, 0, 1]);

        let initiation = client.encapsulate(&packet).unwrap().unwrap();
        let server_events = server.decapsulate(CLIENT_IP, &initiation).unwrap();
        let client_events = deliver(&mut client, SERVER_IP, network_events(&server_events));

        // Parsing the response emits a keepalive and draining emits the packet
        // that was queued before the handshake completed.
        let server_events = deliver(&mut server, CLIENT_IP, network_events(&client_events));

        assert!(server_events
            .iter()
            .any(|event| event == &TunnelEvent::WriteToTunnelV4(packet.clone())));
        assert!(client.time_since_last_handshake().is_some());
        assert!(server.time_since_last_handshake().is_some());
    }

    #[test]
    fn established_tunnel_transports_packets_in_both_directions() {
        let (mut client, mut server) = make_pair();
        let outbound = ipv4_packet([10, 0, 0, 2], [10, 0, 0, 1]);

        let initiation = client.encapsulate(&outbound).unwrap().unwrap();
        let response = server.decapsulate(CLIENT_IP, &initiation).unwrap();
        let completion = deliver(&mut client, SERVER_IP, network_events(&response));
        let _ = deliver(&mut server, CLIENT_IP, network_events(&completion));

        let reply = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2]);
        let encrypted = server.encapsulate(&reply).unwrap().unwrap();
        let events = client.decapsulate(SERVER_IP, &encrypted).unwrap();

        assert_eq!(events, vec![TunnelEvent::WriteToTunnelV4(reply)]);
    }

    #[test]
    fn shared_server_classifier_recovers_handshake_identity() {
        let server_private = SecretKey::new([9; 32]);
        let client_private = SecretKey::new([7; 32]);
        let client_public = PublicKey::new(
            *DalekPublicKey::from(&DalekSecret::from(*client_private.as_bytes())).as_bytes(),
        );
        let server_public = PublicKey::new(
            *DalekPublicKey::from(&DalekSecret::from(*server_private.as_bytes())).as_bytes(),
        );
        let limiter = SharedRateLimiter::for_server(&server_private, 100);
        let mut client = WgTunnel::new(&client_private, &server_public, None, None, 1).unwrap();
        let initiation = client
            .encapsulate(&ipv4_packet([10, 0, 0, 2], [10, 0, 0, 1]))
            .unwrap()
            .unwrap();
        assert_eq!(
            limiter
                .classify(&server_private, CLIENT_IP, &initiation)
                .unwrap(),
            ServerPacketIdentity::PeerKey(*client_public.as_bytes())
        );
    }

    #[test]
    fn zero_limit_returns_cookie_without_peer_work() {
        let server_private = SecretKey::new([9; 32]);
        let client_private = SecretKey::new([7; 32]);
        let server_public = PublicKey::new(
            *DalekPublicKey::from(&DalekSecret::from(*server_private.as_bytes())).as_bytes(),
        );
        let limiter = SharedRateLimiter::for_server(&server_private, 0);
        let mut client = WgTunnel::new(&client_private, &server_public, None, None, 1).unwrap();
        let initiation = client
            .encapsulate(&ipv4_packet([10, 0, 0, 2], [10, 0, 0, 1]))
            .unwrap()
            .unwrap();
        assert!(matches!(
            limiter
                .classify(&server_private, CLIENT_IP, &initiation)
                .unwrap(),
            ServerPacketIdentity::CookieReply(_)
        ));
    }
}
