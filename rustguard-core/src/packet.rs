//! Minimal IP packet validation used at the tunnel boundary.

use ipnet::IpNet;
use std::net::{IpAddr, Ipv4Addr};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4Packet {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub length: usize,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PacketError {
    #[error("packet is shorter than an IPv4 header")]
    TooShort,
    #[error("only IPv4 packets are supported in this milestone")]
    UnsupportedVersion,
    #[error("IPv4 header length is invalid")]
    InvalidHeaderLength,
    #[error("IPv4 total length is invalid")]
    InvalidTotalLength,
    #[error("{role} address {address} is not allowed for the configured peer")]
    AddressNotAllowed {
        role: &'static str,
        address: Ipv4Addr,
    },
}

pub fn parse_ipv4(packet: &[u8]) -> Result<Ipv4Packet, PacketError> {
    if packet.len() < 20 {
        return Err(PacketError::TooShort);
    }
    if packet[0] >> 4 != 4 {
        return Err(PacketError::UnsupportedVersion);
    }

    let header_length = usize::from(packet[0] & 0x0f) * 4;
    if header_length < 20 || header_length > packet.len() {
        return Err(PacketError::InvalidHeaderLength);
    }

    let total_length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_length < header_length || total_length > packet.len() {
        return Err(PacketError::InvalidTotalLength);
    }

    Ok(Ipv4Packet {
        source: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        destination: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        length: total_length,
    })
}

pub fn validate_inbound_source(packet: &[u8], allowed: &[IpNet]) -> Result<usize, PacketError> {
    let parsed = parse_ipv4(packet)?;
    if is_allowed(parsed.source, allowed) {
        Ok(parsed.length)
    } else {
        Err(PacketError::AddressNotAllowed {
            role: "source",
            address: parsed.source,
        })
    }
}

pub fn validate_outbound_destination(
    packet: &[u8],
    allowed: &[IpNet],
) -> Result<usize, PacketError> {
    let parsed = parse_ipv4(packet)?;
    if is_allowed(parsed.destination, allowed) {
        Ok(parsed.length)
    } else {
        Err(PacketError::AddressNotAllowed {
            role: "destination",
            address: parsed.destination,
        })
    }
}

fn is_allowed(address: Ipv4Addr, allowed: &[IpNet]) -> bool {
    allowed
        .iter()
        .any(|network| network.contains(&IpAddr::V4(address)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
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

    #[test]
    fn parses_ipv4_addresses_and_length() {
        let parsed = parse_ipv4(&packet([10, 0, 0, 2], [10, 0, 0, 1])).unwrap();
        assert_eq!(parsed.source, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(parsed.destination, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(parsed.length, 20);
    }

    #[test]
    fn rejects_malformed_and_ipv6_packets() {
        assert_eq!(parse_ipv4(&[0; 19]), Err(PacketError::TooShort));

        let mut ipv6 = packet([10, 0, 0, 2], [10, 0, 0, 1]);
        ipv6[0] = 0x60;
        assert_eq!(parse_ipv4(&ipv6), Err(PacketError::UnsupportedVersion));

        let mut bad_length = packet([10, 0, 0, 2], [10, 0, 0, 1]);
        bad_length[2..4].copy_from_slice(&40_u16.to_be_bytes());
        assert_eq!(
            parse_ipv4(&bad_length),
            Err(PacketError::InvalidTotalLength)
        );
    }

    #[test]
    fn enforces_peer_source_and_destination() {
        let allowed = ["10.0.0.2/32".parse().unwrap()];
        let valid = packet([10, 0, 0, 2], [10, 0, 0, 2]);
        let invalid = packet([10, 0, 0, 3], [10, 0, 0, 3]);

        assert_eq!(validate_inbound_source(&valid, &allowed), Ok(20));
        assert_eq!(validate_outbound_destination(&valid, &allowed), Ok(20));
        assert!(matches!(
            validate_inbound_source(&invalid, &allowed),
            Err(PacketError::AddressNotAllowed { role: "source", .. })
        ));
        assert!(matches!(
            validate_outbound_destination(&invalid, &allowed),
            Err(PacketError::AddressNotAllowed {
                role: "destination",
                ..
            })
        ));
    }
}
