# Goals and Non-Goals

This document controls scope. A feature is not part of RustGuard merely because
another VPN product provides it.

## Product goals

- Provide a usable self-hosted VPN between Linux devices.
- Interoperate in both directions with standard WireGuard implementations.
- Support full-tunnel and split-tunnel IPv4 routing.
- Make every host-network mutation transactional and attributable to RustGuard.
- Provide an optional kill switch that fails closed when requested.
- Configure DNS without permanently replacing or corrupting host resolver state.
- Support graceful shutdown and explicit crash recovery.
- Report meaningful health without exposing keys or packet contents.
- Support multiple personal devices on a single server.
- Provide reproducible installation and systemd service management.
- Back security and reliability claims with automated tests.

## Engineering goals

- Keep unsafe and platform-specific code small and reviewed.
- Separate protocol state, packet transport, host configuration, and CLI logic.
- Prefer typed operations and structured errors over shell-string construction.
- Use maintained dependencies and continuously audit the dependency graph.
- Make setup and cleanup idempotent.
- Keep the repository approachable to another Rust developer.
- Record architectural and security decisions when tradeoffs are non-obvious.

## Project quality goals

- Use clear Rust ownership, error handling, concurrency, and testing practices.
- Keep TUN, UDP, routing, DNS, nftables, NAT, and protocol boundaries explicit.
- Correct prototype defects with reproducible regression evidence.
- Maintain clear requirements, architecture, threat-model, and testing documents.
- Keep CI green and releases reproducible.

## Non-goals

- Designing or modifying the WireGuard cryptographic protocol.
- Claiming anonymity against a global observer, ISP, hosting provider, or server
  operator.
- Providing a commercial network of geographic exit locations.
- Multi-hop routing, onion routing, or traffic-obfuscation protocols.
- Advertising, account management, payment, or subscription infrastructure.
- Windows, macOS, Android, iOS, or graphical clients in the initial project.
- Supporting every Linux DNS manager, firewall frontend, or distribution at
  once.
- Hiding all traffic metadata such as connection times and byte counts.
- Replacing a professional security audit with automated tooling.

## Initial compatibility boundary

The first verified release targets a documented set of current Linux
distributions using:

- The kernel TUN interface.
- nftables for firewall policy.
- `iproute2` for address and route configuration.
- `systemd-resolved` for managed DNS.
- systemd for long-running services.

Other environments must be rejected clearly or documented as unverified rather
than handled through silent best-effort behavior.
