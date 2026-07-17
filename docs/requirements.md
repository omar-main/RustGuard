# Project Requirements

Requirements use three levels:

- **MUST**: required before RustGuard is called usable.
- **SHOULD**: expected for the first polished release unless evidence justifies
  deferral.
- **MAY**: useful follow-up work outside the initial release boundary.

## Tunnel data plane

- The client and server MUST process TUN, UDP, timer, and shutdown events without
  one source indefinitely blocking the others.
- Every output produced by the WireGuard engine MUST be drained and delivered to
  the correct destination.
- Network responses MUST come from the buffer written by the protocol engine.
- Malformed or unauthenticated datagrams MUST NOT reach the TUN interface.
- The client MUST maintain handshakes, keepalives, and rekey operations.
- Idle operation SHOULD not busy-spin or consume significant CPU.
- The data plane MUST interoperate with an official WireGuard peer in both client
  and server roles.

## Configuration and keys

- Invalid key lengths, addresses, ports, routes, and role-specific fields MUST be
  rejected before host networking is changed.
- Configuration errors MUST identify the failing field without revealing secret
  material.
- Configurations containing private keys MUST have secure ownership and mode.
- Generated examples MUST parse successfully.
- Endpoint hostnames SHOULD be resolved deliberately and refreshed safely.
- Private and preshared keys MUST NOT appear in debug, error, or status output.
- Key generation MUST use the operating system CSPRNG.

## Client networking

- Split-tunnel routes MUST cover exactly the configured prefixes.
- Full-tunnel mode MUST preserve a usable path to the VPN endpoint.
- RustGuard MUST record which addresses, routes, rules, and firewall objects it
  created.
- Cleanup MUST remove only RustGuard-owned state.
- Partial setup failure MUST roll back completed changes in reverse order.
- IPv6 MUST either satisfy equivalent requirements or be rejected clearly.

## Kill switch and DNS

- If the kill switch is requested but cannot be guaranteed, startup MUST fail.
- The kill switch MUST permit the transport connection while blocking protected
  traffic outside the tunnel.
- LAN bypass MUST be explicit configuration rather than an implicit default.
- Firewall changes MUST be applied atomically where the platform permits.
- DNS changes MUST be tied to the tunnel lifecycle.
- DNS restoration MUST preserve the original resolver mechanism, including
  symlinks and per-link configuration.
- Crash recovery MUST be documented and tested.

## Server

- The server MUST listen on the configured UDP port and route authenticated
  packets to the correct peer.
- Allowed IP ownership MUST be validated for duplicates and unsafe overlaps.
- The server MUST support at least one peer for the first end-to-end milestone.
- The polished release SHOULD support multiple simultaneous peers.
- Forwarding, NAT, and firewall prerequisites MUST be validated or configured
  through an attributable, reversible mechanism.
- Unauthenticated input SHOULD be rate-limited.

## Lifecycle and observability

- `up`/`start` MUST either finish setup successfully or roll it back.
- `down`/`stop` MUST control the running instance rather than merely print a
  success message.
- `status` MUST report process state and handshake health accurately.
- Shutdown through Ctrl+C, SIGINT, and SIGTERM MUST be graceful.
- Duplicate instances for the same interface MUST be prevented.
- A diagnostic command SHOULD validate prerequisites without changing state.
- Logs MUST exclude keys and packet contents by default.

## Deployment

- A release MUST include client and server binaries from a reproducible CI build.
- Installation and removal MUST be documented.
- systemd unit files SHOULD use the least privileges demonstrated to work.
- Configuration upgrades MUST not silently discard user settings.
- The supported Linux distributions and required system tools MUST be stated.

## Verification gate

RustGuard is usable only when all MUST requirements have automated or explicitly
documented acceptance evidence, the CI workflow is green, dependency auditing
passes under the project's advisory policy, and the limitations remain accurate.
