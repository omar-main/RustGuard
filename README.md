# RustGuard

[![CI](https://github.com/omar-main/RustGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/omar-main/RustGuard/actions/workflows/ci.yml)
![Linux](https://img.shields.io/badge/platform-Linux-2f363d)
![Rust 1.85+](https://img.shields.io/badge/Rust-1.85%2B-b7410e)

RustGuard is an experimental, self-hosted, WireGuard-compatible VPN for Linux,
written in Rust and built around Cloudflare's
[`boringtun`](https://github.com/cloudflare/boringtun) protocol implementation.

It is designed for personal servers and homelabs where the operator wants direct
control over tunnel routing, DNS, firewall policy, process lifecycle,
diagnostics, and recovery.

> [!WARNING]
> RustGuard 0.1.0-rc.1 is an experimental, locally verified release candidate,
> not an independently audited VPN. Do not use it to protect sensitive or
> production traffic. Server forwarding/NAT remains administrator-managed.

## What it does

- A Linux client and self-hosted Linux server
- Compatibility with standard WireGuard peers
- Full-tunnel and split-tunnel IPv4 routing
- Optional fail-closed nftables kill switch
- DNS configuration without persistent host damage
- Clear `up`, `down`, `status`, `check`, and recovery workflows
- Multiple client devices on one personal server
- Reproducible installation with systemd
- Automated interoperability, leak-prevention, and recovery tests

Detailed behavior and acceptance criteria are defined in
[Project requirements](docs/requirements.md).

## Why this project exists

Commercial VPNs are convenient, but they require recurring payment and trust in
a third-party operator. A self-hosted VPN can instead provide secure remote
access and a trusted network path through infrastructure controlled by its user.
RustGuard explores how to build that experience safely without inventing new
cryptography.

Read the full [problem statement](docs/problem-statement.md) and
[goals and non-goals](docs/goals-and-non-goals.md).

## Install

RustGuard currently supports x86-64 Ubuntu 22.04 LTS and Ubuntu 24.04 LTS. A
client needs `iproute2`, `nftables`, and `systemd-resolved`; interoperability and
development tests additionally use `wireguard-tools`.

Install the host tools and build the locked release profile:

```bash
sudo apt update
sudo apt install -y build-essential curl iproute2 nftables pkg-config \
  systemd-resolved wireguard-tools
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

git clone https://github.com/omar-main/RustGuard.git
cd RustGuard
cargo build --workspace --release --locked
sudo bash scripts/install.sh
```

The installer places binaries in `/usr/local/bin`, installs hardened systemd
units, and creates mode-0600 example configurations under `/etc/rustguard`. It
does not enable a service or overwrite an existing configuration.

Generate separate keys for every server and client, then replace all example
keys, addresses, and endpoints:

```bash
rustguard-server genkey
rustguard-client genkey

sudo rustguard-server --config /etc/rustguard/server.toml check
sudo rustguard-client --config /etc/rustguard/client.toml check
```

Enable only the appropriate role on each machine:

```bash
sudo systemctl enable --now rustguard-server.service
# or
sudo systemctl enable --now rustguard-client.service
```

Start with split-tunnel routes and keep SSH or console access available during
the first deployment. See [Deployment](docs/deployment.md) for upgrades and
removal, and [Homelab deployment](docs/homelab.md) for topology and CGNAT notes.

## Current status

The repository contains a release-candidate implementation with:

- TOML configuration parsing and key handling
- A nonblocking Linux TUN abstraction integrated with Tokio readiness
- An owned `boringtun` adapter that drains queued protocol outputs
- A cancellable single-peer IPv4 client and server packet loop
- Transactional split/full IPv4 routing with an endpoint escape route
- Fail-closed nftables policy and per-link `systemd-resolved` DNS integration
- Exact graceful rollback and journal-based forced-crash recovery
- Role-specific configuration validation and startup hostname resolution
- Managed foreground services with exclusive ownership and local IPC
- Live process, handshake, endpoint, policy, and transfer status
- Read-only prerequisite checks and idempotent stale-state recovery
- Independent state, routing, roaming, and diagnostics for multiple server peers
- Shared handshake limiting and per-peer source-address enforcement
- Hardened systemd units, transactional installation, locked release archives,
  checksums, and build provenance
- Unit, supported-platform, lifecycle, security-policy, and namespace CI jobs

The single-peer data path is now verified in disposable Linux network
namespaces. Automated tests cover RustGuard-to-RustGuard transport, a RustGuard
client with an official WireGuard server, and an official WireGuard client with
a RustGuard server. Client-network tests additionally prove exact split/full
routes, transport escape routing, DNS path selection, physical-link leak
blocking, graceful cleanup, and SIGKILL recovery while preserving unrelated
network state.

Lifecycle tests run the shipped examples end to end, reject duplicate instances,
control both roles through root-private Unix sockets, verify systemd readiness
and stopping notifications, and prove stale runtime recovery.

The multi-peer suite runs three official WireGuard clients simultaneously and
proves cross-peer routing, spoof rejection, authenticated endpoint roaming,
unauthenticated-input isolation, and continued service when one peer fails.

The current implementation has deliberate limits:

- The client accepts one server peer; the server accepts up to 256 uniquely
  named peers with non-overlapping IPv4 ownership.
- IPv6 is deliberately rejected by the safe client networking path.
- DNS safety currently requires a working `systemd-resolved`/`resolvectl` setup.
- Server forwarding/NAT is validated but not created or owned by RustGuard.

Work is organized around verified outcomes. A capability is considered complete
only after its acceptance tests pass; documentation alone is not evidence that
the behavior works.

Run the privileged single-peer test matrix on Linux after building the debug
binaries:

```bash
cargo build --workspace --locked
sudo bash scripts/test_single_peer.sh
sudo bash scripts/test_client_networking.sh
sudo bash scripts/test_lifecycle.sh
sudo bash scripts/test_multi_peer.sh
```

## Operational commands

`up` and `start` are foreground service commands. Run them directly while
developing or use a service manager; they do not fork or hide startup errors.

```bash
sudo rustguard-client --config /etc/rustguard/client.toml check
sudo rustguard-client --config /etc/rustguard/client.toml up
sudo rustguard-client status
sudo rustguard-client down
sudo rustguard-client recover

sudo rustguard-server --config /etc/rustguard/server.toml check
sudo rustguard-server --config /etc/rustguard/server.toml start
sudo rustguard-server status
sudo rustguard-server stop
sudo rustguard-server recover
```

See [Operations](docs/operations.md) for ownership, status, hostname, logging,
systemd, and recovery behavior. [Homelab deployment](docs/homelab.md) describes
realistic personal topologies and current prerequisites. Replace all example
keys before deployment.

## Architecture

RustGuard is a Cargo workspace with four crates:

```text
rustguard-core/     Configuration, peer selection, and WireGuard integration
rustguard-tun/      Linux TUN device abstraction
rustguard-client/   Client lifecycle and host-network integration
rustguard-server/   Server lifecycle and peer packet forwarding
```

See [Architecture](docs/architecture.md) for the intended packet and control
flows.

## Development

RustGuard currently targets Linux and requires a Rust toolchain compatible with
the version declared in `Cargo.toml`.

```bash
cargo build --workspace --locked
cargo test --workspace --all-targets --locked
```

The supported release matrix is x86-64 Ubuntu 22.04 LTS and Ubuntu 24.04 LTS.
Creating a TUN device and changing routes, DNS, or nftables rules requires Linux
network-administration privileges. See [Deployment](docs/deployment.md) before
enabling either service.

## Future work

The next useful improvements are intentionally operational rather than protocol
experiments:

- [ ] Add an opt-in, RustGuard-owned server forwarding/NAT mode with exact
  rollback instead of requiring administrator-created rules.
- [ ] Refresh hostname endpoints safely without restarting the client.
- [ ] Add guided peer and key management, including configuration export and QR
  codes for compatible WireGuard clients.
- [ ] Publish signed packages for supported distributions and add an ARM64
  release target for small homelab servers.
- [ ] Separate the privileged networking helper from the packet and control
  processes.
- [ ] Add a terminal UI for setup, peer status, traffic counters, and recovery.
- [ ] Explore an optional local web or desktop UI that talks to the restricted
  backend over authenticated IPC and never runs as root itself.
- [ ] Add IPv6 routing, DNS, leak prevention, and namespace coverage before
  accepting IPv6 configuration.
- [ ] Add structured health and metrics output for homelab monitoring.

Ideas are not treated as supported features until they have executable tests and
updated operational documentation.

## Documentation

- [Problem statement](docs/problem-statement.md)
- [Goals and non-goals](docs/goals-and-non-goals.md)
- [Requirements](docs/requirements.md)
- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Testing strategy](docs/testing-strategy.md)
- [Limitations](docs/limitations.md)
- [Operations](docs/operations.md)
- [Homelab deployment](docs/homelab.md)
- [Deployment and removal](docs/deployment.md)
- [Security review](docs/security-review.md)
- [Release process](docs/release-process.md)
- [Release candidate evidence](docs/release-evidence.md)

## Security

RustGuard delegates the WireGuard protocol to an established implementation and
does not design its own cryptographic protocol. That does not automatically make
the complete application secure: routing, DNS, firewall state, privileges,
dependency health, logging, and cleanup are part of the security boundary.

See the [threat model](docs/threat-model.md) before evaluating or using the
project. Vulnerabilities should follow the private process in
[SECURITY.md](SECURITY.md).

## License

MIT OR Apache-2.0
