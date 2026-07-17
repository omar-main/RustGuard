# Changelog

All notable changes are recorded here. RustGuard follows semantic versioning
once a stable release exists.

## 0.1.0-rc.1 - 2026-07-17

First release candidate of the rebuilt RustGuard VPN:

- Reliable asynchronous IPv4 TUN/UDP transport interoperable with WireGuard.
- Transactional split/full client routing, resolved DNS, and nftables kill switch.
- Exact graceful rollback and journal-based crash recovery.
- Operational lifecycle commands, root-private IPC, status, checks, and recovery.
- Multi-peer server isolation, roaming, longest-prefix selection, and diagnostics.
- Updated protocol/dependency stack and hardened runtime-file handling.
- Hardened systemd units and preserving install/upgrade/uninstall tooling.
- Locked deterministic archives, SHA-256 checksums, provenance, and release CI.

This candidate is not independently audited. It remains IPv4-only, supports one
server peer per client, and requires administrator-managed server forwarding/NAT.
