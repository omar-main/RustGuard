# Security review record

This review defines the security boundary examined for 0.1.0-rc.1. It is an
engineering review, not an independent audit.

## Dependency boundary

- `boringtun` supplies WireGuard protocol and cryptography.
- `boringtun` was upgraded from 0.6.0 to 0.7.1, replacing its legacy dependency
  stack; `x25519-dalek` now uses stable 2.0.1.
- `Cargo.lock` is committed, builds use `--locked`, and `deny.toml` rejects known
  advisories, disallowed licenses, wildcard dependencies, and unknown sources.
- Dependabot monitors Cargo and GitHub Actions updates.

## Unsafe-code boundary

Unsafe Rust is confined to `rustguard-tun/src/linux.rs` and the effective-user-ID
query used for configuration ownership validation. The TUN boundary contains one
`TUNSETIFF` call, bounded interface-name inspection, and reads/writes using slices
whose lengths are passed unchanged. The TUN descriptor is an `OwnedFd`, preventing
manual close and double-close errors. Each unsafe block states its preconditions.

## Privileged-command boundary

The TUN module invokes `ip` with validated interface names and numeric values.
Client networking invokes fixed `ip`, `nft`, and `resolvectl` programs with
structured arguments; no shell evaluates configuration values. Server NAT
preflight invokes read-only `nft list ruleset`. Host mutations are journaled and
rolled back by exact inverse operations.

## Files and local control

Configurations must be regular, non-symlink files owned by the effective user
with no group/other permission bits. Runtime state lives in root-owned mode-0700
`/run/rustguard`. Locks and atomic temporary files use exclusive creation;
status, journal, sockets, and locks are mode 0600. IPC has a two-second timeout.

## Deferred risks

- The root packet process is not privilege-separated.
- `ip`, `nft`, and `resolvectl` are trusted host executables located through
  `PATH`; service-manager environments must use a trusted fixed path.
- RustGuard does not create or own server forwarding/NAT rules.
- IPv6, automatic endpoint refresh, formal verification, fuzzing, and an
  independent audit remain outside this candidate.
