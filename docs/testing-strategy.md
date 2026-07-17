# Testing Strategy

RustGuard's central rule is that a security or interoperability claim needs an
executable test at the lowest practical level and an end-to-end test where the
system boundary matters.

## Test layers

### Unit tests

Fast tests without privileges should cover:

- Configuration parsing and role-specific validation
- Key redaction and zeroization-sensitive APIs
- Longest-prefix peer selection
- Packet source/destination validation
- Route and firewall plan generation
- Gateway and resolver-state parsing
- State-machine transitions and rollback ordering
- CLI argument behavior and error messages

Generated examples should be parsed in tests so documentation cannot ship
invalid keys or fields.

### Component tests

Use in-memory or mocked TUN and UDP transports to verify:

- Fair event-loop handling
- Handshake response draining
- Correct output-buffer ownership
- Timer and keepalive processing
- Clean shutdown while idle or under load
- Malformed datagram handling
- Backpressure and bounded queues

These tests must reproduce the failure modes found in the original prototype.

### Linux network-namespace tests

Disposable namespaces provide real kernel routing without modifying the CI host's
normal network. Tests should create client, server, and simulated internet
namespaces connected by virtual Ethernet pairs.

They should verify:

- Interface creation and address assignment
- RustGuard-to-RustGuard bidirectional ping
- Full-tunnel and split-tunnel routing
- Endpoint escape routing
- Server forwarding and NAT
- Kill-switch behavior before, during, and after tunnel loss
- DNS path selection
- Graceful cleanup and forced-crash recovery
- Preservation of unrelated routes and nftables rules

Every test must clean its own uniquely named namespace and firewall objects.
The single-peer transport matrix is implemented in
`scripts/test_single_peer.sh`. `scripts/test_client_networking.sh` separately
proves split/full routing, endpoint escape, resolved DNS intent, tunneled versus
physical DNS delivery, fail-closed nftables behavior, exact cleanup, and
SIGKILL recovery.
`scripts/test_lifecycle.sh` runs the shipped examples and verifies role checks,
hostname resolution, no-mutation validation failures, exclusive locks, live
status, IPC shutdown, systemd readiness/stopping notifications, private runtime
modes, configured file logging, and idempotent stale recovery.
`scripts/test_multi_peer.sh` runs three official WireGuard clients concurrently
and verifies handshake identity dispatch, per-peer diagnostics, cross-peer
longest-prefix forwarding, inner-source spoof rejection, malformed outer-packet
isolation, authenticated endpoint roaming, forwarding/NAT preflight, and
continued operation after one peer stops.

### WireGuard interoperability tests

CI must cover both directions:

1. RustGuard client to an official WireGuard server.
2. Official WireGuard client to a RustGuard server.

Success requires more than process startup:

- A recent authenticated handshake
- Bidirectional tunneled traffic
- Expected source addresses
- Rekey or reconnection behavior
- No plaintext copy of the test packet on the transport interface

### Failure tests

Inject failures after each setup operation and assert exact rollback. Include:

- Missing TUN or nftables support
- Invalid configuration and permissions
- Occupied UDP port
- Endpoint resolution failure
- Route conflict
- DNS-manager failure
- Firewall application failure
- SIGINT, SIGTERM, and forced termination
- Server disappearance and recovery
- Stale runtime state

## Static and supply-chain checks

CI should run:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo build --workspace --release --locked
cargo deny check
bash scripts/test_install.sh
```

`deny.toml` defines advisory, license, source, and dependency policy. CI also
tests the supported Ubuntu 22.04/24.04 matrix and the declared Rust 1.85 minimum.
Audit-tool failures must be fixed; they are not equivalent to a clean audit.

## Release gate

A release candidate is acceptable only when:

- All required CI jobs are green.
- Interoperability passes in both directions.
- Namespace tests cover routing, DNS, kill switch, cleanup, and recovery.
- Supported configuration examples parse and complete a smoke deployment.
- No unreviewed security advisory violates the project policy.
- Documentation describes observed behavior and current limitations.
- Release artifacts are built from the tagged commit using the locked graph.

## Evidence

Manual scripts may assist development, but instructions that ask a developer to
run commands are not automated tests. The repository should preserve test output
through CI status, release checks, and concise documentation of the environment
and assertion each integration test exercises.
