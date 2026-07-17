# Architecture

This document describes the implemented foundation and intended architecture.
Future-facing sections are identified explicitly.

## Design principles

1. The protocol engine does cryptography; RustGuard orchestrates it.
2. Packet I/O must never block unrelated event sources.
3. Planning host changes is separate from applying them.
4. Every applied mutation has an owner and an inverse operation.
5. Status is derived from observed runtime state, not optimistic messages.
6. A security feature that cannot be enforced causes a clear failure.

## Workspace responsibilities

### `rustguard-core`

Platform-independent behavior:

- Configuration types and role-specific validation
- Secret-bearing key types and redacted formatting
- WireGuard tunnel adapter
- Peer identity, allowed-IP selection, and statistics
- Packet validation and common domain errors

This crate must not change Linux routes, DNS, or firewall state.

### `rustguard-tun`

Linux virtual-interface behavior:

- Create a TUN interface with close-on-exec and nonblocking behavior
- Read and write IP packets through an async-compatible abstraction
- Configure interface attributes through typed operations
- Expose a test seam so the data plane can be tested without root

The unsafe ioctl boundary should remain small and documented.

### `rustguard-client`

Client control plane and data plane:

- Resolve and preserve a transport path to the server endpoint
- Build and apply the client network plan
- Run the TUN/UDP/timer event loop
- Expose lifecycle, status, diagnostics, and recovery commands
- Coordinate routes, DNS, and kill-switch transactions

### `rustguard-server`

Server control plane and data plane:

- Bind the WireGuard UDP listener
- Maintain one protocol state machine per configured peer
- Dispatch inbound datagrams and outbound TUN packets correctly
- Validate server forwarding and NAT prerequisites
- Expose lifecycle, status, diagnostics, and per-peer health

## Client packet flow

Outbound traffic:

```text
Application
    -> Linux routing decision
    -> RustGuard TUN interface
    -> destination/peer validation
    -> WireGuard encapsulation
    -> encrypted UDP datagram
    -> physical network interface
    -> server endpoint
```

Inbound traffic:

```text
Server endpoint
    -> UDP socket
    -> source and WireGuard authentication
    -> drain protocol-engine outputs
       -> encrypted response back to UDP, or
       -> validated IP packet to TUN
    -> Linux network stack
    -> application
```

The endpoint route must remain outside the tunnel. Protected traffic follows the
TUN route, while the kill switch prevents it from using another interface.

## Server packet flow

Inbound client traffic:

```text
UDP listener
    -> peer identification/authentication
    -> peer tunnel state
    -> decrypted packet validation
    -> shared TUN interface
    -> kernel forwarding/NAT
    -> destination network
```

Return traffic:

```text
Destination network
    -> kernel forwarding/NAT
    -> shared TUN interface
    -> longest-prefix peer selection
    -> peer tunnel state
    -> encrypted UDP datagram
    -> learned/configured peer endpoint
```

## Event-loop model

The event loop must multiplex:

- TUN readability
- UDP readability
- WireGuard timer deadlines
- lifecycle commands
- shutdown signals

The implementation uses Tokio readiness for a nonblocking TUN descriptor and
`tokio::select!` to multiplex UDP, TUN, control, timer, and shutdown events.
Each configured server peer owns an independent protocol state machine,
endpoint, timers, counters, and allowed-IP set.

One received UDP datagram can produce multiple protocol-engine results. The
adapter must continue calling the engine's drain mechanism until it reports that
no work remains.

Server handshake initiations first pass a listener-wide MAC/cookie rate limiter.
The encrypted static identity selects the configured peer; established packets
select by BoringTun's high index bits. The selected state machine must then
cryptographically accept the packet before RustGuard learns or changes its UDP
endpoint. Decrypted source addresses are checked against that same peer. TUN
destinations use longest-prefix selection, although configuration rejects
ambiguous ownership overlaps before startup.

## Host-network transaction model

Client networking uses one planned, journaled transaction:

1. Validate configuration and platform prerequisites.
2. Resolve the server endpoint.
3. Create and configure the TUN interface.
4. Discover the current physical route and add an exact endpoint `/32` escape.
5. Atomically install the requested fail-closed nftables output policy.
6. Add exact split prefixes or the two IPv4 full-tunnel half routes.
7. Assign per-link DNS, `~.`, and the DNS default route through `resolvectl`.
8. Start packet transport.

Before each mutation, its exact inverse is persisted under `/run/rustguard`.
On failure or graceful shutdown, completed operations are reversed in strict
reverse order. `emergency-off` consumes the same non-secret journal after a
forced crash. No generic route, resolver file, or shared firewall table is
flushed or restored from a broad snapshot.

## Runtime state

Each role owns an exclusive lock, mode-0600 Unix socket, and non-secret status
file under the mode-0700 `/run/rustguard` directory. Runtime status contains:

- Process identifier and start time
- Interface name
- Resolved endpoint
- Identifiers of RustGuard-owned routes and firewall objects
- Resolver integration mode
- Current handshake classification and transfer counters

Private keys remain in the protected configuration or a dedicated secret file
and are never copied into status state.

`status` and `stop`/`down` send bounded requests to the live control socket.
Foreground packet loops service those requests alongside TUN, UDP, timer, and
signal events. Recovery refuses to act when either a live socket or matching
process owns the role. Confirmed stale files are removed by exact name; client
recovery then consumes the networking ownership journal.

Endpoint hostnames are resolved to IPv4 once, during validated client startup
and before runtime or host-network mutation. The resolved address remains stable
for that process lifetime. Automatic DNS refresh is deferred until reconnection
can change both the transport endpoint and escape route transactionally.

## Privilege boundary

Creating interfaces and changing host networking requires elevated Linux
capabilities. The first correct implementation may run as root, but privileged
operations must be isolated behind narrow modules. Later hardening can separate
setup from the packet process or grant only demonstrated capabilities.

## Decisions intentionally deferred

- Whether server NAT is managed directly or through generated deployment rules
- Cross-platform abstractions

These decisions should be recorded when implementation evidence makes the
tradeoffs concrete.
