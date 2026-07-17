# Problem Statement

## Context

A VPN is more than an encrypted packet format. A usable VPN application must
create a virtual interface, move packets between that interface and a remote
peer, configure routes and DNS, enforce firewall policy, handle privilege
boundaries, expose connection health, and restore the host after errors or
shutdown.

Commercial VPN services package these responsibilities behind a subscription
and ask users to trust the provider's infrastructure and operational claims.
Standard WireGuard tools provide a mature alternative for self-hosting, but the
surrounding setup can still be difficult to understand, automate, and validate.

## Problem

A Linux user who wants a personal VPN needs a small and dependable way to:

1. Connect to a server they control.
2. Route either selected networks or all supported traffic through it.
3. Keep the WireGuard endpoint reachable outside the tunnel.
4. Prevent traffic and DNS leaks when fail-closed operation is requested.
5. Know whether the tunnel is healthy.
6. Stop or recover without leaving routes, DNS, or firewall rules damaged.
7. Prove interoperability with standard WireGuard rather than trusting a claim.

The original RustGuard prototype attempted all of these responsibilities at
once. It produced useful scaffolding, but it did not establish enough runtime or
integration-test evidence to call the result usable.

## Proposed solution

RustGuard will be a self-hosted, WireGuard-compatible VPN client and server for
Linux. It will use a maintained WireGuard protocol engine instead of creating
new cryptography, while implementing the surrounding control plane and Linux
network integration in Rust.

The first useful deployment is intentionally narrow: one Linux client, one
Linux server, IPv4, and a verifiably correct encrypted tunnel. Routing, DNS,
fail-closed firewall behavior, lifecycle management, multiple devices, and
deployment automation are added only when each behavior has an executable test.

## Intended users

- The project owner, for secure remote access and a personal network exit.
- Homelab operators who want auditable routing, DNS, and recovery behavior.
- Rust and systems programmers studying Linux networking and VPN integration.

## Value

For a user, RustGuard should provide a transparent self-hosted VPN experience
without depending on a commercial VPN subscription. The user may still incur
hardware, electricity, ISP, domain, or VPS costs.

For maintainers, the value is that behavior across asynchronous I/O, network
protocols, Linux administration, safe failure, observability, and
interoperability is documented and verified rather than hidden in setup scripts.

## Definition of success

RustGuard succeeds when a clean Linux client and server can be installed from a
documented release, establish and maintain a WireGuard-compatible tunnel, meet
the acceptance criteria in [requirements.md](requirements.md), and recover from
tested failure scenarios without leaking protected traffic or damaging unrelated
host networking state.
