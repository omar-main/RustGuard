# Threat Model

This threat model defines RustGuard's intended security boundary. It is a design
document, not a claim that the current prototype satisfies every control.

## Assets

RustGuard is responsible for protecting:

- Client and server private keys
- Preshared keys when configured
- Confidentiality and integrity of tunneled packet contents in transit
- The user's configured routing and DNS policy
- Availability of the host's pre-existing network configuration after cleanup
- Integrity of peer identity and allowed-IP assignments
- Logs and status output against accidental secret disclosure

## Trust assumptions

- The client and server operating systems are trusted and maintained.
- The user controls the RustGuard configuration and server.
- The WireGuard protocol engine is correctly implemented and maintained.
- The operating-system CSPRNG is secure.
- Root or granted network-administration capabilities can modify the host.
- Dependencies and release artifacts are obtained through the documented build
  and verification process.

## Adversaries

### Local unprivileged user

May attempt to read keys, replace runtime files, exploit predictable paths,
inject lifecycle commands, or influence commands executed by a privileged
RustGuard process.

### Network attacker

May observe, replay, modify, reorder, inject, or drop UDP datagrams; spoof source
addresses; scan the server; and attempt resource exhaustion before
authentication.

### Untrusted local network

May provide hostile DHCP, DNS, gateways, IPv6 router advertisements, or captive
portal behavior and may try to route traffic outside the tunnel.

### Misconfiguration and failure

Operator mistakes, invalid routes, overlapping peers, process crashes, partial
setup, dependency failures, and power loss are treated as security-relevant
events because they can cause leaks or persistent host damage.

### Hosting provider or ISP

Can observe server and client IP addresses, timing, volume, and the server's
ordinary outbound traffic. RustGuard does not claim to hide this metadata.

## Security objectives

- Only a configured peer can authenticate and inject tunneled traffic.
- Protected traffic does not leave outside the tunnel when fail-closed mode is
  enabled.
- DNS uses the configured tunnel path while DNS protection is active.
- RustGuard never logs private keys, preshared keys, or packet contents by
  default.
- A failed setup leaves the host in its original state or a documented
  fail-closed state with a reliable recovery operation.
- Cleanup removes only state created by the same RustGuard instance.
- Unauthenticated network input cannot consume unbounded resources.
- Release dependencies are checked against the project's advisory policy.

## Principal threats and controls

| Threat | Required control |
| --- | --- |
| Packet interception or modification | WireGuard authenticated encryption through a maintained engine |
| Route or DNS leak | Transactional routing, resolver integration, kill switch, namespace tests |
| Endpoint routed into its own tunnel | Explicit endpoint escape route created before tunnel defaults |
| Malicious runtime-file replacement | Private runtime directory, safe file creation, ownership checks |
| Secret exposure in logs | Redacted types, structured logging review, secret-scanning tests |
| Partial setup damages networking | Preflight validation, operation journal, reverse-order rollback |
| Cleanup deletes unrelated rules | Stable ownership identifiers and exact deletion targets |
| Peer impersonation | Public-key identity and authenticated handshake |
| Peer sends unauthorized source IP | Validate decrypted source address against that peer's allowed IPs |
| Server resource exhaustion | Rate limiting, bounded buffers, peer limits, malformed-input tests |
| Stale or vulnerable dependency | Locked dependencies, automated audit, intentional advisory policy |
| Privileged command injection | Typed process arguments, no shell interpolation, strict input validation |

## Out of scope

RustGuard does not protect against:

- A compromised client or server operating system
- A user who exposes private keys or installs an untrusted binary
- Traffic analysis by a sufficiently capable observer
- Visibility of plaintext traffic after it exits the VPN server
- Malicious websites, applications, browser fingerprinting, or account tracking
- Denial of service caused by blocking all traffic between client and server
- Legal or administrative access to a hosting provider
- An unknown vulnerability in the WireGuard engine or operating-system kernel

## Fail-open and fail-closed policy

Default startup failures should roll back and leave ordinary host networking
available. When a user explicitly enables the kill switch, inability to enforce
the required policy must abort startup. After a crash, the preferred state is
fail-closed until a verified recovery command removes only RustGuard-owned state.

This behavior must be tested; log messages alone are not evidence.

The server bounds configured peers at 256 and shares one MAC/cookie handshake
limiter across their protocol engines. Invalid outer datagrams are discarded
without peer allocation. These controls reduce accidental and commodity abuse;
they are not a guarantee of availability against a capable denial-of-service
attacker.

## Review triggers

Update this document when RustGuard adds a platform, privilege model, resolver,
firewall backend, IPC mechanism, automatic configuration service, release
channel, or cryptographic dependency with a different security boundary.
