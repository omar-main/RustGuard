# Limitations

## Release candidate

RustGuard 0.1.0-rc.1 has automated namespace and WireGuard interoperability
coverage, but it is not independently audited and has these known limitations:

- The client accepts one server peer. The server is bounded to 256 peers and
  rejects duplicate keys, names, and overlapping IPv4 ownership.
- Safe client networking is IPv4-only and rejects IPv6 routes, endpoints, and
  DNS servers.
- DNS integration requires `systemd-resolved`; there is intentionally no direct
  `/etc/resolv.conf` fallback.
- Endpoint hostnames resolve once at startup. Address changes require a managed
  restart; automatic refresh is not yet implemented.
- `up` and `start` are foreground commands intended for a terminal or service
  manager; RustGuard does not daemonize itself.
- Server forwarding and an existing nftables masquerade rule can be required and
  validated, but RustGuard does not create or own forwarding/NAT policy yet.
- The combined packet/networking processes run as root inside a restricted
  systemd capability and filesystem sandbox; they are not privilege-separated.
- Official support is limited to x86-64 Ubuntu 22.04 LTS and 24.04 LTS.

These defects should be removed from this list only when a regression test proves
the corrected behavior.

## Intended first release

Even after the first usable release, RustGuard will have deliberate limits:

- Linux only
- A documented subset of Linux distributions and network managers
- No graphical interface
- No mobile client
- No built-in commercial VPN locations
- No multi-hop or traffic-obfuscation mode
- No anonymity guarantee
- No protection after traffic exits the server
- Root or Linux network-administration privileges required for setup
- Operational trust in the client, server, kernel, dependencies, and protocol
  engine

## Self-hosting tradeoffs

Running a personal VPN can avoid a commercial VPN subscription, but it does not
make infrastructure free. A user may need:

- An always-on home device or rented VPS
- Router port forwarding or another reachability mechanism
- Dynamic DNS for a changing home address
- Electricity, bandwidth, domain, or hosting fees
- Maintenance of the server operating system and firewall

A home server normally makes traffic exit through the user's home public IP. A
VPS makes traffic exit through the hosting provider's IP. Neither arrangement
provides the geographic diversity or shared-user anonymity properties sometimes
associated with commercial VPN services.

## Security statement

WireGuard compatibility and use of a protocol library do not establish the
security of the complete application. RustGuard must also correctly handle
privileges, packet validation, routing, DNS, firewall policy, lifecycle,
dependencies, logging, and recovery. RustGuard should still be treated as an
educational systems project rather than independently validated protective
infrastructure. See the [security review](security-review.md) and
[release process](release-process.md).
