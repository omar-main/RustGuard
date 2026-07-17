# Homelab Deployment

RustGuard is designed to fit into a Linux homelab. It combines an externally
reachable UDP service with authenticated
device identities, Linux routing, firewall and DNS policy, systemd lifecycle,
and observable recovery behavior. The current release candidate remains
experimental and should be introduced with an out-of-band recovery path.

## Useful personal scenarios

### Remote access to home services

Run the server on an always-on Linux host and assign each laptop or phone its own
tunnel `/32`. Route only the home subnets containing services such as a NAS,
Home Assistant, Grafana, or an administrative dashboard. This is the smallest
and most appropriate first deployment because ordinary internet traffic remains
outside the tunnel.

### Personal exit path

Use full-tunnel client routing when you want traffic on public Wi-Fi to exit
through your home connection or a VPS. The server host needs IPv4 forwarding and
an attributable nftables masquerade rule. RustGuard can validate those
prerequisites but does not install them yet.

### Multi-device lab

Configure independent peers for a laptop, phone, tablet, and maintenance device.
Each peer has a unique key and IP ownership. Live status shows separate
handshakes, roaming endpoints, routes, and counters, which is useful for daily
operation and troubleshooting.

## Reachability choices

A home server normally needs a router UDP port-forward to the RustGuard listen
port and a stable public address or dynamic-DNS name. Clients behind NAT should
use persistent keepalive when they need their mapping to remain available while
idle, following the [WireGuard guidance](https://www.wireguard.com/quickstart/#nat-and-firewall-traversal-persistence).
If the home connection is behind carrier-grade NAT and cannot accept an
inbound mapping, place the server on a small public VPS or wait for a deliberately
designed relay or rendezvous feature; RustGuard does not provide NAT traversal.

## Suggested first topology

```text
Laptop / phone
      |
 public internet
      |
router UDP port-forward
      |
Linux RustGuard server
      |
homelab subnet and selected services
```

Start with split routes and no LAN-wide forwarding. Add forwarding and NAT only
after the namespace tests, host firewall, return routes, and recovery procedure
are understood. Keep SSH or console access outside RustGuard while experimenting
so a routing mistake cannot lock you out of the server.

## Current boundary

The tested implementation is IPv4-only and requires Linux and `systemd-resolved`
for protected client DNS. RustGuard ships an installer and hardened systemd
units, but remains an unaudited release candidate. It offers encrypted transport
rather than anonymity: the ISP or VPS
provider can still observe endpoints and traffic metadata, and traffic is no
longer protected after leaving the server.
