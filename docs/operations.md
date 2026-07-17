# Operations

RustGuard runs one managed foreground process per role. The client uses `up` and
`down`; the server uses `start` and `stop`. A foreground model keeps startup
failure visible and works with systemd without a second daemonization layer.

## Before starting

Copy the matching file from `examples/`, replace both test keys, set the server
address, and protect the file:

```bash
sudo install -d -m 700 /etc/rustguard
sudo install -m 600 examples/client.toml /etc/rustguard/client.toml
sudo install -m 600 examples/server.toml /etc/rustguard/server.toml
```

The role-specific `check` command validates key material, fields, IPv4 routes,
DNS policy, endpoint resolution, file permissions, `/dev/net/tun`, and required
host commands without creating an interface or changing networking.

## Lifecycle

```bash
sudo rustguard-client --config /etc/rustguard/client.toml check
sudo rustguard-client --config /etc/rustguard/client.toml up
sudo rustguard-client status
sudo rustguard-client down

sudo rustguard-server --config /etc/rustguard/server.toml check
sudo rustguard-server --config /etc/rustguard/server.toml start
sudo rustguard-server status
sudo rustguard-server stop
```

Only one client and one server process may own runtime state. Commands use
mode-0600 Unix sockets inside `/run/rustguard`, whose mode is 0700. Status is
served by the running process and reports process state separately from
`waiting`, `established`, or `stale` handshake state. It also includes endpoint,
routes, DNS/firewall policy where applicable, and tunnel byte counters.

## Hostnames

A client endpoint may be an IPv4 address or hostname followed by a port. The
hostname is resolved once before TUN or host networking setup. RustGuard selects
an IPv4 result and uses that stable address for the process lifetime, including
the endpoint escape route. Restart after the hostname's address changes.

## Multiple devices

Add one `[[peer]]` block per device to the server configuration. Give every peer
a unique `name`, public key, and non-overlapping IPv4 assignment. Server status
reports each peer's handshake age, most recently authenticated endpoint,
allowed-IP ownership, and transfer counters. The server learns endpoint changes
only from packets accepted by that peer's cryptographic state.

For routed homelab or exit-node use, add:

```toml
[server]
require_forwarding = true
require_nat = true
outbound_interface = "eth0"
```

RustGuard then refuses startup unless IPv4 forwarding is enabled and the
existing nftables ruleset contains masquerading for that interface. It validates
these prerequisites but does not create them.

## Recovery

After an ungraceful exit, run the role-specific recovery command:

```bash
sudo rustguard-client recover
sudo rustguard-server recover
```

Recovery first refuses to proceed if a live control socket or matching process
still owns the role. It removes only exact stale runtime files. Client recovery
also reverses the exact route, DNS, and nftables entries recorded in its private
journal. Repeating recovery is safe.

## Logging and systemd

`logging.level` accepts `off`, `error`, `warn`, `info`, `debug`, or `trace`.
`debug_to_file = true` writes a private mode-0600 temporary process log and
removes it on graceful shutdown. Keys and packet contents are never logged.

When `NOTIFY_SOCKET` is provided, each foreground service sends `READY=1` only
after its runtime ownership and tunnel setup are complete. It sends `STOPPING=1`
when its packet loop exits. A systemd unit should therefore use `Type=notify`,
run the foreground `up` or `start` command as `ExecStart`, and let systemd send
SIGTERM for shutdown. The supplied units under `systemd/` restrict capabilities,
devices, writable paths, and several kernel/process surfaces. Installation,
upgrade, service enablement, and removal are covered in
[Deployment](deployment.md).

## Troubleshooting

- Run the role's `check` command before inspecting service logs.
- Use `journalctl -u rustguard-client` or `journalctl -u rustguard-server`; never
  paste active keys into an issue.
- A stale lock after SIGKILL requires `recover`, not manual firewall deletion.
- If client DNS setup fails, verify `systemctl is-active systemd-resolved` and
  that `resolvectl` is installed.
- If a server reports missing forwarding/NAT, inspect `sysctl net.ipv4.ip_forward`
  and `nft list ruleset`; RustGuard does not create those policies.
- If a home endpoint cannot be reached despite port forwarding, check whether
  the ISP connection is behind CGNAT.
