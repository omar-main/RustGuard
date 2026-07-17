# Deployment

RustGuard 0.1.0-rc.1 supports x86-64 Ubuntu 22.04 LTS and Ubuntu 24.04 LTS.
Other systemd-based Linux distributions may work but are not in the release
matrix. The host needs a TUN device, `iproute2`, `nftables`, and WireGuard kernel
support; the client additionally needs `systemd-resolved` when DNS is configured.

## Install from source

Install the Rust toolchain declared in `Cargo.toml`, then run:

```bash
cargo build --workspace --release --locked
sudo bash scripts/install.sh
```

The installer writes binaries to `/usr/local/bin`, units to
`/etc/systemd/system`, and initial mode-0600 example configurations to
`/etc/rustguard`. It never enables a service and never overwrites an existing
configuration. Replace every example key and address before continuing.

Validate first:

```bash
sudo rustguard-client --config /etc/rustguard/client.toml check
sudo rustguard-server --config /etc/rustguard/server.toml check
```

Enable only the role used by that machine:

```bash
sudo systemctl enable --now rustguard-client.service
# or
sudo systemctl enable --now rustguard-server.service
```

## Upgrade

Back up `/etc/rustguard`, stop the affected service, build or unpack the new
release, and run `scripts/install.sh` again. The installer replaces binaries and
units but preserves configuration. Run `check` before restarting. There is no
automatic schema migration in this release candidate.

## Uninstall

```bash
sudo bash scripts/uninstall.sh
```

Uninstall stops both units and removes the binaries and service files. It
deliberately retains `/etc/rustguard` because it may contain private keys.
Delete that directory manually only after deciding how its keys should be
destroyed or retained.

## Privilege boundary

The supplied services run as root but bound the service capability set to
`CAP_NET_ADMIN`, restrict device access to `/dev/net/tun`, make the host
filesystem read-only except for `/run/rustguard`, and apply additional systemd
sandboxing. Root remains necessary for the current combined packet/networking
process. The units do not claim privilege separation.

Full-tunnel server egress still requires administrator-owned forwarding and NAT
configuration outside RustGuard. Keep an out-of-band administration path while
testing routing or firewall changes.
