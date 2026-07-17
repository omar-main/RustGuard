//! RustGuard single-peer VPN server.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ipnet::IpNet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{fs, fs::OpenOptions};
use tokio::net::UdpSocket;
use tokio::time::{interval, MissedTickBehavior};
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

use rustguard_core::{
    check_file_permissions, notify_systemd, parse_ipv4, recover_runtime, send_control,
    validate_inbound_source, Config, ControlRequest, PeerRuntimeStatus, PublicKey, RuntimeOwner,
    RuntimeRole, RuntimeStatus, SecretKey, ServerPacketIdentity, SharedRateLimiter, TunnelEvent,
    WgTunnel,
};
use rustguard_tun::{AsyncTun, LinuxTun};

const PACKET_BUFFER_SIZE: usize = 65_536;
const TIMER_TICK: Duration = Duration::from_millis(100);
const SERVER_HANDSHAKES_PER_SECOND: u64 = 100;

struct ServerPeer {
    name: String,
    public_key: PublicKey,
    allowed_ips: Vec<IpNet>,
    tunnel: WgTunnel,
    bytes_sent: u64,
    bytes_received: u64,
}

#[derive(Parser)]
#[command(name = "rustguard-server")]
#[command(about = "RustGuard VPN server")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(short, long, default_value = "/etc/rustguard/server.toml")]
    config: PathBuf,

    #[arg(short, long)]
    debug: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the server in the foreground.
    Start,
    /// Stop the running server through its local control socket.
    Stop,
    /// Show live process and tunnel status.
    Status,
    /// Generate a WireGuard-compatible keypair.
    Genkey,
    /// Validate configuration and host prerequisites without changing state.
    Check,
    /// Recover confirmed stale server runtime state.
    Recover,
    /// Backwards-compatible alias for check.
    Validate,
}

struct LogCleanup(Option<PathBuf>);

impl Drop for LogCleanup {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = fs::remove_file(path);
        }
    }
}

fn setup_logging(
    debug: bool,
    configured_level: Option<&str>,
    debug_to_file: bool,
) -> Result<LogCleanup> {
    let filter = if debug {
        "debug"
    } else {
        configured_level.unwrap_or("info")
    };
    if debug_to_file {
        let path = std::env::temp_dir().join(format!(
            "rustguard-server-{}-{}.log",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        set_private_file(&path)?;
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new(filter))
            .with_target(false)
            .with_writer(std::sync::Mutex::new(file))
            .try_init()
            .ok();
        Ok(LogCleanup(Some(path)))
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new(filter))
            .with_target(false)
            .try_init()
            .ok();
        Ok(LogCleanup(None))
    }
}

#[cfg(unix)]
fn set_private_file(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_private_file(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Start => cmd_start(&cli.config, cli.debug).await,
        Commands::Stop => cmd_stop().await,
        Commands::Status => cmd_status().await,
        Commands::Genkey => cmd_genkey(),
        Commands::Check | Commands::Validate => cmd_check(&cli.config),
        Commands::Recover => cmd_recover().await,
    }
}

async fn cmd_start(config_path: &Path, debug: bool) -> Result<()> {
    let config = load_server_config(config_path)?;
    validate_server_prerequisites(&config)?;
    let _log_cleanup = setup_logging(
        debug,
        config
            .logging
            .as_ref()
            .map(|logging| logging.level.as_str()),
        config
            .logging
            .as_ref()
            .is_some_and(|logging| logging.debug_to_file),
    )?;
    let listen_port = config.interface.listen_port.unwrap();
    let runtime = RuntimeOwner::acquire(RuntimeRole::Server)
        .context("failed to acquire server runtime ownership")?;

    let tun =
        LinuxTun::new("rg0", config.interface.mtu).context("failed to create TUN interface")?;
    tun.add_address(&config.interface.address.to_string())
        .context("failed to add the TUN address")?;
    tun.up().context("failed to bring the TUN interface up")?;
    let tun = AsyncTun::new(tun).context("failed to register TUN readiness")?;

    let socket = UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, listen_port))
        .await
        .with_context(|| format!("failed to bind UDP port {listen_port}"))?;

    let dispatch_limiter =
        SharedRateLimiter::for_server(&config.interface.private_key, SERVER_HANDSHAKES_PER_SECOND);
    // Classification owns the real global handshake bound. Tunnels share a
    // practically-unlimited verifier to avoid double-counting a packet after
    // it has already passed global MAC/cookie validation.
    let tunnel_limiter = SharedRateLimiter::for_server(&config.interface.private_key, u64::MAX);
    let mut peers = config
        .peers
        .iter()
        .enumerate()
        .map(|(index, peer)| {
            let tunnel = WgTunnel::new_with_rate_limiter(
                &config.interface.private_key,
                &peer.public_key,
                peer.preshared_key.as_ref().map(|key| key.as_bytes()),
                peer.persistent_keepalive,
                u32::try_from(index + 1).expect("peer count is bounded"),
                Some(&tunnel_limiter),
            )
            .context("failed to create WireGuard peer state")?;
            Ok(ServerPeer {
                name: peer
                    .name
                    .clone()
                    .unwrap_or_else(|| format!("peer-{}", index + 1)),
                public_key: peer.public_key.clone(),
                allowed_ips: peer.allowed_ips.clone(),
                tunnel,
                bytes_sent: 0,
                bytes_received: 0,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    info!(
        interface = tun.name(),
        listen_port, "server packet loop started"
    );
    let mut status = RuntimeStatus::starting(RuntimeRole::Server);
    update_server_status(&mut status, &peers);
    runtime.write_status(&status)?;
    if let Err(error) = notify_systemd("READY=1\nSTATUS=RustGuard server is running") {
        warn!(%error, "failed to notify systemd that the server is ready");
    }
    let result = run_server_loop(
        &tun,
        &socket,
        &config.interface.private_key,
        &dispatch_limiter,
        &mut peers,
        &runtime,
        status,
    )
    .await;
    if let Err(error) = notify_systemd("STOPPING=1\nSTATUS=RustGuard server is stopping") {
        warn!(%error, "failed to notify systemd that the server is stopping");
    }
    result
}

fn load_server_config(path: &Path) -> Result<Config> {
    check_file_permissions(path).context("configuration file has insecure permissions")?;
    let config = Config::from_file(path).context("failed to load configuration")?;
    config
        .validate_server()
        .context("invalid server configuration")?;
    Ok(config)
}

fn validate_server_prerequisites(config: &Config) -> Result<()> {
    let Some(server) = &config.server else {
        return Ok(());
    };
    if server.require_forwarding {
        let forwarding = fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
            .context("failed to inspect IPv4 forwarding")?;
        if forwarding.trim() != "1" {
            anyhow::bail!("server requires net.ipv4.ip_forward=1");
        }
    }
    if server.require_nat {
        require_command("nft")?;
        let output = std::process::Command::new("nft")
            .args(["list", "ruleset"])
            .output()
            .context("failed to inspect nftables NAT rules")?;
        if !output.status.success() {
            anyhow::bail!("nft list ruleset failed while validating NAT");
        }
        let rules = String::from_utf8_lossy(&output.stdout);
        let interface = server.outbound_interface.as_deref().unwrap();
        if !rules.contains("masquerade") || !rules.contains(interface) {
            anyhow::bail!("server requires an existing nftables masquerade rule for {interface}");
        }
    }
    Ok(())
}

async fn run_server_loop(
    tun: &AsyncTun,
    socket: &UdpSocket,
    private_key: &SecretKey,
    dispatch_limiter: &SharedRateLimiter,
    peers: &mut [ServerPeer],
    runtime: &RuntimeOwner,
    mut status: RuntimeStatus,
) -> Result<()> {
    let mut tun_buffer = vec![0; PACKET_BUFFER_SIZE];
    let mut udp_buffer = vec![0; PACKET_BUFFER_SIZE];
    let mut timer = interval(TIMER_TICK);
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            biased;

            result = &mut shutdown => {
                result.context("failed to listen for shutdown signals")?;
                info!("shutdown signal received");
                return Ok(());
            }

            result = runtime.accept() => {
                let mut stream = result.context("control socket accept failed")?;
                let request = RuntimeOwner::read_request(&mut stream).await
                    .context("invalid control request")?;
                update_server_status(&mut status, peers);
                runtime.write_status(&status)?;
                RuntimeOwner::reply(&mut stream, &status).await?;
                if request == ControlRequest::Stop {
                    info!("stop requested through control socket");
                    return Ok(());
                }
            }

            result = socket.recv_from(&mut udp_buffer) => {
                let (length, source) = result.context("UDP receive failed")?;
                let identity = match dispatch_limiter.classify(
                    private_key,
                    source.ip(),
                    &udp_buffer[..length],
                ) {
                    Ok(ServerPacketIdentity::CookieReply(cookie)) => {
                        socket.send_to(&cookie, source).await
                            .context("failed to send WireGuard cookie reply")?;
                        continue;
                    }
                    Ok(identity) => identity,
                    Err(error) => {
                        debug!(%source, %error, "discarding unauthenticated datagram");
                        continue;
                    }
                };
                let peer_index = match identity {
                    ServerPacketIdentity::PeerKey(key) => peers
                        .iter()
                        .position(|peer| peer.public_key.as_bytes() == &key),
                    ServerPacketIdentity::PeerIndex(index) => usize::try_from(index)
                        .ok()
                        .and_then(|index| index.checked_sub(1))
                        .filter(|index| *index < peers.len()),
                    ServerPacketIdentity::CookieReply(_) => unreachable!(),
                };
                let Some(peer_index) = peer_index else {
                    debug!(%source, "discarding datagram for an unknown peer");
                    continue;
                };
                let peer = &mut peers[peer_index];
                match peer.tunnel.decapsulate_authenticated(source.ip(), &udp_buffer[..length]) {
                    Ok(output) => {
                        if output.authenticated {
                            peer.tunnel.set_endpoint(source);
                        }
                        peer.bytes_received = peer.bytes_received.saturating_add(
                            dispatch_server_events(tun, socket, source, peer, output.events).await?
                        );
                    }
                    Err(error) => debug!(peer = %peer.name, %source, %error, "discarding peer datagram"),
                }
            }

            result = tun.read_packet(&mut tun_buffer) => {
                let length = result.context("TUN read failed")?;
                let packet = match parse_ipv4(&tun_buffer[..length]) {
                    Ok(packet) => packet,
                    Err(error) => {
                        warn!(%error, "discarding malformed outbound packet");
                        continue;
                    }
                };
                let Some(peer_index) = peer_for_destination(peers, packet.destination) else {
                    warn!(destination = %packet.destination, "discarding outbound packet with no owning peer");
                    continue;
                };
                let peer = &mut peers[peer_index];
                let Some(endpoint) = peer.tunnel.endpoint else {
                    warn!(peer = %peer.name, "discarding outbound packet because peer has no authenticated endpoint");
                    continue;
                };
                if let Some(datagram) = peer.tunnel
                    .encapsulate(&tun_buffer[..packet.length])
                    .context("WireGuard encapsulation failed")?
                {
                    peer.bytes_sent = peer.bytes_sent.saturating_add(packet.length as u64);
                    socket.send_to(&datagram, endpoint).await
                        .context("failed to send encrypted datagram")?;
                }
            }

            _ = timer.tick() => {
                for peer in peers.iter_mut() {
                    match peer.tunnel.update_timers() {
                        Ok(Some(datagram)) => if let Some(endpoint) = peer.tunnel.endpoint {
                            socket.send_to(&datagram, endpoint).await
                                .context("failed to send WireGuard timer datagram")?;
                        },
                        Ok(None) => {}
                        Err(error) => warn!(peer = %peer.name, %error, "WireGuard timer processing failed"),
                    }
                }
            }
        }
    }
}

async fn dispatch_server_events(
    tun: &AsyncTun,
    socket: &UdpSocket,
    endpoint: SocketAddr,
    peer: &ServerPeer,
    events: Vec<TunnelEvent>,
) -> Result<u64> {
    let mut received = 0_u64;
    for event in events {
        match event {
            TunnelEvent::WriteToNetwork(datagram) => {
                socket
                    .send_to(&datagram, endpoint)
                    .await
                    .context("failed to send WireGuard response")?;
            }
            TunnelEvent::WriteToTunnelV4(packet) => {
                let length = match validate_inbound_source(&packet, &peer.allowed_ips) {
                    Ok(length) => length,
                    Err(error) => {
                        warn!(%error, "discarding decrypted packet with an unauthorized source");
                        continue;
                    }
                };
                tun.write_packet(&packet[..length])
                    .await
                    .context("failed to write decrypted packet to TUN")?;
                received = received.saturating_add(length as u64);
            }
            TunnelEvent::WriteToTunnelV6(_) => {
                warn!("discarding IPv6 packet: this milestone is IPv4-only");
            }
        }
    }
    Ok(received)
}

fn peer_for_destination(peers: &[ServerPeer], destination: std::net::Ipv4Addr) -> Option<usize> {
    longest_prefix_owner(
        peers
            .iter()
            .enumerate()
            .map(|(index, peer)| (index, peer.allowed_ips.as_slice())),
        destination,
    )
}

fn longest_prefix_owner<'a>(
    ownership: impl Iterator<Item = (usize, &'a [IpNet])>,
    destination: std::net::Ipv4Addr,
) -> Option<usize> {
    ownership
        .flat_map(|(index, networks)| {
            networks
                .iter()
                .filter(move |network| network.contains(&std::net::IpAddr::V4(destination)))
                .map(move |network| (index, network.prefix_len()))
        })
        .max_by_key(|(_, prefix)| *prefix)
        .map(|(index, _)| index)
}

fn update_server_status(status: &mut RuntimeStatus, peers: &[ServerPeer]) {
    status.peers = peers
        .iter()
        .map(|peer| {
            let age = peer
                .tunnel
                .time_since_last_handshake()
                .map(|age| age.as_secs());
            let handshake = match age {
                Some(seconds) if seconds <= 180 => "established",
                Some(_) => "stale",
                None => "waiting",
            };
            PeerRuntimeStatus {
                name: peer.name.clone(),
                handshake: handshake.into(),
                last_handshake_seconds: age,
                endpoint: peer.tunnel.endpoint.map(|endpoint| endpoint.to_string()),
                allowed_ips: peer.allowed_ips.iter().map(ToString::to_string).collect(),
                bytes_sent: peer.bytes_sent,
                bytes_received: peer.bytes_received,
            }
        })
        .collect();
    let established = status
        .peers
        .iter()
        .filter(|peer| peer.handshake == "established")
        .count();
    status.handshake = if peers.len() == 1 {
        status.peers[0].handshake.clone()
    } else {
        format!("{established}/{} established", peers.len())
    };
    status.endpoint = (peers.len() == 1)
        .then(|| status.peers[0].endpoint.clone())
        .flatten();
    status.routes = peers
        .iter()
        .flat_map(|peer| peer.allowed_ips.iter().map(ToString::to_string))
        .collect();
    status.bytes_sent = peers.iter().map(|peer| peer.bytes_sent).sum();
    status.bytes_received = peers.iter().map(|peer| peer.bytes_received).sum();
}

async fn shutdown_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate = signal(SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
    }

    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await
}

fn cmd_genkey() -> Result<()> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    let mut private_key = [0; 32];
    getrandom::getrandom(&mut private_key)
        .map_err(|error| anyhow::anyhow!("failed to generate random key: {error}"))?;
    private_key[0] &= 248;
    private_key[31] &= 127;
    private_key[31] |= 64;

    let secret = x25519_dalek::StaticSecret::from(private_key);
    let public = x25519_dalek::PublicKey::from(&secret);
    println!("Private key: {}", BASE64.encode(private_key));
    println!("Public key:  {}", BASE64.encode(public.as_bytes()));
    private_key.fill(0);
    Ok(())
}

async fn cmd_stop() -> Result<()> {
    let status = send_control(RuntimeRole::Server, ControlRequest::Stop).await?;
    for _ in 0..50 {
        if send_control(RuntimeRole::Server, ControlRequest::Status)
            .await
            .is_err()
        {
            println!("server pid {} stopped", status.pid);
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    anyhow::bail!("server accepted stop but did not exit within five seconds")
}

async fn cmd_status() -> Result<()> {
    let status = send_control(RuntimeRole::Server, ControlRequest::Status).await?;
    println!("process: {} (pid {})", status.process, status.pid);
    println!("handshake: {}", status.handshake);
    println!(
        "endpoint: {}",
        status.endpoint.as_deref().unwrap_or("not learned")
    );
    println!("allowed routes: {}", status.routes.join(", "));
    println!(
        "transfer: {} bytes sent, {} bytes received",
        status.bytes_sent, status.bytes_received
    );
    for peer in &status.peers {
        println!(
            "peer {}: handshake={}, endpoint={}, allowed={}, transfer={} sent/{} received",
            peer.name,
            peer.handshake,
            peer.endpoint.as_deref().unwrap_or("not learned"),
            peer.allowed_ips.join(","),
            peer.bytes_sent,
            peer.bytes_received
        );
    }
    Ok(())
}

fn cmd_check(config_path: &Path) -> Result<()> {
    let config = load_server_config(config_path)?;
    validate_server_prerequisites(&config)?;
    require_path("/dev/net/tun")?;
    require_command("ip")?;
    println!("configuration: valid server schema");
    println!("listen port: {}", config.interface.listen_port.unwrap());
    println!("TUN, routing, forwarding, and NAT prerequisites: available");
    Ok(())
}

async fn cmd_recover() -> Result<()> {
    recover_runtime(RuntimeRole::Server).await?;
    println!("server stale runtime state recovered");
    Ok(())
}

fn require_path(path: &str) -> Result<()> {
    Path::new(path)
        .exists()
        .then_some(())
        .context(format!("required path {path} is missing"))
}

fn require_command(name: &str) -> Result<()> {
    let available = std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|path| path.join(name).is_file()));
    available
        .then_some(())
        .context(format!("required command {name} is missing"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbound_owner_uses_the_longest_prefix() {
        let broad = vec!["10.0.0.0/8".parse().unwrap()];
        let narrow = vec!["10.20.0.0/16".parse().unwrap()];
        let ownership = [(0, broad.as_slice()), (1, narrow.as_slice())];
        assert_eq!(
            longest_prefix_owner(ownership.into_iter(), "10.20.1.2".parse().unwrap()),
            Some(1)
        );
    }
}
