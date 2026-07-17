//! RustGuard single-peer VPN client.

mod safety;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ipnet::IpNet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{fs, fs::OpenOptions};
use tokio::net::UdpSocket;
use tokio::time::{interval, MissedTickBehavior};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use rustguard_core::{
    check_file_permissions, notify_systemd, recover_runtime, send_control, validate_inbound_source,
    validate_outbound_destination, Config, ControlRequest, RuntimeOwner, RuntimeRole,
    RuntimeStatus, TunnelEvent, WgTunnel,
};
use rustguard_tun::{AsyncTun, LinuxTun, TunDevice};

use safety::SafetyGuard;

const PACKET_BUFFER_SIZE: usize = 65_536;
const TIMER_TICK: Duration = Duration::from_millis(100);

#[derive(Parser)]
#[command(name = "rustguard-client")]
#[command(about = "RustGuard VPN client")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(short, long, default_value = "/etc/rustguard/client.toml")]
    config: PathBuf,

    #[arg(short, long)]
    debug: bool,

    #[arg(long)]
    dry_run: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the VPN tunnel in the foreground.
    Up,
    /// Stop the running client through its local control socket.
    Down,
    /// Show live process and tunnel status.
    Status,
    /// Validate configuration and host prerequisites without changing state.
    Check,
    /// Generate a WireGuard-compatible keypair.
    Genkey,
    /// Recover exact stale runtime and networking state after a crash.
    Recover,
    /// Backwards-compatible alias for recover.
    EmergencyOff,
    /// Exercise Linux TUN creation and packet writes.
    SmokeTest,
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
            "rustguard-client-{}-{}.log",
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
        Commands::Up => cmd_up(&cli.config, cli.dry_run, cli.debug).await,
        Commands::Down => cmd_down().await,
        Commands::Status => cmd_status().await,
        Commands::Check => cmd_check(&cli.config),
        Commands::Genkey => cmd_genkey(),
        Commands::Recover | Commands::EmergencyOff => cmd_recover().await,
        Commands::SmokeTest => cmd_smoke_test(),
    }
}

async fn cmd_up(config_path: &Path, dry_run: bool, debug: bool) -> Result<()> {
    check_file_permissions(config_path).context("configuration file has insecure permissions")?;
    let config = Config::from_file(config_path).context("failed to load configuration")?;
    config
        .validate_client()
        .context("invalid client configuration")?;

    let peer = &config.peers[0];
    let endpoint = peer
        .endpoint
        .as_ref()
        .context("client configuration requires a peer endpoint")?
        .resolve_ipv4()
        .context("failed to resolve peer endpoint before host mutation")?;
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
    let (kill_switch, dns_leak_prevention, allow_lan) = config
        .client
        .as_ref()
        .map(|client| {
            (
                client.kill_switch,
                client.dns_leak_prevention,
                client.allow_lan,
            )
        })
        .unwrap_or((false, false, false));

    if dry_run {
        safety::print_dry_run(
            "rg0",
            endpoint,
            &peer.allowed_ips,
            &config.interface.dns,
            kill_switch,
            dns_leak_prevention,
            allow_lan,
        );
        return Ok(());
    }

    let runtime = RuntimeOwner::acquire(RuntimeRole::Client)
        .context("failed to acquire client runtime ownership")?;

    let tun =
        LinuxTun::new("rg0", config.interface.mtu).context("failed to create TUN interface")?;
    tun.add_address(&config.interface.address.to_string())
        .context("failed to add the TUN address")?;
    tun.up().context("failed to bring the TUN interface up")?;

    // Register the TUN before networking is applied so the safety transaction
    // is dropped (and rolled back) while the interface still exists.
    let tun = AsyncTun::new(tun).context("failed to register TUN readiness")?;

    let _safety = SafetyGuard::apply(
        tun.name(),
        endpoint,
        &peer.allowed_ips,
        &config.interface.dns,
        kill_switch,
        dns_leak_prevention,
        allow_lan,
    )
    .context("failed to apply client networking")?;
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("failed to bind client UDP socket")?;

    let preshared_key = peer.preshared_key.as_ref().map(|key| key.as_bytes());
    let mut tunnel = WgTunnel::new(
        &config.interface.private_key,
        &peer.public_key,
        preshared_key,
        peer.persistent_keepalive,
        0,
    )
    .context("failed to create WireGuard peer state")?;
    tunnel.set_endpoint(endpoint);

    info!(interface = tun.name(), %endpoint, "client packet loop started");
    let mut status = RuntimeStatus::starting(RuntimeRole::Client);
    status.endpoint = Some(endpoint.to_string());
    status.routes = peer.allowed_ips.iter().map(ToString::to_string).collect();
    status.dns = config
        .interface
        .dns
        .iter()
        .map(ToString::to_string)
        .collect();
    status.firewall = kill_switch;
    runtime.write_status(&status)?;
    if let Err(error) = notify_systemd("READY=1\nSTATUS=RustGuard client is running") {
        warn!(%error, "failed to notify systemd that the client is ready");
    }
    let result = run_client_loop(
        &tun,
        &socket,
        &mut tunnel,
        endpoint,
        &peer.allowed_ips,
        &runtime,
        status,
    )
    .await;
    if let Err(error) = notify_systemd("STOPPING=1\nSTATUS=RustGuard client is stopping") {
        warn!(%error, "failed to notify systemd that the client is stopping");
    }
    result
}

async fn run_client_loop(
    tun: &AsyncTun,
    socket: &UdpSocket,
    tunnel: &mut WgTunnel,
    endpoint: SocketAddr,
    allowed_ips: &[IpNet],
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
                update_client_status(&mut status, tunnel);
                runtime.write_status(&status)?;
                RuntimeOwner::reply(&mut stream, &status).await?;
                if request == ControlRequest::Stop {
                    info!("stop requested through control socket");
                    return Ok(());
                }
            }

            result = socket.recv_from(&mut udp_buffer) => {
                let (length, source) = result.context("UDP receive failed")?;
                if source != endpoint {
                    warn!(%source, %endpoint, "discarding datagram from unexpected endpoint");
                    continue;
                }

                match tunnel.decapsulate(source.ip(), &udp_buffer[..length]) {
                    Ok(events) => status.bytes_received = status.bytes_received.saturating_add(dispatch_client_events(
                        tun,
                        socket,
                        endpoint,
                        allowed_ips,
                        events,
                    ).await?),
                    Err(error) => warn!(%source, %error, "discarding invalid WireGuard datagram"),
                }
            }

            result = tun.read_packet(&mut tun_buffer) => {
                let length = result.context("TUN read failed")?;
                let packet_length = match validate_outbound_destination(
                    &tun_buffer[..length],
                    allowed_ips,
                ) {
                    Ok(packet_length) => packet_length,
                    Err(error) => {
                        warn!(%error, "discarding outbound packet not owned by the peer");
                        continue;
                    }
                };

                if let Some(datagram) = tunnel
                    .encapsulate(&tun_buffer[..packet_length])
                    .context("WireGuard encapsulation failed")?
                {
                    status.bytes_sent = status.bytes_sent.saturating_add(packet_length as u64);
                    socket.send_to(&datagram, endpoint).await
                        .context("failed to send encrypted datagram")?;
                }
            }

            _ = timer.tick() => {
                match tunnel.update_timers() {
                    Ok(Some(datagram)) => {
                        socket.send_to(&datagram, endpoint).await
                            .context("failed to send WireGuard timer datagram")?;
                    }
                    Ok(None) => {}
                    Err(error) => warn!(%error, "WireGuard timer processing failed"),
                }
            }
        }
    }
}

async fn dispatch_client_events(
    tun: &AsyncTun,
    socket: &UdpSocket,
    endpoint: SocketAddr,
    allowed_ips: &[IpNet],
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
                let length = match validate_inbound_source(&packet, allowed_ips) {
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

fn update_client_status(status: &mut RuntimeStatus, tunnel: &WgTunnel) {
    status.last_handshake_seconds = tunnel.time_since_last_handshake().map(|age| age.as_secs());
    status.handshake = match status.last_handshake_seconds {
        Some(age) if age <= 180 => "established",
        Some(_) => "stale",
        None => "waiting",
    }
    .into();
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

async fn cmd_down() -> Result<()> {
    let _logging = setup_logging(false, None, false)?;
    let status = send_control(RuntimeRole::Client, ControlRequest::Stop).await?;
    wait_until_stopped(RuntimeRole::Client).await?;
    println!("client pid {} stopped", status.pid);
    Ok(())
}

async fn cmd_status() -> Result<()> {
    let status = send_control(RuntimeRole::Client, ControlRequest::Status).await?;
    print_status(&status);
    Ok(())
}

fn print_status(status: &RuntimeStatus) {
    println!("process: {} (pid {})", status.process, status.pid);
    println!("handshake: {}", status.handshake);
    println!(
        "endpoint: {}",
        status.endpoint.as_deref().unwrap_or("unknown")
    );
    println!("routes: {}", status.routes.join(", "));
    println!(
        "dns: {}",
        if status.dns.is_empty() {
            "disabled".into()
        } else {
            status.dns.join(", ")
        }
    );
    println!(
        "firewall: {}",
        if status.firewall {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!(
        "transfer: {} bytes sent, {} bytes received",
        status.bytes_sent, status.bytes_received
    );
}

fn cmd_check(config_path: &Path) -> Result<()> {
    check_file_permissions(config_path).context("configuration file has insecure permissions")?;
    let config = Config::from_file(config_path).context("failed to load configuration")?;
    config
        .validate_client()
        .context("invalid client configuration")?;
    let endpoint = config.peers[0].endpoint.as_ref().unwrap().resolve_ipv4()?;
    require_path("/dev/net/tun")?;
    require_command("ip")?;
    if config
        .client
        .as_ref()
        .is_some_and(|client| client.kill_switch)
    {
        require_command("nft")?;
    }
    if config
        .client
        .as_ref()
        .is_some_and(|client| client.dns_leak_prevention)
    {
        require_command("resolvectl")?;
    }
    println!("configuration: valid client schema");
    println!(
        "endpoint: {} -> {}",
        config.peers[0].endpoint.as_ref().unwrap().as_str(),
        endpoint
    );
    println!("TUN, routing, firewall, and resolver prerequisites: available");
    Ok(())
}

async fn cmd_recover() -> Result<()> {
    recover_runtime(RuntimeRole::Client).await?;
    safety::emergency_cleanup()?;
    println!("client stale runtime and owned networking state recovered");
    Ok(())
}

async fn wait_until_stopped(role: RuntimeRole) -> Result<()> {
    for _ in 0..50 {
        if send_control(role, ControlRequest::Status).await.is_err() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    anyhow::bail!("client accepted stop but did not exit within five seconds")
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

fn cmd_smoke_test() -> Result<()> {
    let tun = LinuxTun::new("rg_test", 1420)
        .context("failed to create TUN device; run with network-administration privileges")?;
    tun.up().context("failed to bring test interface up")?;
    tun.add_address("10.99.99.1/24")
        .context("failed to add test address")?;

    let packet = [
        0x45, 0, 0, 20, 0, 0, 0, 0, 64, 0, 0, 0, 10, 99, 99, 1, 10, 99, 99, 2,
    ];
    tun.write(&packet).context("failed to write test packet")?;
    info!("TUN smoke test passed");
    Ok(())
}
