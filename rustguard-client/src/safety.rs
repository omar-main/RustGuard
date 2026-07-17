//! Transactional Linux networking for the RustGuard client.
//!
//! Every mutation is recorded in a root-only journal and has one exact inverse.
//! Setup is fail-fast; graceful shutdown and `emergency-off` use the same rollback.

use anyhow::{anyhow, bail, Context, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tracing::{error, info};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const STATE_DIR: &str = "/run/rustguard";
const JOURNAL_FILE: &str = "/run/rustguard/client-rg0.json";

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
struct RouteSpec {
    destination: String,
    via: Option<Ipv4Addr>,
    device: String,
}

impl RouteSpec {
    fn arguments(&self, operation: &str) -> Vec<String> {
        let mut arguments = vec![
            "-4".into(),
            "route".into(),
            operation.into(),
            self.destination.clone(),
        ];
        if let Some(gateway) = self.via {
            arguments.extend(["via".into(), gateway.to_string()]);
        }
        arguments.extend(["dev".into(), self.device.clone()]);
        arguments
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
enum Change {
    Route(RouteSpec),
    Firewall { table: String },
    Dns { interface: String },
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
enum ChangeState {
    Applying,
    Applied,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct JournalEntry {
    change: Change,
    state: ChangeState,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct Journal {
    entries: Vec<JournalEntry>,
}

#[derive(Debug)]
struct NetworkPlan {
    endpoint_route: RouteSpec,
    tunnel_routes: Vec<RouteSpec>,
    firewall: Option<FirewallPlan>,
    dns: Option<DnsPlan>,
}

#[derive(Debug)]
struct FirewallPlan {
    table: String,
    rules: String,
}

#[derive(Debug)]
struct DnsPlan {
    interface: String,
    servers: Vec<IpAddr>,
}

trait Runner {
    fn run(&mut self, program: &str, arguments: &[String], stdin: Option<&str>) -> Result<String>;
}

struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&mut self, program: &str, arguments: &[String], stdin: Option<&str>) -> Result<String> {
        let mut command = Command::new(program);
        command
            .args(arguments)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if stdin.is_some() {
            command.stdin(Stdio::piped());
        }
        let mut child = command
            .spawn()
            .with_context(|| format!("failed to execute {program}"))?;
        if let Some(input) = stdin {
            child
                .stdin
                .take()
                .context("command stdin was unavailable")?
                .write_all(input.as_bytes())
                .with_context(|| format!("failed to write to {program}"))?;
        }
        let output = child
            .wait_with_output()
            .with_context(|| format!("failed to wait for {program}"))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let is_exact_cleanup = (program == "ip" && arguments.iter().any(|arg| arg == "del"))
                || (program == "nft" && arguments.first().is_some_and(|arg| arg == "delete"));
            let already_absent = [
                "No such process",
                "Cannot find device",
                "No such file or directory",
                "does not exist",
            ]
            .iter()
            .any(|message| stderr.contains(message));
            if is_exact_cleanup && already_absent {
                return Ok(String::new());
            }
            bail!(
                "{} {} failed: {}",
                program,
                arguments.join(" "),
                stderr.trim()
            );
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

/// Owns the successfully applied client network transaction.
pub struct SafetyGuard {
    journal_path: PathBuf,
    active: bool,
}

impl SafetyGuard {
    #[allow(clippy::too_many_arguments)]
    pub fn apply(
        tun_name: &str,
        endpoint: SocketAddr,
        allowed_ips: &[IpNet],
        dns_servers: &[IpAddr],
        kill_switch: bool,
        dns_leak_prevention: bool,
        allow_lan: bool,
    ) -> Result<Self> {
        validate_interface_name(tun_name)?;
        let endpoint_ip = ipv4_endpoint(endpoint)?;
        let mut runner = SystemRunner;
        let route_output = runner.run(
            "ip",
            &[
                "-4".into(),
                "route".into(),
                "get".into(),
                endpoint_ip.to_string(),
            ],
            None,
        )?;
        let endpoint_route = parse_endpoint_route(&route_output, endpoint_ip)?;
        let plan = NetworkPlan::new(
            tun_name,
            endpoint,
            endpoint_route,
            allowed_ips,
            dns_servers,
            kill_switch,
            dns_leak_prevention,
            allow_lan,
        )?;
        apply_plan(&plan, &mut runner, Path::new(JOURNAL_FILE))?;
        info!("client networking transaction applied");
        Ok(Self {
            journal_path: PathBuf::from(JOURNAL_FILE),
            active: true,
        })
    }
}

impl Drop for SafetyGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut runner = SystemRunner;
        match rollback_journal(&mut runner, &self.journal_path) {
            Ok(()) => info!("client networking transaction rolled back"),
            Err(error) => error!(%error, "network rollback incomplete; run emergency-off"),
        }
        self.active = false;
    }
}

impl NetworkPlan {
    #[allow(clippy::too_many_arguments)]
    fn new(
        tun_name: &str,
        endpoint: SocketAddr,
        endpoint_route: RouteSpec,
        allowed_ips: &[IpNet],
        dns_servers: &[IpAddr],
        kill_switch: bool,
        dns_leak_prevention: bool,
        allow_lan: bool,
    ) -> Result<Self> {
        let mut destinations = HashSet::new();
        let mut tunnel_routes = Vec::new();
        for network in allowed_ips {
            let IpNet::V4(network) = network else {
                bail!("safe client networking currently supports IPv4 routes only");
            };
            let routes = if network.prefix_len() == 0 {
                vec!["0.0.0.0/1".to_string(), "128.0.0.0/1".to_string()]
            } else {
                vec![network.trunc().to_string()]
            };
            for destination in routes {
                if destinations.insert(destination.clone()) {
                    tunnel_routes.push(RouteSpec {
                        destination,
                        via: None,
                        device: tun_name.into(),
                    });
                }
            }
        }
        if tunnel_routes.is_empty() {
            bail!("at least one IPv4 tunnel route is required");
        }

        let firewall = kill_switch.then(|| FirewallPlan {
            table: format!("rustguard_{tun_name}"),
            rules: nft_rules(tun_name, endpoint, allow_lan),
        });
        let dns = if dns_leak_prevention {
            if dns_servers.is_empty() {
                bail!("DNS leak prevention requires at least one DNS server");
            }
            if dns_servers.iter().any(|server| !server.is_ipv4()) {
                bail!("safe client networking currently supports IPv4 DNS only");
            }
            if dns_servers
                .iter()
                .any(|server| !allowed_ips.iter().any(|network| network.contains(server)))
            {
                bail!("each protected DNS server must be inside a peer allowed network");
            }
            Some(DnsPlan {
                interface: tun_name.into(),
                servers: dns_servers.to_vec(),
            })
        } else {
            None
        };
        Ok(Self {
            endpoint_route,
            tunnel_routes,
            firewall,
            dns,
        })
    }
}

fn apply_plan(plan: &NetworkPlan, runner: &mut dyn Runner, journal_path: &Path) -> Result<()> {
    prepare_journal(journal_path)?;
    let mut journal = Journal::default();
    let result = (|| {
        apply_route(runner, journal_path, &mut journal, &plan.endpoint_route)?;
        if let Some(firewall) = &plan.firewall {
            apply_firewall(runner, journal_path, &mut journal, firewall)?;
        }
        for route in &plan.tunnel_routes {
            apply_route(runner, journal_path, &mut journal, route)?;
        }
        if let Some(dns) = &plan.dns {
            apply_dns(runner, journal_path, &mut journal, dns)?;
        }
        Ok(())
    })();
    if let Err(setup_error) = result {
        let rollback_error = rollback_entries(runner, &journal.entries).err();
        if rollback_error.is_none() {
            remove_journal(journal_path)?;
        }
        return match rollback_error {
            Some(error) => Err(anyhow!(
                "setup failed: {setup_error:#}; rollback also failed: {error:#}"
            )),
            None => Err(setup_error),
        };
    }
    Ok(())
}

fn apply_route(
    runner: &mut dyn Runner,
    path: &Path,
    journal: &mut Journal,
    route: &RouteSpec,
) -> Result<()> {
    begin_change(path, journal, Change::Route(route.clone()))?;
    if let Err(error) = runner.run("ip", &route.arguments("add"), None) {
        abandon_change(path, journal)?;
        return Err(error);
    }
    finish_change(path, journal)
}

fn apply_firewall(
    runner: &mut dyn Runner,
    path: &Path,
    journal: &mut Journal,
    plan: &FirewallPlan,
) -> Result<()> {
    begin_change(
        path,
        journal,
        Change::Firewall {
            table: plan.table.clone(),
        },
    )?;
    if let Err(error) = runner.run("nft", &["-f".into(), "-".into()], Some(&plan.rules)) {
        abandon_change(path, journal)?;
        return Err(error);
    }
    finish_change(path, journal)
}

fn apply_dns(
    runner: &mut dyn Runner,
    path: &Path,
    journal: &mut Journal,
    plan: &DnsPlan,
) -> Result<()> {
    begin_change(
        path,
        journal,
        Change::Dns {
            interface: plan.interface.clone(),
        },
    )?;
    let mut dns_args = vec!["dns".into(), plan.interface.clone()];
    dns_args.extend(plan.servers.iter().map(ToString::to_string));
    let commands = [
        dns_args,
        vec!["domain".into(), plan.interface.clone(), "~.".into()],
        vec![
            "default-route".into(),
            plan.interface.clone(),
            "true".into(),
        ],
    ];
    for arguments in commands {
        if let Err(error) = runner.run("resolvectl", &arguments, None) {
            let revert = runner.run(
                "resolvectl",
                &["revert".into(), plan.interface.clone()],
                None,
            );
            if let Err(revert_error) = revert {
                return Err(anyhow!(
                    "DNS setup failed: {error:#}; immediate DNS revert also failed: {revert_error:#}"
                ));
            }
            abandon_change(path, journal)?;
            return Err(error);
        }
    }
    finish_change(path, journal)
}

fn begin_change(path: &Path, journal: &mut Journal, change: Change) -> Result<()> {
    journal.entries.push(JournalEntry {
        change,
        state: ChangeState::Applying,
    });
    write_journal(path, journal)
}

fn finish_change(path: &Path, journal: &mut Journal) -> Result<()> {
    journal
        .entries
        .last_mut()
        .context("empty network journal")?
        .state = ChangeState::Applied;
    write_journal(path, journal)
}

fn abandon_change(path: &Path, journal: &mut Journal) -> Result<()> {
    journal.entries.pop();
    write_journal(path, journal)
}

fn rollback_journal(runner: &mut dyn Runner, path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let journal: Journal = serde_json::from_slice(&bytes).context("invalid recovery journal")?;
    rollback_entries(runner, &journal.entries)?;
    remove_journal(path)
}

fn rollback_entries(runner: &mut dyn Runner, entries: &[JournalEntry]) -> Result<()> {
    let mut errors = Vec::new();
    for entry in entries.iter().rev() {
        let result = match &entry.change {
            Change::Route(route) => runner.run("ip", &route.arguments("del"), None),
            Change::Firewall { table } => runner.run(
                "nft",
                &[
                    "delete".into(),
                    "table".into(),
                    "inet".into(),
                    table.clone(),
                ],
                None,
            ),
            Change::Dns { interface } => {
                runner.run("resolvectl", &["revert".into(), interface.clone()], None)
            }
        };
        if let Err(error) = result {
            errors.push(error.to_string());
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        bail!("{}", errors.join("; "))
    }
}

fn prepare_journal(path: &Path) -> Result<()> {
    let directory = path.parent().context("journal has no parent directory")?;
    fs::create_dir_all(directory)
        .with_context(|| format!("failed to create {}", directory.display()))?;
    if directory == Path::new(STATE_DIR) {
        set_private_permissions(directory, true)?;
    }
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| {
            format!(
                "{} already exists; another client may own networking (run emergency-off after verifying no client is active)",
                path.display()
            )
        })?;
    set_private_permissions(path, false)?;
    serde_json::to_writer(file, &Journal::default()).context("failed to initialize journal")
}

fn write_journal(path: &Path, journal: &Journal) -> Result<()> {
    let temporary = path.with_extension("json.new");
    if temporary.exists() {
        fs::remove_file(&temporary).context("failed to remove stale temporary journal")?;
    }
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .context("failed to open temporary journal")?;
    set_private_permissions(&temporary, false)?;
    serde_json::to_writer(&file, journal).context("failed to serialize journal")?;
    file.sync_all().context("failed to sync journal")?;
    fs::rename(&temporary, path).context("failed to commit journal")
}

fn remove_journal(path: &Path) -> Result<()> {
    if path.exists() {
        fs::remove_file(path).with_context(|| format!("failed to remove {}", path.display()))?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_permissions(path: &Path, directory: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(
        path,
        fs::Permissions::from_mode(if directory { 0o700 } else { 0o600 }),
    )
    .with_context(|| format!("failed to secure {}", path.display()))
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path, _directory: bool) -> Result<()> {
    Ok(())
}

fn parse_endpoint_route(output: &str, endpoint: Ipv4Addr) -> Result<RouteSpec> {
    let first_line = output
        .lines()
        .next()
        .context("ip route get returned no route")?;
    let fields: Vec<_> = first_line.split_whitespace().collect();
    let device = value_after(&fields, "dev").context("endpoint route has no device")?;
    let via = value_after(&fields, "via")
        .map(str::parse)
        .transpose()
        .context("endpoint route has an invalid IPv4 gateway")?;
    Ok(RouteSpec {
        destination: format!("{endpoint}/32"),
        via,
        device: device.into(),
    })
}

fn value_after<'a>(fields: &'a [&str], key: &str) -> Option<&'a str> {
    fields
        .iter()
        .position(|field| *field == key)
        .and_then(|index| fields.get(index + 1).copied())
}

fn ipv4_endpoint(endpoint: SocketAddr) -> Result<Ipv4Addr> {
    match endpoint.ip() {
        IpAddr::V4(address) => Ok(address),
        IpAddr::V6(_) => bail!("safe client networking currently supports IPv4 endpoints only"),
    }
}

fn validate_interface_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 15
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        bail!("invalid tunnel interface name");
    }
    Ok(())
}

fn nft_rules(tun_name: &str, endpoint: SocketAddr, allow_lan: bool) -> String {
    let endpoint_ip = endpoint.ip();
    let endpoint_port = endpoint.port();
    let table = format!("rustguard_{tun_name}");
    let lan = if allow_lan {
        "        ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } accept\n"
    } else {
        ""
    };
    format!(
        "table inet {table} {{\n    chain output {{\n        type filter hook output priority 0; policy drop;\n        oifname \"lo\" accept\n        oifname \"{tun_name}\" accept\n        ip daddr {endpoint_ip} udp dport {endpoint_port} accept\n{lan}    }}\n}}\n"
    )
}

#[allow(clippy::too_many_arguments)]
pub fn print_dry_run(
    tun_name: &str,
    endpoint: SocketAddr,
    allowed_ips: &[IpNet],
    dns_servers: &[IpAddr],
    kill_switch: bool,
    dns_leak_prevention: bool,
    allow_lan: bool,
) {
    println!(
        "Endpoint escape: ip -4 route get {} followed by an owned /32 route",
        endpoint.ip()
    );
    println!("Tunnel routes:");
    for network in allowed_ips {
        if network.prefix_len() == 0 {
            println!("  ip -4 route add 0.0.0.0/1 dev {tun_name}");
            println!("  ip -4 route add 128.0.0.0/1 dev {tun_name}");
        } else {
            println!("  ip -4 route add {network} dev {tun_name}");
        }
    }
    if kill_switch {
        println!(
            "Kill switch (atomic nft input):\n{}",
            nft_rules(tun_name, endpoint, allow_lan)
        );
    }
    if dns_leak_prevention {
        println!(
            "resolvectl dns {tun_name} {}",
            dns_servers
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" ")
        );
        println!("resolvectl domain {tun_name} ~.");
        println!("resolvectl default-route {tun_name} true");
    }
}

/// Recover only the state named by RustGuard's exact ownership journal.
pub fn emergency_cleanup() -> Result<()> {
    let mut runner = SystemRunner;
    rollback_journal(&mut runner, Path::new(JOURNAL_FILE))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeRunner {
        calls: Vec<String>,
        fail_at: Option<usize>,
    }

    impl Runner for FakeRunner {
        fn run(
            &mut self,
            program: &str,
            arguments: &[String],
            _stdin: Option<&str>,
        ) -> Result<String> {
            self.calls
                .push(format!("{program} {}", arguments.join(" ")));
            if self.fail_at == Some(self.calls.len()) {
                bail!("injected failure");
            }
            Ok(String::new())
        }
    }

    fn endpoint_route() -> RouteSpec {
        RouteSpec {
            destination: "198.51.100.7/32".into(),
            via: Some("192.0.2.1".parse().unwrap()),
            device: "eth0".into(),
        }
    }

    fn plan(full: bool, firewall: bool, dns: bool) -> NetworkPlan {
        NetworkPlan::new(
            "rg0",
            "198.51.100.7:51820".parse().unwrap(),
            endpoint_route(),
            &[if full { "0.0.0.0/0" } else { "10.20.0.0/16" }
                .parse()
                .unwrap()],
            &[if full { "10.0.0.53" } else { "10.20.0.53" }
                .parse()
                .unwrap()],
            firewall,
            dns,
            false,
        )
        .unwrap()
    }

    fn temp_journal(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("rustguard-{name}-{}.json", std::process::id()))
    }

    #[test]
    fn full_tunnel_is_two_half_routes() {
        let plan = plan(true, false, false);
        assert_eq!(
            plan.tunnel_routes
                .iter()
                .map(|r| r.destination.as_str())
                .collect::<Vec<_>>(),
            vec!["0.0.0.0/1", "128.0.0.0/1"]
        );
    }

    #[test]
    fn split_tunnel_is_exact_and_endpoint_escapes() {
        let plan = plan(false, false, false);
        assert_eq!(plan.tunnel_routes[0].destination, "10.20.0.0/16");
        assert_eq!(plan.endpoint_route, endpoint_route());
    }

    #[test]
    fn protected_dns_must_be_routed_through_the_tunnel() {
        let result = NetworkPlan::new(
            "rg0",
            "198.51.100.7:51820".parse().unwrap(),
            endpoint_route(),
            &["10.20.0.0/16".parse().unwrap()],
            &["192.0.2.53".parse().unwrap()],
            false,
            true,
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn kill_switch_is_fail_closed_without_implicit_lan_or_established_bypass() {
        let rules = nft_rules("rg0", "198.51.100.7:51820".parse().unwrap(), false);
        assert!(rules.contains("policy drop"));
        assert!(rules.contains("oifname \"rg0\" accept"));
        assert!(!rules.contains("10.0.0.0/8"));
        assert!(!rules.contains("established"));
        assert!(!rules.contains("chain input"));
    }

    #[test]
    fn parses_gateway_and_direct_endpoint_paths() {
        assert_eq!(
            parse_endpoint_route(
                "198.51.100.7 via 192.0.2.1 dev eth0 src 192.0.2.2",
                "198.51.100.7".parse().unwrap()
            )
            .unwrap(),
            endpoint_route()
        );
        let direct = parse_endpoint_route(
            "198.51.100.7 dev eth0 src 198.51.100.2",
            "198.51.100.7".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(direct.via, None);
        assert_eq!(direct.device, "eth0");
    }

    #[test]
    fn every_setup_failure_rolls_back_applied_changes_in_reverse() {
        for failure in 1..=7 {
            let path = temp_journal(&format!("rollback-{failure}"));
            let _ = fs::remove_file(&path);
            let mut runner = FakeRunner {
                fail_at: Some(failure),
                ..Default::default()
            };
            let result = apply_plan(&plan(true, true, true), &mut runner, &path);
            assert!(result.is_err(), "failure {failure} should abort setup");
            assert!(!path.exists(), "successful rollback should remove journal");
        }
    }

    #[test]
    fn rollback_is_exact_and_preserves_unrelated_state() {
        let path = temp_journal("exact");
        let _ = fs::remove_file(&path);
        let mut runner = FakeRunner::default();
        apply_plan(&plan(false, true, true), &mut runner, &path).unwrap();
        rollback_journal(&mut runner, &path).unwrap();
        assert!(runner
            .calls
            .iter()
            .any(|call| call == "nft delete table inet rustguard_rg0"));
        assert!(runner.calls.iter().all(|call| !call.contains("flush")));
        assert!(runner
            .calls
            .iter()
            .all(|call| !call.contains("resolv.conf")));
        assert!(!path.exists());
    }
}
