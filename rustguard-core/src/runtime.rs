//! Root-private runtime ownership and local lifecycle control.

use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const RUNTIME_DIR: &str = "/run/rustguard";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeRole {
    Client,
    Server,
}

impl RuntimeRole {
    pub fn name(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
        }
    }

    fn path(self, extension: &str) -> PathBuf {
        Path::new(RUNTIME_DIR).join(format!("{}.{}", self.name(), extension))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlRequest {
    Status,
    Stop,
}

impl ControlRequest {
    fn wire(self) -> &'static str {
        match self {
            Self::Status => "STATUS\n",
            Self::Stop => "STOP\n",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "STATUS" => Some(Self::Status),
            "STOP" => Some(Self::Stop),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RuntimeStatus {
    pub role: RuntimeRole,
    pub pid: u32,
    pub started_unix: u64,
    pub process: String,
    pub handshake: String,
    pub last_handshake_seconds: Option<u64>,
    pub endpoint: Option<String>,
    pub routes: Vec<String>,
    pub dns: Vec<String>,
    pub firewall: bool,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    #[serde(default)]
    pub peers: Vec<PeerRuntimeStatus>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PeerRuntimeStatus {
    pub name: String,
    pub handshake: String,
    pub last_handshake_seconds: Option<u64>,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl RuntimeStatus {
    pub fn starting(role: RuntimeRole) -> Self {
        Self {
            role,
            pid: std::process::id(),
            started_unix: now_unix(),
            process: "running".into(),
            handshake: "waiting".into(),
            last_handshake_seconds: None,
            endpoint: None,
            routes: Vec::new(),
            dns: Vec::new(),
            firewall: false,
            bytes_sent: 0,
            bytes_received: 0,
            peers: Vec::new(),
        }
    }
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("another {0} instance owns the runtime lock; use status or recover")]
    AlreadyRunning(&'static str),
    #[error("{0} is not running")]
    NotRunning(&'static str),
    #[error("refusing recovery because {0} is still running")]
    Active(&'static str),
    #[error("runtime I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("runtime state is invalid: {0}")]
    Json(#[from] serde_json::Error),
}

pub struct RuntimeOwner {
    role: RuntimeRole,
    listener: UnixListener,
    lock_path: PathBuf,
    socket_path: PathBuf,
    status_path: PathBuf,
}

impl RuntimeOwner {
    pub fn acquire(role: RuntimeRole) -> Result<Self, RuntimeError> {
        ensure_private_runtime_dir(Path::new(RUNTIME_DIR))?;
        let lock_path = role.path("lock");
        let socket_path = role.path("sock");
        let status_path = role.path("status.json");
        let mut lock = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lock_path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    RuntimeError::AlreadyRunning(role.name())
                } else {
                    RuntimeError::Io(error)
                }
            })?;
        let status_temporary = status_path.with_extension("json.new");
        if let Err(error) = remove_if_present(&status_temporary) {
            let _ = fs::remove_file(&lock_path);
            return Err(RuntimeError::Io(error));
        }
        if let Err(error) = set_mode(&lock_path, 0o600) {
            let _ = fs::remove_file(&lock_path);
            return Err(RuntimeError::Io(error));
        }
        writeln!(lock, "{}", std::process::id())?;
        lock.sync_all()?;

        let _ = fs::remove_file(&socket_path);
        let _ = fs::remove_file(&status_path);
        let listener = match UnixListener::bind(&socket_path) {
            Ok(listener) => listener,
            Err(error) => {
                let _ = fs::remove_file(&lock_path);
                return Err(RuntimeError::Io(error));
            }
        };
        if let Err(error) = set_mode(&socket_path, 0o600) {
            let _ = fs::remove_file(&socket_path);
            let _ = fs::remove_file(&lock_path);
            return Err(RuntimeError::Io(error));
        }
        Ok(Self {
            role,
            listener,
            lock_path,
            socket_path,
            status_path,
        })
    }

    pub async fn accept(&self) -> std::io::Result<UnixStream> {
        self.listener.accept().await.map(|(stream, _)| stream)
    }

    pub fn write_status(&self, status: &RuntimeStatus) -> Result<(), RuntimeError> {
        let temporary = self.status_path.with_extension("json.new");
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        set_mode(&temporary, 0o600)?;
        serde_json::to_writer(&file, status)?;
        file.sync_all()?;
        fs::rename(temporary, &self.status_path)?;
        Ok(())
    }

    pub async fn read_request(stream: &mut UnixStream) -> std::io::Result<ControlRequest> {
        let mut bytes = [0_u8; 32];
        let length = stream.read(&mut bytes).await?;
        let request = std::str::from_utf8(&bytes[..length])
            .ok()
            .and_then(ControlRequest::parse)
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid request")
            })?;
        Ok(request)
    }

    pub async fn reply(
        stream: &mut UnixStream,
        status: &RuntimeStatus,
    ) -> Result<(), RuntimeError> {
        let mut response = serde_json::to_vec(status)?;
        response.push(b'\n');
        stream.write_all(&response).await?;
        Ok(())
    }
}

impl Drop for RuntimeOwner {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket_path);
        let _ = fs::remove_file(&self.status_path);
        let _ = fs::remove_file(&self.lock_path);
        let _ = self.role;
    }
}

pub async fn send_control(
    role: RuntimeRole,
    request: ControlRequest,
) -> Result<RuntimeStatus, RuntimeError> {
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        send_control_inner(role, request),
    )
    .await
    .map_err(|_| {
        RuntimeError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "control request timed out",
        ))
    })?
}

async fn send_control_inner(
    role: RuntimeRole,
    request: ControlRequest,
) -> Result<RuntimeStatus, RuntimeError> {
    let mut stream = UnixStream::connect(role.path("sock"))
        .await
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound
                || error.kind() == std::io::ErrorKind::ConnectionRefused
            {
                RuntimeError::NotRunning(role.name())
            } else {
                RuntimeError::Io(error)
            }
        })?;
    stream.write_all(request.wire().as_bytes()).await?;
    stream.shutdown().await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    Ok(serde_json::from_slice(&response)?)
}

pub async fn recover_runtime(role: RuntimeRole) -> Result<(), RuntimeError> {
    if send_control(role, ControlRequest::Status).await.is_ok() {
        return Err(RuntimeError::Active(role.name()));
    }
    let lock_path = role.path("lock");
    if let Ok(contents) = fs::read_to_string(&lock_path) {
        if let Ok(pid) = contents.trim().parse::<u32>() {
            let executable = fs::read_link(format!("/proc/{pid}/exe")).ok();
            if executable.as_ref().is_some_and(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.contains(&format!("rustguard-{}", role.name())))
            }) {
                return Err(RuntimeError::Active(role.name()));
            }
        }
    }
    for extension in ["sock", "status.json", "lock"] {
        let path = role.path(extension);
        if path.exists() {
            fs::remove_file(path)?;
        }
    }
    remove_if_present(&role.path("status.json").with_extension("json.new"))?;
    Ok(())
}

/// Send a best-effort readiness/status notification when systemd supplied a
/// filesystem `NOTIFY_SOCKET`. Absence is normal outside a service unit.
pub fn notify_systemd(message: &str) -> std::io::Result<()> {
    let Some(name) = std::env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    let socket = std::os::unix::net::UnixDatagram::unbound()?;
    #[cfg(target_os = "linux")]
    {
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::ffi::OsStrExt;
        let bytes = name.as_os_str().as_bytes();
        if bytes.first() == Some(&b'@') {
            let address = std::os::unix::net::SocketAddr::from_abstract_name(&bytes[1..])?;
            socket.send_to_addr(message.as_bytes(), &address)?;
            return Ok(());
        }
    }
    socket.connect(PathBuf::from(name))?;
    socket.send(message.as_bytes())?;
    Ok(())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(unix)]
fn ensure_private_runtime_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("{} is not a real directory", path.display()),
                ));
            }
            if metadata.uid() != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("{} is not owned by root", path.display()),
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::create_dir(path)?,
        Err(error) => return Err(error),
    }
    set_mode(path, 0o700)
}

#[cfg(not(unix))]
fn ensure_private_runtime_dir(path: &Path) -> std::io::Result<()> {
    fs::create_dir_all(path)
}

fn remove_if_present(path: &Path) -> std::io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> std::io::Result<()> {
    Ok(())
}
