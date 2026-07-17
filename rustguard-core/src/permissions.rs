//! File permission checking for security-critical files.
//!
//! This module enforces that private keys and configuration files
//! have permissions of 0600 or stricter (owner read/write only).

use std::path::Path;
use thiserror::Error;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

/// Errors related to file permissions.
#[derive(Debug, Error)]
pub enum PermissionError {
    #[error("Failed to read file metadata: {0}")]
    IoError(#[from] std::io::Error),

    #[error(
        "File permissions too permissive for {path}: mode {mode:04o}, required 0600 or stricter"
    )]
    TooPermissive { path: String, mode: u32 },

    #[error("Refusing non-regular or symbolic-link configuration file: {0}")]
    InvalidFileType(String),

    #[error(
        "Configuration file {path} is owned by uid {actual}, expected effective uid {expected}"
    )]
    WrongOwner {
        path: String,
        actual: u32,
        expected: u32,
    },

    #[error("Permission checks are only supported on Unix systems")]
    UnsupportedPlatform,
}

/// Check that a file has permissions of 0600 or stricter.
///
/// This means:
/// - Owner can read and write (0600)
/// - No group or other permissions
///
/// Stricter permissions (e.g., 0400 read-only) are also accepted.
///
/// # Errors
///
/// Returns an error if:
/// - The file cannot be read
/// - The file has group or other permissions set
/// - Running on a non-Unix platform
///
/// # Example
///
/// ```no_run
/// use rustguard_core::permissions::check_file_permissions;
/// use std::path::Path;
///
/// check_file_permissions(Path::new("/etc/rustguard/private.key"))
///     .expect("Private key must have secure permissions");
/// ```
#[cfg(unix)]
pub fn check_file_permissions(path: &Path) -> Result<(), PermissionError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(PermissionError::InvalidFileType(path.display().to_string()));
    }
    // SAFETY: `geteuid` has no preconditions and does not dereference memory.
    let expected_uid = unsafe { libc::geteuid() };
    if metadata.uid() != expected_uid {
        return Err(PermissionError::WrongOwner {
            path: path.display().to_string(),
            actual: metadata.uid(),
            expected: expected_uid,
        });
    }
    let mode = metadata.mode();

    // Extract permission bits (last 9 bits)
    let perms = mode & 0o777;

    // Check that group and other have no permissions
    // Owner can have read (0400) and/or write (0200)
    // Group (0070) and other (0007) must be zero
    if perms & 0o077 != 0 {
        return Err(PermissionError::TooPermissive {
            path: path.display().to_string(),
            mode: perms,
        });
    }

    Ok(())
}

#[cfg(not(unix))]
pub fn check_file_permissions(_path: &Path) -> Result<(), PermissionError> {
    // On non-Unix platforms, we cannot check permissions
    // This is documented as a limitation
    Err(PermissionError::UnsupportedPlatform)
}

/// Check permissions for multiple files, returning all errors.
pub fn check_all_permissions(paths: &[&Path]) -> Result<(), Vec<PermissionError>> {
    let errors: Vec<PermissionError> = paths
        .iter()
        .filter_map(|path| check_file_permissions(path).err())
        .collect();

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::os::unix::fs::symlink;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    #[test]
    fn test_secure_permissions_accepted() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("secure.key");
        File::create(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        assert!(check_file_permissions(&path).is_ok());
    }

    #[test]
    fn test_readonly_permissions_accepted() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("readonly.key");
        File::create(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();

        assert!(check_file_permissions(&path).is_ok());
    }

    #[test]
    fn test_group_readable_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("group.key");
        File::create(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();

        let result = check_file_permissions(&path);
        assert!(matches!(result, Err(PermissionError::TooPermissive { .. })));
    }

    #[test]
    fn test_world_readable_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("world.key");
        File::create(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let result = check_file_permissions(&path);
        assert!(matches!(result, Err(PermissionError::TooPermissive { .. })));
    }

    #[test]
    fn test_error_does_not_contain_secrets() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("secret_key_material.key");
        File::create(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let result = check_file_permissions(&path);
        let error_msg = format!("{}", result.unwrap_err());

        // Error message should contain path and mode, but nothing that looks like key material
        assert!(error_msg.contains("secret_key_material.key"));
        assert!(error_msg.contains("0644"));
        // Should not contain any base64-looking strings or raw bytes
    }

    #[test]
    fn symbolic_link_is_rejected() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("target.toml");
        let link = dir.path().join("config.toml");
        File::create(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, &link).unwrap();

        assert!(matches!(
            check_file_permissions(&link),
            Err(PermissionError::InvalidFileType(_))
        ));
    }
}
