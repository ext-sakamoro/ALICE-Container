//! Root Filesystem Construction
//!
//! Provides utilities for setting up container root filesystems,
//! including bind mounts, proc/dev setup, and pivot_root preparation.
//!
//! ## Minimal Container Filesystem
//!
//! ```text
//! /container/rootfs/
//! ├── bin/           (bind mount or copy)
//! ├── lib/           (bind mount or copy)
//! ├── lib64/         (bind mount or copy)
//! ├── usr/           (bind mount or copy)
//! ├── etc/           (container-specific)
//! │   ├── hostname
//! │   ├── hosts
//! │   └── resolv.conf
//! ├── proc/          (mount -t proc)
//! ├── dev/           (minimal device nodes)
//! │   ├── null
//! │   ├── zero
//! │   ├── random
//! │   ├── urandom
//! │   └── tty
//! ├── tmp/           (tmpfs)
//! └── .old_root/     (for pivot_root)
//! ```

#[cfg(target_os = "linux")]
use core::ffi::c_int;

#[cfg(feature = "std")]
use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

#[cfg(all(feature = "std", unix))]
use std::os::unix::fs::PermissionsExt;

// ============================================================================
// Mount Flags (Linux values, defined as constants for cross-compilation)
// ============================================================================

/// Mount flags
pub mod mount_flags {
    /// Read-only mount
    pub const MS_RDONLY: u64 = 1;
    /// Don't interpret special files
    pub const MS_NODEV: u64 = 4;
    /// Don't allow setuid
    pub const MS_NOSUID: u64 = 2;
    /// Don't allow exec
    pub const MS_NOEXEC: u64 = 8;
    /// Bind mount
    pub const MS_BIND: u64 = 4096;
    /// Recursive bind
    pub const MS_REC: u64 = 16384;
    /// Private mount
    pub const MS_PRIVATE: u64 = 1 << 18;
    /// Slave mount
    pub const MS_SLAVE: u64 = 1 << 19;
    /// Remount
    pub const MS_REMOUNT: u64 = 32;
}

// ============================================================================
// Error Types
// ============================================================================

/// Root filesystem errors
#[derive(Debug)]
pub enum RootFsError {
    /// Path does not exist
    PathNotFound(String),
    /// Permission denied
    PermissionDenied,
    /// Mount failed
    MountFailed(String),
    /// Device creation failed
    DeviceCreationFailed(String),
    /// I/O error
    IoError(String),
    /// Not supported on this platform
    NotSupported,
}

impl core::fmt::Display for RootFsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RootFsError::PathNotFound(path) => write!(f, "Path not found: {}", path),
            RootFsError::PermissionDenied => write!(f, "Permission denied"),
            RootFsError::MountFailed(msg) => write!(f, "Mount failed: {}", msg),
            RootFsError::DeviceCreationFailed(msg) => write!(f, "Device creation failed: {}", msg),
            RootFsError::IoError(msg) => write!(f, "I/O error: {}", msg),
            RootFsError::NotSupported => write!(f, "Not supported on this platform"),
        }
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for RootFsError {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            RootFsError::PermissionDenied
        } else {
            RootFsError::IoError(e.to_string())
        }
    }
}

// ============================================================================
// Root Filesystem Builder
// ============================================================================

/// Root filesystem builder and manager
#[cfg(feature = "std")]
pub struct RootFs {
    /// Path to root filesystem
    path: PathBuf,
    /// Whether to clean up on drop
    cleanup: bool,
}

#[cfg(feature = "std")]
impl RootFs {
    /// Create a new root filesystem at the given path
    pub fn create(path: impl Into<PathBuf>) -> Result<Self, RootFsError> {
        let path = path.into();

        // Create root directory
        fs::create_dir_all(&path)?;

        // Create essential directories
        let dirs = ["bin", "lib", "lib64", "usr", "etc", "proc", "dev", "sys", "tmp", "root", ".old_root"];
        for dir in dirs {
            fs::create_dir_all(path.join(dir))?;
        }

        // Set tmp permissions (Unix only)
        #[cfg(unix)]
        fs::set_permissions(path.join("tmp"), fs::Permissions::from_mode(0o1777))?;

        Ok(Self {
            path,
            cleanup: false,
        })
    }

    /// Open existing root filesystem
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, RootFsError> {
        let path = path.into();

        if !path.exists() {
            return Err(RootFsError::PathNotFound(path.to_string_lossy().to_string()));
        }

        Ok(Self {
            path,
            cleanup: false,
        })
    }

    /// Set cleanup on drop
    pub fn with_cleanup(mut self) -> Self {
        self.cleanup = true;
        self
    }

    /// Get root path
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Bind mount a host directory into the rootfs (Linux only)
    #[cfg(target_os = "linux")]
    pub fn bind_mount(&self, source: &Path, target: &str) -> Result<(), RootFsError> {
        let target_path = self.path.join(target);
        fs::create_dir_all(&target_path)?;

        mount(
            Some(source),
            &target_path,
            None,
            mount_flags::MS_BIND | mount_flags::MS_REC,
            None,
        )
    }

    /// Bind mount (non-Linux stub)
    #[cfg(not(target_os = "linux"))]
    pub fn bind_mount(&self, _source: &Path, _target: &str) -> Result<(), RootFsError> {
        Err(RootFsError::NotSupported)
    }

    /// Bind mount read-only (Linux only)
    #[cfg(target_os = "linux")]
    pub fn bind_mount_ro(&self, source: &Path, target: &str) -> Result<(), RootFsError> {
        // First bind mount
        self.bind_mount(source, target)?;

        // Then remount read-only
        let target_path = self.path.join(target);
        mount(
            None,
            &target_path,
            None,
            mount_flags::MS_REMOUNT | mount_flags::MS_BIND | mount_flags::MS_RDONLY,
            None,
        )
    }

    /// Bind mount read-only (non-Linux stub)
    #[cfg(not(target_os = "linux"))]
    pub fn bind_mount_ro(&self, _source: &Path, _target: &str) -> Result<(), RootFsError> {
        Err(RootFsError::NotSupported)
    }

    /// Mount proc filesystem (Linux only)
    #[cfg(target_os = "linux")]
    pub fn mount_proc(&self) -> Result<(), RootFsError> {
        mount_proc(&self.path.join("proc"))
    }

    /// Mount proc (non-Linux stub)
    #[cfg(not(target_os = "linux"))]
    pub fn mount_proc(&self) -> Result<(), RootFsError> {
        Err(RootFsError::NotSupported)
    }

    /// Mount sysfs (Linux only)
    #[cfg(target_os = "linux")]
    pub fn mount_sys(&self) -> Result<(), RootFsError> {
        let target = self.path.join("sys");
        mount(
            Some(Path::new("sysfs")),
            &target,
            Some("sysfs"),
            mount_flags::MS_NOSUID | mount_flags::MS_NODEV | mount_flags::MS_NOEXEC,
            None,
        )
    }

    /// Mount sysfs (non-Linux stub)
    #[cfg(not(target_os = "linux"))]
    pub fn mount_sys(&self) -> Result<(), RootFsError> {
        Err(RootFsError::NotSupported)
    }

    /// Mount tmpfs (Linux only)
    #[cfg(target_os = "linux")]
    pub fn mount_tmp(&self) -> Result<(), RootFsError> {
        let target = self.path.join("tmp");
        mount(
            Some(Path::new("tmpfs")),
            &target,
            Some("tmpfs"),
            mount_flags::MS_NOSUID | mount_flags::MS_NODEV,
            Some("size=64M,mode=1777"),
        )
    }

    /// Mount tmpfs (non-Linux stub)
    #[cfg(not(target_os = "linux"))]
    pub fn mount_tmp(&self) -> Result<(), RootFsError> {
        Err(RootFsError::NotSupported)
    }

    /// Set up minimal /dev (Linux only)
    #[cfg(target_os = "linux")]
    pub fn setup_dev(&self) -> Result<(), RootFsError> {
        mount_dev(&self.path.join("dev"))
    }

    /// Setup dev (non-Linux stub)
    #[cfg(not(target_os = "linux"))]
    pub fn setup_dev(&self) -> Result<(), RootFsError> {
        Err(RootFsError::NotSupported)
    }

    /// Write /etc/hostname
    pub fn set_hostname(&self, hostname: &str) -> Result<(), RootFsError> {
        let path = self.path.join("etc/hostname");
        let mut file = File::create(&path)?;
        writeln!(file, "{}", hostname)?;
        Ok(())
    }

    /// Write /etc/hosts
    pub fn set_hosts(&self, hostname: &str) -> Result<(), RootFsError> {
        let path = self.path.join("etc/hosts");
        let mut file = File::create(&path)?;
        writeln!(file, "127.0.0.1\tlocalhost")?;
        writeln!(file, "::1\t\tlocalhost")?;
        writeln!(file, "127.0.0.1\t{}", hostname)?;
        Ok(())
    }

    /// Write /etc/resolv.conf
    pub fn set_resolv_conf(&self, nameservers: &[&str]) -> Result<(), RootFsError> {
        let path = self.path.join("etc/resolv.conf");
        let mut file = File::create(&path)?;
        for ns in nameservers {
            writeln!(file, "nameserver {}", ns)?;
        }
        Ok(())
    }

    /// Copy a file into the rootfs
    pub fn copy_file(&self, source: &Path, target: &str) -> Result<(), RootFsError> {
        let target_path = self.path.join(target);
        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(source, target_path)?;
        Ok(())
    }

    /// Create a symlink
    #[cfg(unix)]
    pub fn symlink(&self, target: &str, link: &str) -> Result<(), RootFsError> {
        let link_path = self.path.join(link);
        if let Some(parent) = link_path.parent() {
            fs::create_dir_all(parent)?;
        }
        std::os::unix::fs::symlink(target, link_path)?;
        Ok(())
    }

    /// Create symlink (non-Unix stub)
    #[cfg(not(unix))]
    pub fn symlink(&self, _target: &str, _link: &str) -> Result<(), RootFsError> {
        Err(RootFsError::NotSupported)
    }

    /// Prepare for pivot_root (Linux only)
    #[cfg(target_os = "linux")]
    pub fn prepare_pivot(&self) -> Result<PathBuf, RootFsError> {
        // Make mount private to avoid affecting host
        mount(
            None,
            Path::new("/"),
            None,
            mount_flags::MS_REC | mount_flags::MS_PRIVATE,
            None,
        )?;

        // Bind mount rootfs to itself
        mount(
            Some(&self.path),
            &self.path,
            None,
            mount_flags::MS_BIND | mount_flags::MS_REC,
            None,
        )?;

        let put_old = self.path.join(".old_root");
        fs::create_dir_all(&put_old)?;

        Ok(put_old)
    }

    /// Prepare for pivot_root (non-Linux stub)
    #[cfg(not(target_os = "linux"))]
    pub fn prepare_pivot(&self) -> Result<PathBuf, RootFsError> {
        Err(RootFsError::NotSupported)
    }

    /// Clean up old root after pivot_root (Linux only)
    #[cfg(target_os = "linux")]
    pub fn cleanup_old_root() -> Result<(), RootFsError> {
        use crate::namespace::{umount2, MNT_DETACH};

        let old_root = Path::new("/.old_root");

        // Unmount old root
        umount2(old_root, MNT_DETACH)
            .map_err(|_| RootFsError::MountFailed("umount old_root".into()))?;

        // Remove directory
        fs::remove_dir(old_root)?;

        Ok(())
    }

    /// Cleanup old root (non-Linux stub)
    #[cfg(not(target_os = "linux"))]
    pub fn cleanup_old_root() -> Result<(), RootFsError> {
        Err(RootFsError::NotSupported)
    }
}

#[cfg(feature = "std")]
impl Drop for RootFs {
    fn drop(&mut self) {
        if self.cleanup {
            // Best effort cleanup
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

// ============================================================================
// Mount Functions (Linux only)
// ============================================================================

/// Low-level mount wrapper (Linux only)
#[cfg(all(feature = "std", target_os = "linux"))]
pub fn mount(
    source: Option<&Path>,
    target: &Path,
    fstype: Option<&str>,
    flags: u64,
    data: Option<&str>,
) -> Result<(), RootFsError> {
    use std::ffi::CString;

    // Convert every path/string argument to a NUL-terminated CString, propagating errors
    // for arguments that could contain interior NUL bytes (paths from user input).
    // filesystem type and mount data strings are caller-controlled &str values that
    // originate from compile-time literals in this module, so unwrap() is safe there.
    let source_c = source
        .map(|s| {
            CString::new(s.to_string_lossy().as_bytes())
                .map_err(|_| RootFsError::IoError("Invalid source path".into()))
        })
        .transpose()?;
    let target_c = CString::new(target.to_string_lossy().as_bytes())
        .map_err(|_| RootFsError::IoError("Invalid target path".into()))?;
    let fstype_c = fstype
        .map(|t| {
            CString::new(t)
                .map_err(|_| RootFsError::IoError("Invalid filesystem type".into()))
        })
        .transpose()?;
    let data_c = data
        .map(|d| {
            CString::new(d)
                .map_err(|_| RootFsError::IoError("Invalid mount data".into()))
        })
        .transpose()?;

    // SAFETY: All pointer arguments are either null (for optional parameters) or point to
    // valid NUL-terminated CString buffers that remain live for the duration of this call.
    // mount(2) only reads the strings and does not retain pointers after returning.
    // The kernel validates all flags and returns -1 on error.
    let ret = unsafe {
        libc::mount(
            source_c.as_ref().map_or(core::ptr::null(), |s| s.as_ptr()),
            target_c.as_ptr(),
            fstype_c.as_ref().map_or(core::ptr::null(), |t| t.as_ptr()),
            flags as libc::c_ulong,
            data_c.as_ref().map_or(core::ptr::null(), |d| d.as_ptr()) as *const libc::c_void,
        )
    };

    if ret < 0 {
        let errno = unsafe { *libc::__errno_location() };
        Err(RootFsError::MountFailed(format!("errno: {}", errno)))
    } else {
        Ok(())
    }
}

/// Mount (non-Linux stub)
#[cfg(all(feature = "std", not(target_os = "linux")))]
pub fn mount(
    _source: Option<&Path>,
    _target: &Path,
    _fstype: Option<&str>,
    _flags: u64,
    _data: Option<&str>,
) -> Result<(), RootFsError> {
    Err(RootFsError::NotSupported)
}

/// Mount proc filesystem (Linux only)
#[cfg(all(feature = "std", target_os = "linux"))]
pub fn mount_proc(target: &Path) -> Result<(), RootFsError> {
    fs::create_dir_all(target)?;

    mount(
        Some(Path::new("proc")),
        target,
        Some("proc"),
        mount_flags::MS_NOSUID | mount_flags::MS_NODEV | mount_flags::MS_NOEXEC,
        None,
    )
}

/// Mount proc (non-Linux stub)
#[cfg(all(feature = "std", not(target_os = "linux")))]
pub fn mount_proc(_target: &Path) -> Result<(), RootFsError> {
    Err(RootFsError::NotSupported)
}

/// Mount minimal /dev with basic device nodes (Linux only)
#[cfg(all(feature = "std", target_os = "linux"))]
pub fn mount_dev(target: &Path) -> Result<(), RootFsError> {
    fs::create_dir_all(target)?;

    // Mount tmpfs for dev
    mount(
        Some(Path::new("tmpfs")),
        target,
        Some("tmpfs"),
        mount_flags::MS_NOSUID,
        Some("mode=755,size=64K"),
    )?;

    // Create device nodes
    create_device_node(target, "null", 1, 3, 0o666)?;
    create_device_node(target, "zero", 1, 5, 0o666)?;
    create_device_node(target, "random", 1, 8, 0o666)?;
    create_device_node(target, "urandom", 1, 9, 0o666)?;
    create_device_node(target, "tty", 5, 0, 0o666)?;
    create_device_node(target, "console", 5, 1, 0o620)?;

    // Create pts directory
    let pts = target.join("pts");
    fs::create_dir_all(&pts)?;

    // Create shm directory
    let shm = target.join("shm");
    fs::create_dir_all(&shm)?;

    // Create symlinks
    std::os::unix::fs::symlink("/proc/self/fd", target.join("fd"))?;
    std::os::unix::fs::symlink("/proc/self/fd/0", target.join("stdin"))?;
    std::os::unix::fs::symlink("/proc/self/fd/1", target.join("stdout"))?;
    std::os::unix::fs::symlink("/proc/self/fd/2", target.join("stderr"))?;

    Ok(())
}

/// Mount dev (non-Linux stub)
#[cfg(all(feature = "std", not(target_os = "linux")))]
pub fn mount_dev(_target: &Path) -> Result<(), RootFsError> {
    Err(RootFsError::NotSupported)
}

/// Create a device node using mknod (Linux only)
#[cfg(all(feature = "std", target_os = "linux"))]
fn create_device_node(
    dev_path: &Path,
    name: &str,
    major: u32,
    minor: u32,
    mode: u32,
) -> Result<(), RootFsError> {
    use std::ffi::CString;

    let path = dev_path.join(name);
    let path_c = CString::new(path.to_string_lossy().as_bytes())
        .map_err(|_| RootFsError::IoError("Invalid path".into()))?;

    let dev = libc::makedev(major, minor);
    // SAFETY: path_c is a valid NUL-terminated CString for the device node path;
    // S_IFCHR | mode is a valid file-type + permission combination; dev is constructed
    // by makedev(3) from caller-supplied major/minor numbers. mknod(2) does not retain
    // the path pointer after returning, and the kernel validates all arguments.
    let ret = unsafe {
        libc::mknod(
            path_c.as_ptr(),
            libc::S_IFCHR | mode as libc::mode_t,
            dev,
        )
    };

    if ret < 0 {
        let errno = unsafe { *libc::__errno_location() };
        // Ignore EEXIST
        if errno != libc::EEXIST {
            return Err(RootFsError::DeviceCreationFailed(format!(
                "{}: errno {}",
                name, errno
            )));
        }
    }

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mount_flags() {
        assert!(mount_flags::MS_RDONLY > 0);
        assert!(mount_flags::MS_BIND > 0);
        assert!(mount_flags::MS_REC > 0);
    }

    #[test]
    fn test_rootfs_error_display() {
        let err = RootFsError::PathNotFound("/test".into());
        assert!(err.to_string().contains("/test"));

        let err = RootFsError::PermissionDenied;
        assert!(err.to_string().contains("Permission"));

        let err = RootFsError::NotSupported;
        assert!(err.to_string().contains("Not supported"));
    }
}
