//! Linux Namespace Isolation
//!
//! Provides direct manipulation of Linux namespaces using `clone(2)`,
//! `unshare(2)`, and `pivot_root(2)` syscalls.
//!
//! ## Namespace Types
//!
//! | Namespace | Flag | Isolates |
//! |-----------|------|----------|
//! | Mount | `CLONE_NEWNS` | Mount points |
//! | PID | `CLONE_NEWPID` | Process IDs |
//! | Network | `CLONE_NEWNET` | Network stack |
//! | UTS | `CLONE_NEWUTS` | Hostname |
//! | IPC | `CLONE_NEWIPC` | IPC primitives |
//! | User | `CLONE_NEWUSER` | User/Group IDs |
//! | Cgroup | `CLONE_NEWCGROUP` | Cgroup root |

use core::ffi::c_int;

#[cfg(feature = "std")]
use std::path::Path;

// ============================================================================
// Namespace Flags (Linux-specific constants)
// ============================================================================

/// Namespace flags for clone/unshare
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespaceFlags(c_int);

impl NamespaceFlags {
    // Linux clone flags - define as constants for cross-platform compilation
    const CLONE_NEWNS_VAL: c_int = 0x00020000;
    const CLONE_NEWPID_VAL: c_int = 0x20000000;
    const CLONE_NEWNET_VAL: c_int = 0x40000000;
    const CLONE_NEWUTS_VAL: c_int = 0x04000000;
    const CLONE_NEWIPC_VAL: c_int = 0x08000000;
    const CLONE_NEWUSER_VAL: c_int = 0x10000000;
    const CLONE_NEWCGROUP_VAL: c_int = 0x02000000;

    /// Mount namespace
    pub const NEWNS: Self = Self(Self::CLONE_NEWNS_VAL);
    /// PID namespace
    pub const NEWPID: Self = Self(Self::CLONE_NEWPID_VAL);
    /// Network namespace
    pub const NEWNET: Self = Self(Self::CLONE_NEWNET_VAL);
    /// UTS namespace (hostname)
    pub const NEWUTS: Self = Self(Self::CLONE_NEWUTS_VAL);
    /// IPC namespace
    pub const NEWIPC: Self = Self(Self::CLONE_NEWIPC_VAL);
    /// User namespace
    pub const NEWUSER: Self = Self(Self::CLONE_NEWUSER_VAL);
    /// Cgroup namespace
    pub const NEWCGROUP: Self = Self(Self::CLONE_NEWCGROUP_VAL);

    /// All namespaces (except user - requires special handling)
    pub const ALL: Self = Self(
        Self::CLONE_NEWNS_VAL
            | Self::CLONE_NEWPID_VAL
            | Self::CLONE_NEWNET_VAL
            | Self::CLONE_NEWUTS_VAL
            | Self::CLONE_NEWIPC_VAL
            | Self::CLONE_NEWCGROUP_VAL,
    );

    /// Container isolation (common set)
    pub const CONTAINER: Self = Self(
        Self::CLONE_NEWNS_VAL
            | Self::CLONE_NEWPID_VAL
            | Self::CLONE_NEWUTS_VAL
            | Self::CLONE_NEWIPC_VAL,
    );

    #[inline]
    pub const fn bits(&self) -> c_int {
        self.0
    }

    #[inline]
    pub const fn from_bits(bits: c_int) -> Self {
        Self(bits)
    }

    #[inline]
    pub const fn contains(&self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

// ============================================================================
// Namespace Operations
// ============================================================================

/// Namespace controller for managing process isolation
pub struct Namespaces {
    /// Flags indicating which namespaces are active
    flags: NamespaceFlags,
}

impl Namespaces {
    /// Create with specified namespace flags
    pub fn new(flags: NamespaceFlags) -> Self {
        Self { flags }
    }

    /// Create with container isolation (Mount, PID, UTS, IPC)
    pub fn container() -> Self {
        Self::new(NamespaceFlags::CONTAINER)
    }

    /// Create with all namespaces except user
    pub fn all() -> Self {
        Self::new(NamespaceFlags::ALL)
    }

    /// Get namespace flags
    pub fn flags(&self) -> NamespaceFlags {
        self.flags
    }

    /// Unshare namespaces for current process (Linux only)
    #[cfg(target_os = "linux")]
    pub fn unshare(&self) -> Result<(), NamespaceError> {
        // SAFETY: self.flags.bits() is a valid combination of CLONE_NEW* flags; unshare(2)
        // validates the flags and returns -1 on error. No pointers are involved.
        let ret = unsafe { libc::unshare(self.flags.bits()) };
        if ret < 0 {
            Err(NamespaceError::from_errno())
        } else {
            Ok(())
        }
    }

    /// Unshare namespaces (non-Linux stub)
    #[cfg(not(target_os = "linux"))]
    pub fn unshare(&self) -> Result<(), NamespaceError> {
        Err(NamespaceError::NotSupported)
    }

    /// Set hostname in UTS namespace (Linux only)
    #[cfg(all(feature = "std", target_os = "linux"))]
    pub fn set_hostname(&self, hostname: &str) -> Result<(), NamespaceError> {
        if !self.flags.contains(NamespaceFlags::NEWUTS) {
            return Err(NamespaceError::NotInNamespace("UTS"));
        }

        // SAFETY: hostname.as_ptr() points to valid UTF-8 bytes for hostname.len() bytes;
        // sethostname(2) only reads the buffer and does not retain the pointer after returning.
        let ret =
            unsafe { libc::sethostname(hostname.as_ptr() as *const libc::c_char, hostname.len()) };

        if ret < 0 {
            Err(NamespaceError::from_errno())
        } else {
            Ok(())
        }
    }

    /// Set hostname (non-Linux stub)
    #[cfg(all(feature = "std", not(target_os = "linux")))]
    pub fn set_hostname(&self, _hostname: &str) -> Result<(), NamespaceError> {
        Err(NamespaceError::NotSupported)
    }
}

// ============================================================================
// Clone with Namespaces
// ============================================================================

/// Clone flags for creating child process
#[derive(Debug, Clone, Copy)]
pub struct CloneFlags {
    /// Namespace flags
    pub namespaces: NamespaceFlags,
    /// Additional clone flags
    pub extra: c_int,
}

impl CloneFlags {
    /// Create clone flags for container
    pub fn container() -> Self {
        Self {
            namespaces: NamespaceFlags::CONTAINER,
            extra: 0,
        }
    }

    /// Get combined flags
    pub fn bits(&self) -> c_int {
        self.namespaces.bits() | self.extra
    }
}

/// Clone a new process with namespaces (Linux only)
///
/// # Safety
///
/// The caller must ensure that the stack memory is valid for the duration of
/// the child process, `child_fn` is safe to execute in the cloned context, and
/// all shared resources are properly synchronized between parent and child.
#[cfg(target_os = "linux")]
pub unsafe fn clone_with_namespaces<F>(
    flags: CloneFlags,
    stack_size: usize,
    child_fn: F,
) -> Result<u32, NamespaceError>
where
    F: FnOnce() -> i32,
{
    const MAP_STACK: c_int = 0x20000;

    // Allocate stack for child
    // SAFETY: MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK with fd=-1 and offset=0 is a standard
    // anonymous stack allocation; the kernel returns MAP_FAILED on error which is checked below.
    let stack = libc::mmap(
        core::ptr::null_mut(),
        stack_size,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | MAP_STACK,
        -1,
        0,
    );

    if stack == libc::MAP_FAILED {
        return Err(NamespaceError::from_errno());
    }

    // Stack grows downward on most architectures
    let stack_top = (stack as usize + stack_size) as *mut libc::c_void;

    // Box the closure to get a stable pointer
    let boxed_fn = Box::new(child_fn);
    let fn_ptr = Box::into_raw(boxed_fn);

    extern "C" fn child_wrapper<F: FnOnce() -> i32>(arg: *mut libc::c_void) -> libc::c_int {
        // SAFETY: arg was created by Box::into_raw in the parent before clone(2); this is the
        // child process and Box::from_raw reclaims ownership exactly once here.
        let boxed_fn = unsafe { Box::from_raw(arg as *mut F) };
        boxed_fn()
    }

    let clone_flags = flags.bits() | libc::SIGCHLD;

    // SAFETY: child_wrapper is a valid extern "C" function pointer; stack_top is one byte past
    // the end of the mmap region (stack grows downward); clone_flags is a valid combination of
    // CLONE_NEW* flags OR'd with SIGCHLD; fn_ptr is a Box-leaked closure pointer passed as the
    // arg to child_wrapper which reclaims it. The kernel validates all flags.
    let pid = libc::clone(
        child_wrapper::<F>,
        stack_top,
        clone_flags,
        fn_ptr as *mut libc::c_void,
    );

    if pid < 0 {
        // Clean up on error
        // SAFETY: fn_ptr was created by Box::into_raw above; Box::from_raw reclaims ownership
        // exactly once on this error path before the pointer is discarded.
        let _ = Box::from_raw(fn_ptr);
        // SAFETY: stack and stack_size match the preceding successful mmap call; this is the
        // only munmap for this mapping on the error path.
        libc::munmap(stack, stack_size);
        return Err(NamespaceError::from_errno());
    }

    Ok(pid as u32)
}

/// Clone with namespaces (non-Linux stub)
///
/// # Safety
///
/// The caller must ensure that `_child_fn` is safe to call in a cloned context
/// and that all resources accessible by the child are properly synchronized.
#[cfg(not(target_os = "linux"))]
pub unsafe fn clone_with_namespaces<F>(
    _flags: CloneFlags,
    _stack_size: usize,
    _child_fn: F,
) -> Result<u32, NamespaceError>
where
    F: FnOnce() -> i32,
{
    Err(NamespaceError::NotSupported)
}

// ============================================================================
// Pivot Root
// ============================================================================

/// Pivot root to new filesystem (Linux only)
#[cfg(all(feature = "std", target_os = "linux"))]
pub fn pivot_root(new_root: &Path, put_old: &Path) -> Result<(), NamespaceError> {
    use std::ffi::CString;

    let new_root_c = CString::new(new_root.to_string_lossy().as_bytes())
        .map_err(|_| NamespaceError::InvalidPath)?;
    let put_old_c = CString::new(put_old.to_string_lossy().as_bytes())
        .map_err(|_| NamespaceError::InvalidPath)?;

    // SAFETY: new_root_c and put_old_c are valid NUL-terminated CStrings; pivot_root(2) only
    // reads the paths and does not retain the pointers after returning. The kernel validates
    // path validity and returns -1 on error.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_pivot_root,
            new_root_c.as_ptr(),
            put_old_c.as_ptr(),
        )
    };

    if ret < 0 {
        Err(NamespaceError::from_errno())
    } else {
        Ok(())
    }
}

/// Pivot root (non-Linux stub)
#[cfg(all(feature = "std", not(target_os = "linux")))]
pub fn pivot_root(_new_root: &Path, _put_old: &Path) -> Result<(), NamespaceError> {
    Err(NamespaceError::NotSupported)
}

/// Unmount a filesystem (Linux only)
#[cfg(all(feature = "std", target_os = "linux"))]
pub fn umount(target: &Path) -> Result<(), NamespaceError> {
    use std::ffi::CString;

    let target_c = CString::new(target.to_string_lossy().as_bytes())
        .map_err(|_| NamespaceError::InvalidPath)?;

    // SAFETY: target_c is a valid NUL-terminated CString; umount(2) only reads the path and
    // does not retain the pointer after returning. The kernel validates the mount point.
    let ret = unsafe { libc::umount(target_c.as_ptr()) };

    if ret < 0 {
        Err(NamespaceError::from_errno())
    } else {
        Ok(())
    }
}

/// Unmount (non-Linux stub)
#[cfg(all(feature = "std", not(target_os = "linux")))]
pub fn umount(_target: &Path) -> Result<(), NamespaceError> {
    Err(NamespaceError::NotSupported)
}

/// Unmount with flags (Linux only)
#[cfg(all(feature = "std", target_os = "linux"))]
pub fn umount2(target: &Path, flags: c_int) -> Result<(), NamespaceError> {
    use std::ffi::CString;

    let target_c = CString::new(target.to_string_lossy().as_bytes())
        .map_err(|_| NamespaceError::InvalidPath)?;

    // SAFETY: target_c is a valid NUL-terminated CString; flags is a valid umount2 flag
    // (e.g. MNT_DETACH); umount2(2) does not retain the pointer after returning.
    let ret = unsafe { libc::umount2(target_c.as_ptr(), flags) };

    if ret < 0 {
        Err(NamespaceError::from_errno())
    } else {
        Ok(())
    }
}

/// Unmount2 (non-Linux stub)
#[cfg(all(feature = "std", not(target_os = "linux")))]
pub fn umount2(_target: &Path, _flags: c_int) -> Result<(), NamespaceError> {
    Err(NamespaceError::NotSupported)
}

/// MNT_DETACH flag for lazy unmount
pub const MNT_DETACH: c_int = 2;

// ============================================================================
// Error Types
// ============================================================================

/// Namespace operation errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamespaceError {
    /// Permission denied (need CAP_SYS_ADMIN)
    PermissionDenied,
    /// Invalid argument
    InvalidArgument,
    /// Out of memory
    OutOfMemory,
    /// Not in required namespace
    NotInNamespace(&'static str),
    /// Invalid path
    InvalidPath,
    /// Operation not supported
    NotSupported,
    /// Generic OS error
    OsError(i32),
}

impl NamespaceError {
    /// Create error from current errno (Linux)
    #[cfg(target_os = "linux")]
    fn from_errno() -> Self {
        // SAFETY: Called on the same thread immediately after a failed syscall; errno is
        // thread-local and valid.
        let errno = unsafe { *libc::__errno_location() };
        match errno {
            libc::EPERM => NamespaceError::PermissionDenied,
            libc::EINVAL => NamespaceError::InvalidArgument,
            libc::ENOMEM => NamespaceError::OutOfMemory,
            libc::ENOSYS => NamespaceError::NotSupported,
            e => NamespaceError::OsError(e),
        }
    }

    /// Create error from errno (non-Linux stub)
    #[cfg(not(target_os = "linux"))]
    #[allow(dead_code)]
    fn from_errno() -> Self {
        NamespaceError::NotSupported
    }
}

impl core::fmt::Display for NamespaceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NamespaceError::PermissionDenied => {
                write!(f, "Permission denied (need CAP_SYS_ADMIN)")
            }
            NamespaceError::InvalidArgument => write!(f, "Invalid argument"),
            NamespaceError::OutOfMemory => write!(f, "Out of memory"),
            NamespaceError::NotInNamespace(ns) => {
                write!(f, "Not in {} namespace", ns)
            }
            NamespaceError::InvalidPath => write!(f, "Invalid path"),
            NamespaceError::NotSupported => write!(f, "Operation not supported on this platform"),
            NamespaceError::OsError(e) => write!(f, "OS error: {}", e),
        }
    }
}

// ============================================================================
// UID/GID Mapping (for User Namespaces)
// ============================================================================

/// UID/GID mapping entry
#[derive(Debug, Clone, Copy)]
pub struct IdMapping {
    /// ID inside the namespace
    pub inner_id: u32,
    /// ID outside the namespace
    pub outer_id: u32,
    /// Range length
    pub count: u32,
}

impl IdMapping {
    /// Create a simple 1:1 mapping
    pub fn identity(id: u32) -> Self {
        Self {
            inner_id: id,
            outer_id: id,
            count: 1,
        }
    }

    /// Create mapping for root inside namespace to current user outside
    pub fn root_to_user(outer_uid: u32) -> Self {
        Self {
            inner_id: 0,
            outer_id: outer_uid,
            count: 1,
        }
    }

    /// Format for `/proc/<pid>/uid_map` or `gid_map`
    pub fn to_map_string(&self) -> String {
        format!("{} {} {}", self.inner_id, self.outer_id, self.count)
    }
}

/// Write UID mapping for a process (Linux only)
#[cfg(all(feature = "std", target_os = "linux"))]
pub fn write_uid_map(pid: u32, mapping: &IdMapping) -> Result<(), NamespaceError> {
    use std::fs::OpenOptions;
    use std::io::Write;

    let path = format!("/proc/{}/uid_map", pid);
    let mut file = OpenOptions::new()
        .write(true)
        .open(&path)
        .map_err(|_| NamespaceError::PermissionDenied)?;

    file.write_all(mapping.to_map_string().as_bytes())
        .map_err(|_| NamespaceError::InvalidArgument)?;

    Ok(())
}

/// Write UID mapping (non-Linux stub)
#[cfg(all(feature = "std", not(target_os = "linux")))]
pub fn write_uid_map(_pid: u32, _mapping: &IdMapping) -> Result<(), NamespaceError> {
    Err(NamespaceError::NotSupported)
}

/// Write GID mapping for a process (Linux only)
#[cfg(all(feature = "std", target_os = "linux"))]
pub fn write_gid_map(pid: u32, mapping: &IdMapping) -> Result<(), NamespaceError> {
    use std::fs::OpenOptions;
    use std::io::Write;

    // Must write "deny" to setgroups first
    let setgroups_path = format!("/proc/{}/setgroups", pid);
    if let Ok(mut file) = OpenOptions::new().write(true).open(&setgroups_path) {
        let _ = file.write_all(b"deny");
    }

    let path = format!("/proc/{}/gid_map", pid);
    let mut file = OpenOptions::new()
        .write(true)
        .open(&path)
        .map_err(|_| NamespaceError::PermissionDenied)?;

    file.write_all(mapping.to_map_string().as_bytes())
        .map_err(|_| NamespaceError::InvalidArgument)?;

    Ok(())
}

/// Write GID mapping (non-Linux stub)
#[cfg(all(feature = "std", not(target_os = "linux")))]
pub fn write_gid_map(_pid: u32, _mapping: &IdMapping) -> Result<(), NamespaceError> {
    Err(NamespaceError::NotSupported)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace_flags() {
        let flags = NamespaceFlags::CONTAINER;
        assert!(flags.contains(NamespaceFlags::NEWNS));
        assert!(flags.contains(NamespaceFlags::NEWPID));
        assert!(!flags.contains(NamespaceFlags::NEWNET));
    }

    #[test]
    fn test_namespace_flags_union() {
        let flags = NamespaceFlags::NEWNS.union(NamespaceFlags::NEWPID);
        assert!(flags.contains(NamespaceFlags::NEWNS));
        assert!(flags.contains(NamespaceFlags::NEWPID));
    }

    #[test]
    fn test_id_mapping() {
        let mapping = IdMapping::root_to_user(1000);
        assert_eq!(mapping.inner_id, 0);
        assert_eq!(mapping.outer_id, 1000);
        assert_eq!(mapping.to_map_string(), "0 1000 1");
    }

    #[test]
    fn test_clone_flags() {
        let flags = CloneFlags::container();
        assert!(flags.bits() & NamespaceFlags::CLONE_NEWNS_VAL != 0);
        assert!(flags.bits() & NamespaceFlags::CLONE_NEWPID_VAL != 0);
    }

    #[test]
    fn test_namespace_error_display() {
        let err = NamespaceError::PermissionDenied;
        assert!(err.to_string().contains("Permission denied"));

        let err = NamespaceError::NotInNamespace("UTS");
        assert!(err.to_string().contains("UTS"));

        let err = NamespaceError::NotSupported;
        assert!(err.to_string().contains("not supported"));
    }
}
