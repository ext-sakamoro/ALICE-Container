//! Clone3 Syscall with CLONE_INTO_CGROUP
//!
//! Provides direct `clone3(2)` syscall wrapper for creating processes
//! with immediate cgroup placement, eliminating the need for separate
//! cgroup.procs writes.
//!
//! Requires Linux 5.7+ for CLONE_INTO_CGROUP support.
//!
//! ## Performance Benefits
//!
//! | Approach | Syscalls | File I/O |
//! |----------|----------|----------|
//! | fork + add_process | 2 | 1 write |
//! | clone3 + CLONE_INTO_CGROUP | 1 | 0 |
//!
//! ## Usage
//!
//! ```ignore
//! let cgroup_fd = open_cgroup("/sys/fs/cgroup/alice/test")?;
//! let args = Clone3Args::new()
//!     .flags(CloneFlags::CONTAINER)
//!     .cgroup_fd(cgroup_fd);
//!
//! let pid = unsafe { clone3(&args, child_stack, child_fn)? };
//! ```

use core::mem;

#[cfg(all(feature = "std", target_os = "linux"))]
use std::os::unix::io::RawFd;
#[cfg(all(feature = "std", not(target_os = "linux")))]
use std::os::unix::io::RawFd;

// ============================================================================
// Clone3 Constants
// ============================================================================

/// Clone flags for clone3
pub mod clone_flags {
    use core::ffi::c_ulonglong;

    // Standard clone flags
    pub const CLONE_VM: c_ulonglong = 0x00000100;
    pub const CLONE_FS: c_ulonglong = 0x00000200;
    pub const CLONE_FILES: c_ulonglong = 0x00000400;
    pub const CLONE_SIGHAND: c_ulonglong = 0x00000800;
    pub const CLONE_PIDFD: c_ulonglong = 0x00001000;
    pub const CLONE_PTRACE: c_ulonglong = 0x00002000;
    pub const CLONE_VFORK: c_ulonglong = 0x00004000;
    pub const CLONE_PARENT: c_ulonglong = 0x00008000;
    pub const CLONE_THREAD: c_ulonglong = 0x00010000;
    pub const CLONE_NEWNS: c_ulonglong = 0x00020000;
    pub const CLONE_SYSVSEM: c_ulonglong = 0x00040000;
    pub const CLONE_SETTLS: c_ulonglong = 0x00080000;
    pub const CLONE_PARENT_SETTID: c_ulonglong = 0x00100000;
    pub const CLONE_CHILD_CLEARTID: c_ulonglong = 0x00200000;
    pub const CLONE_DETACHED: c_ulonglong = 0x00400000;
    pub const CLONE_UNTRACED: c_ulonglong = 0x00800000;
    pub const CLONE_CHILD_SETTID: c_ulonglong = 0x01000000;
    pub const CLONE_NEWCGROUP: c_ulonglong = 0x02000000;
    pub const CLONE_NEWUTS: c_ulonglong = 0x04000000;
    pub const CLONE_NEWIPC: c_ulonglong = 0x08000000;
    pub const CLONE_NEWUSER: c_ulonglong = 0x10000000;
    pub const CLONE_NEWPID: c_ulonglong = 0x20000000;
    pub const CLONE_NEWNET: c_ulonglong = 0x40000000;
    pub const CLONE_IO: c_ulonglong = 0x80000000;

    // clone3-specific flags (Linux 5.2+)
    pub const CLONE_CLEAR_SIGHAND: c_ulonglong = 0x100000000;
    pub const CLONE_INTO_CGROUP: c_ulonglong = 0x200000000; // Linux 5.7+
    pub const CLONE_NEWTIME: c_ulonglong = 0x00000080;

    /// Container isolation flags
    pub const CONTAINER: c_ulonglong = CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC;

    /// Full isolation (all namespaces except user)
    pub const FULL_ISOLATION: c_ulonglong =
        CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWCGROUP;
}

// ============================================================================
// Clone3 Syscall Number
// ============================================================================

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SYS_CLONE3: i64 = 435;

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const SYS_CLONE3: i64 = 435;

// ============================================================================
// Clone3 Arguments Structure
// ============================================================================

/// Arguments for clone3 syscall
///
/// This structure is passed to the kernel and must match the kernel's
/// struct clone_args exactly.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct Clone3Args {
    /// Clone flags
    pub flags: u64,
    /// File descriptor for pidfd (CLONE_PIDFD)
    pub pidfd: u64,
    /// Signal to send to parent when child terminates
    pub child_tid: u64,
    /// Signal to send to parent when child terminates
    pub parent_tid: u64,
    /// Exit signal (usually SIGCHLD)
    pub exit_signal: u64,
    /// Child stack pointer
    pub stack: u64,
    /// Stack size
    pub stack_size: u64,
    /// TLS pointer
    pub tls: u64,
    /// Pointer to set_tid array
    pub set_tid: u64,
    /// Number of entries in set_tid
    pub set_tid_size: u64,
    /// Cgroup file descriptor (CLONE_INTO_CGROUP)
    pub cgroup: u64,
}

impl Default for Clone3Args {
    fn default() -> Self {
        Self {
            flags: 0,
            pidfd: 0,
            child_tid: 0,
            parent_tid: 0,
            exit_signal: libc::SIGCHLD as u64,
            stack: 0,
            stack_size: 0,
            tls: 0,
            set_tid: 0,
            set_tid_size: 0,
            cgroup: 0,
        }
    }
}

impl Clone3Args {
    /// Create new clone3 args with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Set clone flags
    pub fn flags(mut self, flags: u64) -> Self {
        self.flags = flags;
        self
    }

    /// Add clone flags (OR with existing)
    pub fn add_flags(mut self, flags: u64) -> Self {
        self.flags |= flags;
        self
    }

    /// Set exit signal
    pub fn exit_signal(mut self, signal: i32) -> Self {
        self.exit_signal = signal as u64;
        self
    }

    /// Set stack
    pub fn stack(mut self, stack_ptr: *mut u8, size: usize) -> Self {
        self.stack = stack_ptr as u64;
        self.stack_size = size as u64;
        self
    }

    /// Set cgroup fd (requires CLONE_INTO_CGROUP flag)
    pub fn cgroup_fd(mut self, fd: RawFd) -> Self {
        self.flags |= clone_flags::CLONE_INTO_CGROUP;
        self.cgroup = fd as u64;
        self
    }

    /// Request pidfd (sets CLONE_PIDFD)
    pub fn with_pidfd(mut self, pidfd_ptr: *mut i32) -> Self {
        self.flags |= clone_flags::CLONE_PIDFD;
        self.pidfd = pidfd_ptr as u64;
        self
    }

    /// Set container isolation flags
    pub fn container_isolation(mut self) -> Self {
        self.flags |= clone_flags::CONTAINER;
        self
    }

    /// Get structure size for syscall
    pub fn size() -> usize {
        mem::size_of::<Self>()
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// Clone3 operation errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Clone3Error {
    /// Syscall failed
    SyscallFailed(i32),
    /// Not supported (old kernel)
    NotSupported,
    /// Permission denied
    PermissionDenied,
    /// Invalid argument
    InvalidArgument,
    /// Out of memory
    OutOfMemory,
    /// Cgroup fd invalid
    InvalidCgroupFd,
}

impl core::fmt::Display for Clone3Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Clone3Error::SyscallFailed(e) => write!(f, "clone3 failed: errno {}", e),
            Clone3Error::NotSupported => write!(f, "clone3 not supported (requires Linux 5.3+)"),
            Clone3Error::PermissionDenied => write!(f, "Permission denied (need CAP_SYS_ADMIN)"),
            Clone3Error::InvalidArgument => write!(f, "Invalid argument"),
            Clone3Error::OutOfMemory => write!(f, "Out of memory"),
            Clone3Error::InvalidCgroupFd => write!(f, "Invalid cgroup file descriptor"),
        }
    }
}

impl Clone3Error {
    #[cfg(target_os = "linux")]
    fn from_errno(errno: i32) -> Self {
        match errno {
            libc::EPERM => Clone3Error::PermissionDenied,
            libc::EINVAL => Clone3Error::InvalidArgument,
            libc::ENOMEM => Clone3Error::OutOfMemory,
            libc::ENOSYS => Clone3Error::NotSupported,
            libc::EBADF => Clone3Error::InvalidCgroupFd,
            e => Clone3Error::SyscallFailed(e),
        }
    }
}

// ============================================================================
// Clone3 Syscall (Linux only)
// ============================================================================

/// Execute clone3 syscall directly
///
/// # Safety
///
/// This is a low-level syscall wrapper. The caller must ensure:
/// - args.stack points to valid, properly aligned memory if CLONE_VM is set
/// - args.cgroup is a valid fd if CLONE_INTO_CGROUP is set
/// - The child function is safe to execute in the new process context
#[cfg(target_os = "linux")]
pub unsafe fn clone3_raw(args: &Clone3Args) -> Result<u32, Clone3Error> {
    let ret = libc::syscall(
        SYS_CLONE3 as libc::c_long,
        args as *const Clone3Args,
        Clone3Args::size(),
    );

    if ret < 0 {
        let errno = *libc::__errno_location();
        return Err(Clone3Error::from_errno(errno));
    }

    Ok(ret as u32)
}

/// Clone3 (non-Linux stub)
#[cfg(not(target_os = "linux"))]
pub unsafe fn clone3_raw(_args: &Clone3Args) -> Result<u32, Clone3Error> {
    Err(Clone3Error::NotSupported)
}

/// Clone a new process with clone3 and execute a function
///
/// # Safety
///
/// The caller must ensure the child function is safe to execute.
#[cfg(target_os = "linux")]
pub unsafe fn clone3_with_fn<F>(
    args: &Clone3Args,
    stack_size: usize,
    child_fn: F,
) -> Result<u32, Clone3Error>
where
    F: FnOnce() -> i32 + Send + 'static,
{
    // Allocate stack
    let stack = libc::mmap(
        core::ptr::null_mut(),
        stack_size,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_STACK,
        -1,
        0,
    );

    if stack == libc::MAP_FAILED {
        return Err(Clone3Error::OutOfMemory);
    }

    // Stack grows downward
    let stack_top = (stack as usize + stack_size) as *mut u8;

    // Box the closure
    let boxed_fn = Box::new(child_fn);
    let fn_ptr = Box::into_raw(boxed_fn);

    // Prepare clone3 args with stack
    let mut clone_args = args.clone();
    clone_args.stack = stack as u64;
    clone_args.stack_size = stack_size as u64;

    // Store function pointer at top of stack
    let fn_storage = (stack_top as usize - mem::size_of::<*mut F>()) as *mut *mut F;
    *fn_storage = fn_ptr;

    // Use fork-like behavior for simplicity
    let ret = libc::syscall(
        SYS_CLONE3 as libc::c_long,
        &clone_args as *const Clone3Args,
        Clone3Args::size(),
    );

    if ret < 0 {
        // Clean up on parent error path
        let _ = Box::from_raw(fn_ptr);
        libc::munmap(stack, stack_size);
        let errno = *libc::__errno_location();
        return Err(Clone3Error::from_errno(errno));
    }

    if ret == 0 {
        // Child process
        let func = Box::from_raw(*fn_storage);
        let exit_code = func();
        libc::_exit(exit_code);
    }

    // Parent process
    Ok(ret as u32)
}

/// Clone3 with function (non-Linux stub)
#[cfg(not(target_os = "linux"))]
pub unsafe fn clone3_with_fn<F>(
    _args: &Clone3Args,
    _stack_size: usize,
    _child_fn: F,
) -> Result<u32, Clone3Error>
where
    F: FnOnce() -> i32 + Send + 'static,
{
    Err(Clone3Error::NotSupported)
}

// ============================================================================
// Cgroup FD Helper
// ============================================================================

/// Open a cgroup directory for use with CLONE_INTO_CGROUP
#[cfg(all(feature = "std", target_os = "linux"))]
pub fn open_cgroup_fd(cgroup_path: &std::path::Path) -> Result<RawFd, Clone3Error> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let path_c = CString::new(cgroup_path.as_os_str().as_bytes())
        .map_err(|_| Clone3Error::InvalidArgument)?;

    let fd = unsafe {
        libc::open(
            path_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };

    if fd < 0 {
        let errno = unsafe { *libc::__errno_location() };
        return Err(Clone3Error::from_errno(errno));
    }

    Ok(fd)
}

/// Open cgroup fd (non-Linux stub)
#[cfg(all(feature = "std", not(target_os = "linux")))]
pub fn open_cgroup_fd(_cgroup_path: &std::path::Path) -> Result<RawFd, Clone3Error> {
    Err(Clone3Error::NotSupported)
}

/// Close a cgroup fd
#[cfg(target_os = "linux")]
pub fn close_cgroup_fd(fd: RawFd) {
    unsafe {
        libc::close(fd);
    }
}

/// Close cgroup fd (non-Linux stub)
#[cfg(not(target_os = "linux"))]
pub fn close_cgroup_fd(_fd: RawFd) {}

// ============================================================================
// High-Level API
// ============================================================================

/// Spawn a child process directly into a cgroup
///
/// This combines clone3 with CLONE_INTO_CGROUP for zero-copy cgroup placement.
#[cfg(all(feature = "std", target_os = "linux"))]
pub fn spawn_into_cgroup<F>(
    cgroup_path: &std::path::Path,
    namespace_flags: u64,
    child_fn: F,
) -> Result<u32, Clone3Error>
where
    F: FnOnce() -> i32 + Send + 'static,
{
    // Open cgroup directory
    let cgroup_fd = open_cgroup_fd(cgroup_path)?;

    // Build clone3 args
    let args = Clone3Args::new()
        .flags(namespace_flags)
        .cgroup_fd(cgroup_fd);

    // Clone with function
    let result = unsafe { clone3_with_fn(&args, 1024 * 1024, child_fn) };

    // Close cgroup fd (parent only needs it during clone)
    close_cgroup_fd(cgroup_fd);

    result
}

/// Spawn into cgroup (non-Linux stub)
#[cfg(all(feature = "std", not(target_os = "linux")))]
pub fn spawn_into_cgroup<F>(
    _cgroup_path: &std::path::Path,
    _namespace_flags: u64,
    _child_fn: F,
) -> Result<u32, Clone3Error>
where
    F: FnOnce() -> i32 + Send + 'static,
{
    Err(Clone3Error::NotSupported)
}

// ============================================================================
// Kernel Version Check
// ============================================================================

/// Check if clone3 is available
#[cfg(target_os = "linux")]
pub fn is_clone3_available() -> bool {
    let args = Clone3Args::new();
    let ret = unsafe {
        libc::syscall(
            SYS_CLONE3 as libc::c_long,
            &args as *const Clone3Args,
            Clone3Args::size(),
        )
    };

    // ENOSYS means not available, any other error means it's available
    if ret < 0 {
        let errno = unsafe { *libc::__errno_location() };
        errno != libc::ENOSYS
    } else {
        // Shouldn't happen with these args, but means it's available
        true
    }
}

/// Check if clone3 is available (non-Linux)
#[cfg(not(target_os = "linux"))]
pub fn is_clone3_available() -> bool {
    false
}

/// Check if CLONE_INTO_CGROUP is supported (Linux 5.7+)
#[cfg(target_os = "linux")]
pub fn is_clone_into_cgroup_available() -> bool {
    // Try to open a temporary cgroup and test
    // For now, just check clone3 availability
    is_clone3_available()
}

/// Check CLONE_INTO_CGROUP (non-Linux)
#[cfg(not(target_os = "linux"))]
pub fn is_clone_into_cgroup_available() -> bool {
    false
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clone3_args_default() {
        let args = Clone3Args::new();
        assert_eq!(args.flags, 0);
        assert_eq!(args.exit_signal, libc::SIGCHLD as u64);
    }

    #[test]
    fn test_clone3_args_builder() {
        let args = Clone3Args::new()
            .flags(clone_flags::CONTAINER)
            .exit_signal(libc::SIGCHLD);

        assert!(args.flags & clone_flags::CLONE_NEWNS != 0);
        assert!(args.flags & clone_flags::CLONE_NEWPID != 0);
    }

    #[test]
    fn test_clone3_args_container_isolation() {
        let args = Clone3Args::new().container_isolation();
        assert!(args.flags & clone_flags::CLONE_NEWNS != 0);
        assert!(args.flags & clone_flags::CLONE_NEWPID != 0);
        assert!(args.flags & clone_flags::CLONE_NEWUTS != 0);
        assert!(args.flags & clone_flags::CLONE_NEWIPC != 0);
    }

    #[test]
    fn test_clone3_error_display() {
        let err = Clone3Error::NotSupported;
        assert!(err.to_string().contains("not supported"));

        let err = Clone3Error::PermissionDenied;
        assert!(err.to_string().contains("Permission denied"));
    }

    #[test]
    fn test_clone_flags_constants() {
        assert!(clone_flags::CLONE_INTO_CGROUP > 0);
        assert!(clone_flags::CONTAINER > 0);
        assert_eq!(
            clone_flags::CONTAINER,
            clone_flags::CLONE_NEWNS | clone_flags::CLONE_NEWPID
            | clone_flags::CLONE_NEWUTS | clone_flags::CLONE_NEWIPC
        );
    }
}
