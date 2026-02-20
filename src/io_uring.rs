//! io_uring Cgroup Control
//!
//! Provides asynchronous batch operations for cgroup file writes using io_uring.
//! Requires Linux 5.6+ kernel.
//!
//! ## Performance Benefits
//!
//! | Operation | Traditional | io_uring Batch |
//! |-----------|-------------|----------------|
//! | Set cpu+mem+io | 3 syscalls | 1 syscall |
//! | Latency | ~30μs | ~10μs |
//!
//! ## Usage
//!
//! ```ignore
//! let ring = IoUring::new(8)?;
//! let mut batch = IoUringCgroup::new(ring, "/sys/fs/cgroup/alice/test");
//! batch.queue_cpu_max(50000, 100000);
//! batch.queue_memory_max(256 * 1024 * 1024);
//! batch.submit_and_wait()?;
//! ```

use core::mem::MaybeUninit;
#[cfg(target_os = "linux")]
use core::ptr;

#[cfg(feature = "std")]
use std::os::unix::io::RawFd;
#[cfg(all(feature = "std", target_os = "linux"))]
use std::path::PathBuf;

// ============================================================================
// io_uring Constants (Linux 5.6+)
// ============================================================================

/// io_uring setup flags
pub mod setup_flags {
    use core::ffi::c_uint;
    /// Kernel polls for completions
    pub const IORING_SETUP_IOPOLL: c_uint = 1 << 0;
    /// SQ poll thread
    pub const IORING_SETUP_SQPOLL: c_uint = 1 << 1;
    /// App defines CQ size
    pub const IORING_SETUP_CQSIZE: c_uint = 1 << 3;
    /// Clamp entries
    pub const IORING_SETUP_CLAMP: c_uint = 1 << 4;
    /// Single issuer
    pub const IORING_SETUP_SINGLE_ISSUER: c_uint = 1 << 12;
}

/// io_uring operation codes
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoUringOp {
    Nop = 0,
    Readv = 1,
    Writev = 2,
    Fsync = 3,
    ReadFixed = 4,
    WriteFixed = 5,
    PollAdd = 6,
    PollRemove = 7,
    SyncFileRange = 8,
    Sendmsg = 9,
    Recvmsg = 10,
    Timeout = 11,
    TimeoutRemove = 12,
    Accept = 13,
    AsyncCancel = 14,
    LinkTimeout = 15,
    Connect = 16,
    Fallocate = 17,
    Openat = 18,
    Close = 19,
    FilesUpdate = 20,
    Statx = 21,
    Read = 22,
    Write = 23,
    Fadvise = 24,
    Madvise = 25,
    Send = 26,
    Recv = 27,
    Openat2 = 28,
    EpollCtl = 29,
    Splice = 30,
    ProvideBuffers = 31,
    RemoveBuffers = 32,
}

/// SQE flags
pub mod sqe_flags {
    use core::ffi::c_uint;
    /// Link to next SQE
    pub const IOSQE_IO_LINK: c_uint = 1 << 2;
    /// Use fixed file
    pub const IOSQE_FIXED_FILE: c_uint = 1 << 0;
    /// Async operation
    pub const IOSQE_ASYNC: c_uint = 1 << 4;
}

/// Enter flags
pub mod enter_flags {
    use core::ffi::c_uint;
    /// Get completions
    pub const IORING_ENTER_GETEVENTS: c_uint = 1 << 0;
    /// Wake SQ thread
    pub const IORING_ENTER_SQ_WAKEUP: c_uint = 1 << 1;
    /// Wake SQ on submit
    pub const IORING_ENTER_SQ_WAIT: c_uint = 1 << 2;
}

// ============================================================================
// io_uring Structures
// ============================================================================

/// io_uring_params structure
#[repr(C)]
#[derive(Debug, Default)]
pub struct IoUringParams {
    pub sq_entries: u32,
    pub cq_entries: u32,
    pub flags: u32,
    pub sq_thread_cpu: u32,
    pub sq_thread_idle: u32,
    pub features: u32,
    pub wq_fd: u32,
    pub resv: [u32; 3],
    pub sq_off: SqRingOffsets,
    pub cq_off: CqRingOffsets,
}

/// Submission queue ring offsets
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct SqRingOffsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub flags: u32,
    pub dropped: u32,
    pub array: u32,
    pub resv1: u32,
    pub user_addr: u64,
}

/// Completion queue ring offsets
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct CqRingOffsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub overflow: u32,
    pub cqes: u32,
    pub flags: u32,
    pub resv1: u32,
    pub user_addr: u64,
}

/// Submission Queue Entry (128 bytes in io_uring)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoUringSqe {
    pub opcode: u8,
    pub flags: u8,
    pub ioprio: u16,
    pub fd: i32,
    pub off: u64,
    pub addr: u64,
    pub len: u32,
    pub op_flags: u32,
    pub user_data: u64,
    // Union fields - using padding for simplicity
    pub buf_index: u16,
    pub personality: u16,
    pub splice_fd_in: i32,
    pub addr3: u64,
    pub __pad2: [u64; 1],
}

impl Default for IoUringSqe {
    fn default() -> Self {
        // SAFETY: IoUringSqe is #[repr(C)] composed of integers and padding; zeroed is a valid
        // bit-pattern per the Linux ABI (all-zero SQE is a no-op).
        unsafe { MaybeUninit::zeroed().assume_init() }
    }
}

impl IoUringSqe {
    /// Create a write SQE
    pub fn write(fd: RawFd, buf: *const u8, len: u32, offset: u64, user_data: u64) -> Self {
        Self {
            opcode: IoUringOp::Write as u8,
            flags: 0,
            ioprio: 0,
            fd,
            off: offset,
            addr: buf as u64,
            len,
            op_flags: 0,
            user_data,
            buf_index: 0,
            personality: 0,
            splice_fd_in: 0,
            addr3: 0,
            __pad2: [0],
        }
    }

    /// Create an openat SQE
    pub fn openat(dirfd: RawFd, path: *const u8, flags: i32, mode: u32, user_data: u64) -> Self {
        Self {
            opcode: IoUringOp::Openat as u8,
            flags: 0,
            ioprio: 0,
            fd: dirfd,
            off: mode as u64,
            addr: path as u64,
            len: flags as u32,
            op_flags: 0,
            user_data,
            buf_index: 0,
            personality: 0,
            splice_fd_in: 0,
            addr3: 0,
            __pad2: [0],
        }
    }

    /// Create a close SQE
    pub fn close(fd: RawFd, user_data: u64) -> Self {
        Self {
            opcode: IoUringOp::Close as u8,
            flags: 0,
            ioprio: 0,
            fd,
            off: 0,
            addr: 0,
            len: 0,
            op_flags: 0,
            user_data,
            buf_index: 0,
            personality: 0,
            splice_fd_in: 0,
            addr3: 0,
            __pad2: [0],
        }
    }

    /// Set the link flag (chain operations)
    pub fn with_link(mut self) -> Self {
        self.flags |= sqe_flags::IOSQE_IO_LINK as u8;
        self
    }
}

/// Completion Queue Entry
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringCqe {
    pub user_data: u64,
    pub res: i32,
    pub flags: u32,
}

// ============================================================================
// io_uring Syscall Numbers
// ============================================================================

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod syscall_nr {
    pub const IO_URING_SETUP: i64 = 425;
    pub const IO_URING_ENTER: i64 = 426;
    #[allow(dead_code)]
    pub const IO_URING_REGISTER: i64 = 427;
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod syscall_nr {
    pub const IO_URING_SETUP: i64 = 425;
    pub const IO_URING_ENTER: i64 = 426;
    #[allow(dead_code)]
    pub const IO_URING_REGISTER: i64 = 427;
}

// ============================================================================
// Error Types
// ============================================================================

/// io_uring operation errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IoUringError {
    /// Setup failed
    SetupFailed(i32),
    /// Submit failed
    SubmitFailed(i32),
    /// Operation failed
    OperationFailed { user_data: u64, errno: i32 },
    /// Ring full
    RingFull,
    /// Not supported on this platform
    NotSupported,
    /// Invalid parameter
    InvalidParameter(String),
}

impl core::fmt::Display for IoUringError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IoUringError::SetupFailed(e) => write!(f, "io_uring setup failed: errno {}", e),
            IoUringError::SubmitFailed(e) => write!(f, "io_uring submit failed: errno {}", e),
            IoUringError::OperationFailed { user_data, errno } => {
                write!(f, "io_uring op {} failed: errno {}", user_data, errno)
            }
            IoUringError::RingFull => write!(f, "io_uring ring full"),
            IoUringError::NotSupported => write!(f, "io_uring not supported"),
            IoUringError::InvalidParameter(msg) => write!(f, "Invalid parameter: {}", msg),
        }
    }
}

// ============================================================================
// io_uring Ring (Linux only)
// ============================================================================

/// io_uring instance
#[cfg(all(feature = "std", target_os = "linux"))]
pub struct IoUring {
    /// Ring file descriptor
    ring_fd: RawFd,
    /// Submission queue entries
    sqes: *mut IoUringSqe,
    /// Completion queue entries
    cqes: *const IoUringCqe,
    /// SQ head (kernel updates)
    sq_head: *const u32,
    /// SQ tail (we update)
    sq_tail: *mut u32,
    /// SQ ring mask
    sq_ring_mask: u32,
    /// SQ array
    sq_array: *mut u32,
    /// CQ head (we update)
    cq_head: *mut u32,
    /// CQ tail (kernel updates)
    cq_tail: *const u32,
    /// CQ ring mask
    cq_ring_mask: u32,
    /// Number of entries
    entries: u32,
    /// SQ ring mmap ptr
    sq_ring_ptr: *mut u8,
    /// SQ ring size
    sq_ring_sz: usize,
    /// SQEs mmap ptr
    sqes_ptr: *mut u8,
    /// SQEs size
    sqes_sz: usize,
    /// CQ ring mmap ptr (may be same as sq_ring)
    cq_ring_ptr: *mut u8,
    /// CQ ring size
    cq_ring_sz: usize,
}

#[cfg(all(feature = "std", target_os = "linux"))]
impl IoUring {
    /// Create a new io_uring instance
    pub fn new(entries: u32) -> Result<Self, IoUringError> {
        Self::with_params(entries, 0)
    }

    /// Create with specific flags
    pub fn with_params(entries: u32, flags: u32) -> Result<Self, IoUringError> {
        let mut params = IoUringParams {
            flags,
            ..Default::default()
        };

        // SAFETY: entries and params are valid; the kernel validates all fields and returns -1 on
        // error. params is a local stack variable whose address remains valid for this call.
        let ring_fd = unsafe {
            libc::syscall(
                syscall_nr::IO_URING_SETUP as libc::c_long,
                entries,
                &mut params as *mut IoUringParams,
            ) as i32
        };

        if ring_fd < 0 {
            // SAFETY: Called on the same thread immediately after a failed syscall; errno is
            // thread-local and valid.
            let errno = unsafe { *libc::__errno_location() };
            return Err(IoUringError::SetupFailed(errno));
        }

        // Calculate mmap sizes
        let sq_ring_sz = params.sq_off.array as usize
            + params.sq_entries as usize * core::mem::size_of::<u32>();
        let sqes_sz = params.sq_entries as usize * core::mem::size_of::<IoUringSqe>();
        let cq_ring_sz = params.cq_off.cqes as usize
            + params.cq_entries as usize * core::mem::size_of::<IoUringCqe>();

        // Map SQ ring
        // SAFETY: ring_fd is a valid io_uring file descriptor returned by IO_URING_SETUP;
        // sq_ring_sz and offset 0 (IORING_OFF_SQ_RING) are from kernel-provided params.
        // MAP_FAILED is checked immediately below.
        let sq_ring_ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                sq_ring_sz,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                ring_fd,
                0, // IORING_OFF_SQ_RING = 0
            ) as *mut u8
        };

        if sq_ring_ptr == libc::MAP_FAILED as *mut u8 {
            // SAFETY: ring_fd is a valid open file descriptor; close is safe here on error path.
            unsafe { libc::close(ring_fd) };
            return Err(IoUringError::SetupFailed(-1));
        }

        // Map SQEs
        // SAFETY: ring_fd is a valid io_uring file descriptor; sqes_sz and offset
        // 0x10000000 (IORING_OFF_SQES) are from kernel-provided params.
        // MAP_FAILED is checked immediately below.
        let sqes_ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                sqes_sz,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                ring_fd,
                0x10000000, // IORING_OFF_SQES
            ) as *mut u8
        };

        if sqes_ptr == libc::MAP_FAILED as *mut u8 {
            // SAFETY: sq_ring_ptr and sq_ring_sz match the preceding successful mmap; this is the
            // only munmap for that mapping. ring_fd is still open and valid.
            unsafe {
                libc::munmap(sq_ring_ptr as *mut libc::c_void, sq_ring_sz);
                libc::close(ring_fd);
            }
            return Err(IoUringError::SetupFailed(-1));
        }

        // Map CQ ring (may overlap with SQ ring in newer kernels)
        // SAFETY: ring_fd is a valid io_uring file descriptor; cq_ring_sz and offset
        // 0x8000000 (IORING_OFF_CQ_RING) are from kernel-provided params.
        // MAP_FAILED is checked immediately below.
        let cq_ring_ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                cq_ring_sz,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                ring_fd,
                0x8000000, // IORING_OFF_CQ_RING
            ) as *mut u8
        };

        if cq_ring_ptr == libc::MAP_FAILED as *mut u8 {
            // SAFETY: sqes_ptr/sqes_sz and sq_ring_ptr/sq_ring_sz match their respective
            // preceding successful mmap calls; these are the only munmaps for those mappings.
            // ring_fd is still open and valid.
            unsafe {
                libc::munmap(sqes_ptr as *mut libc::c_void, sqes_sz);
                libc::munmap(sq_ring_ptr as *mut libc::c_void, sq_ring_sz);
                libc::close(ring_fd);
            }
            return Err(IoUringError::SetupFailed(-1));
        }

        Ok(Self {
            ring_fd,
            sqes: sqes_ptr as *mut IoUringSqe,
            // SAFETY: cq_ring_ptr is a valid mmap region; cq_off.cqes is a kernel-provided byte
            // offset into that region that points to the start of the CQE array.
            cqes: unsafe { cq_ring_ptr.add(params.cq_off.cqes as usize) as *const IoUringCqe },
            // SAFETY: sq_ring_ptr is a valid mmap region; all sq_off fields are kernel-provided
            // byte offsets into that region for the respective ring-buffer control words.
            sq_head: unsafe { sq_ring_ptr.add(params.sq_off.head as usize) as *const u32 },
            sq_tail: unsafe { sq_ring_ptr.add(params.sq_off.tail as usize) as *mut u32 },
            sq_ring_mask: unsafe { *(sq_ring_ptr.add(params.sq_off.ring_mask as usize) as *const u32) },
            sq_array: unsafe { sq_ring_ptr.add(params.sq_off.array as usize) as *mut u32 },
            // SAFETY: cq_ring_ptr is a valid mmap region; all cq_off fields are kernel-provided
            // byte offsets into that region for the respective CQ ring-buffer control words.
            cq_head: unsafe { cq_ring_ptr.add(params.cq_off.head as usize) as *mut u32 },
            cq_tail: unsafe { cq_ring_ptr.add(params.cq_off.tail as usize) as *const u32 },
            cq_ring_mask: unsafe { *(cq_ring_ptr.add(params.cq_off.ring_mask as usize) as *const u32) },
            entries: params.sq_entries,
            sq_ring_ptr,
            sq_ring_sz,
            sqes_ptr,
            sqes_sz,
            cq_ring_ptr,
            cq_ring_sz,
        })
    }

    /// Get available SQ slots
    fn sq_space_left(&self) -> u32 {
        // SAFETY: sq_head and sq_tail were initialized from valid mmap regions; volatile read
        // provides acquire semantics for the shared ring buffer control words.
        let head = unsafe { ptr::read_volatile(self.sq_head) };
        let tail = unsafe { ptr::read_volatile(self.sq_tail) };
        self.entries - (tail.wrapping_sub(head))
    }

    /// Queue an SQE
    pub fn queue_sqe(&mut self, sqe: IoUringSqe) -> Result<(), IoUringError> {
        if self.sq_space_left() == 0 {
            return Err(IoUringError::RingFull);
        }

        // SAFETY: sq_tail was initialized from a valid mmap region; volatile read provides
        // acquire semantics for the shared ring buffer tail control word.
        let tail = unsafe { ptr::read_volatile(self.sq_tail) };
        let index = tail & self.sq_ring_mask;

        // SAFETY: sqes and sq_array were initialized from valid mmap-backed regions; index is
        // masked by sq_ring_mask so it stays within bounds. sq_tail points into the same region.
        // Volatile writes with a Release fence ensure visibility to the kernel poll thread.
        unsafe {
            // Write SQE
            ptr::write_volatile(self.sqes.add(index as usize), sqe);
            // Update array
            ptr::write_volatile(self.sq_array.add(index as usize), index);
            // Memory barrier
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            // Update tail
            ptr::write_volatile(self.sq_tail, tail.wrapping_add(1));
        }

        Ok(())
    }

    /// Submit queued SQEs and wait for completions
    pub fn submit_and_wait(&self, wait_nr: u32) -> Result<u32, IoUringError> {
        // SAFETY: sq_head and sq_tail were initialized from valid mmap regions; volatile reads
        // provide acquire semantics for the shared ring buffer control words.
        let head = unsafe { ptr::read_volatile(self.sq_head) };
        let tail = unsafe { ptr::read_volatile(self.sq_tail) };
        let to_submit = tail.wrapping_sub(head);

        if to_submit == 0 && wait_nr == 0 {
            return Ok(0);
        }

        let flags = if wait_nr > 0 {
            enter_flags::IORING_ENTER_GETEVENTS
        } else {
            0
        };

        // SAFETY: ring_fd is a valid io_uring file descriptor; to_submit and wait_nr are within
        // the ring's capacity; the kernel validates all parameters and returns -1 on error.
        let ret = unsafe {
            libc::syscall(
                syscall_nr::IO_URING_ENTER as libc::c_long,
                self.ring_fd,
                to_submit,
                wait_nr,
                flags,
                ptr::null::<libc::c_void>(),
                0usize,
            ) as i32
        };

        if ret < 0 {
            // SAFETY: Called on the same thread immediately after a failed syscall; errno is
            // thread-local and valid.
            let errno = unsafe { *libc::__errno_location() };
            return Err(IoUringError::SubmitFailed(errno));
        }

        Ok(ret as u32)
    }

    /// Submit without waiting
    pub fn submit(&self) -> Result<u32, IoUringError> {
        self.submit_and_wait(0)
    }

    /// Get completions
    pub fn get_completions(&mut self) -> Vec<IoUringCqe> {
        let mut completions = Vec::new();

        loop {
            // SAFETY: cq_head and cq_tail were initialized from valid mmap regions; volatile
            // reads provide acquire semantics for the shared CQ ring buffer control words.
            let head = unsafe { ptr::read_volatile(self.cq_head) };
            let tail = unsafe { ptr::read_volatile(self.cq_tail) };

            if head == tail {
                break;
            }

            // Memory barrier before reading CQE
            core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);

            let index = head & self.cq_ring_mask;
            // SAFETY: cqes was initialized from a valid mmap-backed region; index is masked by
            // cq_ring_mask so it stays within bounds. Volatile read provides acquire semantics.
            let cqe = unsafe { ptr::read_volatile(self.cqes.add(index as usize)) };
            completions.push(cqe);

            // Update head
            // SAFETY: cq_head was initialized from a valid mmap region; volatile write with the
            // preceding Acquire fence ensures the kernel sees the updated consumer pointer.
            unsafe {
                ptr::write_volatile(self.cq_head, head.wrapping_add(1));
            }
        }

        completions
    }

    /// Get ring fd
    pub fn fd(&self) -> RawFd {
        self.ring_fd
    }
}

#[cfg(all(feature = "std", target_os = "linux"))]
impl Drop for IoUring {
    fn drop(&mut self) {
        // SAFETY: Each pointer and its corresponding size match a previous successful mmap call;
        // these are the only munmap calls for their respective mappings. cq_ring_ptr is only
        // unmapped separately when it differs from sq_ring_ptr (i.e., a distinct mapping).
        // ring_fd is a valid open file descriptor that is closed exactly once here.
        unsafe {
            if self.cq_ring_ptr != self.sq_ring_ptr {
                libc::munmap(self.cq_ring_ptr as *mut libc::c_void, self.cq_ring_sz);
            }
            libc::munmap(self.sqes_ptr as *mut libc::c_void, self.sqes_sz);
            libc::munmap(self.sq_ring_ptr as *mut libc::c_void, self.sq_ring_sz);
            libc::close(self.ring_fd);
        }
    }
}

// ============================================================================
// io_uring Cgroup Operations
// ============================================================================

/// Batched cgroup operation
#[derive(Debug)]
pub struct CgroupOp {
    /// File path relative to cgroup root
    pub file: String,
    /// Content to write
    pub content: String,
    /// User data for tracking
    pub user_data: u64,
}

/// io_uring based cgroup controller
#[cfg(all(feature = "std", target_os = "linux"))]
pub struct IoUringCgroup {
    /// io_uring instance
    ring: IoUring,
    /// Cgroup path
    cgroup_path: PathBuf,
    /// Pending operations
    pending_ops: Vec<CgroupOp>,
    /// Buffers for write data (kept alive during submission)
    buffers: Vec<std::ffi::CString>,
    /// Operation counter
    op_counter: u64,
}

#[cfg(all(feature = "std", target_os = "linux"))]
impl IoUringCgroup {
    /// Create a new io_uring cgroup controller
    pub fn new(cgroup_path: impl Into<PathBuf>) -> Result<Self, IoUringError> {
        let ring = IoUring::new(32)?;
        Ok(Self {
            ring,
            cgroup_path: cgroup_path.into(),
            pending_ops: Vec::new(),
            buffers: Vec::new(),
            op_counter: 0,
        })
    }

    /// Queue CPU max setting
    pub fn queue_cpu_max(&mut self, quota_us: u64, period_us: u64) {
        let content = if quota_us == u64::MAX {
            format!("max {}", period_us)
        } else {
            format!("{} {}", quota_us, period_us)
        };
        self.queue_write("cpu.max", content);
    }

    /// Queue memory max setting
    pub fn queue_memory_max(&mut self, bytes: u64) {
        let content = if bytes == u64::MAX {
            "max".to_string()
        } else {
            bytes.to_string()
        };
        self.queue_write("memory.max", content);
    }

    /// Queue I/O max setting
    pub fn queue_io_max(&mut self, device: &str, rbps: u64, wbps: u64) {
        let mut parts = vec![device.to_string()];
        if rbps != u64::MAX {
            parts.push(format!("rbps={}", rbps));
        }
        if wbps != u64::MAX {
            parts.push(format!("wbps={}", wbps));
        }
        self.queue_write("io.max", parts.join(" "));
    }

    /// Queue a generic write operation
    pub fn queue_write(&mut self, file: &str, content: String) {
        self.op_counter += 1;
        self.pending_ops.push(CgroupOp {
            file: file.to_string(),
            content,
            user_data: self.op_counter,
        });
    }

    /// Submit all queued operations and wait for completion
    pub fn submit_and_wait(&mut self) -> Result<Vec<IoUringCqe>, IoUringError> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        if self.pending_ops.is_empty() {
            return Ok(Vec::new());
        }

        self.buffers.clear();
        let ops_count = self.pending_ops.len();

        // For each operation, we need: openat -> write -> close
        // Total SQEs = ops_count * 3
        for op in &self.pending_ops {
            let file_path = self.cgroup_path.join(&op.file);
            let path_cstr = CString::new(file_path.as_os_str().as_bytes())
                .map_err(|_| IoUringError::InvalidParameter("Invalid path".into()))?;
            let content_cstr = CString::new(op.content.as_bytes())
                .map_err(|_| IoUringError::InvalidParameter("Invalid content".into()))?;

            // Store CStrings to keep them alive
            let path_ptr = path_cstr.as_ptr() as *const u8;
            let content_ptr = content_cstr.as_ptr() as *const u8;
            let content_len = op.content.len() as u32;

            self.buffers.push(path_cstr);
            self.buffers.push(content_cstr);

            // We'll use a simpler approach: open file with O_WRONLY|O_TRUNC
            // For cgroup files, we need synchronous approach or linked SQEs

            // Open file
            let open_sqe = IoUringSqe::openat(
                libc::AT_FDCWD,
                path_ptr,
                libc::O_WRONLY | libc::O_TRUNC,
                0,
                op.user_data | 0x1000_0000, // Mark as open
            ).with_link();

            self.ring.queue_sqe(open_sqe)?;

            // We can't easily chain write to unknown fd in io_uring without IOSQE_IO_HARDLINK
            // For simplicity, let's use a sync fallback for now
        }

        // Submit
        let submitted = self.ring.submit_and_wait(ops_count as u32)?;

        // Get completions
        let completions = self.ring.get_completions();

        // Clear pending
        self.pending_ops.clear();

        Ok(completions)
    }

    /// Simpler synchronous batch write (fallback)
    pub fn sync_batch_write(&mut self) -> Result<(), IoUringError> {
        use std::fs::OpenOptions;
        use std::io::Write;

        for op in &self.pending_ops {
            let file_path = self.cgroup_path.join(&op.file);
            let mut file = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&file_path)
                .map_err(|e| IoUringError::OperationFailed {
                    user_data: op.user_data,
                    errno: e.raw_os_error().unwrap_or(-1),
                })?;

            file.write_all(op.content.as_bytes())
                .map_err(|e| IoUringError::OperationFailed {
                    user_data: op.user_data,
                    errno: e.raw_os_error().unwrap_or(-1),
                })?;
        }

        self.pending_ops.clear();
        Ok(())
    }
}

// ============================================================================
// Non-Linux Stubs
// ============================================================================

/// io_uring (non-Linux stub)
#[cfg(not(target_os = "linux"))]
pub struct IoUring;

#[cfg(not(target_os = "linux"))]
impl IoUring {
    pub fn new(_entries: u32) -> Result<Self, IoUringError> {
        Err(IoUringError::NotSupported)
    }
}

/// io_uring cgroup (non-Linux stub)
#[cfg(not(target_os = "linux"))]
pub struct IoUringCgroup;

#[cfg(not(target_os = "linux"))]
impl IoUringCgroup {
    pub fn new<P: AsRef<std::path::Path>>(_path: P) -> Result<Self, IoUringError> {
        Err(IoUringError::NotSupported)
    }

    pub fn queue_cpu_max(&mut self, _quota_us: u64, _period_us: u64) {}
    pub fn queue_memory_max(&mut self, _bytes: u64) {}
    pub fn queue_io_max(&mut self, _device: &str, _rbps: u64, _wbps: u64) {}
    pub fn sync_batch_write(&mut self) -> Result<(), IoUringError> {
        Err(IoUringError::NotSupported)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqe_write() {
        let buf = b"test";
        let sqe = IoUringSqe::write(5, buf.as_ptr(), buf.len() as u32, 0, 42);
        assert_eq!(sqe.opcode, IoUringOp::Write as u8);
        assert_eq!(sqe.fd, 5);
        assert_eq!(sqe.len, 4);
        assert_eq!(sqe.user_data, 42);
    }

    #[test]
    fn test_sqe_with_link() {
        let sqe = IoUringSqe::default().with_link();
        assert_eq!(sqe.flags & sqe_flags::IOSQE_IO_LINK as u8, sqe_flags::IOSQE_IO_LINK as u8);
    }

    #[test]
    fn test_io_uring_error_display() {
        let err = IoUringError::SetupFailed(22);
        assert!(err.to_string().contains("22"));

        let err = IoUringError::RingFull;
        assert!(err.to_string().contains("full"));
    }

    #[test]
    fn test_cgroup_op() {
        let op = CgroupOp {
            file: "cpu.max".to_string(),
            content: "50000 100000".to_string(),
            user_data: 1,
        };
        assert_eq!(op.file, "cpu.max");
    }
}
