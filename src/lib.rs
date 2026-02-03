//! # ALICE-Container
//!
//! **Minimal Container Runtime with Direct Kernel Control**
//!
//! A Rust library for running isolated processes with direct cgroup v2 and
//! namespace manipulation, without relying on Docker, Podman, or systemd.
//!
//! ## Features
//!
//! | Feature | Description |
//! |---------|-------------|
//! | **Direct Cgroup v2** | Microsecond-level resource control via `/sys/fs/cgroup` |
//! | **Namespace Isolation** | `clone(2)`, `unshare(2)`, `pivot_root(2)` |
//! | **Dynamic Scheduling** | CPU quota adjustment for latency-sensitive workloads |
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    ALICE-Container                          │
//! ├─────────────────────────────────────────────────────────────┤
//! │                                                             │
//! │  Container::create()                                        │
//! │         │                                                   │
//! │         ▼                                                   │
//! │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    │
//! │  │  Namespace  │    │   Cgroup    │    │   RootFS    │    │
//! │  │  (unshare)  │    │   (v2)      │    │ (pivot_root)│    │
//! │  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘    │
//! │         │                  │                  │            │
//! │         └──────────────────┼──────────────────┘            │
//! │                            ▼                               │
//! │                    ┌─────────────┐                         │
//! │                    │  Scheduler  │                         │
//! │                    │ (cpu.max)   │                         │
//! │                    └──────┬──────┘                         │
//! │                           │                                │
//! │                           ▼                                │
//! │                   Isolated Process                         │
//! │                                                             │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use alice_container::prelude::*;
//!
//! // Create container with resource limits
//! let config = ContainerConfig::builder()
//!     .cpu_quota_us(100_000)      // 100ms per 1s period
//!     .memory_max(256 * 1024 * 1024)  // 256 MB
//!     .build();
//!
//! let mut container = Container::create("my-container", config)?;
//!
//! // Start and execute command
//! container.start()?;
//! let exit_code = container.exec(&["/bin/sh", "-c", "echo hello"])?;
//!
//! // Cleanup
//! container.stop()?;
//! container.destroy()?;
//! ```
//!
//! ## Requirements
//!
//! - Linux kernel 5.0+ (cgroup v2 unified hierarchy)
//! - Root privileges (CAP_SYS_ADMIN)
//! - Cgroup v2 mounted at `/sys/fs/cgroup`
//!
//! ## Optional Features
//!
//! | Feature | Kernel | Description |
//! |---------|--------|-------------|
//! | `io_uring` | 5.6+ | Async batched cgroup writes |
//! | `clone3` | 5.7+ | CLONE_INTO_CGROUP support |
//! | `psi` | 4.20+ | Pressure Stall Information monitoring |
//! | `full` | 5.7+ | All advanced features |

#![cfg_attr(not(feature = "std"), no_std)]

// Core modules
pub mod cgroup;
pub mod namespace;
pub mod scheduler;
pub mod container;
pub mod rootfs;

// Advanced modules (feature-gated)
#[cfg(feature = "io_uring")]
pub mod io_uring;

#[cfg(feature = "clone3")]
pub mod clone3;

#[cfg(feature = "psi")]
pub mod psi;

/// Prelude for convenient imports
pub mod prelude {
    pub use crate::cgroup::{CgroupController, CgroupError, CpuConfig, MemoryConfig, IoConfig};
    pub use crate::namespace::{Namespaces, NamespaceFlags, pivot_root};
    pub use crate::scheduler::{DynamicScheduler, SchedulerConfig};
    pub use crate::container::{Container, ContainerConfig, ContainerState, ContainerError};
    pub use crate::rootfs::{RootFs, mount_proc, mount_dev};

    // io_uring exports
    #[cfg(feature = "io_uring")]
    pub use crate::io_uring::{IoUring, IoUringCgroup, IoUringError, IoUringSqe, IoUringCqe};

    // clone3 exports
    #[cfg(feature = "clone3")]
    pub use crate::clone3::{Clone3Args, Clone3Error, clone_flags, spawn_into_cgroup};

    // PSI exports
    #[cfg(feature = "psi")]
    pub use crate::psi::{PsiMonitor, PsiScheduler, PsiTrigger, PsiError, PsiEvent, PsiResource, PsiLevel};
}

pub use prelude::*;

// ============================================================================
// Common Types
// ============================================================================

/// Result type for container operations
pub type Result<T> = core::result::Result<T, ContainerError>;

/// Process ID type
pub type Pid = u32;

// ============================================================================
// Constants
// ============================================================================

/// Default cgroup mount point
pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// ALICE cgroup subtree
pub const ALICE_CGROUP: &str = "/sys/fs/cgroup/alice";

/// Default CPU period (100ms)
pub const DEFAULT_CPU_PERIOD_US: u64 = 100_000;

/// Default memory limit (1GB)
pub const DEFAULT_MEMORY_MAX: u64 = 1024 * 1024 * 1024;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_CPU_PERIOD_US, 100_000);
        assert_eq!(DEFAULT_MEMORY_MAX, 1024 * 1024 * 1024);
    }
}
