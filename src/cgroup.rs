//! Direct Cgroup v2 Control
//!
//! Provides direct manipulation of Linux cgroup v2 unified hierarchy
//! without systemd or other intermediaries.
//!
//! ## Cgroup v2 Interface Files
//!
//! | File | Description | Example |
//! |------|-------------|---------|
//! | `cpu.max` | CPU quota and period | `100000 1000000` (10% CPU) |
//! | `memory.max` | Memory limit | `268435456` (256MB) |
//! | `memory.current` | Current memory usage | Read-only |
//! | `io.max` | I/O bandwidth limit | `8:0 rbps=1048576 wbps=1048576` |
//! | `cgroup.procs` | Process membership | Write PID to add |
//! | `cgroup.controllers` | Available controllers | Read-only |

use core::fmt;

#[cfg(feature = "std")]
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

// ============================================================================
// Error Types
// ============================================================================

/// Cgroup operation errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CgroupError {
    /// Cgroup path does not exist
    NotFound(String),
    /// Permission denied
    PermissionDenied,
    /// Invalid cgroup parameter
    InvalidParameter(String),
    /// I/O error
    IoError(String),
    /// Cgroup v2 not available
    CgroupV2NotAvailable,
    /// Controller not enabled
    ControllerNotEnabled(String),
}

impl fmt::Display for CgroupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CgroupError::NotFound(path) => write!(f, "Cgroup not found: {}", path),
            CgroupError::PermissionDenied => write!(f, "Permission denied"),
            CgroupError::InvalidParameter(msg) => write!(f, "Invalid parameter: {}", msg),
            CgroupError::IoError(msg) => write!(f, "I/O error: {}", msg),
            CgroupError::CgroupV2NotAvailable => write!(f, "Cgroup v2 not available"),
            CgroupError::ControllerNotEnabled(ctrl) => {
                write!(f, "Controller not enabled: {}", ctrl)
            }
        }
    }
}

// ============================================================================
// Configuration Types
// ============================================================================

/// CPU controller configuration
#[derive(Debug, Clone, Copy)]
pub struct CpuConfig {
    /// CPU quota in microseconds per period
    /// Set to u64::MAX for unlimited
    pub quota_us: u64,
    /// CPU period in microseconds (default: 100000 = 100ms)
    pub period_us: u64,
    /// CPU weight (1-10000, default: 100)
    pub weight: u16,
}

impl Default for CpuConfig {
    fn default() -> Self {
        Self {
            quota_us: u64::MAX,  // Unlimited
            period_us: 100_000,  // 100ms
            weight: 100,
        }
    }
}

impl CpuConfig {
    /// Create config for specific CPU percentage
    ///
    /// # Arguments
    /// * `percent` - CPU percentage (1-100 for single core, >100 for multiple cores)
    pub fn from_percent(percent: u32) -> Self {
        let period_us = 100_000u64;
        let quota_us = (period_us as u64 * percent as u64) / 100;
        Self {
            quota_us,
            period_us,
            weight: 100,
        }
    }

    /// Format for cpu.max file: "quota period"
    pub fn to_cpu_max(&self) -> String {
        if self.quota_us == u64::MAX {
            format!("max {}", self.period_us)
        } else {
            format!("{} {}", self.quota_us, self.period_us)
        }
    }
}

/// Memory controller configuration
#[derive(Debug, Clone, Copy)]
pub struct MemoryConfig {
    /// Maximum memory in bytes (memory.max)
    pub max: u64,
    /// High memory threshold in bytes (memory.high)
    pub high: u64,
    /// Minimum memory guarantee in bytes (memory.min)
    pub min: u64,
    /// Enable OOM killer (default: true)
    pub oom_kill: bool,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            max: u64::MAX,   // Unlimited
            high: u64::MAX,  // No throttling
            min: 0,          // No guarantee
            oom_kill: true,
        }
    }
}

impl MemoryConfig {
    /// Create config with specific memory limit
    pub fn with_limit(bytes: u64) -> Self {
        Self {
            max: bytes,
            high: bytes * 90 / 100,  // Throttle at 90%
            min: 0,
            oom_kill: true,
        }
    }
}

/// I/O controller configuration
#[derive(Debug, Clone)]
pub struct IoConfig {
    /// Device major:minor
    pub device: String,
    /// Read bytes per second limit
    pub rbps: u64,
    /// Write bytes per second limit
    pub wbps: u64,
    /// Read IOPS limit
    pub riops: u64,
    /// Write IOPS limit
    pub wiops: u64,
}

impl IoConfig {
    /// Create I/O config for a device
    pub fn new(device: &str) -> Self {
        Self {
            device: device.to_string(),
            rbps: u64::MAX,
            wbps: u64::MAX,
            riops: u64::MAX,
            wiops: u64::MAX,
        }
    }

    /// Format for io.max file
    pub fn to_io_max(&self) -> String {
        let mut parts = vec![self.device.clone()];

        if self.rbps != u64::MAX {
            parts.push(format!("rbps={}", self.rbps));
        }
        if self.wbps != u64::MAX {
            parts.push(format!("wbps={}", self.wbps));
        }
        if self.riops != u64::MAX {
            parts.push(format!("riops={}", self.riops));
        }
        if self.wiops != u64::MAX {
            parts.push(format!("wiops={}", self.wiops));
        }

        parts.join(" ")
    }
}

// ============================================================================
// Cgroup Controller
// ============================================================================

/// Direct cgroup v2 controller
///
/// Manages a single cgroup hierarchy for container resource control.
#[cfg(feature = "std")]
pub struct CgroupController {
    /// Path to this cgroup (e.g., /sys/fs/cgroup/alice/container-123)
    path: PathBuf,
    /// Container ID
    container_id: String,
}

#[cfg(feature = "std")]
impl CgroupController {
    /// Create a new cgroup for a container
    ///
    /// Creates directory at `/sys/fs/cgroup/alice/<container_id>`
    pub fn create(container_id: &str) -> Result<Self, CgroupError> {
        let alice_root = Path::new(crate::ALICE_CGROUP);

        // Ensure ALICE cgroup root exists
        if !alice_root.exists() {
            fs::create_dir_all(alice_root)
                .map_err(|e| CgroupError::IoError(e.to_string()))?;
        }

        // Create container cgroup
        let path = alice_root.join(container_id);
        if !path.exists() {
            fs::create_dir(&path)
                .map_err(|e| CgroupError::IoError(e.to_string()))?;
        }

        // Enable controllers
        let controller = Self {
            path,
            container_id: container_id.to_string(),
        };

        controller.enable_controllers()?;

        Ok(controller)
    }

    /// Open existing cgroup
    pub fn open(container_id: &str) -> Result<Self, CgroupError> {
        let path = Path::new(crate::ALICE_CGROUP).join(container_id);

        if !path.exists() {
            return Err(CgroupError::NotFound(path.to_string_lossy().to_string()));
        }

        Ok(Self {
            path,
            container_id: container_id.to_string(),
        })
    }

    /// Enable CPU, memory, and I/O controllers
    fn enable_controllers(&self) -> Result<(), CgroupError> {
        // Write to parent's cgroup.subtree_control
        let parent = Path::new(crate::ALICE_CGROUP);
        let subtree_control = parent.join("cgroup.subtree_control");

        if subtree_control.exists() {
            // Enable controllers: +cpu +memory +io
            Self::write_file(&subtree_control, "+cpu +memory +io")
                .or_else(|_| {
                    // Try enabling one by one if combined fails
                    Self::write_file(&subtree_control, "+cpu")?;
                    Self::write_file(&subtree_control, "+memory")?;
                    Self::write_file(&subtree_control, "+io")
                })?;
        }

        Ok(())
    }

    /// Set CPU limits
    pub fn set_cpu(&self, config: &CpuConfig) -> Result<(), CgroupError> {
        // cpu.max: "quota period"
        let cpu_max = self.path.join("cpu.max");
        Self::write_file(&cpu_max, &config.to_cpu_max())?;

        // cpu.weight
        let cpu_weight = self.path.join("cpu.weight");
        if cpu_weight.exists() {
            Self::write_file(&cpu_weight, &config.weight.to_string())?;
        }

        Ok(())
    }

    /// Set CPU quota directly (microseconds)
    pub fn set_cpu_max(&self, quota_us: u64, period_us: u64) -> Result<(), CgroupError> {
        let config = CpuConfig {
            quota_us,
            period_us,
            weight: 100,
        };
        self.set_cpu(&config)
    }

    /// Set memory limits
    pub fn set_memory(&self, config: &MemoryConfig) -> Result<(), CgroupError> {
        // memory.max
        let memory_max = self.path.join("memory.max");
        let max_str = if config.max == u64::MAX {
            "max".to_string()
        } else {
            config.max.to_string()
        };
        Self::write_file(&memory_max, &max_str)?;

        // memory.high
        let memory_high = self.path.join("memory.high");
        if memory_high.exists() && config.high != u64::MAX {
            Self::write_file(&memory_high, &config.high.to_string())?;
        }

        // memory.min
        let memory_min = self.path.join("memory.min");
        if memory_min.exists() && config.min > 0 {
            Self::write_file(&memory_min, &config.min.to_string())?;
        }

        // memory.oom.group (if available)
        let oom_group = self.path.join("memory.oom.group");
        if oom_group.exists() {
            let val = if config.oom_kill { "1" } else { "0" };
            Self::write_file(&oom_group, val)?;
        }

        Ok(())
    }

    /// Set memory limit directly (bytes)
    pub fn set_memory_max(&self, bytes: u64) -> Result<(), CgroupError> {
        let config = MemoryConfig::with_limit(bytes);
        self.set_memory(&config)
    }

    /// Set I/O limits
    pub fn set_io(&self, config: &IoConfig) -> Result<(), CgroupError> {
        let io_max = self.path.join("io.max");
        if io_max.exists() {
            Self::write_file(&io_max, &config.to_io_max())?;
        }
        Ok(())
    }

    /// Set I/O bandwidth limits directly
    pub fn set_io_max(&self, device: &str, rbps: u64, wbps: u64) -> Result<(), CgroupError> {
        let mut config = IoConfig::new(device);
        config.rbps = rbps;
        config.wbps = wbps;
        self.set_io(&config)
    }

    /// Set all resource limits in a single batched operation (io_uring)
    ///
    /// Uses io_uring for async batch writes when available.
    /// Falls back to synchronous writes if io_uring is not available.
    ///
    /// # Performance
    ///
    /// - With io_uring: 1 syscall for all operations
    /// - Without: 3+ separate write syscalls
    #[cfg(feature = "io_uring")]
    pub fn set_all_batched(
        &self,
        cpu: &CpuConfig,
        memory: &MemoryConfig,
        io: Option<&IoConfig>,
    ) -> Result<(), CgroupError> {
        use crate::io_uring::IoUringCgroup;

        // Try io_uring batched write
        match IoUringCgroup::new(&self.path) {
            Ok(mut batch) => {
                batch.queue_cpu_max(cpu.quota_us, cpu.period_us);
                batch.queue_memory_max(memory.max);
                if let Some(io_config) = io {
                    batch.queue_io_max(&io_config.device, io_config.rbps, io_config.wbps);
                }

                // Use sync batch write (simpler, still batched)
                batch.sync_batch_write()
                    .map_err(|e| CgroupError::IoError(e.to_string()))
            }
            Err(_) => {
                // Fall back to individual writes
                self.set_cpu(cpu)?;
                self.set_memory(memory)?;
                if let Some(io_config) = io {
                    self.set_io(io_config)?;
                }
                Ok(())
            }
        }
    }

    /// Batched set (fallback without io_uring)
    #[cfg(not(feature = "io_uring"))]
    pub fn set_all_batched(
        &self,
        cpu: &CpuConfig,
        memory: &MemoryConfig,
        io: Option<&IoConfig>,
    ) -> Result<(), CgroupError> {
        self.set_cpu(cpu)?;
        self.set_memory(memory)?;
        if let Some(io_config) = io {
            self.set_io(io_config)?;
        }
        Ok(())
    }

    /// Add a process to this cgroup
    pub fn add_process(&self, pid: u32) -> Result<(), CgroupError> {
        let cgroup_procs = self.path.join("cgroup.procs");
        Self::write_file(&cgroup_procs, &pid.to_string())
    }

    /// Get current memory usage
    pub fn memory_current(&self) -> Result<u64, CgroupError> {
        let memory_current = self.path.join("memory.current");
        let content = Self::read_file(&memory_current)?;
        content.trim().parse::<u64>()
            .map_err(|e| CgroupError::InvalidParameter(e.to_string()))
    }

    /// Get current CPU usage (microseconds)
    pub fn cpu_usage_us(&self) -> Result<u64, CgroupError> {
        let cpu_stat = self.path.join("cpu.stat");
        let content = Self::read_file(&cpu_stat)?;

        // Parse "usage_usec XXXX" line
        for line in content.lines() {
            if line.starts_with("usage_usec") {
                if let Some(val) = line.split_whitespace().nth(1) {
                    return val.parse::<u64>()
                        .map_err(|e| CgroupError::InvalidParameter(e.to_string()));
                }
            }
        }

        Err(CgroupError::InvalidParameter("usage_usec not found".into()))
    }

    /// Get list of processes in this cgroup
    pub fn processes(&self) -> Result<Vec<u32>, CgroupError> {
        let cgroup_procs = self.path.join("cgroup.procs");
        let content = Self::read_file(&cgroup_procs)?;

        let pids: Vec<u32> = content
            .lines()
            .filter_map(|line| line.trim().parse().ok())
            .collect();

        Ok(pids)
    }

    /// Freeze all processes in this cgroup
    pub fn freeze(&self) -> Result<(), CgroupError> {
        let cgroup_freeze = self.path.join("cgroup.freeze");
        if cgroup_freeze.exists() {
            Self::write_file(&cgroup_freeze, "1")?;
        }
        Ok(())
    }

    /// Unfreeze all processes in this cgroup
    pub fn unfreeze(&self) -> Result<(), CgroupError> {
        let cgroup_freeze = self.path.join("cgroup.freeze");
        if cgroup_freeze.exists() {
            Self::write_file(&cgroup_freeze, "0")?;
        }
        Ok(())
    }

    /// Kill all processes in this cgroup
    #[cfg(target_os = "linux")]
    pub fn kill_all(&self) -> Result<(), CgroupError> {
        let cgroup_kill = self.path.join("cgroup.kill");
        if cgroup_kill.exists() {
            Self::write_file(&cgroup_kill, "1")?;
        } else {
            // Fallback: send SIGKILL to all processes
            for pid in self.processes()? {
                // SAFETY: pid is a valid process ID read from cgroup.procs which only contains
                // live process IDs; SIGKILL is always deliverable and the signal number is valid.
                unsafe {
                    libc::kill(pid as i32, libc::SIGKILL);
                }
            }
        }
        Ok(())
    }

    /// Kill all processes (non-Linux stub)
    #[cfg(not(target_os = "linux"))]
    pub fn kill_all(&self) -> Result<(), CgroupError> {
        Err(CgroupError::CgroupV2NotAvailable)
    }

    /// Destroy this cgroup
    ///
    /// Kills all processes and removes the cgroup directory.
    #[cfg(target_os = "linux")]
    pub fn destroy(self) -> Result<(), CgroupError> {
        // Kill all processes first
        self.kill_all()?;

        // Wait briefly for processes to terminate
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Remove cgroup directory
        fs::remove_dir(&self.path)
            .map_err(|e| CgroupError::IoError(e.to_string()))?;

        Ok(())
    }

    /// Destroy (non-Linux stub)
    #[cfg(not(target_os = "linux"))]
    pub fn destroy(self) -> Result<(), CgroupError> {
        Err(CgroupError::CgroupV2NotAvailable)
    }

    /// Get cgroup path
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get container ID
    pub fn container_id(&self) -> &str {
        &self.container_id
    }

    // Helper: write to cgroup file
    fn write_file(path: &Path, content: &str) -> Result<(), CgroupError> {
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    CgroupError::PermissionDenied
                } else if e.kind() == std::io::ErrorKind::NotFound {
                    CgroupError::NotFound(path.to_string_lossy().to_string())
                } else {
                    CgroupError::IoError(e.to_string())
                }
            })?;

        file.write_all(content.as_bytes())
            .map_err(|e| CgroupError::IoError(e.to_string()))?;

        Ok(())
    }

    // Helper: read from cgroup file
    fn read_file(path: &Path) -> Result<String, CgroupError> {
        let mut file = File::open(path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    CgroupError::NotFound(path.to_string_lossy().to_string())
                } else {
                    CgroupError::IoError(e.to_string())
                }
            })?;

        let mut content = String::new();
        file.read_to_string(&mut content)
            .map_err(|e| CgroupError::IoError(e.to_string()))?;

        Ok(content)
    }
}

#[cfg(feature = "std")]
impl Drop for CgroupController {
    fn drop(&mut self) {
        // Note: We don't auto-destroy on drop to allow explicit lifecycle control
        // Users should call destroy() explicitly when done
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_config_default() {
        let config = CpuConfig::default();
        assert_eq!(config.period_us, 100_000);
        assert_eq!(config.quota_us, u64::MAX);
        assert_eq!(config.to_cpu_max(), "max 100000");
    }

    #[test]
    fn test_cpu_config_from_percent() {
        let config = CpuConfig::from_percent(50);
        assert_eq!(config.quota_us, 50_000);
        assert_eq!(config.period_us, 100_000);
        assert_eq!(config.to_cpu_max(), "50000 100000");
    }

    #[test]
    fn test_memory_config_with_limit() {
        let config = MemoryConfig::with_limit(256 * 1024 * 1024);
        assert_eq!(config.max, 256 * 1024 * 1024);
        assert_eq!(config.high, 256 * 1024 * 1024 * 90 / 100);
    }

    #[test]
    fn test_io_config() {
        let mut config = IoConfig::new("8:0");
        config.rbps = 1048576;
        config.wbps = 524288;

        let io_max = config.to_io_max();
        assert!(io_max.contains("8:0"));
        assert!(io_max.contains("rbps=1048576"));
        assert!(io_max.contains("wbps=524288"));
    }

    #[test]
    fn test_cgroup_error_display() {
        let err = CgroupError::NotFound("/sys/fs/cgroup/test".into());
        assert!(err.to_string().contains("not found"));

        let err = CgroupError::PermissionDenied;
        assert!(err.to_string().contains("Permission denied"));
    }
}
