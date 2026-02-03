//! PSI (Pressure Stall Information) Integration
//!
//! Provides event-driven CPU pressure monitoring using Linux PSI subsystem.
//! Eliminates polling by using epoll/io_uring to receive pressure notifications.
//!
//! Requires Linux 4.20+ for PSI, Linux 5.2+ for PSI triggers.
//!
//! ## Performance Benefits
//!
//! | Approach | CPU Overhead | Latency |
//! |----------|--------------|---------|
//! | Polling cpu.stat | ~1% | 10ms |
//! | PSI epoll | ~0% | <1ms |
//!
//! ## Usage
//!
//! ```ignore
//! let monitor = PsiMonitor::new()?;
//! monitor.add_trigger(PsiTrigger::cpu_some(50_000, 1_000_000))?;
//!
//! loop {
//!     if let Some(event) = monitor.wait_event(Duration::from_millis(100))? {
//!         match event {
//!             PsiEvent::CpuPressure { level, .. } => {
//!                 scheduler.adjust_quota(level);
//!             }
//!         }
//!     }
//! }
//! ```

#[cfg(all(feature = "std", target_os = "linux"))]
use core::ffi::c_int;

#[cfg(all(feature = "std", target_os = "linux"))]
use std::fs::File;
#[cfg(all(feature = "std", target_os = "linux"))]
use std::os::unix::io::RawFd;

#[cfg(all(feature = "std", target_os = "linux"))]
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::io::AsRawFd,
    path::Path,
    time::Duration,
};

// ============================================================================
// PSI Constants
// ============================================================================

/// PSI resource types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsiResource {
    /// CPU pressure
    Cpu,
    /// Memory pressure
    Memory,
    /// I/O pressure
    Io,
}

impl PsiResource {
    /// Get the proc path for this resource
    pub fn proc_path(&self) -> &'static str {
        match self {
            PsiResource::Cpu => "/proc/pressure/cpu",
            PsiResource::Memory => "/proc/pressure/memory",
            PsiResource::Io => "/proc/pressure/io",
        }
    }

    /// Get cgroup PSI file name
    pub fn cgroup_file(&self) -> &'static str {
        match self {
            PsiResource::Cpu => "cpu.pressure",
            PsiResource::Memory => "memory.pressure",
            PsiResource::Io => "io.pressure",
        }
    }
}

/// PSI level (some vs full)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsiLevel {
    /// Some tasks stalled (partial pressure)
    Some,
    /// All tasks stalled (full pressure)
    Full,
}

impl PsiLevel {
    fn as_str(&self) -> &'static str {
        match self {
            PsiLevel::Some => "some",
            PsiLevel::Full => "full",
        }
    }
}

// ============================================================================
// PSI Trigger
// ============================================================================

/// PSI trigger configuration
///
/// A trigger fires when the stall time exceeds `threshold_us` within `window_us`.
#[derive(Debug, Clone)]
pub struct PsiTrigger {
    /// Resource to monitor
    pub resource: PsiResource,
    /// Pressure level
    pub level: PsiLevel,
    /// Stall time threshold in microseconds
    pub threshold_us: u64,
    /// Time window in microseconds
    pub window_us: u64,
}

impl PsiTrigger {
    /// Create a new trigger
    pub fn new(resource: PsiResource, level: PsiLevel, threshold_us: u64, window_us: u64) -> Self {
        Self {
            resource,
            level,
            threshold_us,
            window_us,
        }
    }

    /// Create CPU "some" trigger (partial stalls)
    pub fn cpu_some(threshold_us: u64, window_us: u64) -> Self {
        Self::new(PsiResource::Cpu, PsiLevel::Some, threshold_us, window_us)
    }

    /// Create CPU "full" trigger (complete stalls)
    pub fn cpu_full(threshold_us: u64, window_us: u64) -> Self {
        Self::new(PsiResource::Cpu, PsiLevel::Full, threshold_us, window_us)
    }

    /// Create memory trigger
    pub fn memory(level: PsiLevel, threshold_us: u64, window_us: u64) -> Self {
        Self::new(PsiResource::Memory, level, threshold_us, window_us)
    }

    /// Create I/O trigger
    pub fn io(level: PsiLevel, threshold_us: u64, window_us: u64) -> Self {
        Self::new(PsiResource::Io, level, threshold_us, window_us)
    }

    /// Format trigger string for writing to PSI file
    pub fn to_trigger_string(&self) -> String {
        format!(
            "{} {} {}",
            self.level.as_str(),
            self.threshold_us,
            self.window_us
        )
    }
}

// ============================================================================
// PSI Statistics
// ============================================================================

/// PSI statistics from reading pressure file
#[derive(Debug, Clone, Default)]
pub struct PsiStats {
    /// "some" statistics
    pub some: PsiStatLine,
    /// "full" statistics (not available for CPU)
    pub full: Option<PsiStatLine>,
}

/// Single line of PSI statistics
#[derive(Debug, Clone, Default)]
pub struct PsiStatLine {
    /// Average percentage over 10 seconds
    pub avg10: f64,
    /// Average percentage over 60 seconds
    pub avg60: f64,
    /// Average percentage over 300 seconds
    pub avg300: f64,
    /// Total stall time in microseconds
    pub total: u64,
}

impl PsiStats {
    /// Parse PSI file content
    #[cfg(feature = "std")]
    pub fn parse(content: &str) -> Self {
        let mut stats = PsiStats::default();

        for line in content.lines() {
            if line.starts_with("some") {
                stats.some = PsiStatLine::parse_line(line);
            } else if line.starts_with("full") {
                stats.full = Some(PsiStatLine::parse_line(line));
            }
        }

        stats
    }
}

impl PsiStatLine {
    /// Parse a single PSI stat line
    fn parse_line(line: &str) -> Self {
        let mut stat = PsiStatLine::default();

        for part in line.split_whitespace().skip(1) {
            if let Some((key, value)) = part.split_once('=') {
                match key {
                    "avg10" => stat.avg10 = value.parse().unwrap_or(0.0),
                    "avg60" => stat.avg60 = value.parse().unwrap_or(0.0),
                    "avg300" => stat.avg300 = value.parse().unwrap_or(0.0),
                    "total" => stat.total = value.parse().unwrap_or(0),
                    _ => {}
                }
            }
        }

        stat
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// PSI operation errors
#[derive(Debug)]
pub enum PsiError {
    /// PSI not available
    NotAvailable,
    /// Trigger registration failed
    TriggerFailed(String),
    /// Epoll error
    EpollError(i32),
    /// I/O error
    IoError(String),
    /// Not supported on this platform
    NotSupported,
}

impl core::fmt::Display for PsiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PsiError::NotAvailable => write!(f, "PSI not available (requires Linux 4.20+)"),
            PsiError::TriggerFailed(msg) => write!(f, "Trigger registration failed: {}", msg),
            PsiError::EpollError(e) => write!(f, "epoll error: errno {}", e),
            PsiError::IoError(msg) => write!(f, "I/O error: {}", msg),
            PsiError::NotSupported => write!(f, "PSI not supported on this platform"),
        }
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for PsiError {
    fn from(e: std::io::Error) -> Self {
        PsiError::IoError(e.to_string())
    }
}

// ============================================================================
// PSI Event
// ============================================================================

/// PSI event received from monitor
#[derive(Debug, Clone)]
pub enum PsiEvent {
    /// CPU pressure event
    CpuPressure {
        level: PsiLevel,
        threshold_us: u64,
        window_us: u64,
    },
    /// Memory pressure event
    MemoryPressure {
        level: PsiLevel,
        threshold_us: u64,
        window_us: u64,
    },
    /// I/O pressure event
    IoPressure {
        level: PsiLevel,
        threshold_us: u64,
        window_us: u64,
    },
}

// ============================================================================
// Registered Trigger
// ============================================================================

/// A registered PSI trigger with its file descriptor
#[cfg(all(feature = "std", target_os = "linux"))]
struct RegisteredTrigger {
    /// Original trigger configuration
    trigger: PsiTrigger,
    /// File handle (kept open for notifications)
    file: File,
    /// File descriptor
    fd: RawFd,
}

// ============================================================================
// PSI Monitor (Linux only)
// ============================================================================

/// Event-driven PSI monitor using epoll
#[cfg(all(feature = "std", target_os = "linux"))]
pub struct PsiMonitor {
    /// Epoll file descriptor
    epoll_fd: RawFd,
    /// Registered triggers
    triggers: Vec<RegisteredTrigger>,
    /// Cgroup path (optional)
    cgroup_path: Option<std::path::PathBuf>,
}

#[cfg(all(feature = "std", target_os = "linux"))]
impl PsiMonitor {
    /// Create a new PSI monitor for system-wide pressure
    pub fn new() -> Result<Self, PsiError> {
        Self::with_cgroup(None)
    }

    /// Create a PSI monitor for a specific cgroup
    pub fn for_cgroup(cgroup_path: impl Into<std::path::PathBuf>) -> Result<Self, PsiError> {
        Self::with_cgroup(Some(cgroup_path.into()))
    }

    fn with_cgroup(cgroup_path: Option<std::path::PathBuf>) -> Result<Self, PsiError> {
        // Check if PSI is available
        if !Path::new("/proc/pressure").exists() {
            return Err(PsiError::NotAvailable);
        }

        // Create epoll instance
        let epoll_fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if epoll_fd < 0 {
            let errno = unsafe { *libc::__errno_location() };
            return Err(PsiError::EpollError(errno));
        }

        Ok(Self {
            epoll_fd,
            triggers: Vec::new(),
            cgroup_path,
        })
    }

    /// Add a PSI trigger
    pub fn add_trigger(&mut self, trigger: PsiTrigger) -> Result<(), PsiError> {
        // Determine the file path
        let path = if let Some(ref cgroup) = self.cgroup_path {
            cgroup.join(trigger.resource.cgroup_file())
        } else {
            std::path::PathBuf::from(trigger.resource.proc_path())
        };

        // Open file for writing trigger and receiving notifications
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)?;

        // Write trigger configuration
        let trigger_str = trigger.to_trigger_string();
        file.write_all(trigger_str.as_bytes())
            .map_err(|e| PsiError::TriggerFailed(e.to_string()))?;

        let fd = file.as_raw_fd();

        // Add to epoll
        let mut event = libc::epoll_event {
            events: libc::EPOLLPRI as u32,
            u64: self.triggers.len() as u64,
        };

        let ret = unsafe { libc::epoll_ctl(self.epoll_fd, libc::EPOLL_CTL_ADD, fd, &mut event) };

        if ret < 0 {
            let errno = unsafe { *libc::__errno_location() };
            return Err(PsiError::EpollError(errno));
        }

        self.triggers.push(RegisteredTrigger { trigger, file, fd });

        Ok(())
    }

    /// Wait for a PSI event
    pub fn wait_event(&self, timeout: Duration) -> Result<Option<PsiEvent>, PsiError> {
        let timeout_ms = timeout.as_millis() as c_int;

        let mut events = [libc::epoll_event { events: 0, u64: 0 }; 16];

        let nfds = unsafe {
            libc::epoll_wait(
                self.epoll_fd,
                events.as_mut_ptr(),
                events.len() as c_int,
                timeout_ms,
            )
        };

        if nfds < 0 {
            let errno = unsafe { *libc::__errno_location() };
            if errno == libc::EINTR {
                return Ok(None);
            }
            return Err(PsiError::EpollError(errno));
        }

        if nfds == 0 {
            return Ok(None);
        }

        // Process first event
        let event = &events[0];
        let trigger_idx = event.u64 as usize;

        if trigger_idx < self.triggers.len() {
            let trigger = &self.triggers[trigger_idx].trigger;

            let psi_event = match trigger.resource {
                PsiResource::Cpu => PsiEvent::CpuPressure {
                    level: trigger.level,
                    threshold_us: trigger.threshold_us,
                    window_us: trigger.window_us,
                },
                PsiResource::Memory => PsiEvent::MemoryPressure {
                    level: trigger.level,
                    threshold_us: trigger.threshold_us,
                    window_us: trigger.window_us,
                },
                PsiResource::Io => PsiEvent::IoPressure {
                    level: trigger.level,
                    threshold_us: trigger.threshold_us,
                    window_us: trigger.window_us,
                },
            };

            return Ok(Some(psi_event));
        }

        Ok(None)
    }

    /// Read current PSI statistics
    pub fn read_stats(&self, resource: PsiResource) -> Result<PsiStats, PsiError> {
        let path = if let Some(ref cgroup) = self.cgroup_path {
            cgroup.join(resource.cgroup_file())
        } else {
            std::path::PathBuf::from(resource.proc_path())
        };

        let mut content = String::new();
        File::open(&path)?.read_to_string(&mut content)?;

        Ok(PsiStats::parse(&content))
    }

    /// Get number of registered triggers
    pub fn trigger_count(&self) -> usize {
        self.triggers.len()
    }
}

#[cfg(all(feature = "std", target_os = "linux"))]
impl Drop for PsiMonitor {
    fn drop(&mut self) {
        // Remove triggers from epoll
        for trigger in &self.triggers {
            unsafe {
                libc::epoll_ctl(
                    self.epoll_fd,
                    libc::EPOLL_CTL_DEL,
                    trigger.fd,
                    core::ptr::null_mut(),
                );
            }
        }
        // Close epoll fd
        unsafe {
            libc::close(self.epoll_fd);
        }
    }
}

// ============================================================================
// PSI-Driven Scheduler
// ============================================================================

/// PSI-driven dynamic scheduler
///
/// Uses PSI events to adjust CPU quota reactively instead of polling.
#[cfg(all(feature = "std", target_os = "linux"))]
pub struct PsiScheduler {
    /// PSI monitor
    monitor: PsiMonitor,
    /// Cgroup path
    cgroup_path: std::path::PathBuf,
    /// Current CPU quota
    current_quota_us: u64,
    /// Minimum quota
    min_quota_us: u64,
    /// Maximum quota
    max_quota_us: u64,
    /// Period
    period_us: u64,
    /// Burst multiplier on pressure
    burst_multiplier: f64,
}

#[cfg(all(feature = "std", target_os = "linux"))]
impl PsiScheduler {
    /// Create a new PSI-driven scheduler
    pub fn new(cgroup_path: impl Into<std::path::PathBuf>) -> Result<Self, PsiError> {
        let cgroup_path = cgroup_path.into();
        let monitor = PsiMonitor::for_cgroup(&cgroup_path)?;

        Ok(Self {
            monitor,
            cgroup_path,
            current_quota_us: 100_000,
            min_quota_us: 10_000,
            max_quota_us: 100_000,
            period_us: 100_000,
            burst_multiplier: 1.5,
        })
    }

    /// Configure quota limits
    pub fn configure(
        mut self,
        min_quota_us: u64,
        max_quota_us: u64,
        initial_quota_us: u64,
    ) -> Self {
        self.min_quota_us = min_quota_us;
        self.max_quota_us = max_quota_us;
        self.current_quota_us = initial_quota_us;
        self
    }

    /// Start monitoring with default triggers
    pub fn start(&mut self) -> Result<(), PsiError> {
        // Add CPU pressure trigger: 50ms stall per 1 second window
        self.monitor.add_trigger(PsiTrigger::cpu_some(50_000, 1_000_000))?;

        // Write initial quota
        self.write_quota(self.current_quota_us)?;

        Ok(())
    }

    /// Process events (non-blocking)
    pub fn tick(&mut self) -> Result<Option<PsiEvent>, PsiError> {
        let event = self.monitor.wait_event(Duration::from_millis(0))?;

        if let Some(ref e) = event {
            match e {
                PsiEvent::CpuPressure { level, .. } => {
                    self.handle_cpu_pressure(*level)?;
                }
                _ => {}
            }
        }

        Ok(event)
    }

    /// Block waiting for events
    pub fn wait(&mut self, timeout: Duration) -> Result<Option<PsiEvent>, PsiError> {
        let event = self.monitor.wait_event(timeout)?;

        if let Some(ref e) = event {
            match e {
                PsiEvent::CpuPressure { level, .. } => {
                    self.handle_cpu_pressure(*level)?;
                }
                _ => {}
            }
        }

        Ok(event)
    }

    fn handle_cpu_pressure(&mut self, level: PsiLevel) -> Result<(), PsiError> {
        let new_quota = match level {
            PsiLevel::Some => {
                // Moderate pressure: increase quota
                let increased = (self.current_quota_us as f64 * self.burst_multiplier) as u64;
                increased.min(self.max_quota_us)
            }
            PsiLevel::Full => {
                // Severe pressure: maximize quota
                self.max_quota_us
            }
        };

        if new_quota != self.current_quota_us {
            self.write_quota(new_quota)?;
            self.current_quota_us = new_quota;
        }

        Ok(())
    }

    fn write_quota(&self, quota_us: u64) -> Result<(), PsiError> {
        let cpu_max_path = self.cgroup_path.join("cpu.max");
        let content = format!("{} {}", quota_us, self.period_us);

        std::fs::write(&cpu_max_path, content)?;

        Ok(())
    }

    /// Get current quota
    pub fn current_quota(&self) -> u64 {
        self.current_quota_us
    }
}

// ============================================================================
// Non-Linux Stubs
// ============================================================================

/// PSI Monitor (non-Linux stub)
#[cfg(not(target_os = "linux"))]
pub struct PsiMonitor;

#[cfg(not(target_os = "linux"))]
impl PsiMonitor {
    pub fn new() -> Result<Self, PsiError> {
        Err(PsiError::NotSupported)
    }
}

/// PSI Scheduler (non-Linux stub)
#[cfg(not(target_os = "linux"))]
pub struct PsiScheduler;

#[cfg(not(target_os = "linux"))]
impl PsiScheduler {
    pub fn new<P: AsRef<std::path::Path>>(_path: P) -> Result<Self, PsiError> {
        Err(PsiError::NotSupported)
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Check if PSI is available on this system
#[cfg(target_os = "linux")]
pub fn is_psi_available() -> bool {
    Path::new("/proc/pressure/cpu").exists()
}

/// Check PSI availability (non-Linux)
#[cfg(not(target_os = "linux"))]
pub fn is_psi_available() -> bool {
    false
}

/// Check if PSI triggers are supported (Linux 5.2+)
#[cfg(all(feature = "std", target_os = "linux"))]
pub fn is_psi_triggers_available() -> bool {
    // Try to write a trigger to /proc/pressure/cpu
    if let Ok(mut file) = OpenOptions::new()
        .write(true)
        .open("/proc/pressure/cpu")
    {
        // Try writing a trigger - this will fail gracefully on older kernels
        let result = file.write_all(b"some 500000 1000000");
        result.is_ok()
    } else {
        false
    }
}

/// Check PSI triggers (non-Linux)
#[cfg(not(all(feature = "std", target_os = "linux")))]
pub fn is_psi_triggers_available() -> bool {
    false
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_psi_resource_paths() {
        assert_eq!(PsiResource::Cpu.proc_path(), "/proc/pressure/cpu");
        assert_eq!(PsiResource::Memory.proc_path(), "/proc/pressure/memory");
        assert_eq!(PsiResource::Io.proc_path(), "/proc/pressure/io");
    }

    #[test]
    fn test_psi_trigger_string() {
        let trigger = PsiTrigger::cpu_some(50_000, 1_000_000);
        assert_eq!(trigger.to_trigger_string(), "some 50000 1000000");

        let trigger = PsiTrigger::cpu_full(100_000, 1_000_000);
        assert_eq!(trigger.to_trigger_string(), "full 100000 1000000");
    }

    #[test]
    fn test_psi_stats_parse() {
        let content = "some avg10=0.00 avg60=0.00 avg300=0.00 total=12345\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0";
        let stats = PsiStats::parse(content);

        assert_eq!(stats.some.total, 12345);
        assert!(stats.full.is_some());
    }

    #[test]
    fn test_psi_stat_line_parse() {
        let line = "some avg10=1.23 avg60=4.56 avg300=7.89 total=123456";
        let stat = PsiStatLine::parse_line(line);

        assert!((stat.avg10 - 1.23).abs() < 0.01);
        assert!((stat.avg60 - 4.56).abs() < 0.01);
        assert!((stat.avg300 - 7.89).abs() < 0.01);
        assert_eq!(stat.total, 123456);
    }

    #[test]
    fn test_psi_error_display() {
        let err = PsiError::NotAvailable;
        assert!(err.to_string().contains("not available"));

        let err = PsiError::NotSupported;
        assert!(err.to_string().contains("not supported"));
    }

    #[test]
    fn test_psi_level() {
        assert_eq!(PsiLevel::Some.as_str(), "some");
        assert_eq!(PsiLevel::Full.as_str(), "full");
    }
}
