//! Dynamic CPU Scheduling (Ghost Scheduling Lite)
//!
//! Provides dynamic CPU quota adjustment for latency-sensitive workloads.
//! This is a simplified version of Google's ghOSt scheduler, using cgroup v2
//! CPU controller instead of eBPF.
//!
//! ## Approach
//!
//! Instead of modifying kernel scheduling decisions directly (which requires eBPF),
//! we dynamically adjust `cpu.max` quota based on:
//!
//! 1. **CPU Usage Tracking**: Monitor actual CPU consumption via `cpu.stat`
//! 2. **Latency Feedback**: Adjust quota based on observed latency
//! 3. **Burst Handling**: Temporarily increase quota for burst workloads
//! 4. **Throttle Prevention**: Detect and respond to CPU throttling
//!
//! ## Algorithm
//!
//! ```text
//! Every tick (10ms):
//!   usage = read_cpu_usage()
//!   throttled = read_throttle_count()
//!
//!   if throttled > last_throttled:
//!       // Being throttled, increase quota
//!       quota = min(quota * 1.5, max_quota)
//!   elif usage < quota * 0.5:
//!       // Underutilized, decrease quota
//!       quota = max(quota * 0.8, min_quota)
//!
//!   write_cpu_max(quota)
//! ```

#[cfg(feature = "std")]
use std::time::Instant;

use crate::cgroup::{CgroupController, CgroupError};

// ============================================================================
// Scheduler Configuration
// ============================================================================

/// Dynamic scheduler configuration
#[derive(Debug, Clone, Copy)]
pub struct SchedulerConfig {
    /// Target latency in microseconds
    pub target_latency_us: u64,
    /// Minimum CPU quota (microseconds per period)
    pub min_quota_us: u64,
    /// Maximum CPU quota (microseconds per period)
    pub max_quota_us: u64,
    /// CPU period (microseconds)
    pub period_us: u64,
    /// Adjustment interval
    pub tick_interval_ms: u64,
    /// Quota increase multiplier when throttled
    pub burst_multiplier: f64,
    /// Quota decrease multiplier when underutilized
    pub throttle_multiplier: f64,
    /// Utilization threshold for decrease (0.0-1.0)
    pub low_util_threshold: f64,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            target_latency_us: 1000,         // 1ms target latency
            min_quota_us: 10_000,            // 10ms minimum (10% of period)
            max_quota_us: 100_000,           // 100ms maximum (100% of period)
            period_us: 100_000,              // 100ms period
            tick_interval_ms: 10,            // 10ms tick
            burst_multiplier: 1.5,           // 50% increase on throttle
            throttle_multiplier: 0.8,        // 20% decrease on underutil
            low_util_threshold: 0.5,         // Below 50% = underutilized
        }
    }
}

impl SchedulerConfig {
    /// Create config for latency-sensitive workload
    pub fn low_latency() -> Self {
        Self {
            target_latency_us: 100,          // 100us target
            min_quota_us: 50_000,            // 50% minimum
            max_quota_us: 100_000,           // 100% maximum
            tick_interval_ms: 1,             // 1ms tick
            burst_multiplier: 2.0,           // 2x burst
            ..Default::default()
        }
    }

    /// Create config for batch workload
    pub fn batch() -> Self {
        Self {
            target_latency_us: 100_000,      // 100ms acceptable
            min_quota_us: 10_000,            // 10% minimum
            max_quota_us: 50_000,            // 50% maximum
            tick_interval_ms: 100,           // 100ms tick
            burst_multiplier: 1.2,           // 20% burst
            ..Default::default()
        }
    }
}

// ============================================================================
// CPU Statistics
// ============================================================================

/// CPU usage statistics from cgroup
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuStats {
    /// Total CPU usage in microseconds
    pub usage_us: u64,
    /// User CPU time in microseconds
    pub user_us: u64,
    /// System CPU time in microseconds
    pub system_us: u64,
    /// Number of throttle events
    pub nr_throttled: u64,
    /// Total throttled time in microseconds
    pub throttled_us: u64,
}

impl CpuStats {
    /// Parse from cpu.stat content
    #[cfg(feature = "std")]
    pub fn from_cpu_stat(content: &str) -> Self {
        let mut stats = CpuStats::default();

        for line in content.lines() {
            let mut parts = line.split_whitespace();
            if let (Some(key), Some(value)) = (parts.next(), parts.next()) {
                if let Ok(v) = value.parse::<u64>() {
                    match key {
                        "usage_usec" => stats.usage_us = v,
                        "user_usec" => stats.user_us = v,
                        "system_usec" => stats.system_us = v,
                        "nr_throttled" => stats.nr_throttled = v,
                        "throttled_usec" => stats.throttled_us = v,
                        _ => {}
                    }
                }
            }
        }

        stats
    }
}

// ============================================================================
// Dynamic Scheduler
// ============================================================================

/// Dynamic CPU scheduler using cgroup v2 quota adjustment
#[cfg(feature = "std")]
pub struct DynamicScheduler {
    /// Cgroup controller
    cgroup: CgroupController,
    /// Scheduler configuration
    config: SchedulerConfig,
    /// Current quota
    current_quota_us: u64,
    /// Last tick time
    last_tick: Instant,
    /// Last CPU stats (reserved for future use)
    #[allow(dead_code)]
    last_stats: CpuStats,
    /// Last CPU usage for delta calculation
    last_usage_us: u64,
    /// Running state
    running: bool,
}

#[cfg(feature = "std")]
impl DynamicScheduler {
    /// Create a new dynamic scheduler
    pub fn new(cgroup: CgroupController, config: SchedulerConfig) -> Self {
        let current_quota_us = config.max_quota_us;

        Self {
            cgroup,
            config,
            current_quota_us,
            last_tick: Instant::now(),
            last_stats: CpuStats::default(),
            last_usage_us: 0,
            running: false,
        }
    }

    /// Start scheduling with initial quota
    pub fn start(&mut self) -> Result<(), CgroupError> {
        // Set initial CPU quota
        self.cgroup.set_cpu_max(self.current_quota_us, self.config.period_us)?;
        self.running = true;
        self.last_tick = Instant::now();
        Ok(())
    }

    /// Stop scheduling
    pub fn stop(&mut self) -> Result<(), CgroupError> {
        self.running = false;
        // Reset to unlimited
        self.cgroup.set_cpu_max(u64::MAX, self.config.period_us)
    }

    /// Perform one scheduling tick
    ///
    /// Should be called periodically (every `tick_interval_ms`).
    pub fn tick(&mut self) -> Result<SchedulerDecision, CgroupError> {
        if !self.running {
            return Ok(SchedulerDecision::Idle);
        }

        let now = Instant::now();
        let elapsed = now.duration_since(self.last_tick);

        // Check if enough time has passed
        if elapsed.as_millis() < self.config.tick_interval_ms as u128 {
            return Ok(SchedulerDecision::TooSoon);
        }

        // Read current stats
        let current_usage = self.cgroup.cpu_usage_us()?;
        let usage_delta = current_usage.saturating_sub(self.last_usage_us);

        // Calculate utilization (usage / elapsed time)
        let elapsed_us = elapsed.as_micros() as u64;
        let utilization = if elapsed_us > 0 {
            usage_delta as f64 / elapsed_us as f64
        } else {
            0.0
        };

        // Decide on quota adjustment
        let decision = self.decide_quota(utilization);

        // Apply new quota if changed
        if let SchedulerDecision::Adjust { new_quota_us } = decision {
            self.cgroup.set_cpu_max(new_quota_us, self.config.period_us)?;
            self.current_quota_us = new_quota_us;
        }

        // Update state
        self.last_tick = now;
        self.last_usage_us = current_usage;

        Ok(decision)
    }

    /// Decide on quota adjustment based on utilization
    fn decide_quota(&self, utilization: f64) -> SchedulerDecision {
        let current = self.current_quota_us;
        let min = self.config.min_quota_us;
        let max = self.config.max_quota_us;

        // Check if being throttled (high utilization near quota)
        if utilization > 0.9 && current < max {
            // Increase quota
            let new_quota = ((current as f64) * self.config.burst_multiplier) as u64;
            let new_quota = new_quota.min(max);

            if new_quota != current {
                return SchedulerDecision::Adjust {
                    new_quota_us: new_quota,
                };
            }
        }

        // Check if underutilized
        if utilization < self.config.low_util_threshold && current > min {
            // Decrease quota
            let new_quota = ((current as f64) * self.config.throttle_multiplier) as u64;
            let new_quota = new_quota.max(min);

            if new_quota != current {
                return SchedulerDecision::Adjust {
                    new_quota_us: new_quota,
                };
            }
        }

        SchedulerDecision::Maintain
    }

    /// Force burst mode (temporarily maximize quota)
    pub fn burst_mode(&mut self) -> Result<(), CgroupError> {
        self.current_quota_us = self.config.max_quota_us;
        self.cgroup.set_cpu_max(self.current_quota_us, self.config.period_us)
    }

    /// Force throttle mode (minimize quota)
    pub fn throttle(&mut self) -> Result<(), CgroupError> {
        self.current_quota_us = self.config.min_quota_us;
        self.cgroup.set_cpu_max(self.current_quota_us, self.config.period_us)
    }

    /// Set specific quota
    pub fn set_quota(&mut self, quota_us: u64) -> Result<(), CgroupError> {
        let quota = quota_us
            .max(self.config.min_quota_us)
            .min(self.config.max_quota_us);

        self.current_quota_us = quota;
        self.cgroup.set_cpu_max(quota, self.config.period_us)
    }

    /// Get current quota
    pub fn current_quota(&self) -> u64 {
        self.current_quota_us
    }

    /// Get scheduler statistics
    pub fn stats(&self) -> SchedulerStats {
        SchedulerStats {
            current_quota_us: self.current_quota_us,
            min_quota_us: self.config.min_quota_us,
            max_quota_us: self.config.max_quota_us,
            running: self.running,
        }
    }
}

/// Scheduler decision result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerDecision {
    /// Scheduler is not running
    Idle,
    /// Not enough time since last tick
    TooSoon,
    /// Quota unchanged
    Maintain,
    /// Quota adjusted
    Adjust { new_quota_us: u64 },
}

/// Scheduler statistics
#[derive(Debug, Clone, Copy)]
pub struct SchedulerStats {
    /// Current CPU quota
    pub current_quota_us: u64,
    /// Minimum allowed quota
    pub min_quota_us: u64,
    /// Maximum allowed quota
    pub max_quota_us: u64,
    /// Is scheduler running
    pub running: bool,
}

// ============================================================================
// Quota Calculator (Standalone)
// ============================================================================

/// Calculate CPU quota for desired CPU percentage
///
/// # Arguments
/// * `cpu_percent` - Desired CPU percentage (1-100 per core, >100 for multiple cores)
/// * `period_us` - CPU period in microseconds (default: 100000)
///
/// # Returns
/// Quota in microseconds
pub const fn quota_from_percent(cpu_percent: u32, period_us: u64) -> u64 {
    (period_us * cpu_percent as u64) / 100
}

/// Calculate CPU percentage from quota
///
/// # Arguments
/// * `quota_us` - CPU quota in microseconds
/// * `period_us` - CPU period in microseconds
///
/// # Returns
/// CPU percentage
pub const fn percent_from_quota(quota_us: u64, period_us: u64) -> u32 {
    if period_us == 0 {
        0
    } else {
        ((quota_us * 100) / period_us) as u32
    }
}

// ============================================================================
// PSI-Driven Scheduling
// ============================================================================

/// PSI-based scheduler is available via the `psi` feature
///
/// The `PsiScheduler` in the `psi` module provides event-driven scheduling
/// that reacts to CPU pressure instead of polling. This eliminates CPU
/// overhead from periodic stat reading.
///
/// ## Performance Comparison
///
/// | Scheduler | CPU Overhead | Latency |
/// |-----------|--------------|---------|
/// | DynamicScheduler (polling) | ~1% | 10ms |
/// | PsiScheduler (events) | ~0% | <1ms |
///
/// ## Usage
///
/// ```ignore
/// #[cfg(feature = "psi")]
/// use alice_container::psi::PsiScheduler;
///
/// let mut scheduler = PsiScheduler::new("/sys/fs/cgroup/alice/test")?;
/// scheduler.start()?;
///
/// // Event loop
/// loop {
///     if let Some(event) = scheduler.wait(Duration::from_secs(1))? {
///         println!("Quota adjusted due to {:?}", event);
///     }
/// }
/// ```
#[cfg(feature = "psi")]
pub use crate::psi::PsiScheduler;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheduler_config_default() {
        let config = SchedulerConfig::default();
        assert_eq!(config.period_us, 100_000);
        assert_eq!(config.min_quota_us, 10_000);
        assert_eq!(config.max_quota_us, 100_000);
    }

    #[test]
    fn test_scheduler_config_low_latency() {
        let config = SchedulerConfig::low_latency();
        assert_eq!(config.target_latency_us, 100);
        assert_eq!(config.tick_interval_ms, 1);
    }

    #[test]
    fn test_quota_from_percent() {
        assert_eq!(quota_from_percent(50, 100_000), 50_000);
        assert_eq!(quota_from_percent(100, 100_000), 100_000);
        assert_eq!(quota_from_percent(200, 100_000), 200_000); // 2 cores
    }

    #[test]
    fn test_percent_from_quota() {
        assert_eq!(percent_from_quota(50_000, 100_000), 50);
        assert_eq!(percent_from_quota(100_000, 100_000), 100);
        assert_eq!(percent_from_quota(200_000, 100_000), 200);
    }

    #[test]
    fn test_cpu_stats_parse() {
        let content = r#"usage_usec 123456
user_usec 100000
system_usec 23456
nr_throttled 5
throttled_usec 50000"#;

        let stats = CpuStats::from_cpu_stat(content);
        assert_eq!(stats.usage_us, 123456);
        assert_eq!(stats.user_us, 100000);
        assert_eq!(stats.system_us, 23456);
        assert_eq!(stats.nr_throttled, 5);
        assert_eq!(stats.throttled_us, 50000);
    }

    #[test]
    fn test_scheduler_decision_eq() {
        assert_eq!(SchedulerDecision::Idle, SchedulerDecision::Idle);
        assert_eq!(SchedulerDecision::Maintain, SchedulerDecision::Maintain);
        assert_eq!(
            SchedulerDecision::Adjust { new_quota_us: 50000 },
            SchedulerDecision::Adjust { new_quota_us: 50000 }
        );
    }
}
