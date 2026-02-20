//! Container Lifecycle Management
//!
//! Provides the main `Container` abstraction that combines cgroups, namespaces,
//! and filesystem isolation into a complete container runtime.
//!
//! ## Lifecycle
//!
//! ```text
//! create() → start() → exec() → stop() → destroy()
//!               ↓          ↑
//!            pause() → resume()
//! ```
//!
//! ## States
//!
//! | State | Description |
//! |-------|-------------|
//! | Created | Container configured but not running |
//! | Running | Init process active |
//! | Paused | All processes frozen |
//! | Stopped | All processes terminated |

use core::fmt;

#[cfg(feature = "std")]
use std::path::{Path, PathBuf};

use crate::cgroup::{CgroupController, CgroupError, CpuConfig, MemoryConfig, IoConfig};
use crate::namespace::{NamespaceFlags, NamespaceError};

// ============================================================================
// Container State
// ============================================================================

/// Container state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerState {
    /// Container created but not started
    Created,
    /// Container is running
    Running,
    /// Container is paused (frozen)
    Paused,
    /// Container is stopped
    Stopped,
}

impl fmt::Display for ContainerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContainerState::Created => write!(f, "created"),
            ContainerState::Running => write!(f, "running"),
            ContainerState::Paused => write!(f, "paused"),
            ContainerState::Stopped => write!(f, "stopped"),
        }
    }
}

// ============================================================================
// Container Configuration
// ============================================================================

/// Container resource and isolation configuration
#[derive(Debug, Clone)]
pub struct ContainerConfig {
    /// Root filesystem path
    pub rootfs: PathBuf,
    /// Hostname
    pub hostname: String,
    /// Working directory inside container
    pub workdir: PathBuf,
    /// Environment variables
    pub env: Vec<(String, String)>,
    /// Namespace flags
    pub namespaces: NamespaceFlags,
    /// CPU configuration
    pub cpu: CpuConfig,
    /// Memory configuration
    pub memory: MemoryConfig,
    /// I/O configuration (optional)
    pub io: Option<IoConfig>,
    /// Read-only root filesystem
    pub readonly_rootfs: bool,
    /// Enable networking
    pub network: bool,
}

impl Default for ContainerConfig {
    fn default() -> Self {
        Self {
            rootfs: PathBuf::from("/"),
            hostname: "container".to_string(),
            workdir: PathBuf::from("/"),
            env: vec![
                ("PATH".to_string(), "/usr/local/bin:/usr/bin:/bin".to_string()),
                ("HOME".to_string(), "/root".to_string()),
            ],
            namespaces: NamespaceFlags::CONTAINER,
            cpu: CpuConfig::default(),
            memory: MemoryConfig::default(),
            io: None,
            readonly_rootfs: false,
            network: false,
        }
    }
}

impl ContainerConfig {
    /// Create a new configuration builder
    pub fn builder() -> ContainerConfigBuilder {
        ContainerConfigBuilder::new()
    }
}

/// Builder for ContainerConfig
#[derive(Debug, Clone)]
pub struct ContainerConfigBuilder {
    config: ContainerConfig,
}

impl ContainerConfigBuilder {
    /// Create a new builder with defaults
    pub fn new() -> Self {
        Self {
            config: ContainerConfig::default(),
        }
    }

    /// Set root filesystem path
    pub fn rootfs(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.rootfs = path.into();
        self
    }

    /// Set hostname
    pub fn hostname(mut self, name: impl Into<String>) -> Self {
        self.config.hostname = name.into();
        self
    }

    /// Set working directory
    pub fn workdir(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.workdir = path.into();
        self
    }

    /// Add environment variable
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.config.env.push((key.into(), value.into()));
        self
    }

    /// Set CPU quota in microseconds
    pub fn cpu_quota_us(mut self, quota: u64) -> Self {
        self.config.cpu.quota_us = quota;
        self
    }

    /// Set CPU percentage (convenience method)
    pub fn cpu_percent(mut self, percent: u32) -> Self {
        self.config.cpu = CpuConfig::from_percent(percent);
        self
    }

    /// Set memory limit in bytes
    pub fn memory_max(mut self, bytes: u64) -> Self {
        self.config.memory = MemoryConfig::with_limit(bytes);
        self
    }

    /// Enable network namespace
    pub fn with_network(mut self) -> Self {
        self.config.network = true;
        self.config.namespaces = self.config.namespaces.union(NamespaceFlags::NEWNET);
        self
    }

    /// Set read-only root filesystem
    pub fn readonly(mut self) -> Self {
        self.config.readonly_rootfs = true;
        self
    }

    /// Build the configuration
    pub fn build(self) -> ContainerConfig {
        self.config
    }
}

impl Default for ContainerConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Container Error
// ============================================================================

/// Container operation errors
#[derive(Debug)]
pub enum ContainerError {
    /// Cgroup error
    Cgroup(CgroupError),
    /// Namespace error
    Namespace(NamespaceError),
    /// Invalid state transition
    InvalidState {
        current: ContainerState,
        operation: &'static str,
    },
    /// Process error
    ProcessError(String),
    /// Configuration error
    ConfigError(String),
    /// I/O error
    IoError(String),
    /// Container not found
    NotFound(String),
}

impl fmt::Display for ContainerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContainerError::Cgroup(e) => write!(f, "Cgroup error: {}", e),
            ContainerError::Namespace(e) => write!(f, "Namespace error: {}", e),
            ContainerError::InvalidState { current, operation } => {
                write!(f, "Cannot {} container in {} state", operation, current)
            }
            ContainerError::ProcessError(msg) => write!(f, "Process error: {}", msg),
            ContainerError::ConfigError(msg) => write!(f, "Config error: {}", msg),
            ContainerError::IoError(msg) => write!(f, "I/O error: {}", msg),
            ContainerError::NotFound(id) => write!(f, "Container not found: {}", id),
        }
    }
}

impl From<CgroupError> for ContainerError {
    fn from(e: CgroupError) -> Self {
        ContainerError::Cgroup(e)
    }
}

impl From<NamespaceError> for ContainerError {
    fn from(e: NamespaceError) -> Self {
        ContainerError::Namespace(e)
    }
}

// ============================================================================
// Container
// ============================================================================

/// A container instance
#[cfg(feature = "std")]
pub struct Container {
    /// Unique container ID
    id: String,
    /// Container configuration
    config: ContainerConfig,
    /// Cgroup controller
    cgroup: CgroupController,
    /// Current state
    state: ContainerState,
    /// Init process PID (if running)
    init_pid: Option<u32>,
}

#[cfg(feature = "std")]
impl Container {
    /// Create a new container
    ///
    /// # Arguments
    /// * `id` - Unique container identifier
    /// * `config` - Container configuration
    pub fn create(id: &str, config: ContainerConfig) -> Result<Self, ContainerError> {
        // Validate configuration
        if !config.rootfs.exists() {
            return Err(ContainerError::ConfigError(format!(
                "Root filesystem does not exist: {}",
                config.rootfs.display()
            )));
        }

        // Create cgroup
        let cgroup = CgroupController::create(id)?;

        // Apply resource limits
        cgroup.set_cpu(&config.cpu)?;
        cgroup.set_memory(&config.memory)?;

        if let Some(ref io) = config.io {
            cgroup.set_io(io)?;
        }

        Ok(Self {
            id: id.to_string(),
            config,
            cgroup,
            state: ContainerState::Created,
            init_pid: None,
        })
    }

    /// Start the container
    pub fn start(&mut self) -> Result<(), ContainerError> {
        if self.state != ContainerState::Created && self.state != ContainerState::Stopped {
            return Err(ContainerError::InvalidState {
                current: self.state,
                operation: "start",
            });
        }

        // Try clone3 with CLONE_INTO_CGROUP first (zero-copy cgroup placement)
        #[cfg(all(feature = "clone3", target_os = "linux"))]
        {
            if let Ok(pid) = self.spawn_init_clone3() {
                self.init_pid = Some(pid);
                self.state = ContainerState::Running;
                // No add_process needed - clone3 already placed process in cgroup
                return Ok(());
            }
            // Fall through to legacy method if clone3 fails
        }

        // Legacy fork + add_process method
        let pid = self.spawn_init()?;

        self.init_pid = Some(pid);
        self.state = ContainerState::Running;

        // Add init process to cgroup (separate syscall)
        self.cgroup.add_process(pid)?;

        Ok(())
    }

    /// Spawn init using clone3 with CLONE_INTO_CGROUP (Linux 5.7+)
    ///
    /// This eliminates the separate cgroup.procs write by placing the
    /// new process directly into the cgroup during clone.
    #[cfg(all(feature = "clone3", target_os = "linux"))]
    fn spawn_init_clone3(&self) -> Result<u32, ContainerError> {
        use crate::clone3::{Clone3Args, clone3_raw, open_cgroup_fd, close_cgroup_fd, clone_flags};

        // Open cgroup directory fd
        let cgroup_fd = open_cgroup_fd(self.cgroup.path())
            .map_err(|e| ContainerError::ProcessError(format!("open cgroup fd: {}", e)))?;

        // Build clone3 args with CLONE_INTO_CGROUP
        let namespace_flags = self.config.namespaces.bits() as u64;
        let args = Clone3Args::new()
            .flags(namespace_flags)
            .cgroup_fd(cgroup_fd);

        // Perform clone3
        let result = unsafe { clone3_raw(&args) };

        // Close cgroup fd in parent
        close_cgroup_fd(cgroup_fd);

        match result {
            Ok(0) => {
                // Child process
                // SAFETY: pause(2) is always safe to call; it blocks until a signal is received
                // and has no preconditions on process state.
                unsafe {
                    libc::pause();
                }
                std::process::exit(0);
            }
            Ok(pid) => Ok(pid),
            Err(e) => Err(ContainerError::ProcessError(format!("clone3: {}", e))),
        }
    }

    /// Spawn the init process in new namespaces
    #[cfg(target_os = "linux")]
    fn spawn_init(&self) -> Result<u32, ContainerError> {
        // For now, use a simple fork approach
        // In production, would use clone() with namespace flags

        // SAFETY: No threads are running that would be silently killed by fork at this point
        // (single-threaded init path); all file descriptors are valid. The child calls only
        // async-signal-safe functions (pause, _exit) before exec.
        let pid = unsafe { libc::fork() };

        match pid {
            -1 => Err(ContainerError::ProcessError("fork failed".into())),
            0 => {
                // Child process - this would set up namespaces
                // For testing, just sleep
                // SAFETY: pause(2) is always safe to call; it blocks until a signal is received.
                unsafe {
                    libc::pause();
                }
                std::process::exit(0);
            }
            child_pid => Ok(child_pid as u32),
        }
    }

    /// Spawn init process (non-Linux stub)
    #[cfg(not(target_os = "linux"))]
    fn spawn_init(&self) -> Result<u32, ContainerError> {
        Err(ContainerError::ProcessError("Container runtime requires Linux".into()))
    }

    /// Execute a command in the container
    ///
    /// # Arguments
    /// * `cmd` - Command and arguments
    ///
    /// # Returns
    /// Exit code of the command
    pub fn exec(&mut self, cmd: &[&str]) -> Result<i32, ContainerError> {
        if self.state != ContainerState::Running {
            return Err(ContainerError::InvalidState {
                current: self.state,
                operation: "exec",
            });
        }

        if cmd.is_empty() {
            return Err(ContainerError::ConfigError("Empty command".into()));
        }

        use std::process::Command;

        // Execute command in container's namespace
        // In production, would use nsenter or setns
        let output = Command::new(cmd[0])
            .args(&cmd[1..])
            .current_dir(&self.config.workdir)
            .envs(self.config.env.iter().cloned())
            .output()
            .map_err(|e| ContainerError::ProcessError(e.to_string()))?;

        Ok(output.status.code().unwrap_or(-1))
    }

    /// Pause the container (freeze all processes)
    pub fn pause(&mut self) -> Result<(), ContainerError> {
        if self.state != ContainerState::Running {
            return Err(ContainerError::InvalidState {
                current: self.state,
                operation: "pause",
            });
        }

        self.cgroup.freeze()?;
        self.state = ContainerState::Paused;

        Ok(())
    }

    /// Resume a paused container
    pub fn resume(&mut self) -> Result<(), ContainerError> {
        if self.state != ContainerState::Paused {
            return Err(ContainerError::InvalidState {
                current: self.state,
                operation: "resume",
            });
        }

        self.cgroup.unfreeze()?;
        self.state = ContainerState::Running;

        Ok(())
    }

    /// Stop the container
    #[cfg(target_os = "linux")]
    pub fn stop(&mut self) -> Result<(), ContainerError> {
        if self.state != ContainerState::Running && self.state != ContainerState::Paused {
            return Err(ContainerError::InvalidState {
                current: self.state,
                operation: "stop",
            });
        }

        // Kill all processes
        self.cgroup.kill_all()?;

        // Wait for init to exit
        if let Some(pid) = self.init_pid {
            // SAFETY: pid is a valid child process ID obtained from fork/clone3; status is a
            // local stack variable passed by mutable pointer as required by waitpid(2).
            unsafe {
                let mut status: libc::c_int = 0;
                libc::waitpid(pid as i32, &mut status, 0);
            }
        }

        self.init_pid = None;
        self.state = ContainerState::Stopped;

        Ok(())
    }

    /// Stop the container (non-Linux stub)
    #[cfg(not(target_os = "linux"))]
    pub fn stop(&mut self) -> Result<(), ContainerError> {
        Err(ContainerError::ProcessError("Container runtime requires Linux".into()))
    }

    /// Destroy the container
    ///
    /// Stops the container if running and removes all resources.
    pub fn destroy(mut self) -> Result<(), ContainerError> {
        // Stop if running
        if self.state == ContainerState::Running || self.state == ContainerState::Paused {
            self.stop()?;
        }

        // Remove cgroup
        self.cgroup.destroy()?;

        Ok(())
    }

    // Getters

    /// Get container ID
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get current state
    pub fn state(&self) -> ContainerState {
        self.state
    }

    /// Get init process PID
    pub fn pid(&self) -> Option<u32> {
        self.init_pid
    }

    /// Get configuration
    pub fn config(&self) -> &ContainerConfig {
        &self.config
    }

    /// Get cgroup path
    pub fn cgroup_path(&self) -> &Path {
        self.cgroup.path()
    }

    /// Get current memory usage
    pub fn memory_usage(&self) -> Result<u64, ContainerError> {
        Ok(self.cgroup.memory_current()?)
    }

    /// Get current CPU usage
    pub fn cpu_usage(&self) -> Result<u64, ContainerError> {
        Ok(self.cgroup.cpu_usage_us()?)
    }

    /// Update CPU limits
    pub fn update_cpu(&mut self, config: &CpuConfig) -> Result<(), ContainerError> {
        self.cgroup.set_cpu(config)?;
        self.config.cpu = *config;
        Ok(())
    }

    /// Update memory limits
    pub fn update_memory(&mut self, config: &MemoryConfig) -> Result<(), ContainerError> {
        self.cgroup.set_memory(config)?;
        self.config.memory = *config;
        Ok(())
    }
}

#[cfg(feature = "std")]
impl fmt::Debug for Container {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Container")
            .field("id", &self.id)
            .field("state", &self.state)
            .field("init_pid", &self.init_pid)
            .finish()
    }
}

// ============================================================================
// Container Info (for listing)
// ============================================================================

/// Container information for listing
#[derive(Debug, Clone)]
pub struct ContainerInfo {
    /// Container ID
    pub id: String,
    /// Current state
    pub state: ContainerState,
    /// Init PID
    pub pid: Option<u32>,
    /// Memory usage in bytes
    pub memory_usage: u64,
    /// CPU usage in microseconds
    pub cpu_usage: u64,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_container_state_display() {
        assert_eq!(ContainerState::Created.to_string(), "created");
        assert_eq!(ContainerState::Running.to_string(), "running");
        assert_eq!(ContainerState::Paused.to_string(), "paused");
        assert_eq!(ContainerState::Stopped.to_string(), "stopped");
    }

    #[test]
    fn test_container_config_builder() {
        let config = ContainerConfig::builder()
            .hostname("test-container")
            .cpu_percent(50)
            .memory_max(256 * 1024 * 1024)
            .env("FOO", "bar")
            .build();

        assert_eq!(config.hostname, "test-container");
        assert_eq!(config.cpu.quota_us, 50_000);
        assert_eq!(config.memory.max, 256 * 1024 * 1024);
    }

    #[test]
    fn test_container_config_with_network() {
        let config = ContainerConfig::builder()
            .with_network()
            .build();

        assert!(config.network);
        assert!(config.namespaces.contains(NamespaceFlags::NEWNET));
    }

    #[test]
    fn test_container_error_display() {
        let err = ContainerError::InvalidState {
            current: ContainerState::Stopped,
            operation: "exec",
        };
        assert!(err.to_string().contains("stopped"));
        assert!(err.to_string().contains("exec"));
    }
}
