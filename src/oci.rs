//! OCI Runtime Specification 構造体
//!
//! Open Container Initiative Runtime Spec v1.0 に準拠した
//! コンテナ設定の構造体群。既存の `ContainerConfig` との相互変換を提供。

use crate::container::ContainerConfig;
use crate::namespace::NamespaceFlags;

// ============================================================================
// OCI Spec 構造体
// ============================================================================

/// OCI Runtime Specification のトップレベル構造体。
#[derive(Debug, Clone)]
pub struct OciSpec {
    /// OCI バージョン (例: "1.0.2")。
    pub oci_version: String,
    /// プロセス定義。
    pub process: OciProcess,
    /// ルートファイルシステム。
    pub root: OciRoot,
    /// ホスト名。
    pub hostname: String,
    /// マウントポイント。
    pub mounts: Vec<OciMount>,
    /// Linux 固有設定。
    pub linux: OciLinux,
}

impl Default for OciSpec {
    fn default() -> Self {
        Self {
            oci_version: "1.0.2".to_string(),
            process: OciProcess::default(),
            root: OciRoot::default(),
            hostname: "container".to_string(),
            mounts: default_mounts(),
            linux: OciLinux::default(),
        }
    }
}

/// OCI プロセス定義。
#[derive(Debug, Clone)]
pub struct OciProcess {
    /// 実行コマンドと引数。
    pub args: Vec<String>,
    /// 環境変数 (KEY=VALUE 形式)。
    pub env: Vec<String>,
    /// 作業ディレクトリ。
    pub cwd: String,
    /// ユーザー設定。
    pub user: OciUser,
    /// ターミナル割り当て。
    pub terminal: bool,
}

impl Default for OciProcess {
    fn default() -> Self {
        Self {
            args: vec!["/bin/sh".to_string()],
            env: vec![
                "PATH=/usr/local/bin:/usr/bin:/bin".to_string(),
                "HOME=/root".to_string(),
            ],
            cwd: "/".to_string(),
            user: OciUser::default(),
            terminal: false,
        }
    }
}

/// OCI ユーザー設定。
#[derive(Debug, Clone, Default)]
pub struct OciUser {
    /// UID。
    pub uid: u32,
    /// GID。
    pub gid: u32,
    /// 追加 GID。
    pub additional_gids: Vec<u32>,
}

/// OCI ルートファイルシステム。
#[derive(Debug, Clone)]
pub struct OciRoot {
    /// ルートパス。
    pub path: String,
    /// 読み取り専用か。
    pub readonly: bool,
}

impl Default for OciRoot {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            readonly: false,
        }
    }
}

/// OCI マウントポイント。
#[derive(Debug, Clone)]
pub struct OciMount {
    /// マウント先。
    pub destination: String,
    /// ファイルシステムタイプ。
    pub fs_type: String,
    /// マウント元。
    pub source: String,
    /// マウントオプション。
    pub options: Vec<String>,
}

/// デフォルトのマウントポイント (proc, sysfs, devtmpfs)。
#[must_use]
pub fn default_mounts() -> Vec<OciMount> {
    vec![
        OciMount {
            destination: "/proc".to_string(),
            fs_type: "proc".to_string(),
            source: "proc".to_string(),
            options: vec![
                "nosuid".to_string(),
                "noexec".to_string(),
                "nodev".to_string(),
            ],
        },
        OciMount {
            destination: "/sys".to_string(),
            fs_type: "sysfs".to_string(),
            source: "sysfs".to_string(),
            options: vec![
                "nosuid".to_string(),
                "noexec".to_string(),
                "nodev".to_string(),
                "ro".to_string(),
            ],
        },
        OciMount {
            destination: "/dev".to_string(),
            fs_type: "tmpfs".to_string(),
            source: "tmpfs".to_string(),
            options: vec![
                "nosuid".to_string(),
                "strictatime".to_string(),
                "mode=755".to_string(),
            ],
        },
    ]
}

// ============================================================================
// Linux 固有設定
// ============================================================================

/// OCI Linux 固有設定。
#[derive(Debug, Clone)]
pub struct OciLinux {
    /// 名前空間リスト。
    pub namespaces: Vec<OciNamespace>,
    /// リソース制限。
    pub resources: OciLinuxResources,
    /// Seccomp プロファイル名 (参照のみ)。
    pub seccomp_profile: Option<String>,
    /// `AppArmor` プロファイル名。
    pub apparmor_profile: Option<String>,
    /// 読み取り専用パス。
    pub readonly_paths: Vec<String>,
    /// マスクパス。
    pub masked_paths: Vec<String>,
}

impl Default for OciLinux {
    fn default() -> Self {
        Self {
            namespaces: default_namespaces(),
            resources: OciLinuxResources::default(),
            seccomp_profile: None,
            apparmor_profile: None,
            readonly_paths: vec![
                "/proc/bus".to_string(),
                "/proc/fs".to_string(),
                "/proc/irq".to_string(),
                "/proc/sys".to_string(),
                "/proc/sysrq-trigger".to_string(),
            ],
            masked_paths: vec![
                "/proc/kcore".to_string(),
                "/proc/keys".to_string(),
                "/proc/timer_list".to_string(),
            ],
        }
    }
}

/// OCI 名前空間の種類。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OciNamespaceType {
    /// PID 名前空間。
    Pid,
    /// ネットワーク名前空間。
    Network,
    /// マウント名前空間。
    Mount,
    /// IPC 名前空間。
    Ipc,
    /// UTS 名前空間。
    Uts,
    /// ユーザー名前空間。
    User,
    /// Cgroup 名前空間。
    Cgroup,
}

impl OciNamespaceType {
    /// OCI spec の文字列表記。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pid => "pid",
            Self::Network => "network",
            Self::Mount => "mount",
            Self::Ipc => "ipc",
            Self::Uts => "uts",
            Self::User => "user",
            Self::Cgroup => "cgroup",
        }
    }

    /// `NamespaceFlags` の対応ビットに変換。
    #[must_use]
    pub const fn to_namespace_flag(&self) -> NamespaceFlags {
        match self {
            Self::Pid => NamespaceFlags::NEWPID,
            Self::Network => NamespaceFlags::NEWNET,
            Self::Mount => NamespaceFlags::NEWNS,
            Self::Ipc => NamespaceFlags::NEWIPC,
            Self::Uts => NamespaceFlags::NEWUTS,
            Self::User => NamespaceFlags::NEWUSER,
            Self::Cgroup => NamespaceFlags::NEWCGROUP,
        }
    }
}

/// OCI 名前空間定義。
#[derive(Debug, Clone)]
pub struct OciNamespace {
    /// 名前空間の種類。
    pub ns_type: OciNamespaceType,
    /// 既存名前空間のパス (None で新規作成)。
    pub path: Option<String>,
}

/// デフォルトの名前空間リスト (PID, Mount, IPC, UTS)。
#[must_use]
fn default_namespaces() -> Vec<OciNamespace> {
    vec![
        OciNamespace {
            ns_type: OciNamespaceType::Pid,
            path: None,
        },
        OciNamespace {
            ns_type: OciNamespaceType::Mount,
            path: None,
        },
        OciNamespace {
            ns_type: OciNamespaceType::Ipc,
            path: None,
        },
        OciNamespace {
            ns_type: OciNamespaceType::Uts,
            path: None,
        },
    ]
}

/// OCI Linux リソース制限。
#[derive(Debug, Clone, Default)]
pub struct OciLinuxResources {
    /// CPU 制限。
    pub cpu: OciCpuResources,
    /// メモリ制限。
    pub memory: OciMemoryResources,
}

/// OCI CPU リソース。
#[derive(Debug, Clone, Default)]
pub struct OciCpuResources {
    /// CPU クォータ (マイクロ秒)。
    pub quota: Option<u64>,
    /// CPU ピリオド (マイクロ秒)。
    pub period: Option<u64>,
    /// CPU シェア。
    pub shares: Option<u64>,
}

/// OCI メモリリソース。
#[derive(Debug, Clone, Default)]
pub struct OciMemoryResources {
    /// メモリ制限 (バイト)。
    pub limit: Option<u64>,
    /// スワップ制限 (バイト)。
    pub swap: Option<u64>,
}

// ============================================================================
// ContainerConfig ↔ OCI Spec 変換
// ============================================================================

/// 既存の `ContainerConfig` から `OciSpec` に変換。
#[must_use]
pub fn from_container_config(config: &ContainerConfig) -> OciSpec {
    let env: Vec<String> = config.env.iter().map(|(k, v)| format!("{k}={v}")).collect();

    let mut namespaces = Vec::new();
    if config.namespaces.contains(NamespaceFlags::NEWPID) {
        namespaces.push(OciNamespace {
            ns_type: OciNamespaceType::Pid,
            path: None,
        });
    }
    if config.namespaces.contains(NamespaceFlags::NEWNS) {
        namespaces.push(OciNamespace {
            ns_type: OciNamespaceType::Mount,
            path: None,
        });
    }
    if config.namespaces.contains(NamespaceFlags::NEWIPC) {
        namespaces.push(OciNamespace {
            ns_type: OciNamespaceType::Ipc,
            path: None,
        });
    }
    if config.namespaces.contains(NamespaceFlags::NEWUTS) {
        namespaces.push(OciNamespace {
            ns_type: OciNamespaceType::Uts,
            path: None,
        });
    }
    if config.namespaces.contains(NamespaceFlags::NEWNET) {
        namespaces.push(OciNamespace {
            ns_type: OciNamespaceType::Network,
            path: None,
        });
    }
    if config.namespaces.contains(NamespaceFlags::NEWUSER) {
        namespaces.push(OciNamespace {
            ns_type: OciNamespaceType::User,
            path: None,
        });
    }

    let cpu = OciCpuResources {
        quota: Some(config.cpu.quota_us),
        period: Some(config.cpu.period_us),
        shares: None,
    };

    let memory = OciMemoryResources {
        limit: Some(config.memory.max),
        swap: None,
    };

    OciSpec {
        oci_version: "1.0.2".to_string(),
        process: OciProcess {
            args: vec!["/bin/sh".to_string()],
            env,
            cwd: config.workdir.to_string_lossy().to_string(),
            user: OciUser::default(),
            terminal: false,
        },
        root: OciRoot {
            path: config.rootfs.to_string_lossy().to_string(),
            readonly: config.readonly_rootfs,
        },
        hostname: config.hostname.clone(),
        mounts: default_mounts(),
        linux: OciLinux {
            namespaces,
            resources: OciLinuxResources { cpu, memory },
            ..OciLinux::default()
        },
    }
}

/// `OciSpec` から `ContainerConfig` に変換。
#[must_use]
pub fn to_container_config(spec: &OciSpec) -> ContainerConfig {
    use crate::cgroup::{CpuConfig, MemoryConfig};
    use std::path::PathBuf;

    let env: Vec<(String, String)> = spec
        .process
        .env
        .iter()
        .filter_map(|e| {
            let mut parts = e.splitn(2, '=');
            let key = parts.next()?.to_string();
            let value = parts.next().unwrap_or("").to_string();
            Some((key, value))
        })
        .collect();

    let mut flags = NamespaceFlags::from_bits(0);
    for ns in &spec.linux.namespaces {
        flags = flags.union(ns.ns_type.to_namespace_flag());
    }

    let network = spec
        .linux
        .namespaces
        .iter()
        .any(|ns| ns.ns_type == OciNamespaceType::Network);

    let cpu_quota = spec.linux.resources.cpu.quota.unwrap_or(100_000);
    let cpu_period = spec.linux.resources.cpu.period.unwrap_or(100_000);

    let memory_max = spec.linux.resources.memory.limit.unwrap_or(1_073_741_824);

    ContainerConfig {
        rootfs: PathBuf::from(&spec.root.path),
        hostname: spec.hostname.clone(),
        workdir: PathBuf::from(&spec.process.cwd),
        env,
        namespaces: flags,
        cpu: CpuConfig {
            quota_us: cpu_quota,
            period_us: cpu_period,
            ..CpuConfig::default()
        },
        memory: MemoryConfig::with_limit(memory_max),
        io: None,
        readonly_rootfs: spec.root.readonly,
        network,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_spec() {
        let spec = OciSpec::default();
        assert_eq!(spec.oci_version, "1.0.2");
        assert_eq!(spec.hostname, "container");
        assert!(!spec.root.readonly);
    }

    #[test]
    fn default_process() {
        let proc = OciProcess::default();
        assert_eq!(proc.args, vec!["/bin/sh"]);
        assert_eq!(proc.cwd, "/");
        assert!(!proc.terminal);
    }

    #[test]
    fn default_user() {
        let user = OciUser::default();
        assert_eq!(user.uid, 0);
        assert_eq!(user.gid, 0);
        assert!(user.additional_gids.is_empty());
    }

    #[test]
    fn default_mounts_has_proc() {
        let mounts = default_mounts();
        assert!(mounts.iter().any(|m| m.destination == "/proc"));
        assert!(mounts.iter().any(|m| m.destination == "/sys"));
        assert!(mounts.iter().any(|m| m.destination == "/dev"));
    }

    #[test]
    fn namespace_type_as_str() {
        assert_eq!(OciNamespaceType::Pid.as_str(), "pid");
        assert_eq!(OciNamespaceType::Network.as_str(), "network");
        assert_eq!(OciNamespaceType::Mount.as_str(), "mount");
        assert_eq!(OciNamespaceType::Ipc.as_str(), "ipc");
        assert_eq!(OciNamespaceType::Uts.as_str(), "uts");
        assert_eq!(OciNamespaceType::User.as_str(), "user");
        assert_eq!(OciNamespaceType::Cgroup.as_str(), "cgroup");
    }

    #[test]
    fn namespace_type_to_flag() {
        let flag = OciNamespaceType::Pid.to_namespace_flag();
        assert_eq!(flag, NamespaceFlags::NEWPID);

        let flag = OciNamespaceType::Network.to_namespace_flag();
        assert_eq!(flag, NamespaceFlags::NEWNET);
    }

    #[test]
    fn default_linux_has_masked_paths() {
        let linux = OciLinux::default();
        assert!(!linux.masked_paths.is_empty());
        assert!(linux.masked_paths.iter().any(|p| p.contains("kcore")));
    }

    #[test]
    fn default_linux_has_readonly_paths() {
        let linux = OciLinux::default();
        assert!(!linux.readonly_paths.is_empty());
        assert!(linux.readonly_paths.iter().any(|p| p.contains("/proc/sys")));
    }

    #[test]
    fn from_container_config_roundtrip() {
        let config = ContainerConfig::default();
        let spec = from_container_config(&config);
        let config2 = to_container_config(&spec);

        assert_eq!(config.hostname, config2.hostname);
        assert_eq!(config.readonly_rootfs, config2.readonly_rootfs);
        assert_eq!(config.network, config2.network);
    }

    #[test]
    fn from_container_config_env() {
        let config = ContainerConfig::builder().env("FOO", "bar").build();
        let spec = from_container_config(&config);
        assert!(spec.process.env.iter().any(|e| e == "FOO=bar"));
    }

    #[test]
    fn from_container_config_with_network() {
        let config = ContainerConfig::builder().with_network().build();
        let spec = from_container_config(&config);
        assert!(spec
            .linux
            .namespaces
            .iter()
            .any(|ns| ns.ns_type == OciNamespaceType::Network));
    }

    #[test]
    fn to_container_config_env_parsing() {
        let mut spec = OciSpec::default();
        spec.process.env = vec!["KEY=value".to_string(), "EMPTY=".to_string()];
        let config = to_container_config(&spec);
        assert!(config.env.iter().any(|(k, v)| k == "KEY" && v == "value"));
        assert!(config.env.iter().any(|(k, v)| k == "EMPTY" && v.is_empty()));
    }

    #[test]
    fn oci_cpu_resources_default() {
        let cpu = OciCpuResources::default();
        assert!(cpu.quota.is_none());
        assert!(cpu.period.is_none());
        assert!(cpu.shares.is_none());
    }

    #[test]
    fn oci_memory_resources_default() {
        let mem = OciMemoryResources::default();
        assert!(mem.limit.is_none());
        assert!(mem.swap.is_none());
    }
}
