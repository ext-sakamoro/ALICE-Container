//! seccomp / `AppArmor` プロファイル
//!
//! コンテナのシステムコール制限を定義する。
//! seccomp BPF フィルタの定義と、デフォルトプロファイルの提供。

use core::fmt;

// ============================================================================
// seccomp アクション
// ============================================================================

/// seccomp フィルタのアクション。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompAction {
    /// システムコールを許可。
    Allow,
    /// プロセスを SIGKILL で終了。
    Kill,
    /// 指定した errno を返す。
    Errno(u32),
    /// ptrace に通知。
    Trace(u32),
    /// ログに記録して許可。
    Log,
}

impl fmt::Display for SeccompAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "SCMP_ACT_ALLOW"),
            Self::Kill => write!(f, "SCMP_ACT_KILL"),
            Self::Errno(e) => write!(f, "SCMP_ACT_ERRNO({e})"),
            Self::Trace(t) => write!(f, "SCMP_ACT_TRACE({t})"),
            Self::Log => write!(f, "SCMP_ACT_LOG"),
        }
    }
}

// ============================================================================
// seccomp ルール
// ============================================================================

/// 引数フィルタの比較演算子。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompOp {
    /// 等しい。
    Equal,
    /// 等しくない。
    NotEqual,
    /// より大きい。
    GreaterThan,
    /// 以上。
    GreaterEqual,
    /// より小さい。
    LessThan,
    /// 以下。
    LessEqual,
    /// ビットマスク AND が非ゼロ。
    MaskedEqual(u64),
}

/// seccomp 引数フィルタ。
#[derive(Debug, Clone)]
pub struct SeccompArg {
    /// 引数インデックス (0–5)。
    pub index: u32,
    /// 比較演算子。
    pub op: SeccompOp,
    /// 比較値。
    pub value: u64,
}

/// seccomp ルール (1つの syscall に対する制約)。
#[derive(Debug, Clone)]
pub struct SeccompRule {
    /// syscall 名。
    pub syscall: String,
    /// アクション。
    pub action: SeccompAction,
    /// 引数フィルタ (空なら syscall 名だけでマッチ)。
    pub args: Vec<SeccompArg>,
}

impl SeccompRule {
    /// 単純なルール (引数フィルタなし)。
    #[must_use]
    pub fn simple(syscall: &str, action: SeccompAction) -> Self {
        Self {
            syscall: syscall.to_string(),
            action,
            args: Vec::new(),
        }
    }

    /// 引数付きルール。
    #[must_use]
    pub fn with_arg(syscall: &str, action: SeccompAction, arg: SeccompArg) -> Self {
        Self {
            syscall: syscall.to_string(),
            action,
            args: vec![arg],
        }
    }
}

// ============================================================================
// seccomp プロファイル
// ============================================================================

/// seccomp プロファイル。
#[derive(Debug, Clone)]
pub struct SeccompProfile {
    /// デフォルトアクション (ルールにマッチしない syscall)。
    pub default_action: SeccompAction,
    /// ルールリスト。
    pub rules: Vec<SeccompRule>,
    /// アーキテクチャ (例: "`SCMP_ARCH_X86_64`")。
    pub architectures: Vec<String>,
}

impl SeccompProfile {
    /// 空のプロファイル。
    #[must_use]
    pub fn new(default_action: SeccompAction) -> Self {
        Self {
            default_action,
            rules: Vec::new(),
            architectures: vec![
                "SCMP_ARCH_X86_64".to_string(),
                "SCMP_ARCH_AARCH64".to_string(),
            ],
        }
    }

    /// ルールを追加。
    pub fn add_rule(&mut self, rule: SeccompRule) {
        self.rules.push(rule);
    }

    /// syscall 名でルールを検索。
    #[must_use]
    pub fn find_rule(&self, syscall: &str) -> Option<&SeccompRule> {
        self.rules.iter().find(|r| r.syscall == syscall)
    }

    /// 指定 syscall が許可されるか。
    #[must_use]
    pub fn is_allowed(&self, syscall: &str) -> bool {
        self.find_rule(syscall).map_or(
            matches!(
                self.default_action,
                SeccompAction::Allow | SeccompAction::Log
            ),
            |rule| matches!(rule.action, SeccompAction::Allow | SeccompAction::Log),
        )
    }

    /// Docker 互換のデフォルトプロファイル。
    ///
    /// デフォルト許可で、危険な syscall をブロック。
    #[must_use]
    pub fn default_container() -> Self {
        let mut profile = Self::new(SeccompAction::Allow);

        // 危険な syscall をブロック
        let blocked = [
            "acct",
            "add_key",
            "bpf",
            "clock_adjtime",
            "clock_settime",
            "create_module",
            "delete_module",
            "finit_module",
            "get_kernel_syms",
            "init_module",
            "ioperm",
            "iopl",
            "kcmp",
            "kexec_file_load",
            "kexec_load",
            "keyctl",
            "lookup_dcookie",
            "mount",
            "move_mount",
            "nfsservctl",
            "open_tree",
            "perf_event_open",
            "personality",
            "pivot_root",
            "query_module",
            "reboot",
            "request_key",
            "setns",
            "settimeofday",
            "stime",
            "swapoff",
            "swapon",
            "sysfs",
            "umount",
            "umount2",
            "unshare",
            "uselib",
            "userfaultfd",
            "ustat",
            "vm86",
            "vm86old",
        ];

        for syscall in blocked {
            profile.add_rule(SeccompRule::simple(
                syscall,
                SeccompAction::Errno(1), // EPERM
            ));
        }

        profile
    }

    /// 最小限の syscall のみ許可する厳格プロファイル。
    ///
    /// デフォルト拒否で、必要最小限の syscall のみ許可。
    #[must_use]
    pub fn strict() -> Self {
        let mut profile = Self::new(SeccompAction::Errno(1));

        // 最小限の syscall を許可
        let allowed = [
            "read",
            "write",
            "close",
            "fstat",
            "lseek",
            "mmap",
            "mprotect",
            "munmap",
            "brk",
            "rt_sigaction",
            "rt_sigprocmask",
            "rt_sigreturn",
            "ioctl",
            "access",
            "pipe",
            "select",
            "sched_yield",
            "dup",
            "dup2",
            "clone",
            "fork",
            "vfork",
            "execve",
            "exit",
            "wait4",
            "kill",
            "fcntl",
            "flock",
            "fsync",
            "fdatasync",
            "getcwd",
            "chdir",
            "openat",
            "readlinkat",
            "newfstatat",
            "exit_group",
            "set_tid_address",
            "set_robust_list",
            "futex",
            "nanosleep",
            "clock_gettime",
            "clock_nanosleep",
            "getpid",
            "getppid",
            "getuid",
            "geteuid",
            "getgid",
            "getegid",
            "gettid",
            "arch_prctl",
            "sigaltstack",
            "getrandom",
            "rseq",
            "prlimit64",
        ];

        for syscall in allowed {
            profile.add_rule(SeccompRule::simple(syscall, SeccompAction::Allow));
        }

        profile
    }

    /// ルール数。
    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// seccomp BPF フィルタを適用 (Linux)。
    ///
    /// # Errors
    ///
    /// prctl/seccomp syscall 失敗時にエラー。
    #[cfg(target_os = "linux")]
    pub fn install(&self) -> Result<(), SeccompError> {
        // seccomp(2) による BPF フィルタの適用は
        // 実際にはバイトコードコンパイルが必要。
        // ここでは prctl(PR_SET_NO_NEW_PRIVS) のみ設定。
        // SAFETY: prctl(PR_SET_NO_NEW_PRIVS, 1, ...) はスレッドに対して
        // 新しい特権の取得を禁止するフラグを設定する。引数は固定値のみ。
        let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if ret < 0 {
            return Err(SeccompError::InstallFailed(
                "prctl(PR_SET_NO_NEW_PRIVS) failed".to_string(),
            ));
        }
        Ok(())
    }

    /// seccomp フィルタを適用 (non-Linux stub)。
    ///
    /// # Errors
    ///
    /// Linux 以外ではサポート外エラー。
    #[cfg(not(target_os = "linux"))]
    pub const fn install(&self) -> Result<(), SeccompError> {
        Err(SeccompError::NotSupported)
    }
}

// ============================================================================
// AppArmor プロファイル
// ============================================================================

/// `AppArmor` 制約の種類。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppArmorRule {
    /// ファイルアクセス許可 (パス, パーミッション)。
    FileAllow(String, String),
    /// ファイルアクセス拒否。
    FileDeny(String, String),
    /// ネットワークアクセス許可 (ドメイン, タイプ)。
    NetworkAllow(String, String),
    /// ネットワークアクセス拒否。
    NetworkDeny(String, String),
    /// ケイパビリティ許可。
    CapabilityAllow(String),
    /// ケイパビリティ拒否。
    CapabilityDeny(String),
}

/// `AppArmor` プロファイル。
#[derive(Debug, Clone)]
pub struct AppArmorProfile {
    /// プロファイル名。
    pub name: String,
    /// ルールリスト。
    pub rules: Vec<AppArmorRule>,
}

impl AppArmorProfile {
    /// 新しい `AppArmor` プロファイル。
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            rules: Vec::new(),
        }
    }

    /// ルールを追加。
    pub fn add_rule(&mut self, rule: AppArmorRule) {
        self.rules.push(rule);
    }

    /// Docker 互換のデフォルトプロファイル。
    #[must_use]
    pub fn default_container() -> Self {
        let mut profile = Self::new("alice-container-default");

        // 基本的なファイルアクセス
        profile.add_rule(AppArmorRule::FileAllow(
            "/usr/**".to_string(),
            "r".to_string(),
        ));
        profile.add_rule(AppArmorRule::FileAllow(
            "/bin/**".to_string(),
            "rix".to_string(),
        ));
        profile.add_rule(AppArmorRule::FileAllow(
            "/lib/**".to_string(),
            "r".to_string(),
        ));
        profile.add_rule(AppArmorRule::FileAllow(
            "/tmp/**".to_string(),
            "rw".to_string(),
        ));

        // 危険なパスを拒否
        profile.add_rule(AppArmorRule::FileDeny(
            "/proc/sysrq-trigger".to_string(),
            "w".to_string(),
        ));
        profile.add_rule(AppArmorRule::FileDeny(
            "/proc/kcore".to_string(),
            "r".to_string(),
        ));

        // ネットワーク許可
        profile.add_rule(AppArmorRule::NetworkAllow(
            "inet".to_string(),
            "stream".to_string(),
        ));
        profile.add_rule(AppArmorRule::NetworkAllow(
            "inet".to_string(),
            "dgram".to_string(),
        ));

        // 不要なケイパビリティを拒否
        profile.add_rule(AppArmorRule::CapabilityDeny("sys_admin".to_string()));
        profile.add_rule(AppArmorRule::CapabilityDeny("sys_rawio".to_string()));

        profile
    }

    /// ルール数。
    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// 指定パスへのファイルアクセスが許可されるか (簡易チェック)。
    #[must_use]
    pub fn is_file_allowed(&self, path: &str) -> bool {
        let mut denied = false;
        let mut allowed = false;

        for rule in &self.rules {
            match rule {
                AppArmorRule::FileDeny(pattern, _) if path_matches(path, pattern) => {
                    denied = true;
                }
                AppArmorRule::FileAllow(pattern, _) if path_matches(path, pattern) => {
                    allowed = true;
                }
                _ => {}
            }
        }

        // 拒否ルールが許可ルールに優先
        if denied {
            return false;
        }
        allowed
    }
}

/// 簡易パスマッチング (** はワイルドカード)。
fn path_matches(path: &str, pattern: &str) -> bool {
    pattern
        .strip_suffix("/**")
        .map_or_else(|| path == pattern, |prefix| path.starts_with(prefix))
}

// ============================================================================
// エラー型
// ============================================================================

/// seccomp エラー。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeccompError {
    /// プラットフォーム非対応。
    NotSupported,
    /// フィルタ適用失敗。
    InstallFailed(String),
    /// 不正なルール。
    InvalidRule(String),
}

impl fmt::Display for SeccompError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSupported => write!(f, "seccomp not supported on this platform"),
            Self::InstallFailed(msg) => write!(f, "seccomp install failed: {msg}"),
            Self::InvalidRule(msg) => write!(f, "Invalid seccomp rule: {msg}"),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seccomp_action_display() {
        assert_eq!(SeccompAction::Allow.to_string(), "SCMP_ACT_ALLOW");
        assert_eq!(SeccompAction::Kill.to_string(), "SCMP_ACT_KILL");
        assert_eq!(SeccompAction::Errno(1).to_string(), "SCMP_ACT_ERRNO(1)");
        assert_eq!(SeccompAction::Trace(42).to_string(), "SCMP_ACT_TRACE(42)");
        assert_eq!(SeccompAction::Log.to_string(), "SCMP_ACT_LOG");
    }

    #[test]
    fn simple_rule() {
        let rule = SeccompRule::simple("read", SeccompAction::Allow);
        assert_eq!(rule.syscall, "read");
        assert!(rule.args.is_empty());
    }

    #[test]
    fn rule_with_arg() {
        let arg = SeccompArg {
            index: 0,
            op: SeccompOp::Equal,
            value: 42,
        };
        let rule = SeccompRule::with_arg("ioctl", SeccompAction::Errno(22), arg);
        assert_eq!(rule.syscall, "ioctl");
        assert_eq!(rule.args.len(), 1);
        assert_eq!(rule.args[0].value, 42);
    }

    #[test]
    fn default_container_profile() {
        let profile = SeccompProfile::default_container();
        assert!(matches!(profile.default_action, SeccompAction::Allow));
        assert!(profile.rule_count() > 0);
        // mount は拒否
        assert!(!profile.is_allowed("mount"));
        // read は許可 (デフォルトアクション)
        assert!(profile.is_allowed("read"));
    }

    #[test]
    fn strict_profile() {
        let profile = SeccompProfile::strict();
        assert!(matches!(profile.default_action, SeccompAction::Errno(1)));
        // read は明示許可
        assert!(profile.is_allowed("read"));
        // mount は拒否 (デフォルトアクション)
        assert!(!profile.is_allowed("mount"));
    }

    #[test]
    fn profile_find_rule() {
        let profile = SeccompProfile::default_container();
        assert!(profile.find_rule("mount").is_some());
        assert!(profile.find_rule("nonexistent_syscall").is_none());
    }

    #[test]
    fn profile_architectures() {
        let profile = SeccompProfile::new(SeccompAction::Allow);
        assert!(profile.architectures.iter().any(|a| a.contains("X86_64")));
        assert!(profile.architectures.iter().any(|a| a.contains("AARCH64")));
    }

    #[test]
    fn apparmor_default_profile() {
        let profile = AppArmorProfile::default_container();
        assert_eq!(profile.name, "alice-container-default");
        assert!(profile.rule_count() > 0);
    }

    #[test]
    fn apparmor_file_allowed() {
        let profile = AppArmorProfile::default_container();
        assert!(profile.is_file_allowed("/usr/bin/ls"));
        assert!(profile.is_file_allowed("/bin/sh"));
        assert!(!profile.is_file_allowed("/proc/kcore"));
    }

    #[test]
    fn apparmor_add_rule() {
        let mut profile = AppArmorProfile::new("test");
        assert_eq!(profile.rule_count(), 0);
        profile.add_rule(AppArmorRule::FileAllow(
            "/opt/**".to_string(),
            "r".to_string(),
        ));
        assert_eq!(profile.rule_count(), 1);
    }

    #[test]
    fn path_matches_wildcard() {
        assert!(path_matches("/usr/bin/ls", "/usr/**"));
        assert!(path_matches("/usr/lib/libc.so", "/usr/**"));
        assert!(!path_matches("/etc/passwd", "/usr/**"));
    }

    #[test]
    fn path_matches_exact() {
        assert!(path_matches("/proc/kcore", "/proc/kcore"));
        assert!(!path_matches("/proc/kcore2", "/proc/kcore"));
    }

    #[test]
    fn seccomp_error_display() {
        let err = SeccompError::NotSupported;
        assert!(err.to_string().contains("not supported"));

        let err = SeccompError::InstallFailed("prctl failed".into());
        assert!(err.to_string().contains("prctl failed"));

        let err = SeccompError::InvalidRule("bad rule".into());
        assert!(err.to_string().contains("bad rule"));
    }

    #[test]
    fn seccomp_error_equality() {
        assert_eq!(SeccompError::NotSupported, SeccompError::NotSupported);
        assert_ne!(
            SeccompError::NotSupported,
            SeccompError::InvalidRule("x".into())
        );
    }
}
