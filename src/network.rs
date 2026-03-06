//! コンテナネットワーク分離 — veth ペア・ブリッジ・netns
//!
//! Linux のネットワーク名前空間と仮想イーサネット (veth) を使って、
//! コンテナ間のネットワーク分離を実現する。

use core::fmt;

// ============================================================================
// ネットワーク設定
// ============================================================================

/// コンテナネットワーク設定。
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// ブリッジ名 (例: "alice-br0")。
    pub bridge_name: String,
    /// ホスト側 veth 名 (例: "veth-host-abc")。
    pub veth_host: String,
    /// コンテナ側 veth 名 (例: "veth-ct-abc")。
    pub veth_container: String,
    /// コンテナ IP (CIDR表記、例: "10.0.0.2/24")。
    pub container_ip: String,
    /// ゲートウェイ IP (ブリッジの IP、例: "10.0.0.1")。
    pub gateway_ip: String,
    /// サブネットマスクのビット長。
    pub subnet_bits: u8,
    /// MTU (デフォルト 1500)。
    pub mtu: u16,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            bridge_name: "alice-br0".to_string(),
            veth_host: "veth-host-0".to_string(),
            veth_container: "veth-ct-0".to_string(),
            container_ip: "10.0.0.2/24".to_string(),
            gateway_ip: "10.0.0.1".to_string(),
            subnet_bits: 24,
            mtu: 1500,
        }
    }
}

impl NetworkConfig {
    /// コンテナIDから自動生成。
    #[must_use]
    pub fn from_container_id(id: &str, index: u16) -> Self {
        let short_id = if id.len() > 8 { &id[..8] } else { id };
        Self {
            bridge_name: "alice-br0".to_string(),
            veth_host: format!("veth-h-{short_id}"),
            veth_container: format!("veth-c-{short_id}"),
            container_ip: format!("10.0.0.{}/24", index + 2),
            gateway_ip: "10.0.0.1".to_string(),
            subnet_bits: 24,
            mtu: 1500,
        }
    }

    /// IP部分のみ取得 (CIDRプレフィックスを除去)。
    #[must_use]
    pub fn ip_without_prefix(&self) -> &str {
        self.container_ip
            .split('/')
            .next()
            .unwrap_or(&self.container_ip)
    }
}

// ============================================================================
// veth ペア
// ============================================================================

/// 仮想イーサネットペア。
#[derive(Debug, Clone)]
pub struct VethPair {
    /// ホスト側インターフェース名。
    pub host_name: String,
    /// コンテナ側インターフェース名。
    pub container_name: String,
    /// MTU。
    pub mtu: u16,
    /// 作成済みか。
    created: bool,
}

impl VethPair {
    /// 新しい veth ペアを定義。
    #[must_use]
    pub fn new(host_name: &str, container_name: &str, mtu: u16) -> Self {
        Self {
            host_name: host_name.to_string(),
            container_name: container_name.to_string(),
            mtu,
            created: false,
        }
    }

    /// `NetworkConfig` から生成。
    #[must_use]
    pub fn from_config(config: &NetworkConfig) -> Self {
        Self::new(&config.veth_host, &config.veth_container, config.mtu)
    }

    /// veth ペアを作成 (Linux: `ip link add`)。
    ///
    /// # Errors
    ///
    /// 権限不足やインターフェース名重複時にエラー。
    #[cfg(target_os = "linux")]
    pub fn create(&mut self) -> Result<(), NetworkError> {
        use std::process::Command;

        let output = Command::new("ip")
            .args([
                "link",
                "add",
                &self.host_name,
                "type",
                "veth",
                "peer",
                "name",
                &self.container_name,
            ])
            .output()
            .map_err(|e| NetworkError::CommandFailed(e.to_string()))?;

        if !output.status.success() {
            return Err(NetworkError::CommandFailed(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ));
        }

        // MTU 設定
        let _ = Command::new("ip")
            .args(["link", "set", &self.host_name, "mtu", &self.mtu.to_string()])
            .output();

        self.created = true;
        Ok(())
    }

    /// veth ペアを作成 (non-Linux stub)。
    ///
    /// # Errors
    ///
    /// Linux以外ではサポート外エラー。
    #[cfg(not(target_os = "linux"))]
    pub const fn create(&mut self) -> Result<(), NetworkError> {
        Err(NetworkError::NotSupported)
    }

    /// veth ペアを削除。
    ///
    /// # Errors
    ///
    /// 削除失敗時にエラー。
    #[cfg(target_os = "linux")]
    pub fn destroy(&mut self) -> Result<(), NetworkError> {
        use std::process::Command;

        // ホスト側を削除すればペアは自動削除
        let output = Command::new("ip")
            .args(["link", "del", &self.host_name])
            .output()
            .map_err(|e| NetworkError::CommandFailed(e.to_string()))?;

        if !output.status.success() {
            return Err(NetworkError::CommandFailed(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ));
        }

        self.created = false;
        Ok(())
    }

    /// veth ペアを削除 (non-Linux stub)。
    ///
    /// # Errors
    ///
    /// Linux以外ではサポート外エラー。
    #[cfg(not(target_os = "linux"))]
    pub const fn destroy(&mut self) -> Result<(), NetworkError> {
        Err(NetworkError::NotSupported)
    }

    /// コンテナ側 veth をネットワーク名前空間に移動。
    ///
    /// # Errors
    ///
    /// PID不正や権限不足時にエラー。
    #[cfg(target_os = "linux")]
    pub fn move_to_netns(&self, pid: u32) -> Result<(), NetworkError> {
        use std::process::Command;

        let output = Command::new("ip")
            .args([
                "link",
                "set",
                &self.container_name,
                "netns",
                &pid.to_string(),
            ])
            .output()
            .map_err(|e| NetworkError::CommandFailed(e.to_string()))?;

        if !output.status.success() {
            return Err(NetworkError::CommandFailed(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ));
        }
        Ok(())
    }

    /// コンテナ側 veth をネットワーク名前空間に移動 (non-Linux stub)。
    ///
    /// # Errors
    ///
    /// Linux以外ではサポート外エラー。
    #[cfg(not(target_os = "linux"))]
    pub const fn move_to_netns(&self, _pid: u32) -> Result<(), NetworkError> {
        Err(NetworkError::NotSupported)
    }

    /// 作成済みか。
    #[must_use]
    pub const fn is_created(&self) -> bool {
        self.created
    }
}

// ============================================================================
// ブリッジ
// ============================================================================

/// Linux ブリッジ。
#[derive(Debug, Clone)]
pub struct Bridge {
    /// ブリッジ名。
    pub name: String,
    /// ブリッジ IP (CIDR)。
    pub ip: String,
    /// 作成済みか。
    created: bool,
}

impl Bridge {
    /// 新しいブリッジを定義。
    #[must_use]
    pub fn new(name: &str, ip: &str) -> Self {
        Self {
            name: name.to_string(),
            ip: ip.to_string(),
            created: false,
        }
    }

    /// `NetworkConfig` から生成。
    #[must_use]
    pub fn from_config(config: &NetworkConfig) -> Self {
        let bridge_ip = format!("{}/{}", config.gateway_ip, config.subnet_bits);
        Self::new(&config.bridge_name, &bridge_ip)
    }

    /// ブリッジを作成して UP。
    ///
    /// # Errors
    ///
    /// 権限不足や名前重複時にエラー。
    #[cfg(target_os = "linux")]
    pub fn create(&mut self) -> Result<(), NetworkError> {
        use std::process::Command;

        // ブリッジ作成
        let output = Command::new("ip")
            .args(["link", "add", "name", &self.name, "type", "bridge"])
            .output()
            .map_err(|e| NetworkError::CommandFailed(e.to_string()))?;

        if !output.status.success() {
            return Err(NetworkError::CommandFailed(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ));
        }

        // IP アドレス設定
        let _ = Command::new("ip")
            .args(["addr", "add", &self.ip, "dev", &self.name])
            .output();

        // UP
        let _ = Command::new("ip")
            .args(["link", "set", &self.name, "up"])
            .output();

        self.created = true;
        Ok(())
    }

    /// ブリッジを作成 (non-Linux stub)。
    ///
    /// # Errors
    ///
    /// Linux以外ではサポート外エラー。
    #[cfg(not(target_os = "linux"))]
    pub const fn create(&mut self) -> Result<(), NetworkError> {
        Err(NetworkError::NotSupported)
    }

    /// veth をブリッジに接続。
    ///
    /// # Errors
    ///
    /// 接続失敗時にエラー。
    #[cfg(target_os = "linux")]
    pub fn attach_veth(&self, veth_host: &str) -> Result<(), NetworkError> {
        use std::process::Command;

        let output = Command::new("ip")
            .args(["link", "set", veth_host, "master", &self.name])
            .output()
            .map_err(|e| NetworkError::CommandFailed(e.to_string()))?;

        if !output.status.success() {
            return Err(NetworkError::CommandFailed(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ));
        }

        // veth ホスト側を UP
        let _ = Command::new("ip")
            .args(["link", "set", veth_host, "up"])
            .output();

        Ok(())
    }

    /// veth をブリッジに接続 (non-Linux stub)。
    ///
    /// # Errors
    ///
    /// Linux以外ではサポート外エラー。
    #[cfg(not(target_os = "linux"))]
    pub const fn attach_veth(&self, _veth_host: &str) -> Result<(), NetworkError> {
        Err(NetworkError::NotSupported)
    }

    /// ブリッジを削除。
    ///
    /// # Errors
    ///
    /// 削除失敗時にエラー。
    #[cfg(target_os = "linux")]
    pub fn destroy(&mut self) -> Result<(), NetworkError> {
        use std::process::Command;

        let output = Command::new("ip")
            .args(["link", "del", &self.name])
            .output()
            .map_err(|e| NetworkError::CommandFailed(e.to_string()))?;

        if !output.status.success() {
            return Err(NetworkError::CommandFailed(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ));
        }

        self.created = false;
        Ok(())
    }

    /// ブリッジを削除 (non-Linux stub)。
    ///
    /// # Errors
    ///
    /// Linux以外ではサポート外エラー。
    #[cfg(not(target_os = "linux"))]
    pub const fn destroy(&mut self) -> Result<(), NetworkError> {
        Err(NetworkError::NotSupported)
    }

    /// 作成済みか。
    #[must_use]
    pub const fn is_created(&self) -> bool {
        self.created
    }
}

// ============================================================================
// ネットワークセットアップ
// ============================================================================

/// コンテナネットワークを一括セットアップ。
///
/// 1. ブリッジ作成 (存在しなければ)
/// 2. veth ペア作成
/// 3. ホスト側 veth をブリッジに接続
/// 4. コンテナ側 veth をネットワーク名前空間に移動
///
/// # Errors
///
/// いずれかのステップが失敗した場合にエラー。
#[cfg(target_os = "linux")]
pub fn setup_container_network(
    config: &NetworkConfig,
    container_pid: u32,
) -> Result<(Bridge, VethPair), NetworkError> {
    let mut bridge = Bridge::from_config(config);
    bridge.create()?;

    let mut veth = VethPair::from_config(config);
    veth.create()?;

    bridge.attach_veth(&veth.host_name)?;
    veth.move_to_netns(container_pid)?;

    Ok((bridge, veth))
}

/// コンテナネットワークを一括セットアップ (non-Linux stub)。
///
/// # Errors
///
/// Linux以外ではサポート外エラー。
#[cfg(not(target_os = "linux"))]
pub const fn setup_container_network(
    _config: &NetworkConfig,
    _container_pid: u32,
) -> Result<(Bridge, VethPair), NetworkError> {
    Err(NetworkError::NotSupported)
}

/// コンテナネットワークを一括解放。
///
/// # Errors
///
/// 解放失敗時にエラー。
pub fn teardown_container_network(
    bridge: &mut Bridge,
    veth: &mut VethPair,
) -> Result<(), NetworkError> {
    // veth 削除 (ブリッジからの接続も自動解除)
    if veth.is_created() {
        veth.destroy()?;
    }
    // ブリッジ削除
    if bridge.is_created() {
        bridge.destroy()?;
    }
    Ok(())
}

// ============================================================================
// エラー型
// ============================================================================

/// ネットワーク操作エラー。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkError {
    /// プラットフォーム非対応。
    NotSupported,
    /// コマンド実行失敗。
    CommandFailed(String),
    /// インターフェースが見つからない。
    InterfaceNotFound(String),
    /// アドレス設定エラー。
    AddressError(String),
    /// 権限不足。
    PermissionDenied,
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSupported => write!(f, "Network isolation not supported on this platform"),
            Self::CommandFailed(msg) => write!(f, "Network command failed: {msg}"),
            Self::InterfaceNotFound(name) => write!(f, "Interface not found: {name}"),
            Self::AddressError(msg) => write!(f, "Address error: {msg}"),
            Self::PermissionDenied => write!(f, "Permission denied (need CAP_NET_ADMIN)"),
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
    fn default_config() {
        let config = NetworkConfig::default();
        assert_eq!(config.bridge_name, "alice-br0");
        assert_eq!(config.mtu, 1500);
        assert_eq!(config.subnet_bits, 24);
    }

    #[test]
    fn config_from_container_id() {
        let config = NetworkConfig::from_container_id("abcdef1234567890", 0);
        assert_eq!(config.veth_host, "veth-h-abcdef12");
        assert_eq!(config.veth_container, "veth-c-abcdef12");
        assert_eq!(config.container_ip, "10.0.0.2/24");
    }

    #[test]
    fn config_from_short_id() {
        let config = NetworkConfig::from_container_id("abc", 5);
        assert_eq!(config.veth_host, "veth-h-abc");
        assert_eq!(config.container_ip, "10.0.0.7/24");
    }

    #[test]
    fn ip_without_prefix() {
        let config = NetworkConfig::default();
        assert_eq!(config.ip_without_prefix(), "10.0.0.2");
    }

    #[test]
    fn ip_without_prefix_no_slash() {
        let config = NetworkConfig {
            container_ip: "10.0.0.5".to_string(),
            ..NetworkConfig::default()
        };
        assert_eq!(config.ip_without_prefix(), "10.0.0.5");
    }

    #[test]
    fn veth_pair_new() {
        let veth = VethPair::new("veth-h", "veth-c", 9000);
        assert_eq!(veth.host_name, "veth-h");
        assert_eq!(veth.container_name, "veth-c");
        assert_eq!(veth.mtu, 9000);
        assert!(!veth.is_created());
    }

    #[test]
    fn veth_from_config() {
        let config = NetworkConfig::default();
        let veth = VethPair::from_config(&config);
        assert_eq!(veth.host_name, config.veth_host);
        assert_eq!(veth.container_name, config.veth_container);
        assert_eq!(veth.mtu, config.mtu);
    }

    #[test]
    fn bridge_new() {
        let bridge = Bridge::new("br-test", "10.0.0.1/24");
        assert_eq!(bridge.name, "br-test");
        assert_eq!(bridge.ip, "10.0.0.1/24");
        assert!(!bridge.is_created());
    }

    #[test]
    fn bridge_from_config() {
        let config = NetworkConfig::default();
        let bridge = Bridge::from_config(&config);
        assert_eq!(bridge.name, "alice-br0");
        assert_eq!(bridge.ip, "10.0.0.1/24");
    }

    #[test]
    fn network_error_display() {
        let err = NetworkError::NotSupported;
        assert!(err.to_string().contains("not supported"));

        let err = NetworkError::CommandFailed("ip failed".into());
        assert!(err.to_string().contains("ip failed"));

        let err = NetworkError::InterfaceNotFound("eth0".into());
        assert!(err.to_string().contains("eth0"));

        let err = NetworkError::PermissionDenied;
        assert!(err.to_string().contains("Permission denied"));
    }

    #[test]
    fn network_error_equality() {
        assert_eq!(NetworkError::NotSupported, NetworkError::NotSupported);
        assert_eq!(
            NetworkError::PermissionDenied,
            NetworkError::PermissionDenied
        );
        assert_ne!(NetworkError::NotSupported, NetworkError::PermissionDenied);
    }

    #[test]
    fn teardown_not_created() {
        let mut bridge = Bridge::new("br-x", "10.0.0.1/24");
        let mut veth = VethPair::new("vh", "vc", 1500);
        // 未作成なら teardown は何もしない
        let result = teardown_container_network(&mut bridge, &mut veth);
        assert!(result.is_ok());
    }

    #[test]
    fn veth_pair_debug() {
        let veth = VethPair::new("a", "b", 1500);
        let dbg = format!("{veth:?}");
        assert!(dbg.contains("VethPair"));
    }

    #[test]
    fn bridge_debug() {
        let bridge = Bridge::new("br0", "10.0.0.1/24");
        let dbg = format!("{bridge:?}");
        assert!(dbg.contains("Bridge"));
    }
}
