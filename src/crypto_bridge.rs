//! ALICE-Container × ALICE-Crypto bridge
//!
//! Encrypted container secrets management (XChaCha20-Poly1305).
//!
//! Author: Moroya Sakamoto

use alice_crypto::{seal, open, blake3_hash, Key, Hash};

/// A sealed (encrypted) container secret
#[derive(Debug, Clone)]
pub struct SealedSecret {
    pub name_hash: Hash,
    pub ciphertext: Vec<u8>,
}

/// Encrypted secret store for container environment variables
pub struct ContainerSecretStore {
    key: Key,
    pub sealed_secrets: Vec<SealedSecret>,
}

impl ContainerSecretStore {
    /// Create store with a container-specific encryption key
    pub fn new(key: Key) -> Self {
        Self { key, sealed_secrets: Vec::new() }
    }

    /// Derive a container-specific key from master key + container ID
    pub fn derive_container_key(container_id: &str, master_key: &Key) -> Key {
        let context = format!("alice-container:{}", container_id);
        let mut material = [0u8; 64];
        material[..32].copy_from_slice(master_key.as_bytes());
        let ctx_bytes = context.as_bytes();
        let copy_len = ctx_bytes.len().min(32);
        material[32..32 + copy_len].copy_from_slice(&ctx_bytes[..copy_len]);
        let hash = blake3_hash(&material);
        Key::from(*hash.as_bytes())
    }

    /// Seal a secret (name + value → encrypted)
    pub fn seal_secret(&mut self, name: &str, value: &[u8]) -> Result<SealedSecret, String> {
        let name_hash = blake3_hash(name.as_bytes());
        let ciphertext = seal(&self.key, value).map_err(|e| format!("Seal error: {:?}", e))?;
        let secret = SealedSecret { name_hash, ciphertext };
        self.sealed_secrets.push(secret.clone());
        Ok(secret)
    }

    /// Open a sealed secret
    pub fn open_secret(&self, sealed: &SealedSecret) -> Result<Vec<u8>, String> {
        open(&self.key, &sealed.ciphertext).map_err(|e| format!("Open error: {:?}", e))
    }

    /// Find and open a secret by name
    pub fn get_secret(&self, name: &str) -> Result<Vec<u8>, String> {
        let name_hash = blake3_hash(name.as_bytes());
        for sealed in &self.sealed_secrets {
            if sealed.name_hash == name_hash {
                return self.open_secret(sealed);
            }
        }
        Err(format!("Secret '{}' not found", name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Key {
        Key::from([0x42u8; 32])
    }

    #[test]
    fn test_seal_open_roundtrip() {
        let mut store = ContainerSecretStore::new(test_key());
        let secret = store.seal_secret("DB_PASSWORD", b"hunter2").unwrap();
        let plaintext = store.open_secret(&secret).unwrap();
        assert_eq!(plaintext, b"hunter2");
    }

    #[test]
    fn test_get_by_name() {
        let mut store = ContainerSecretStore::new(test_key());
        store.seal_secret("API_KEY", b"sk-12345").unwrap();
        store.seal_secret("DB_HOST", b"10.0.0.1").unwrap();
        let val = store.get_secret("API_KEY").unwrap();
        assert_eq!(val, b"sk-12345");
    }

    #[test]
    fn test_derive_container_key() {
        let master = test_key();
        let k1 = ContainerSecretStore::derive_container_key("container-a", &master);
        let k2 = ContainerSecretStore::derive_container_key("container-b", &master);
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn test_wrong_key_fails() {
        let mut store = ContainerSecretStore::new(test_key());
        let secret = store.seal_secret("SECRET", b"value").unwrap();
        let wrong_store = ContainerSecretStore::new(Key::from([0xFFu8; 32]));
        assert!(wrong_store.open_secret(&secret).is_err());
    }
}
