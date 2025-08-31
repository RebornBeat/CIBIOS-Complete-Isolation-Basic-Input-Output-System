// =============================================================================
// STORAGE ENCRYPTION MODULE - cibios/src/storage/encryption.rs
// =============================================================================

use anyhow::{Context, Result as AnyhowResult};
use serde::{Deserialize, Serialize};
use crate::core::hardware::HardwareAbstraction;
use crate::core::crypto::{CryptographicEngine, EncryptionKey};
use shared::crypto::encryption::{EncryptionAlgorithm, DataEncryption};

/// Storage encryption for secure firmware operations
#[derive(Debug)]
pub struct StorageEncryption {
    encryption_enabled: bool,
    crypto_engine: Arc<CryptographicEngine>,
    storage_key: Option<EncryptionKey>,
}

/// Storage key manager for encryption keys
#[derive(Debug)]
pub struct StorageKeyManager {
    keys: HashMap<String, EncryptionKey>,
    hardware: Arc<HardwareAbstraction>,
}

/// Encrypted storage interface
#[derive(Debug)]
pub struct EncryptedStorage {
    storage: Arc<dyn FilesystemInterface>,
    encryption: Arc<StorageEncryption>,
}

impl StorageEncryption {
    /// Initialize storage encryption
    pub async fn initialize(hardware: &HardwareAbstraction) -> AnyhowResult<Self> {
        info!("Initializing storage encryption for firmware");

        let crypto_engine = Arc::new(CryptographicEngine::initialize(hardware).await
            .context("Failed to initialize cryptographic engine for storage")?);

        // Check if storage encryption is required
        let encryption_enabled = hardware.get_security_capabilities().hardware_encryption;

        let storage_key = if encryption_enabled {
            Some(crypto_engine.derive_storage_key().await
                .context("Failed to derive storage encryption key")?)
        } else {
            None
        };

        Ok(Self {
            encryption_enabled,
            crypto_engine,
            storage_key,
        })
    }

    /// Check if encryption is enabled
    pub fn is_enabled(&self) -> bool {
        self.encryption_enabled && self.storage_key.is_some()
    }

    /// Encrypt data for storage
    pub async fn encrypt_data(&self, data: &[u8]) -> AnyhowResult<Vec<u8>> {
        if !self.is_enabled() {
            return Ok(data.to_vec());
        }

        let key = self.storage_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Storage encryption key not available"))?;

        self.crypto_engine.encrypt_data(data, key).await
            .context("Failed to encrypt storage data")
    }

    /// Decrypt data from storage
    pub async fn decrypt_data(&self, encrypted_data: &[u8]) -> AnyhowResult<Vec<u8>> {
        if !self.is_enabled() {
            return Ok(encrypted_data.to_vec());
        }

        let key = self.storage_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Storage encryption key not available"))?;

        self.crypto_engine.decrypt_data(encrypted_data, key).await
            .context("Failed to decrypt storage data")
    }
}
