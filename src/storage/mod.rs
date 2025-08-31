// =============================================================================
// CIBIOS STORAGE MODULE - cibios/src/storage/mod.rs
// Basic storage device access for firmware operations
// =============================================================================

//! Storage device access for CIBIOS firmware operations
//! 
//! This module provides the minimal storage functionality needed by CIBIOS
//! firmware to load the CIBOS operating system, manage firmware configuration,
//! and handle backup/recovery operations. It does not provide full filesystem
//! support - that is the responsibility of the CIBOS kernel.

// External dependencies for storage operations
use anyhow::{Context, Result as AnyhowResult};
use serde::{Deserialize, Serialize};
use log::{debug, error, info, warn};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::collections::HashMap;
use uuid::Uuid;

// CIBIOS core integration
use crate::core::hardware::{HardwareAbstraction, HardwareCapabilities};
use crate::core::crypto::{CryptographicEngine, IntegrityVerification};
use crate::core::verification::{ImageVerification, ComponentVerification};

// Storage component exports
pub use self::block_device::{BlockDevice, BlockDeviceInterface, DeviceCapabilities};
pub use self::filesystem::{BasicFilesystem, FilesystemInterface, FileAccess};
pub use self::encryption::{StorageEncryption, EncryptedStorage, StorageKeyManager};

// Storage module declarations
pub mod block_device;
pub mod filesystem;
pub mod encryption;

// Shared type imports
use shared::types::hardware::{StorageCapabilities, StorageType};
use shared::types::isolation::{StorageBoundary, IsolationLevel};
use shared::types::error::{StorageError, FilesystemError, EncryptionError};

/// Main storage interface for CIBIOS firmware operations
#[derive(Debug)]
pub struct StorageInterface {
    pub block_devices: HashMap<String, Arc<dyn BlockDeviceInterface>>,
    pub filesystem: Arc<dyn FilesystemInterface>,
    pub encryption: Arc<StorageEncryption>,
    pub verification: Arc<StorageVerification>,
}

/// Storage verification for secure firmware operations
#[derive(Debug)]
pub struct StorageVerification {
    pub crypto_engine: Arc<CryptographicEngine>,
    pub verification_keys: HashMap<String, Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfiguration {
    pub available_devices: Vec<StorageDeviceInfo>,
    pub default_device: Option<String>,
    pub encryption_enabled: bool,
    pub verification_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageDeviceInfo {
    pub device_id: String,
    pub device_type: StorageType,
    pub capacity: u64,
    pub bootable: bool,
    pub encrypted: bool,
}

impl StorageInterface {
    /// Initialize storage interface with device detection
    pub async fn initialize(hardware: &HardwareAbstraction) -> AnyhowResult<Self> {
        info!("Initializing CIBIOS storage interface");

        // Detect available storage devices
        let block_devices = Self::detect_storage_devices(hardware).await
            .context("Storage device detection failed")?;

        // Initialize basic filesystem access
        let filesystem = Arc::new(BasicFilesystem::initialize(&block_devices).await
            .context("Filesystem initialization failed")?);

        // Initialize storage encryption
        let encryption = Arc::new(StorageEncryption::initialize(hardware).await
            .context("Storage encryption initialization failed")?);

        // Initialize storage verification
        let verification = Arc::new(StorageVerification::initialize(hardware).await
            .context("Storage verification initialization failed")?);

        info!("CIBIOS storage interface initialized successfully");

        Ok(Self {
            block_devices,
            filesystem,
            encryption,
            verification,
        })
    }

    /// Load CIBOS operating system image from storage
    pub async fn load_os_image(&self, image_path: &str) -> AnyhowResult<Vec<u8>> {
        info!("Loading CIBOS image from storage: {}", image_path);

        // Read image file through filesystem interface
        let image_data = self.filesystem.read_file(image_path).await
            .context("Failed to read OS image file")?;

        // Verify image integrity
        self.verification.verify_image_integrity(&image_data).await
            .context("OS image integrity verification failed")?;

        info!("CIBOS image loaded and verified: {} bytes", image_data.len());
        Ok(image_data)
    }

    /// Save firmware configuration to storage
    pub async fn save_firmware_config(&self, config: &crate::core::FirmwareConfiguration) -> AnyhowResult<()> {
        info!("Saving firmware configuration to storage");

        // Serialize configuration
        let config_data = serde_json::to_vec(config)
            .context("Failed to serialize firmware configuration")?;

        // Encrypt configuration if required
        let encrypted_data = if self.encryption.is_enabled() {
            self.encryption.encrypt_data(&config_data).await
                .context("Failed to encrypt firmware configuration")?
        } else {
            config_data
        };

        // Write configuration file
        self.filesystem.write_file("/cibios/config.json", &encrypted_data).await
            .context("Failed to write firmware configuration")?;

        info!("Firmware configuration saved successfully");
        Ok(())
    }

    /// Load firmware configuration from storage
    pub async fn load_firmware_config(&self) -> AnyhowResult<crate::core::FirmwareConfiguration> {
        info!("Loading firmware configuration from storage");

        // Read configuration file
        let encrypted_data = self.filesystem.read_file("/cibios/config.json").await
            .context("Failed to read firmware configuration")?;

        // Decrypt configuration if needed
        let config_data = if self.encryption.is_enabled() {
            self.encryption.decrypt_data(&encrypted_data).await
                .context("Failed to decrypt firmware configuration")?
        } else {
            encrypted_data
        };

        // Deserialize configuration
        let config = serde_json::from_slice(&config_data)
            .context("Failed to deserialize firmware configuration")?;

        info!("Firmware configuration loaded successfully");
        Ok(config)
    }

    /// Detect available storage devices
    async fn detect_storage_devices(
        hardware: &HardwareAbstraction
    ) -> AnyhowResult<HashMap<String, Arc<dyn BlockDeviceInterface>>> {
        let mut devices = HashMap::new();

        // Detect different storage device types
        let storage_capabilities = hardware.get_storage_capabilities();
        
        for device_info in &storage_capabilities.detected_devices {
            let device = match device_info.device_type {
                StorageType::HDD => {
                    Arc::new(HDDBlockDevice::new(&device_info.device_path).await?) as Arc<dyn BlockDeviceInterface>
                }
                StorageType::SSD => {
                    Arc::new(SSDBlockDevice::new(&device_info.device_path).await?) as Arc<dyn BlockDeviceInterface>
                }
                StorageType::EMMC => {
                    Arc::new(EMMCBlockDevice::new(&device_info.device_path).await?) as Arc<dyn BlockDeviceInterface>
                }
                StorageType::NVME => {
                    Arc::new(NVMEBlockDevice::new(&device_info.device_path).await?) as Arc<dyn BlockDeviceInterface>
                }
                _ => continue, // Skip unsupported device types
            };

            devices.insert(device_info.device_id.clone(), device);
        }

        Ok(devices)
    }
}
