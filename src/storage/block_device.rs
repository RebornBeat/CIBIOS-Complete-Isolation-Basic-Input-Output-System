// =============================================================================
// STORAGE BLOCK DEVICE MODULE - cibios/src/storage/block_device.rs
// =============================================================================

use anyhow::{Context, Result as AnyhowResult};
use serde::{Deserialize, Serialize};
use async_trait::async_trait;
use std::path::Path;

/// Block device interface for storage access
#[async_trait]
pub trait BlockDeviceInterface: Send + Sync + std::fmt::Debug {
    /// Read data from device at specified offset
    async fn read(&self, offset: u64, buffer: &mut [u8]) -> AnyhowResult<usize>;
    
    /// Write data to device at specified offset
    async fn write(&self, offset: u64, data: &[u8]) -> AnyhowResult<usize>;
    
    /// Get device capacity in bytes
    fn capacity(&self) -> u64;
    
    /// Get device sector size
    fn sector_size(&self) -> u32;
    
    /// Check if device is bootable
    fn is_bootable(&self) -> bool;
}

/// Block device capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCapabilities {
    pub capacity: u64,
    pub sector_size: u32,
    pub read_only: bool,
    pub bootable: bool,
    pub removable: bool,
}

/// Generic block device implementation
#[derive(Debug)]
pub struct BlockDevice {
    device_path: String,
    capabilities: DeviceCapabilities,
    device_handle: Option<tokio::fs::File>,
}

/// HDD-specific block device implementation
#[derive(Debug)]
pub struct HDDBlockDevice {
    device_path: String,
    capabilities: DeviceCapabilities,
}

/// SSD-specific block device implementation
#[derive(Debug)]
pub struct SSDBlockDevice {
    device_path: String,
    capabilities: DeviceCapabilities,
}

/// eMMC-specific block device implementation
#[derive(Debug)]
pub struct EMMCBlockDevice {
    device_path: String,
    capabilities: DeviceCapabilities,
}

/// NVMe-specific block device implementation
#[derive(Debug)]
pub struct NVMEBlockDevice {
    device_path: String,
    capabilities: DeviceCapabilities,
}

impl HDDBlockDevice {
    pub async fn new(device_path: &str) -> AnyhowResult<Self> {
        let capabilities = Self::detect_capabilities(device_path).await?;
        Ok(Self {
            device_path: device_path.to_string(),
            capabilities,
        })
    }

    async fn detect_capabilities(device_path: &str) -> AnyhowResult<DeviceCapabilities> {
        // HDD-specific capability detection would go here
        // For now, return default capabilities
        Ok(DeviceCapabilities {
            capacity: 1_000_000_000_000, // 1TB default
            sector_size: 512,
            read_only: false,
            bootable: true,
            removable: false,
        })
    }
}

#[async_trait]
impl BlockDeviceInterface for HDDBlockDevice {
    async fn read(&self, offset: u64, buffer: &mut [u8]) -> AnyhowResult<usize> {
        // HDD-specific read implementation
        tokio::fs::File::open(&self.device_path).await?
            .read_at(buffer, offset).await
            .context("Failed to read from HDD")
    }

    async fn write(&self, offset: u64, data: &[u8]) -> AnyhowResult<usize> {
        // HDD-specific write implementation
        tokio::fs::OpenOptions::new()
            .write(true)
            .open(&self.device_path).await?
            .write_at(data, offset).await
            .context("Failed to write to HDD")
    }

    fn capacity(&self) -> u64 { self.capabilities.capacity }
    fn sector_size(&self) -> u32 { self.capabilities.sector_size }
    fn is_bootable(&self) -> bool { self.capabilities.bootable }
}

// Similar implementations for SSD, eMMC, and NVMe would follow the same pattern

impl SSDBlockDevice {
    pub async fn new(device_path: &str) -> AnyhowResult<Self> {
        let capabilities = Self::detect_capabilities(device_path).await?;
        Ok(Self {
            device_path: device_path.to_string(),
            capabilities,
        })
    }

    async fn detect_capabilities(device_path: &str) -> AnyhowResult<DeviceCapabilities> {
        Ok(DeviceCapabilities {
            capacity: 500_000_000_000, // 500GB default
            sector_size: 512,
            read_only: false,
            bootable: true,
            removable: false,
        })
    }
}

#[async_trait]
impl BlockDeviceInterface for SSDBlockDevice {
    async fn read(&self, offset: u64, buffer: &mut [u8]) -> AnyhowResult<usize> {
        tokio::fs::File::open(&self.device_path).await?
            .read_at(buffer, offset).await
            .context("Failed to read from SSD")
    }

    async fn write(&self, offset: u64, data: &[u8]) -> AnyhowResult<usize> {
        tokio::fs::OpenOptions::new()
            .write(true)
            .open(&self.device_path).await?
            .write_at(data, offset).await
            .context("Failed to write to SSD")
    }

    fn capacity(&self) -> u64 { self.capabilities.capacity }
    fn sector_size(&self) -> u32 { self.capabilities.sector_size }
    fn is_bootable(&self) -> bool { self.capabilities.bootable }
}

// Add the missing trait implementations for file operations
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

trait AsyncReadAt {
    fn read_at<'a>(&'a mut self, buf: &'a mut [u8], offset: u64) -> impl std::future::Future<Output = std::io::Result<usize>> + 'a;
}

trait AsyncWriteAt {
    fn write_at<'a>(&'a mut self, buf: &'a [u8], offset: u64) -> impl std::future::Future<Output = std::io::Result<usize>> + 'a;
}

impl AsyncReadAt for tokio::fs::File {
    async fn read_at(&mut self, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
        self.seek(std::io::SeekFrom::Start(offset)).await?;
        self.read(buf).await
    }
}

impl AsyncWriteAt for tokio::fs::File {
    async fn write_at(&mut self, buf: &[u8], offset: u64) -> std::io::Result<usize> {
        self.seek(std::io::SeekFrom::Start(offset)).await?;
        self.write(buf).await
    }
}
