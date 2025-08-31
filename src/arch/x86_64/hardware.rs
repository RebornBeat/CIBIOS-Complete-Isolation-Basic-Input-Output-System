// =============================================================================
// X86_64 HARDWARE MODULE - cibios/src/arch/x86_64/hardware.rs
// Hardware abstraction and capabilities detection for x86_64 processors
// =============================================================================

use anyhow::{Context, Result as AnyhowResult};
use serde::{Deserialize, Serialize};
use log::{debug, error, info, warn};
use raw_cpuid::{CpuId, CpuIdReaderNative};
use bit_field::BitField;
use x86_64::registers::control::{Cr0, Cr4, Cr0Flags, Cr4Flags};
use std::sync::Arc;
use std::collections::HashMap;

// CIBIOS core imports
use crate::core::hardware::{HardwareAbstraction, HardwareCapabilities};
use crate::core::crypto::{CryptographicEngine, HardwareCrypto};

// Assembly interface imports
use super::asm::{x86_64_boot_initialize_hardware};

// Shared type imports
use shared::types::hardware::{
    ProcessorArchitecture, SecurityCapabilities, VirtualizationSupport,
    DisplayCapabilities, InputCapabilities, NetworkCapabilities, StorageCapabilities
};
use shared::types::error::{HardwareError, ArchitectureError};

/// x86_64 hardware abstraction layer providing universal compatibility
#[derive(Debug)]
pub struct X86_64Hardware {
    pub capabilities: X86_64Capabilities,
    pub configuration: X86_64Configuration,
    pub cpu_info: CpuInformation,
    pub hardware_features: HardwareFeatureSet,
}

/// x86_64 processor capabilities detection and management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X86_64Capabilities {
    pub supports_vt_x: bool,
    pub supports_aes_ni: bool,
    pub supports_rdrand: bool,
    pub supports_smep: bool,
    pub supports_smap: bool,
    pub supports_mpx: bool,
    pub supports_cet: bool,
    pub memory_protection_keys: bool,
    pub max_physical_address_bits: u8,
    pub max_virtual_address_bits: u8,
}

/// x86_64 hardware configuration for firmware operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X86_64Configuration {
    pub enable_hardware_acceleration: bool,
    pub vt_x_configuration: Option<VTxConfiguration>,
    pub memory_configuration: X86_64MemoryConfiguration,
    pub security_configuration: X86_64SecurityConfiguration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VTxConfiguration {
    pub enable_vt_x: bool,
    pub enable_ept: bool,
    pub enable_vpid: bool,
    pub unrestricted_guest: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X86_64MemoryConfiguration {
    pub page_size: PageSize,
    pub enable_pae: bool,
    pub enable_nx_bit: bool,
    pub enable_smep: bool,
    pub enable_smap: bool,
    pub memory_protection_keys: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PageSize {
    Size4KB,
    Size2MB,
    Size1GB,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X86_64SecurityConfiguration {
    pub hardware_rng: bool,
    pub aes_acceleration: bool,
    pub control_flow_integrity: bool,
    pub shadow_stack: bool,
}

/// CPU information detected during hardware initialization
#[derive(Debug, Clone)]
pub struct CpuInformation {
    pub vendor: CpuVendor,
    pub brand_string: String,
    pub family: u32,
    pub model: u32,
    pub stepping: u32,
    pub core_count: u32,
    pub thread_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuVendor {
    Intel,
    AMD,
    Unknown(u32),
}

/// Hardware feature detection and management
#[derive(Debug)]
pub struct HardwareFeatureSet {
    pub cpu_features: HashMap<String, bool>,
    pub security_features: HashMap<String, bool>,
    pub virtualization_features: HashMap<String, bool>,
}

impl X86_64Hardware {
    /// Initialize x86_64 hardware abstraction with capability detection
    pub async fn initialize() -> AnyhowResult<Self> {
        info!("Initializing x86_64 hardware abstraction");

        // Detect CPU capabilities using CPUID
        let cpu_info = Self::detect_cpu_information()
            .context("CPU information detection failed")?;

        // Detect x86_64 specific capabilities
        let capabilities = Self::detect_x86_64_capabilities(&cpu_info)
            .context("x86_64 capability detection failed")?;

        // Load default hardware configuration
        let configuration = X86_64Configuration::default_for_capabilities(&capabilities);

        // Detect additional hardware features
        let hardware_features = Self::detect_hardware_features(&cpu_info)
            .context("Hardware feature detection failed")?;

        info!("x86_64 hardware initialization completed");
        info!("Detected CPU: {} {} cores", cpu_info.brand_string, cpu_info.core_count);
        info!("VT-x support: {}", capabilities.supports_vt_x);

        Ok(Self {
            capabilities,
            configuration,
            cpu_info,
            hardware_features,
        })
    }

    /// Detect CPU information using CPUID instruction
    fn detect_cpu_information() -> AnyhowResult<CpuInformation> {
        let cpuid = CpuId::new();

        // Get vendor information
        let vendor_info = cpuid.get_vendor_info()
            .ok_or_else(|| anyhow::anyhow!("Failed to get CPU vendor information"))?;

        let vendor = match vendor_info.as_str() {
            "GenuineIntel" => CpuVendor::Intel,
            "AuthenticAMD" => CpuVendor::AMD,
            _ => CpuVendor::Unknown(0),
        };

        // Get processor info
        let processor_info = cpuid.get_processor_info()
            .ok_or_else(|| anyhow::anyhow!("Failed to get processor information"))?;

        // Get brand string
        let brand_string = cpuid.get_processor_brand_string()
            .map(|brand| brand.as_str().to_string())
            .unwrap_or_else(|| "Unknown CPU".to_string());

        // Detect core and thread count
        let (core_count, thread_count) = Self::detect_core_count(&cpuid);

        Ok(CpuInformation {
            vendor,
            brand_string,
            family: processor_info.family_id() as u32,
            model: processor_info.model_id() as u32,
            stepping: processor_info.stepping_id() as u32,
            core_count,
            thread_count,
        })
    }

    /// Detect x86_64 specific capabilities and security features
    fn detect_x86_64_capabilities(cpu_info: &CpuInformation) -> AnyhowResult<X86_64Capabilities> {
        let cpuid = CpuId::new();

        // Check for virtualization support (VT-x for Intel, SVM for AMD)
        let supports_vt_x = match cpu_info.vendor {
            CpuVendor::Intel => {
                cpuid.get_feature_info()
                    .map(|info| info.has_vmx())
                    .unwrap_or(false)
            }
            CpuVendor::AMD => {
                cpuid.get_svm_info()
                    .map(|info| info.has_svm())
                    .unwrap_or(false)
            }
            _ => false,
        };

        // Check for AES-NI support
        let supports_aes_ni = cpuid.get_feature_info()
            .map(|info| info.has_aesni())
            .unwrap_or(false);

        // Check for RDRAND support
        let supports_rdrand = cpuid.get_feature_info()
            .map(|info| info.has_rdrand())
            .unwrap_or(false);

        // Check for security features
        let extended_features = cpuid.get_extended_feature_info();
        let supports_smep = extended_features
            .map(|info| info.has_smep())
            .unwrap_or(false);

        let supports_smap = extended_features
            .map(|info| info.has_smap())
            .unwrap_or(false);

        let supports_mpx = extended_features
            .map(|info| info.has_mpx())
            .unwrap_or(false);

        let supports_cet = extended_features
            .map(|info| info.has_cet_ss() || info.has_cet_ibt())
            .unwrap_or(false);

        let memory_protection_keys = extended_features
            .map(|info| info.has_pku())
            .unwrap_or(false);

        // Detect address space capabilities
        let address_info = cpuid.get_processor_capacity_feature_info();
        let max_physical_address_bits = address_info
            .map(|info| info.physical_address_bits())
            .unwrap_or(36);

        let max_virtual_address_bits = address_info
            .map(|info| info.linear_address_bits())
            .unwrap_or(48);

        Ok(X86_64Capabilities {
            supports_vt_x,
            supports_aes_ni,
            supports_rdrand,
            supports_smep,
            supports_smap,
            supports_mpx,
            supports_cet,
            memory_protection_keys,
            max_physical_address_bits,
            max_virtual_address_bits,
        })
    }

    /// Detect CPU core and thread count
    fn detect_core_count(cpuid: &CpuId) -> (u32, u32) {
        // Try to get topology information
        if let Some(topology) = cpuid.get_processor_topology_info() {
            let core_count = topology.x2apic_id_shift() as u32;
            let thread_count = if let Some(cache_info) = cpuid.get_cache_info() {
                cache_info.num_sharing_cache() as u32
            } else {
                core_count
            };
            (core_count, thread_count)
        } else {
            // Fallback detection
            (1, 1)
        }
    }

    /// Detect additional hardware features beyond CPU
    fn detect_hardware_features(cpu_info: &CpuInformation) -> AnyhowResult<HardwareFeatureSet> {
        let mut cpu_features = HashMap::new();
        let mut security_features = HashMap::new();
        let mut virtualization_features = HashMap::new();

        // Add CPU feature detection
        cpu_features.insert("x86_64".to_string(), true);
        cpu_features.insert("long_mode".to_string(), true);

        // Add security feature detection
        security_features.insert("hardware_isolation".to_string(), true);
        
        // Add virtualization feature detection based on vendor
        match cpu_info.vendor {
            CpuVendor::Intel => {
                virtualization_features.insert("vt_x".to_string(), true);
            }
            CpuVendor::AMD => {
                virtualization_features.insert("svm".to_string(), true);
            }
            _ => {}
        }

        Ok(HardwareFeatureSet {
            cpu_features,
            security_features,
            virtualization_features,
        })
    }

    /// Check if VT-x virtualization is supported
    pub fn supports_vt_x(&self) -> bool {
        self.capabilities.supports_vt_x
    }

    /// Get hardware configuration for initialization
    pub fn get_configuration(&self) -> &X86_64Configuration {
        &self.configuration
    }

    /// Get security capabilities for isolation setup
    pub fn get_security_capabilities(&self) -> SecurityCapabilities {
        SecurityCapabilities {
            hardware_virtualization: self.capabilities.supports_vt_x,
            hardware_encryption: self.capabilities.supports_aes_ni,
            trusted_platform_module: false, // Would be detected separately
            secure_boot_support: false,     // Would be detected separately
            memory_encryption: false,       // Would be detected separately
        }
    }
}

impl X86_64Configuration {
    /// Create default configuration based on detected capabilities
    pub fn default_for_capabilities(capabilities: &X86_64Capabilities) -> Self {
        Self {
            enable_hardware_acceleration: capabilities.supports_vt_x,
            vt_x_configuration: if capabilities.supports_vt_x {
                Some(VTxConfiguration {
                    enable_vt_x: false, // User choice - conservative default
                    enable_ept: capabilities.supports_vt_x,
                    enable_vpid: capabilities.supports_vt_x,
                    unrestricted_guest: false,
                })
            } else {
                None
            },
            memory_configuration: X86_64MemoryConfiguration {
                page_size: PageSize::Size4KB,
                enable_pae: true,
                enable_nx_bit: true,
                enable_smep: capabilities.supports_smep,
                enable_smap: capabilities.supports_smap,
                memory_protection_keys: capabilities.memory_protection_keys,
            },
            security_configuration: X86_64SecurityConfiguration {
                hardware_rng: capabilities.supports_rdrand,
                aes_acceleration: capabilities.supports_aes_ni,
                control_flow_integrity: capabilities.supports_cet,
                shadow_stack: capabilities.supports_cet,
            },
        }
    }
}
