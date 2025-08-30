// =============================================================================
// x86_64 ARCHITECTURE SUBMODULE ORGANIZATION - cibios/src/arch/x86_64/boot.rs
// Module organization for x86_64 boot functionality
// =============================================================================

//! x86_64 boot sequence implementation
//! 
//! This module coordinates the x86_64-specific boot process, including
//! hardware initialization, VT-x setup, and memory configuration.

use anyhow::{Context, Result as AnyhowResult};
use serde::{Deserialize, Serialize};
use log::{debug, error, info, warn};

// CIBIOS core integration
use crate::core::boot::{BootSequence, BootConfiguration, BootResult};
use crate::core::hardware::{HardwareAbstraction, HardwareInitialization};
use crate::core::memory::{MemoryInitialization, EarlyMemorySetup};

// x86_64 specific imports
use super::hardware::{X86_64Hardware, X86_64Capabilities};
use super::memory::{X86_64Memory, X86_64MemoryManager};
use super::virtualization::{X86_64Virtualization, VTxConfiguration};

// Assembly interface imports
use super::asm::{
    x86_64_boot_initialize_hardware,
    x86_64_vt_x_enable_virtualization,
    x86_64_memory_setup_page_tables
};

// Shared types
use shared::types::hardware::{ProcessorArchitecture, HardwarePlatform};
use shared::types::isolation::{IsolationLevel, BoundaryConfiguration};

/// x86_64 boot sequence coordinator
#[derive(Debug)]
pub struct X86_64BootSequence {
    hardware: X86_64Hardware,
    memory_manager: X86_64MemoryManager,
    virtualization: Option<X86_64Virtualization>,
}

/// x86_64 boot configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X86_64BootConfiguration {
    pub enable_vt_x: bool,
    pub memory_configuration: X86_64MemoryConfiguration,
    pub isolation_configuration: BoundaryConfiguration,
}

/// x86_64 memory configuration for boot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X86_64MemoryConfiguration {
    pub page_size: PageSize,
    pub enable_pae: bool,
    pub enable_nx_bit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PageSize {
    Size4KB,
    Size2MB,
    Size1GB,
}

/// x86_64 hardware initialization coordinator
pub struct X86_64HardwareInit;

impl X86_64BootSequence {
    pub async fn initialize(config: &X86_64BootConfiguration) -> AnyhowResult<Self> {
        info!("Initializing x86_64 boot sequence");
        
        // Initialize x86_64 hardware
        let hardware = X86_64Hardware::initialize().await
            .context("x86_64 hardware initialization failed")?;
            
        // Initialize memory management
        let memory_manager = X86_64MemoryManager::initialize(&hardware).await
            .context("x86_64 memory manager initialization failed")?;
            
        // Initialize virtualization if enabled and available
        let virtualization = if config.enable_vt_x && hardware.supports_vt_x() {
            Some(X86_64Virtualization::initialize(&hardware).await
                .context("VT-x virtualization initialization failed")?)
        } else {
            None
        };
        
        Ok(Self {
            hardware,
            memory_manager,
            virtualization,
        })
    }
    
    pub async fn execute_boot_sequence(&self) -> AnyhowResult<BootResult> {
        info!("Executing x86_64 boot sequence");
        
        // Step 1: Initialize hardware through assembly
        let hardware_result = unsafe {
            x86_64_boot_initialize_hardware()
        };
        
        if hardware_result != 0 {
            return Err(anyhow::anyhow!("Hardware initialization failed: {}", hardware_result));
        }
        
        // Step 2: Setup memory and page tables
        let memory_config = self.memory_manager.get_configuration();
        let memory_result = unsafe {
            x86_64_memory_setup_page_tables(&memory_config as *const _)
        };
        
        if memory_result < 0 {
            return Err(anyhow::anyhow!("Memory setup failed: {}", memory_result));
        }
        
        // Step 3: Enable VT-x if available
        if let Some(_vt_x) = &self.virtualization {
            let vt_x_result = unsafe {
                x86_64_vt_x_enable_virtualization()
            };
            
            if vt_x_result {
                info!("VT-x virtualization enabled successfully");
            } else {
                warn!("VT-x virtualization activation failed");
            }
        }
        
        Ok(BootResult {
            success: true,
            hardware_initialized: true,
            memory_configured: true,
            virtualization_enabled: self.virtualization.is_some(),
        })
    }
}
