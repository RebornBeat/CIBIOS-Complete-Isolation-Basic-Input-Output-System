// =============================================================================
// x86 ARCHITECTURE IMPLEMENTATION - cibios/src/arch/x86/mod.rs
// x86 32-bit Architecture Support for Legacy Hardware
// =============================================================================

// External x86 dependencies
use anyhow::{Context, Result as AnyhowResult};
use serde::{Deserialize, Serialize};
use log::{debug, error, info, warn};
use std::sync::Arc;

// CIBIOS core imports for x86 integration
use crate::core::hardware::{HardwareAbstraction, HardwareCapabilities};
use crate::core::memory::{MemoryConfiguration, MemoryBoundaries};
use crate::core::isolation::{IsolationBoundaries, FirmwareIsolation};

// x86 specific module exports
pub use self::boot::{X86BootSequence, X86HardwareInit, X86BootConfiguration};
pub use self::hardware::{X86Hardware, X86Capabilities, X86Configuration};
pub use self::memory::{X86Memory, X86MemoryManager};
pub use self::main::{X86Runtime, X86FirmwareMain};

// Assembly interface imports for x86 hardware bridge functions
use crate::arch::x86::asm::{
    x86_boot_initialize_hardware,
    x86_memory_setup_boundaries,
    x86_transfer_control_to_os
};

// Shared imports for x86 integration
use shared::types::hardware::{ProcessorArchitecture, SecurityCapabilities};
use shared::types::isolation::{HardwareIsolationLevel};
use shared::types::error::{ArchitectureError, MemoryError};
use shared::protocols::handoff::HandoffData;

// Module declarations for x86 components
pub mod boot;
pub mod hardware;
pub mod memory;
pub mod main;

/// x86 architecture runtime for legacy hardware support
#[derive(Debug)]
pub struct X86Runtime {
    hardware: X86Hardware,
    memory_manager: X86MemoryManager,
    boot_config: X86BootConfiguration,
}

impl X86Runtime {
    /// Initialize x86 runtime with legacy hardware support
    pub async fn initialize() -> AnyhowResult<Self> {
        info!("Initializing x86 CIBIOS runtime for legacy hardware");

        // Initialize x86 hardware abstraction
        let hardware = X86Hardware::initialize().await
            .context("x86 hardware initialization failed")?;

        // Initialize x86 memory management
        let memory_manager = X86MemoryManager::initialize(&hardware).await
            .context("x86 memory manager initialization failed")?;

        // Load x86 boot configuration
        let boot_config = X86BootConfiguration::load_default().await
            .context("x86 boot configuration loading failed")?;

        info!("x86 runtime initialization completed");

        Ok(Self {
            hardware,
            memory_manager,
            boot_config,
        })
    }

    /// Execute x86 boot sequence for legacy systems
    pub async fn execute_boot_sequence(&self) -> AnyhowResult<()> {
        info!("Executing x86 boot sequence");

        // Initialize x86 hardware
        let hardware_result = unsafe {
            x86_boot_initialize_hardware()
        };

        if hardware_result != 0 {
            return Err(anyhow::anyhow!("x86 hardware initialization failed: {}", hardware_result));
        }

        // Setup x86 memory boundaries
        let memory_config = self.memory_manager.get_memory_configuration();
        let memory_result = unsafe {
            x86_memory_setup_boundaries(&memory_config as *const _)
        };

        if memory_result < 0 {
            return Err(anyhow::anyhow!("x86 memory setup failed: {}", memory_result));
        }

        info!("x86 boot sequence completed successfully");
        Ok(())
    }
}

// Assembly module for x86 hardware interface
mod asm {
    use shared::types::hardware::MemoryConfiguration;
    use shared::protocols::handoff::HandoffData;

    extern "C" {
        /// Initialize x86 hardware during CIBIOS boot sequence
        pub fn x86_boot_initialize_hardware() -> u32;

        /// Setup x86 memory boundaries and protection
        pub fn x86_memory_setup_boundaries(config: *const MemoryConfiguration) -> i32;

        /// Transfer control to CIBOS from x86 CIBIOS
        pub fn x86_transfer_control_to_os(entry_point: u64, handoff_data: *const HandoffData) -> !;
    }
}
