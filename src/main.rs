// =============================================================================
// CIBIOS FIRMWARE - cibios/src/main.rs
// Complete Isolation Basic I/O System Executable Entry Point
// =============================================================================

// External runtime dependencies
use anyhow::{Context, Result as AnyhowResult};
use log::{debug, error, info, warn, LevelFilter};
use env_logger::Builder as LogBuilder;
use clap::{Arg, Command, ArgMatches};
use serde::{Deserialize, Serialize};
use std::process;
use std::time::Duration;

// CIBIOS library imports
use cibios::{CIBIOSRuntime, FirmwareConfiguration, InitializationResult};
use cibios::core::boot::{BootSequence, BootConfiguration};
use cibios::core::hardware::{HardwareAbstraction, HardwareDiscovery};
use cibios::core::verification::{ImageVerification, OSImagePath};
use cibios::core::handoff::{ControlTransfer, OSEntryPoint};
use cibios::ui::setup::{FirmwareSetupInterface, SetupConfiguration};
use cibios::security::attestation::{HardwareAttestation, AttestationChain};

// Architecture-specific main imports
#[cfg(target_arch = "x86_64")]
use cibios::arch::x86_64::{X86_64Runtime, X86_64Configuration};

#[cfg(target_arch = "aarch64")]
use cibios::arch::aarch64::{AArch64Runtime, AArch64Configuration};

#[cfg(target_arch = "x86")]
use cibios::arch::x86::{X86Runtime, X86Configuration};

#[cfg(target_arch = "riscv64")]
use cibios::arch::riscv64::{RiscV64Runtime, RiscV64Configuration};

// Shared type imports
use shared::types::hardware::{HardwarePlatform, ProcessorArchitecture};
use shared::types::error::{CIBIOSError, SystemError as SharedSystemError};
use shared::types::config::{SystemConfiguration, PlatformConfiguration};
use shared::protocols::handoff::{HandoffData, HandoffResult};

/// CIBIOS firmware entry point - called when system powers on
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Architecture-specific hardware initialization
    unsafe {
        cibios::arch::x86_64::asm::x86_64_boot_initialize_hardware();
    }

    // Transfer to Rust main function
    if let Err(e) = tokio::runtime::Runtime::new()
        .expect("Failed to create async runtime")
        .block_on(firmware_main())
    {
        panic!("CIBIOS firmware initialization failed: {}", e);
    }

    // Transfer control to CIBOS never returns
    unreachable!();
}

#[cfg(target_arch = "aarch64")]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    // ARM64-specific hardware initialization
    unsafe {
        cibios::arch::aarch64::asm::aarch64_boot_initialize_hardware();
    }

    // Transfer to Rust main function
    if let Err(e) = tokio::runtime::Runtime::new()
        .expect("Failed to create async runtime")
        .block_on(firmware_main())
    {
        panic!("CIBIOS firmware initialization failed: {}", e);
    }

    unreachable!();
}

/// Main firmware initialization and OS transfer coordination
async fn firmware_main() -> AnyhowResult<()> {
    // Initialize logging for firmware operation
    LogBuilder::from_default_env()
        .filter_level(LevelFilter::Info)
        .init();

    info!("CIBIOS {} starting firmware initialization", env!("CARGO_PKG_VERSION"));

    // Initialize CIBIOS runtime with hardware detection
    let runtime = CIBIOSRuntime::initialize().await
        .context("CIBIOS runtime initialization failed")?;

    info!("Hardware initialization completed successfully");

    // Check if firmware setup is required
    if !runtime.is_configured().await? {
        info!("First boot detected - entering firmware setup");
        let setup_result = run_firmware_setup(&runtime).await
            .context("Firmware setup failed")?;
        
        if !setup_result.setup_complete {
            return Err(anyhow::anyhow!("Firmware setup was not completed"));
        }
    }

    // Load and verify CIBOS operating system
    let os_image_path = runtime.get_os_image_path().await?;
    let verified_os_image = runtime.verify_os_image(&os_image_path).await
        .context("CIBOS verification failed")?;

    info!("CIBOS operating system verified successfully");

    // Determine OS entry point
    let os_entry_point = runtime.parse_os_entry_point(&verified_os_image)
        .context("Failed to parse CIBOS entry point")?;

    // Final preparation and control transfer
    runtime.finalize_isolation_boundaries().await
        .context("Failed to finalize isolation boundaries")?;

    info!("Transferring control to CIBOS kernel");

    // Transfer control to CIBOS - this function never returns
    runtime.transfer_to_os(os_entry_point, &verified_os_image);
}

/// Run firmware setup interface for initial configuration
async fn run_firmware_setup(runtime: &CIBIOSRuntime) -> AnyhowResult<SetupResult> {
    info!("Starting firmware setup interface");

    // Create setup interface
    let setup_interface = FirmwareSetupInterface::new(runtime).await
        .context("Failed to create setup interface")?;

    // Display hardware detection results
    setup_interface.display_hardware_info().await?;

    // Configure authentication methods
    let auth_config = setup_interface.configure_authentication().await
        .context("Authentication configuration failed")?;

    // Configure isolation preferences
    let isolation_config = setup_interface.configure_isolation().await
        .context("Isolation configuration failed")?;

    // Save configuration and complete setup
    runtime.save_configuration(&auth_config, &isolation_config).await
        .context("Failed to save firmware configuration")?;

    Ok(SetupResult { setup_complete: true })
}

#[derive(Debug)]
struct SetupResult {
    setup_complete: bool,
}
