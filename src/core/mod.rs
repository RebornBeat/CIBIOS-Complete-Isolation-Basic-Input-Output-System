// =============================================================================
// CIBIOS CORE MODULE ORGANIZATION - cibios/src/core/mod.rs
// =============================================================================

//! Core CIBIOS firmware functionality
//! 
//! This module contains the essential firmware components that provide
//! hardware abstraction, cryptographic verification, and isolation
//! enforcement at the firmware level.

// External dependencies for core functionality
use anyhow::{Context, Result as AnyhowResult};
use serde::{Deserialize, Serialize};
use log::{debug, error, info, warn};

// Internal core module exports
pub use self::boot::{BootSequence, BootConfiguration, BootResult, BootError};
pub use self::hardware::{HardwareAbstraction, HardwareCapabilities, HardwareConfiguration, HardwareError};
pub use self::crypto::{CryptographicEngine, VerificationEngine, SignatureVerification, CryptoError};
pub use self::isolation::{IsolationBoundaries, IsolationEnforcement, FirmwareIsolation, IsolationError};
pub use self::memory::{MemoryInitialization, MemoryConfiguration, MemoryBoundaries, MemoryError};
pub use self::verification::{ImageVerification, ComponentVerification, IntegrityVerification, VerificationError};
pub use self::handoff::{OSHandoffData, ControlTransfer, HandoffProtocol, HandoffError};

// Shared type imports
use shared::types::hardware::{HardwarePlatform, ProcessorArchitecture, SecurityCapabilities};
use shared::types::isolation::{IsolationLevel, BoundaryConfiguration};
use shared::types::error::{CIBIOSError, SystemError};
use shared::crypto::verification::{SignatureAlgorithm, HashAlgorithm};

// Core module declarations
pub mod boot;
pub mod hardware;
pub mod crypto;
pub mod isolation;
pub mod memory;
pub mod verification;
pub mod handoff;

/// Main CIBIOS runtime structure coordinating firmware operation
#[derive(Debug)]
pub struct CIBIOSRuntime {
    pub hardware: HardwareAbstraction,
    pub isolation: IsolationBoundaries,
    pub crypto: CryptographicEngine,
    pub memory: MemoryConfiguration,
}

/// Firmware configuration loaded during initialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareConfiguration {
    pub platform: HardwarePlatform,
    pub architecture: ProcessorArchitecture,
    pub security: SecurityCapabilities,
    pub isolation: BoundaryConfiguration,
}

/// Result of firmware initialization operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitializationResult {
    pub success: bool,
    pub hardware_ready: bool,
    pub isolation_active: bool,
    pub crypto_initialized: bool,
}
