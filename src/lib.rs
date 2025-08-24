//! # CIBIOS: Complete Isolation Basic Input/Output System
//! 
//! Revolutionary firmware foundation that provides mathematical security guarantees
//! through hardware-enforced isolation from the moment power is applied.
//! 
//! ## Architecture Overview
//! 
//! CIBIOS establishes the secure boot foundation that enables CIBOS to achieve
//! mathematical isolation guarantees across all supported hardware platforms:
//! - x86_64: Intel VT-x virtualization and hardware security features
//! - AArch64: ARM TrustZone and virtualization extensions  
//! - RISC-V: Platform Security Architecture and custom isolation mechanisms
//! 
//! ## Security Model
//! 
//! Unlike traditional BIOS/UEFI systems that rely on trust chains, CIBIOS
//! implements mathematical verification of system integrity through:
//! - Cryptographic verification of all boot components
//! - Hardware-enforced isolation boundary establishment
//! - Immutable security policy enforcement
//! - Anti-tampering protection with hardware validation
//! 
//! ## Integration with CIBOS
//! 
//! CIBIOS provides the hardware security foundation that CIBOS requires:
//! ```rust
//! use cibios::isolation::IsolationBoundary;
//! use cibios::crypto::VerificationResult;
//! 
//! // CIBIOS verifies CIBOS before loading
//! let verification = cibios::crypto::verify_os_image(&cibos_image)?;
//! let boundaries = cibios::isolation::setup_hardware_isolation()?;
//! cibios::boot::transfer_to_os(cibos_image, boundaries);
//! ```

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
#![feature(asm_const)]
#![feature(naked_functions)]
#![feature(global_asm)]

// External crate imports organized by functionality
// Cryptographic operations
use sha3::{Digest, Sha3_256, Sha3_512};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use blake3::{Hash as Blake3Hash, Hasher as Blake3Hasher};

// Hardware abstraction and low-level operations
use bitflags::bitflags;
use volatile::{Volatile, ReadOnly, WriteOnly, ReadWrite};
use spin::{Mutex, RwLock, Once};
use heapless::{Vec as HeaplessVec, String as HeaplessString, FnvIndexMap};

// Memory management and allocation
use linked_list_allocator::LockedHeap;
use buddy_system_allocator::LockedHeap as BuddyHeap;

// Serialization for configuration and data structures
use serde::{Serialize, Deserialize};
use postcard::{from_bytes, to_vec};

// Time and random number generation
use rand_core::{RngCore, CryptoRng};
use getrandom::getrandom;

// Architecture-specific and assembly integration
use core::arch::{asm, global_asm};
use core::mem::{size_of, align_of, MaybeUninit};
use core::ptr::{addr_of, addr_of_mut, NonNull};
use core::slice::{from_raw_parts, from_raw_parts_mut};
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};

// Error handling and result types
use core::fmt::{Debug, Display, Formatter, Result as FmtResult};
use core::convert::{TryFrom, TryInto};
use core::ops::{Deref, DerefMut, Range, RangeInclusive};

// Internal module declarations with architectural organization
pub mod arch;
pub mod crypto;
pub mod hardware;
pub mod isolation;
pub mod boot;
pub mod ui;
pub mod config;

// Platform-specific integration points
#[cfg(feature = "desktop")]
pub mod desktop;
#[cfg(feature = "mobile")]
pub mod mobile;

// Internal ecosystem imports organized by functional area
use arch::common::{ArchitectureCapabilities, HardwareFeatures, SecurityLevel};
use arch::{ArchInitialization, VirtualizationSupport, MemoryProtection};

use crypto::{
    VerificationEngine, SignatureVerification, HashComputation,
    EntropyCollection, KeyDerivation, CryptographicState
};

use hardware::{
    HardwareDetection, SecurityFeatureInitialization, PowerManagement,
    DeviceEnumeration, CapabilityDiscovery, HardwareValidation
};

use isolation::{
    BoundaryEstablishment, MemoryDomainSeparation, ContextSwitchProtection,
    ProcessorStateIsolation, InterruptIsolation, CachePartitioning
};

use boot::{
    EarlyInitialization, HardwareBootstrap, SecurityBootstrap,
    OperatingSystemLoader, BootSequenceCoordination, HandoffProtocol
};

use ui::{
    TerminalInterface, FramebufferManagement, InputHandling,
    DisplayCoordination, UserInteraction, BootProgressDisplay
};

use config::{
    SecurityPolicyEnforcement, HardwareProfileManagement,
    BootConfiguration, TamperDetection, PolicyValidation
};

// Crate-level shared types representing core CIBIOS abstractions
/// Complete system state during CIBIOS operation
#[derive(Debug, Clone)]
pub struct CibiosSystemState {
    /// Current boot phase and progress
    pub boot_phase: BootPhase,
    /// Hardware capabilities discovered during initialization
    pub hardware_capabilities: ArchitectureCapabilities,
    /// Security features successfully initialized
    pub security_state: SecurityInitializationState,
    /// Isolation boundaries established for CIBOS handoff
    pub isolation_boundaries: IsolationConfiguration,
    /// Cryptographic verification state
    pub crypto_state: CryptographicValidationState,
    /// UI subsystem status
    pub ui_state: UserInterfaceState,
    /// Power management configuration
    pub power_state: PowerManagementState,
}

/// Boot phase progression through CIBIOS initialization
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootPhase {
    /// Hardware initialization and detection
    HardwareInit,
    /// Cryptographic subsystem initialization
    CryptoInit,
    /// Security feature activation
    SecurityInit,
    /// Isolation boundary establishment
    IsolationSetup,
    /// Operating system verification and preparation
    OsVerification,
    /// Final handoff preparation
    HandoffPreparation,
    /// Successful completion
    Complete,
    /// Critical failure requiring system halt
    Failed(BootFailureReason),
}

/// Detailed failure categorization for debugging and security analysis
#[derive(Debug, Clone, Copy)]
pub enum BootFailureReason {
    /// Hardware required for security not available
    HardwareIncompatible,
    /// Cryptographic verification of boot components failed
    CryptoVerificationFailed,
    /// Security features could not be initialized
    SecurityInitializationFailed,
    /// Memory protection setup failed
    IsolationSetupFailed,
    /// CIBOS image verification failed
    OsVerificationFailed,
    /// Hardware tampering detected
    TamperingDetected,
    /// Configuration corruption detected
    ConfigurationCorrupted,
}

/// Hardware security capabilities discovered during boot
#[derive(Debug, Clone)]
pub struct SecurityInitializationState {
    /// Virtualization support (VT-x, AMD-V, ARM Virtualization)
    pub virtualization_enabled: bool,
    /// Memory protection features available
    pub memory_protection_level: MemoryProtectionLevel,
    /// Hardware security module availability
    pub hsm_available: bool,
    /// Trusted execution environment support
    pub tee_support: TeeSupport,
    /// Hardware entropy source availability
    pub hardware_entropy: bool,
    /// Secure boot chain validation
    pub secure_boot_valid: bool,
}

/// Memory protection capability levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryProtectionLevel {
    /// Basic page-level protection
    Basic,
    /// Hardware virtualization with extended page tables
    Extended,
    /// Full memory encryption and isolation
    Advanced,
}

/// Trusted execution environment support classification
#[derive(Debug, Clone)]
pub enum TeeSupport {
    /// No TEE support available
    None,
    /// Intel TXT/SGX support
    IntelTxt,
    /// ARM TrustZone support
    ArmTrustZone,
    /// AMD Memory Guard support
    AmdMemoryGuard,
    /// Custom RISC-V secure execution
    RiscVCustom,
}

/// Isolation boundary configuration for CIBOS handoff
#[derive(Debug, Clone)]
pub struct IsolationConfiguration {
    /// Memory domains established for component isolation
    pub memory_domains: HeaplessVec<MemoryDomain, 32>,
    /// CPU context switching protection
    pub context_protection: ContextProtectionConfig,
    /// Interrupt isolation configuration
    pub interrupt_isolation: InterruptIsolationConfig,
    /// Cache partitioning setup
    pub cache_partitioning: CachePartitionConfig,
    /// Hardware virtualization configuration
    pub virtualization_config: VirtualizationConfig,
}

/// Individual memory domain for component isolation
#[derive(Debug, Clone)]
pub struct MemoryDomain {
    /// Unique domain identifier
    pub domain_id: u32,
    /// Physical memory range assigned to domain
    pub memory_range: Range<u64>,
    /// Access permissions for this domain
    pub permissions: MemoryPermissions,
    /// Cryptographic key for memory encryption
    pub encryption_key: Option<[u8; 32]>,
}

/// Memory access permissions for domains
#[derive(Debug, Clone, Copy)]
pub struct MemoryPermissions {
    /// Read access allowed
    pub read: bool,
    /// Write access allowed
    pub write: bool,
    /// Execute access allowed
    pub execute: bool,
    /// DMA access allowed
    pub dma: bool,
}

/// CPU context switching protection configuration
#[derive(Debug, Clone)]
pub struct ContextProtectionConfig {
    /// Register set isolation enabled
    pub register_isolation: bool,
    /// FPU state isolation enabled
    pub fpu_isolation: bool,
    /// Debug register protection
    pub debug_protection: bool,
    /// Performance counter isolation
    pub perfcounter_isolation: bool,
}

/// Interrupt handling isolation configuration
#[derive(Debug, Clone)]
pub struct InterruptIsolationConfig {
    /// Interrupt vector table protection
    pub ivt_protection: bool,
    /// Per-domain interrupt routing
    pub domain_routing: bool,
    /// Interrupt stack isolation
    pub stack_isolation: bool,
}

/// CPU cache partitioning configuration
#[derive(Debug, Clone)]
pub struct CachePartitionConfig {
    /// L1 cache partitioning enabled
    pub l1_partitioning: bool,
    /// L2 cache partitioning enabled  
    pub l2_partitioning: bool,
    /// L3 cache partitioning enabled
    pub l3_partitioning: bool,
    /// TLB partitioning enabled
    pub tlb_partitioning: bool,
}

/// Hardware virtualization configuration
#[derive(Debug, Clone)]
pub struct VirtualizationConfig {
    /// Extended page tables enabled
    pub ept_enabled: bool,
    /// VMCS shadowing enabled
    pub vmcs_shadowing: bool,
    /// VPID support enabled
    pub vpid_enabled: bool,
    /// Unrestricted guest support
    pub unrestricted_guest: bool,
}

/// Cryptographic validation state throughout boot process
#[derive(Debug, Clone)]
pub struct CryptographicValidationState {
    /// Boot component signatures verified
    pub components_verified: HeaplessVec<ComponentVerification, 16>,
    /// Current entropy pool state
    pub entropy_state: EntropyPoolState,
    /// Key derivation state for session keys
    pub key_derivation_state: KeyDerivationState,
    /// Hardware security module state
    pub hsm_state: HsmState,
}

/// Individual component verification result
#[derive(Debug, Clone)]
pub struct ComponentVerification {
    /// Component identifier
    pub component_name: HeaplessString<32>,
    /// Verification result
    pub verified: bool,
    /// Signature algorithm used
    pub signature_algorithm: SignatureAlgorithm,
    /// Verification timestamp
    pub verification_time: u64,
    /// Component hash
    pub component_hash: [u8; 32],
}

/// Cryptographic signature algorithms supported
#[derive(Debug, Clone, Copy)]
pub enum SignatureAlgorithm {
    /// Ed25519 signature scheme
    Ed25519,
    /// RSA-4096 with PSS padding
    Rsa4096Pss,
    /// ECDSA with P-384 curve
    EcdsaP384,
    /// Post-quantum signature scheme
    PostQuantum,
}

/// Entropy collection and pool management state
#[derive(Debug, Clone)]
pub struct EntropyPoolState {
    /// Available entropy bits in pool
    pub available_entropy: u32,
    /// Hardware entropy source status
    pub hardware_sources: HeaplessVec<EntropySource, 8>,
    /// Pool initialization complete
    pub pool_initialized: bool,
    /// Last reseeding timestamp
    pub last_reseed: u64,
}

/// Individual entropy source information
#[derive(Debug, Clone)]
pub struct EntropySource {
    /// Entropy source identifier
    pub source_id: EntropySourceId,
    /// Source availability status
    pub available: bool,
    /// Entropy rate (bits per second)
    pub entropy_rate: u32,
    /// Quality assessment
    pub quality: EntropyQuality,
}

/// Hardware entropy source identification
#[derive(Debug, Clone, Copy)]
pub enum EntropySourceId {
    /// CPU hardware random number generator
    CpuHwrng,
    /// TPM entropy source
    TpmEntropy,
    /// System timing entropy
    TimingEntropy,
    /// Environmental sensor entropy
    SensorEntropy,
}

/// Entropy source quality assessment
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EntropyQuality {
    /// Low quality entropy source
    Low,
    /// Medium quality entropy source
    Medium,
    /// High quality entropy source
    High,
    /// Cryptographically verified entropy source
    Cryptographic,
}

/// Key derivation state management
#[derive(Debug, Clone)]
pub struct KeyDerivationState {
    /// Master key derivation complete
    pub master_key_derived: bool,
    /// Session keys generated
    pub session_keys_generated: bool,
    /// Key derivation algorithm in use
    pub kdf_algorithm: KdfAlgorithm,
    /// Key rotation timestamp
    pub last_rotation: u64,
}

/// Key derivation function algorithms
#[derive(Debug, Clone, Copy)]
pub enum KdfAlgorithm {
    /// HKDF with SHA-256
    HkdfSha256,
    /// HKDF with SHA-512
    HkdfSha512,
    /// Argon2id for password-based derivation
    Argon2id,
    /// PBKDF2 with SHA-256
    Pbkdf2Sha256,
}

/// Hardware Security Module state
#[derive(Debug, Clone)]
pub struct HsmState {
    /// HSM availability
    pub available: bool,
    /// HSM type identifier
    pub hsm_type: HsmType,
    /// Initialization complete
    pub initialized: bool,
    /// Supported operations
    pub capabilities: HsmCapabilities,
}

/// Hardware Security Module type identification
#[derive(Debug, Clone, Copy)]
pub enum HsmType {
    /// Discrete TPM 2.0
    Tpm2Discrete,
    /// Firmware TPM (fTPM)
    Tpm2Firmware,
    /// Intel Platform Trust Technology
    IntelPtt,
    /// ARM TrustZone secure world
    ArmTrustZone,
    /// Custom secure element
    CustomSecureElement,
}

/// HSM capability flags
#[derive(Debug, Clone)]
pub struct HsmCapabilities {
    /// Key generation support
    pub key_generation: bool,
    /// Digital signature support
    pub digital_signatures: bool,
    /// Key attestation support
    pub key_attestation: bool,
    /// Sealed storage support
    pub sealed_storage: bool,
    /// Random number generation
    pub random_generation: bool,
}

/// User interface subsystem state
#[derive(Debug, Clone)]
pub struct UserInterfaceState {
    /// Display output availability
    pub display_available: bool,
    /// Input method availability
    pub input_available: bool,
    /// Current UI mode
    pub ui_mode: UiMode,
    /// Boot progress display state
    pub progress_state: BootProgressState,
}

/// User interface operational mode
#[derive(Debug, Clone, Copy)]
pub enum UiMode {
    /// Text-mode terminal interface
    Terminal,
    /// Framebuffer graphics interface
    Framebuffer,
    /// Serial console interface
    Serial,
    /// Network remote interface
    Network,
    /// No UI available (headless)
    Headless,
}

/// Boot progress display state
#[derive(Debug, Clone)]
pub struct BootProgressState {
    /// Current progress percentage (0-100)
    pub progress_percentage: u8,
    /// Current status message
    pub status_message: HeaplessString<64>,
    /// Error messages if any
    pub error_messages: HeaplessVec<HeaplessString<128>, 8>,
    /// Detailed log entries
    pub log_entries: HeaplessVec<LogEntry, 32>,
}

/// Individual log entry for boot process
#[derive(Debug, Clone)]
pub struct LogEntry {
    /// Log entry timestamp
    pub timestamp: u64,
    /// Log severity level
    pub level: LogLevel,
    /// Log message content
    pub message: HeaplessString<128>,
    /// Source component
    pub component: HeaplessString<16>,
}

/// Log severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    /// Debug information
    Debug,
    /// Informational message
    Info,
    /// Warning condition
    Warning,
    /// Error condition
    Error,
    /// Critical system failure
    Critical,
}

/// Power management state and configuration
#[derive(Debug, Clone)]
pub struct PowerManagementState {
    /// Current power state
    pub power_state: PowerState,
    /// Available power management features
    pub pm_features: PowerManagementFeatures,
    /// Thermal management state
    pub thermal_state: ThermalState,
    /// Battery state (mobile platforms)
    pub battery_state: Option<BatteryState>,
}

/// System power states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerState {
    /// Full power operation
    Active,
    /// Reduced power operation
    PowerSave,
    /// Suspend to RAM
    Suspend,
    /// Hibernate to disk
    Hibernate,
    /// Power off
    PowerOff,
}

/// Available power management features
#[derive(Debug, Clone)]
pub struct PowerManagementFeatures {
    /// CPU frequency scaling
    pub cpu_scaling: bool,
    /// Dynamic voltage scaling
    pub voltage_scaling: bool,
    /// Sleep state support
    pub sleep_states: HeaplessVec<SleepState, 8>,
    /// Wake event configuration
    pub wake_events: HeaplessVec<WakeEvent, 16>,
}

/// CPU sleep state support
#[derive(Debug, Clone, Copy)]
pub enum SleepState {
    /// C1 - Halt state
    C1,
    /// C2 - Stop state
    C2,
    /// C3 - Sleep state
    C3,
    /// C6 - Deep sleep state
    C6,
    /// C7 - Deeper sleep state
    C7,
}

/// Wake event configuration
#[derive(Debug, Clone)]
pub struct WakeEvent {
    /// Wake event source
    pub source: WakeEventSource,
    /// Event enabled
    pub enabled: bool,
    /// Wake sensitivity
    pub sensitivity: WakeSensitivity,
}

/// Wake event sources
#[derive(Debug, Clone, Copy)]
pub enum WakeEventSource {
    /// Keyboard input
    Keyboard,
    /// Mouse input
    Mouse,
    /// Network activity
    Network,
    /// Timer event
    Timer,
    /// USB device activity
    Usb,
    /// Power button
    PowerButton,
}

/// Wake event sensitivity levels
#[derive(Debug, Clone, Copy)]
pub enum WakeSensitivity {
    /// Low sensitivity (major events only)
    Low,
    /// Medium sensitivity (normal events)
    Medium,
    /// High sensitivity (any event)
    High,
}

/// Thermal management state
#[derive(Debug, Clone)]
pub struct ThermalState {
    /// Current system temperature
    pub current_temperature: i32,
    /// Thermal zones monitored
    pub thermal_zones: HeaplessVec<ThermalZone, 8>,
    /// Cooling device status
    pub cooling_devices: HeaplessVec<CoolingDevice, 4>,
    /// Thermal policy active
    pub thermal_policy: ThermalPolicy,
}

/// Individual thermal zone monitoring
#[derive(Debug, Clone)]
pub struct ThermalZone {
    /// Zone identifier
    pub zone_id: u32,
    /// Zone name
    pub zone_name: HeaplessString<16>,
    /// Current temperature
    pub temperature: i32,
    /// Critical temperature threshold
    pub critical_temp: i32,
    /// Warning temperature threshold
    pub warning_temp: i32,
}

/// Cooling device status and control
#[derive(Debug, Clone)]
pub struct CoolingDevice {
    /// Device identifier
    pub device_id: u32,
    /// Device type
    pub device_type: CoolingDeviceType,
    /// Current cooling level (0-100)
    pub current_level: u8,
    /// Maximum cooling capability
    pub max_level: u8,
    /// Device operational status
    pub operational: bool,
}

/// Types of cooling devices
#[derive(Debug, Clone, Copy)]
pub enum CoolingDeviceType {
    /// CPU fan
    CpuFan,
    /// Case fan
    CaseFan,
    /// Liquid cooling pump
    LiquidCooling,
    /// Passive heat sink
    PassiveHeatsink,
}

/// Thermal management policy
#[derive(Debug, Clone, Copy)]
pub enum ThermalPolicy {
    /// Performance priority (higher temperatures allowed)
    Performance,
    /// Balanced thermal management
    Balanced,
    /// Conservative thermal management
    Conservative,
    /// Aggressive cooling (quiet priority)
    Quiet,
}

/// Battery state for mobile platforms
#[derive(Debug, Clone)]
pub struct BatteryState {
    /// Current charge level (0-100)
    pub charge_level: u8,
    /// Battery health status
    pub health: BatteryHealth,
    /// Charging status
    pub charging_status: ChargingStatus,
    /// Estimated remaining time (minutes)
    pub time_remaining: Option<u32>,
    /// Power consumption rate (watts)
    pub power_consumption: f32,
}

/// Battery health assessment
#[derive(Debug, Clone, Copy)]
pub enum BatteryHealth {
    /// Battery in good condition
    Good,
    /// Battery showing wear
    Fair,
    /// Battery needs replacement
    Poor,
    /// Battery critical condition
    Critical,
    /// Battery status unknown
    Unknown,
}

/// Battery charging status
#[derive(Debug, Clone, Copy)]
pub enum ChargingStatus {
    /// Battery charging
    Charging,
    /// Battery discharging
    Discharging,
    /// Battery full
    Full,
    /// Charging error
    ChargingError,
}

// Error hierarchy for CIBIOS operations
/// Comprehensive error type for all CIBIOS operations
#[derive(Debug, Clone)]
pub enum CibiosError {
    /// Hardware-related errors
    Hardware(HardwareError),
    /// Cryptographic operation errors
    Crypto(CryptoError),
    /// Boot process errors
    Boot(BootError),
    /// Configuration errors
    Config(ConfigError),
    /// UI subsystem errors
    Ui(UiError),
    /// Power management errors
    Power(PowerError),
}

/// Hardware subsystem error types
#[derive(Debug, Clone)]
pub enum HardwareError {
    /// Required hardware feature not available
    FeatureNotAvailable(HeaplessString<32>),
    /// Hardware initialization failed
    InitializationFailed(HeaplessString<64>),
    /// Hardware validation failed
    ValidationFailed(HeaplessString<64>),
    /// Hardware tampering detected
    TamperingDetected,
    /// Incompatible hardware configuration
    IncompatibleConfiguration,
}

/// Cryptographic operation error types
#[derive(Debug, Clone)]
pub enum CryptoError {
    /// Signature verification failed
    VerificationFailed,
    /// Insufficient entropy for operation
    InsufficientEntropy,
    /// Key derivation failed
    KeyDerivationFailed,
    /// Hash computation failed
    HashComputationFailed,
    /// HSM operation failed
    HsmOperationFailed(HeaplessString<32>),
}

/// Boot process error types
#[derive(Debug, Clone)]
pub enum BootError {
    /// Early initialization failed
    EarlyInitFailed(HeaplessString<64>),
    /// OS image verification failed
    OsVerificationFailed,
    /// Memory setup failed
    MemorySetupFailed,
    /// Security initialization failed
    SecurityInitFailed(HeaplessString<64>),
    /// Handoff preparation failed
    HandoffFailed,
}

/// Configuration error types
#[derive(Debug, Clone)]
pub enum ConfigError {
    /// Configuration file corrupted
    ConfigCorrupted,
    /// Invalid configuration parameter
    InvalidParameter(HeaplessString<32>),
    /// Missing required configuration
    MissingConfiguration(HeaplessString<32>),
    /// Configuration version mismatch
    VersionMismatch,
}

/// UI subsystem error types
#[derive(Debug, Clone)]
pub enum UiError {
    /// Display initialization failed
    DisplayInitFailed,
    /// Input system initialization failed
    InputInitFailed,
    /// Unsupported display mode
    UnsupportedMode,
    /// UI resources unavailable
    ResourcesUnavailable,
}

/// Power management error types
#[derive(Debug, Clone)]
pub enum PowerError {
    /// Power management initialization failed
    InitFailed,
    /// Thermal management failed
    ThermalFailed,
    /// Battery management failed
    BatteryFailed,
    /// Power state transition failed
    StateTransitionFailed,
}

// Implement Display for user-friendly error messages
impl Display for CibiosError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            CibiosError::Hardware(e) => write!(f, "Hardware error: {:?}", e),
            CibiosError::Crypto(e) => write!(f, "Cryptographic error: {:?}", e),
            CibiosError::Boot(e) => write!(f, "Boot error: {:?}", e),
            CibiosError::Config(e) => write!(f, "Configuration error: {:?}", e),
            CibiosError::Ui(e) => write!(f, "UI error: {:?}", e),
            CibiosError::Power(e) => write!(f, "Power management error: {:?}", e),
        }
    }
}

// Core trait definitions for CIBIOS ecosystem integration
/// Primary CIBIOS initialization and operation trait
pub trait CibiosCore {
    /// Initialize CIBIOS with hardware detection and security setup
    fn initialize() -> Result<Self, CibiosError> where Self: Sized;
    
    /// Get current system state
    fn system_state(&self) -> &CibiosSystemState;
    
    /// Verify and load operating system image
    fn verify_and_load_os(&mut self, os_image: &[u8]) -> Result<(), CibiosError>;
    
    /// Transfer control to verified operating system
    fn transfer_to_os(self, os_entry_point: u64) -> !;
    
    /// Handle critical system failure
    fn handle_critical_failure(&mut self, failure: BootFailureReason) -> !;
}

/// Hardware abstraction trait for cross-platform support
pub trait HardwareAbstraction {
    /// Detect and enumerate hardware capabilities
    fn detect_hardware() -> Result<ArchitectureCapabilities, HardwareError>;
    
    /// Initialize security features
    fn initialize_security() -> Result<SecurityInitializationState, HardwareError>;
    
    /// Setup memory protection and isolation
    fn setup_isolation() -> Result<IsolationConfiguration, HardwareError>;
    
    /// Configure power management
    fn configure_power_management() -> Result<PowerManagementState, HardwareError>;
}

/// Cryptographic operations trait for security functions
pub trait CryptographicOperations {
    /// Initialize cryptographic subsystem
    fn initialize_crypto() -> Result<CryptographicValidationState, CryptoError>;
    
    /// Verify component signature
    fn verify_signature(
        &self, 
        data: &[u8], 
        signature: &[u8], 
        public_key: &[u8]
    ) -> Result<bool, CryptoError>;
    
    /// Generate secure random bytes
    fn generate_random(&mut self, buffer: &mut [u8]) -> Result<(), CryptoError>;
    
    /// Derive key material
    fn derive_key(&self, seed: &[u8], salt: &[u8], output: &mut [u8]) -> Result<(), CryptoError>;
}

/// User interface abstraction for boot-time interaction
pub trait UserInterface {
    /// Initialize UI subsystem
    fn initialize_ui() -> Result<Self, UiError> where Self: Sized;
    
    /// Display boot progress
    fn display_progress(&mut self, state: &BootProgressState) -> Result<(), UiError>;
    
    /// Display error message
    fn display_error(&mut self, error: &CibiosError) -> Result<(), UiError>;
    
    /// Get user input if available
    fn get_user_input(&mut self) -> Result<Option<UserInput>, UiError>;
    
    /// Clear display
    fn clear_display(&mut self) -> Result<(), UiError>;
}

/// User input types for boot-time interaction
#[derive(Debug, Clone)]
pub enum UserInput {
    /// Keyboard key press
    KeyPress(KeyCode),
    /// Mouse/touch input
    PointerInput(PointerEvent),
    /// Gesture input (mobile)
    Gesture(GestureType),
}

/// Keyboard key codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyCode {
    /// Enter/Return key
    Enter,
    /// Escape key
    Escape,
    /// Function keys
    Function(u8),
    /// Arrow keys
    Arrow(ArrowDirection),
    /// Alphanumeric keys
    Alphanumeric(char),
    /// Special keys
    Special(SpecialKey),
}

/// Arrow key directions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArrowDirection {
    /// Up arrow
    Up,
    /// Down arrow
    Down,
    /// Left arrow
    Left,
    /// Right arrow
    Right,
}

/// Special key types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecialKey {
    /// Space bar
    Space,
    /// Backspace
    Backspace,
    /// Tab key
    Tab,
    /// Shift key
    Shift,
    /// Control key
    Control,
    /// Alt key
    Alt,
}

/// Pointer/mouse event types
#[derive(Debug, Clone)]
pub struct PointerEvent {
    /// Event type
    pub event_type: PointerEventType,
    /// X coordinate
    pub x: u32,
    /// Y coordinate
    pub y: u32,
}

/// Pointer event types
#[derive(Debug, Clone, Copy)]
pub enum PointerEventType {
    /// Button press
    Press,
    /// Button release
    Release,
    /// Pointer movement
    Move,
    /// Scroll wheel
    Scroll(ScrollDirection),
}

/// Scroll directions
#[derive(Debug, Clone, Copy)]
pub enum ScrollDirection {
    /// Scroll up
    Up,
    /// Scroll down
    Down,
    /// Scroll left
    Left,
    /// Scroll right
    Right,
}

/// Gesture types for touch interfaces
#[derive(Debug, Clone, Copy)]
pub enum GestureType {
    /// Tap gesture
    Tap,
    /// Double tap gesture
    DoubleTap,
    /// Long press gesture
    LongPress,
    /// Swipe gesture
    Swipe(SwipeDirection),
    /// Pinch gesture
    Pinch(PinchType),
}

/// Swipe gesture directions
#[derive(Debug, Clone, Copy)]
pub enum SwipeDirection {
    /// Swipe up
    Up,
    /// Swipe down
    Down,
    /// Swipe left
    Left,
    /// Swipe right
    Right,
}

/// Pinch gesture types
#[derive(Debug, Clone, Copy)]
pub enum PinchType {
    /// Pinch to zoom in
    ZoomIn,
    /// Pinch to zoom out
    ZoomOut,
}

// Public re-exports organized by functional area for clean API
/// Core CIBIOS types and functions
pub use crate::{
    CibiosSystemState, BootPhase, BootFailureReason,
    CibiosCore, CibiosError
};

/// Hardware abstraction and detection
pub use crate::{
    SecurityInitializationState, MemoryProtectionLevel, TeeSupport,
    IsolationConfiguration, MemoryDomain, MemoryPermissions,
    HardwareAbstraction, HardwareError
};

/// Cryptographic operations and security
pub use crate::{
    CryptographicValidationState, ComponentVerification, SignatureAlgorithm,
    EntropyPoolState, EntropySource, EntropySourceId, EntropyQuality,
    KeyDerivationState, KdfAlgorithm, HsmState, HsmType, HsmCapabilities,
    CryptographicOperations, CryptoError
};

/// User interface and interaction
pub use crate::{
    UserInterfaceState, UiMode, BootProgressState, LogEntry, LogLevel,
    UserInterface, UserInput, KeyCode, PointerEvent, GestureType,
    UiError
};

/// Power and thermal management
pub use crate::{
    PowerManagementState, PowerState, PowerManagementFeatures,
    ThermalState, ThermalZone, CoolingDevice, ThermalPolicy,
    BatteryState, BatteryHealth, ChargingStatus,
    PowerError
};

/// Architecture-specific integration points
pub use arch::{
    ArchitectureCapabilities, HardwareFeatures, SecurityLevel,
    ArchInitialization, VirtualizationSupport, MemoryProtection
};

/// Boot process coordination
pub use boot::{
    EarlyInitialization, HardwareBootstrap, SecurityBootstrap,
    OperatingSystemLoader, BootSequenceCoordination, HandoffProtocol,
    BootError
};

/// Configuration management
pub use config::{
    SecurityPolicyEnforcement, HardwareProfileManagement,
    BootConfiguration, TamperDetection, PolicyValidation,
    ConfigError
};
