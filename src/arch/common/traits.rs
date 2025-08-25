//! # CIBIOS Architecture Common Traits
//!
//! This module defines the fundamental traits that all architecture-specific
//! implementations must satisfy. These traits establish the contracts that
//! enable CIBIOS to provide identical security guarantees across all supported
//! hardware platforms.
//!
//! ## Contract-Based Architecture
//!
//! Traditional operating systems use inheritance hierarchies that create tight
//! coupling and platform-specific behavior. CIBIOS uses trait-based contracts
//! that specify behavioral requirements without dictating implementation details.
//!
//! This approach enables:
//! 1. **Mathematical Guarantees**: Traits specify security properties that
//!    implementations must satisfy, enabling formal reasoning about security.
//! 2. **Platform Independence**: The same security code works identically
//!    across x86_64, ARM64, and RISC-V.
//! 3. **Optimal Performance**: Platform-specific implementations can use
//!    the best available hardware features while maintaining compatibility.
//!
//! ## Key Design Principles
//!
//! 1. **Capability-Based Contracts**: Traits specify what security capabilities
//!    must be provided, not how to provide them.
//! 2. **Error Handling Integration**: All traits include comprehensive error
//!    handling that preserves security properties even during failures.
//! 3. **Async-First Design**: All potentially blocking operations are async
//!    to enable efficient resource utilization without compromising isolation.

use async_trait::async_trait;
use core::{
    fmt::{Debug, Display},
    future::Future,
    pin::Pin,
};

use crate::arch::common::types::{
    ArchitectureCapabilities, HardwareFeatures, SecurityLevel, IsolationCapability,
    MemoryProtectionLevel, ProcessorFeature, SecurityFeature, CapabilityError,
};

/// Core architecture initialization trait
///
/// This trait defines the contract that all architecture-specific implementations
/// must satisfy for system initialization. The key insight is that initialization
/// is not just about "getting the system running" - it's about establishing the
/// mathematical foundations that enable security guarantees.
///
/// Every implementation of this trait must establish hardware-enforced isolation
/// boundaries that make certain privacy violations mathematically impossible.
#[async_trait]
pub trait ArchInitialization: Debug + Send + Sync {
    /// Type representing architecture-specific initialization errors
    type InitError: Debug + Display + Send + Sync;
    
    /// Type representing architecture-specific configuration
    type Config: Debug + Clone + Send + Sync;
    
    /// Initialize the architecture-specific components
    ///
    /// This method is responsible for setting up the hardware-specific features
    /// that enable CIBIOS's mathematical security guarantees. It must:
    ///
    /// 1. **Detect Hardware Capabilities**: Identify what isolation and security
    ///    features are available on this specific hardware platform.
    ///
    /// 2. **Initialize Security Features**: Enable and configure hardware
    ///    security features like virtualization, memory protection, and
    ///    cryptographic acceleration.
    ///
    /// 3. **Establish Isolation Boundaries**: Set up the hardware-enforced
    ///    boundaries that will mathematically guarantee application isolation.
    ///
    /// 4. **Verify Security Properties**: Confirm that the initialized system
    ///    can actually provide the mathematical guarantees that CIBOS requires.
    ///
    /// The method is async because hardware initialization may involve waiting
    /// for hardware components to stabilize or complete initialization sequences.
    async fn initialize(&mut self, config: Self::Config) -> Result<ArchitectureCapabilities, Self::InitError>;
    
    /// Verify that initialization was successful and security properties hold
    ///
    /// This method provides a mathematical verification that the initialization
    /// process actually established the security properties it claims to have
    /// established. This is crucial for maintaining mathematical guarantees.
    async fn verify_initialization(&self) -> Result<bool, Self::InitError>;
    
    /// Get the current architecture capabilities
    ///
    /// This returns the complete set of capabilities that are currently available
    /// and configured. This may change during runtime as features are enabled
    /// or disabled, or as hardware conditions change.
    fn current_capabilities(&self) -> &ArchitectureCapabilities;
    
    /// Check if the architecture can support a specific security level
    ///
    /// This is used by higher-level code to determine what security guarantees
    /// can be made. The implementation must return true only if it can
    /// mathematically guarantee the requested security level.
    fn can_support_security_level(&self, level: SecurityLevel) -> bool;
    
    /// Prepare for system shutdown
    ///
    /// This method safely disables hardware features in the correct order
    /// to ensure that shutdown doesn't compromise security. For example,
    /// it must ensure that memory encryption keys are properly cleared.
    async fn prepare_shutdown(&mut self) -> Result<(), Self::InitError>;
}

/// Hardware virtualization support trait
///
/// Virtualization is the foundation of CIBIOS's mathematical isolation guarantees.
/// This trait defines the contract for enabling and managing hardware virtualization
/// features that create mathematically guaranteed isolation domains.
#[async_trait]
pub trait VirtualizationSupport: Debug + Send + Sync {
    /// Type representing virtualization-specific errors
    type VirtError: Debug + Display + Send + Sync;
    
    /// Type representing a virtualized execution context
    type VirtContext: Debug + Send + Sync;
    
    /// Check if hardware virtualization is available
    ///
    /// This method determines whether the current hardware platform has
    /// virtualization capabilities that CIBIOS can use to create isolation
    /// domains. It must check both hardware presence and proper configuration.
    fn virtualization_available(&self) -> bool;
    
    /// Initialize hardware virtualization
    ///
    /// This method enables and configures hardware virtualization features.
    /// It must set up virtualization in a way that provides mathematical
    /// isolation guarantees - guest code cannot access host resources or
    /// observe other guests.
    async fn initialize_virtualization(&mut self) -> Result<(), Self::VirtError>;
    
    /// Create a new isolated virtualization context
    ///
    /// This method creates a new virtualized execution environment that is
    /// mathematically isolated from all other contexts. The implementation
    /// must guarantee that code running in this context cannot access or
    /// observe any resources belonging to other contexts.
    async fn create_context(&mut self) -> Result<Self::VirtContext, Self::VirtError>;
    
    /// Configure memory isolation for a virtualization context
    ///
    /// This method sets up memory isolation boundaries that prevent the
    /// virtualized context from accessing memory belonging to other contexts
    /// or to the host system. The isolation must be mathematically guaranteed
    /// by hardware.
    async fn configure_memory_isolation(
        &mut self,
        context: &mut Self::VirtContext,
        memory_layout: MemoryLayout,
    ) -> Result<(), Self::VirtError>;
    
    /// Enable hardware-enforced isolation features
    ///
    /// This method enables specific hardware features that strengthen isolation
    /// guarantees. Examples include extended page tables, VPID/ASID support,
    /// and hardware-enforced privilege separation.
    async fn enable_isolation_features(
        &mut self,
        context: &mut Self::VirtContext,
        features: &[IsolationCapability],
    ) -> Result<(), Self::VirtError>;
    
    /// Verify isolation properties of a context
    ///
    /// This method mathematically verifies that a virtualization context
    /// actually provides the isolation properties it claims to provide.
    /// This is essential for maintaining mathematical security guarantees.
    async fn verify_isolation(
        &self,
        context: &Self::VirtContext,
    ) -> Result<bool, Self::VirtError>;
    
    /// Destroy a virtualization context
    ///
    /// This method safely destroys a virtualization context, ensuring that
    /// all associated resources are properly cleaned up and that no information
    /// leakage occurs during the destruction process.
    async fn destroy_context(&mut self, context: Self::VirtContext) -> Result<(), Self::VirtError>;
}

/// Memory layout specification for virtualization contexts
#[derive(Debug, Clone)]
pub struct MemoryLayout {
    /// Base physical address for this context's memory
    pub base_address: u64,
    /// Size of memory allocated to this context
    pub size: u64,
    /// Memory protection flags
    pub protection: MemoryProtectionFlags,
    /// Memory encryption requirements
    pub encryption_required: bool,
}

/// Memory protection flags for isolation contexts
#[derive(Debug, Clone, Copy)]
pub struct MemoryProtectionFlags {
    /// Memory is readable
    pub readable: bool,
    /// Memory is writable
    pub writable: bool,
    /// Memory is executable
    pub executable: bool,
    /// Memory is accessible from user mode
    pub user_accessible: bool,
}

/// Memory protection and management trait
///
/// Memory protection is essential for mathematical isolation guarantees.
/// This trait defines how architecture-specific code must implement memory
/// protection mechanisms that prevent unauthorized access between isolation
/// domains.
#[async_trait]
pub trait MemoryProtection: Debug + Send + Sync {
    /// Type representing memory protection errors
    type MemoryError: Debug + Display + Send + Sync;
    
    /// Type representing a protected memory region
    type ProtectedRegion: Debug + Send + Sync;
    
    /// Get the current memory protection level
    ///
    /// This returns the strongest memory protection level that the current
    /// hardware configuration can provide. This determines what mathematical
    /// guarantees we can make about memory isolation.
    fn current_protection_level(&self) -> MemoryProtectionLevel;
    
    /// Initialize memory protection subsystem
    ///
    /// This method sets up the memory management hardware to provide the
    /// strongest possible isolation guarantees. It must configure page tables,
    /// memory encryption, and other hardware features to create mathematical
    /// isolation between memory domains.
    async fn initialize_memory_protection(&mut self) -> Result<(), Self::MemoryError>;
    
    /// Create a protected memory region with isolation guarantees
    ///
    /// This method creates a new memory region that is mathematically isolated
    /// from all other memory regions. Code with access to this region cannot
    /// access any other memory region, and vice versa.
    async fn create_protected_region(
        &mut self,
        size: u64,
        protection: MemoryProtectionFlags,
    ) -> Result<Self::ProtectedRegion, Self::MemoryError>;
    
    /// Configure memory encryption for a protected region
    ///
    /// This method enables hardware memory encryption for a protected region,
    /// providing cryptographic protection in addition to access control
    /// protection. The encryption must be mathematically secure and key
    /// management must be hardware-enforced.
    async fn configure_memory_encryption(
        &mut self,
        region: &mut Self::ProtectedRegion,
        encryption_params: MemoryEncryptionParams,
    ) -> Result<(), Self::MemoryError>;
    
    /// Verify memory protection properties
    ///
    /// This method mathematically verifies that memory protection is working
    /// correctly and that isolation boundaries are actually enforced by
    /// hardware. This is crucial for maintaining mathematical guarantees.
    async fn verify_memory_protection(
        &self,
        region: &Self::ProtectedRegion,
    ) -> Result<bool, Self::MemoryError>;
    
    /// Map memory into an isolation domain
    ///
    /// This method makes a protected memory region accessible to code running
    /// in a specific isolation domain. The mapping must preserve isolation
    /// guarantees - the domain cannot access memory not explicitly mapped to it.
    async fn map_memory_to_domain(
        &mut self,
        region: &Self::ProtectedRegion,
        domain_id: DomainId,
        virtual_address: u64,
    ) -> Result<(), Self::MemoryError>;
    
    /// Unmap memory from an isolation domain
    ///
    /// This method removes access to a memory region from an isolation domain.
    /// The unmapping must be immediate and complete - the domain must not be
    /// able to access the memory after this call returns.
    async fn unmap_memory_from_domain(
        &mut self,
        region: &Self::ProtectedRegion,
        domain_id: DomainId,
    ) -> Result<(), Self::MemoryError>;
    
    /// Destroy a protected memory region
    ///
    /// This method safely destroys a protected memory region, ensuring that
    /// all data is securely erased and that no information leakage occurs.
    /// If the region was encrypted, the encryption keys must be securely
    /// destroyed as well.
    async fn destroy_protected_region(
        &mut self,
        region: Self::ProtectedRegion,
    ) -> Result<(), Self::MemoryError>;
}

/// Memory encryption parameters
#[derive(Debug, Clone)]
pub struct MemoryEncryptionParams {
    /// Encryption algorithm to use
    pub algorithm: MemoryEncryptionAlgorithm,
    /// Key derivation method
    pub key_derivation: KeyDerivationMethod,
    /// Whether keys should be stored in hardware
    pub hardware_key_storage: bool,
}

/// Memory encryption algorithms supported by hardware
#[derive(Debug, Clone, Copy)]
pub enum MemoryEncryptionAlgorithm {
    /// AES encryption with hardware key management
    HardwareAes,
    /// ChaCha20 encryption with hardware key management
    HardwareChaCha20,
    /// Platform-specific encryption
    PlatformSpecific,
}

/// Key derivation methods for memory encryption
#[derive(Debug, Clone, Copy)]
pub enum KeyDerivationMethod {
    /// Hardware-based key derivation
    Hardware,
    /// Key derivation from platform-specific entropy
    PlatformEntropy,
    /// Key derivation from multiple entropy sources
    CombinedEntropy,
}

/// Isolation domain identifier
///
/// This represents a unique identifier for an isolation domain. Domains are
/// the fundamental unit of isolation in CIBIOS - each domain is mathematically
/// isolated from all other domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DomainId {
    /// Unique identifier for this domain
    pub id: u64,
    /// Domain type classification
    pub domain_type: DomainType,
}

/// Types of isolation domains
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomainType {
    /// Application isolation domain
    Application,
    /// System service isolation domain
    SystemService,
    /// Kernel component isolation domain
    KernelComponent,
    /// Cryptographic operation isolation domain
    CryptographicOperation,
}

/// Hardware abstraction trait that ties everything together
///
/// This trait represents the complete hardware abstraction interface that
/// CIBIOS uses to interact with platform-specific hardware. It combines
/// all the other traits into a coherent interface that provides mathematical
/// security guarantees.
#[async_trait]
pub trait HardwareAbstraction:
    ArchInitialization + VirtualizationSupport + MemoryProtection + Debug + Send + Sync
{
    /// Combined error type for all hardware operations
    type HardwareError: Debug + Display + Send + Sync;
    
    /// Get comprehensive hardware capabilities
    ///
    /// This method returns the complete set of hardware capabilities that are
    /// available and properly configured. This is used by higher-level code
    /// to determine what security guarantees can be provided.
    fn get_hardware_capabilities(&self) -> &ArchitectureCapabilities;
    
    /// Get detailed hardware features
    ///
    /// This provides more detailed information about specific hardware features
    /// that are available. This is used for performance optimization and
    /// feature-specific configuration.
    fn get_hardware_features(&self) -> &HardwareFeatures;
    
    /// Perform comprehensive hardware validation
    ///
    /// This method performs a complete validation of all hardware security
    /// features to ensure that they are working correctly and providing the
    /// expected mathematical guarantees. This should be called periodically
    /// to detect hardware failures or security compromises.
    async fn validate_hardware_security(&self) -> Result<bool, Self::HardwareError>;
    
    /// Create a complete isolation domain
    ///
    /// This method creates a complete isolation domain that includes virtualized
    /// execution context, protected memory regions, and all necessary security
    /// configurations. The domain is mathematically guaranteed to be isolated
    /// from all other domains.
    async fn create_isolation_domain(
        &mut self,
        domain_type: DomainType,
        memory_requirements: u64,
        capabilities: &[IsolationCapability],
    ) -> Result<DomainId, Self::HardwareError>;
    
    /// Configure cross-domain communication
    ///
    /// This method sets up controlled communication channels between isolation
    /// domains. The communication must preserve isolation guarantees - domains
    /// can only communicate through explicitly configured channels with
    /// well-defined security properties.
    async fn configure_domain_communication(
        &mut self,
        source_domain: DomainId,
        target_domain: DomainId,
        communication_type: CommunicationType,
    ) -> Result<CommunicationChannelId, Self::HardwareError>;
    
    /// Destroy an isolation domain
    ///
    /// This method safely destroys an isolation domain and all associated
    /// resources. All data belonging to the domain must be securely erased,
    /// and all communication channels must be properly closed.
    async fn destroy_isolation_domain(&mut self, domain_id: DomainId) -> Result<(), Self::HardwareError>;
    
    /// Perform emergency security shutdown
    ///
    /// This method immediately shuts down all hardware security features in
    /// a way that maximizes security even if the shutdown is forced. This
    /// is used when a security breach is detected or when the system must
    /// shut down immediately.
    async fn emergency_security_shutdown(&mut self) -> Result<(), Self::HardwareError>;
}

/// Types of communication between isolation domains
#[derive(Debug, Clone, Copy)]
pub enum CommunicationType {
    /// One-way message passing (source can send to target)
    OneWayMessaging,
    /// Bidirectional message passing
    BidirectionalMessaging,
    /// Shared memory region (with access control)
    ControlledSharedMemory,
    /// Synchronization primitives (mutexes, semaphores)
    Synchronization,
}

/// Communication channel identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CommunicationChannelId {
    /// Unique identifier for this channel
    pub id: u64,
    /// Source domain for this channel
    pub source: DomainId,
    /// Target domain for this channel
    pub target: DomainId,
}
