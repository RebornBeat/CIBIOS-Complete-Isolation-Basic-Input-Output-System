//! # CIBIOS Architecture Common Types
//!
//! This module defines the fundamental types that enable CIBIOS to provide
//! mathematical security guarantees across all supported hardware platforms.
//! These types abstract hardware capabilities in a way that allows our isolation
//! and security systems to work identically on x86_64, ARM64, and RISC-V.
//!
//! ## Design Philosophy
//!
//! Traditional operating systems create platform-specific abstractions that
//! force different behavior on different hardware. CIBIOS inverts this model:
//! we define capability-based abstractions that enable identical security
//! guarantees regardless of underlying hardware, while still exploiting
//! platform-specific optimizations.
//!
//! ## Key Architectural Principles
//!
//! 1. **Capability-Based Abstraction**: Instead of "this is an x86 system",
//!    we think "this system has virtualization capability X with isolation
//!    guarantees Y". This allows mathematical reasoning about security.
//!
//! 2. **Guaranteed Isolation**: Every type includes fields that define the
//!    mathematical isolation properties it can provide, not just functional
//!    capabilities.
//!
//! 3. **Universal Compatibility**: Types are designed so that any valid
//!    configuration works on any supported platform, with platform-specific
//!    optimizations applied transparently.

#![no_std]
#![deny(missing_docs)]

use core::{
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    convert::{TryFrom, TryInto},
    cmp::{PartialEq, Eq, PartialOrd, Ord, Ordering},
    hash::{Hash, Hasher},
    ops::{BitAnd, BitOr, BitXor, Not},
};

use serde::{Serialize, Deserialize};
use heapless::{Vec as HeaplessVec, String as HeaplessString};

/// Complete architecture capabilities for a hardware platform
///
/// This structure represents everything CIBIOS needs to know about the
/// underlying hardware to provide mathematical security guarantees. Think
/// of this as the "capability passport" for a hardware platform.
///
/// The key insight is that we don't care if something is "x86" or "ARM" - 
/// we care about what isolation and security guarantees it can mathematically
/// provide. This abstraction enables identical security behavior across
/// all platforms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchitectureCapabilities {
    /// Processor features that affect security and isolation
    /// These are the fundamental building blocks for mathematical guarantees
    pub processor_features: HeaplessVec<ProcessorFeature, 64>,
    
    /// Security features available for exploitation by CIBIOS
    /// Each feature includes isolation guarantee specifications
    pub security_features: HeaplessVec<SecurityFeature, 32>,
    
    /// Hardware virtualization support level and capabilities
    /// This determines what mathematical isolation boundaries we can establish
    pub virtualization_support: bool,
    
    /// Isolation capabilities that can be mathematically guaranteed
    /// This is what makes CIBOS revolutionary - hardware-guaranteed isolation
    pub isolation_capabilities: HeaplessVec<IsolationCapability, 16>,
    
    /// Memory protection mechanisms available
    /// These enable the memory domain isolation that makes privacy mathematically guaranteed
    pub memory_protection_level: MemoryProtectionLevel,
    
    /// Hardware entropy sources for cryptographic operations
    /// Quality of randomness affects strength of mathematical guarantees
    pub entropy_sources: HeaplessVec<EntropySource, 8>,
    
    /// Hardware acceleration capabilities for cryptographic operations
    /// These affect performance but not correctness of security guarantees
    pub crypto_acceleration: HeaplessVec<CryptoAcceleration, 16>,
}

impl ArchitectureCapabilities {
    /// Create new architecture capabilities with basic defaults
    ///
    /// This provides a minimal capability set that can work on any platform,
    /// ensuring that CIBIOS can boot even on hardware without advanced features.
    /// Advanced capabilities are detected and added dynamically.
    pub fn new_minimal() -> Self {
        ArchitectureCapabilities {
            processor_features: HeaplessVec::new(),
            security_features: HeaplessVec::new(),
            virtualization_support: false,
            isolation_capabilities: HeaplessVec::new(),
            memory_protection_level: MemoryProtectionLevel::Basic,
            entropy_sources: HeaplessVec::new(),
            crypto_acceleration: HeaplessVec::new(),
        }
    }
    
    /// Check if this architecture can provide a specific isolation guarantee
    ///
    /// This is a key method for mathematical reasoning about security. Instead
    /// of asking "is this x86?", we ask "can this hardware mathematically
    /// guarantee memory domain separation?". This enables platform-independent
    /// security proofs.
    pub fn can_guarantee_isolation(&self, required_isolation: IsolationCapability) -> bool {
        self.isolation_capabilities.iter()
            .any(|capability| capability.includes(&required_isolation))
    }
    
    /// Get the maximum security level this architecture can support
    ///
    /// Security levels are mathematical specifications, not performance metrics.
    /// A SecurityLevel::Mathematical means we can provide proofs that certain
    /// privacy violations are impossible, not just unlikely.
    pub fn maximum_security_level(&self) -> SecurityLevel {
        if self.isolation_capabilities.iter()
            .any(|cap| matches!(cap, IsolationCapability::HardwareEnforcedMemoryDomains { .. }))
            && self.virtualization_support
            && self.memory_protection_level >= MemoryProtectionLevel::HardwareEnforced {
            SecurityLevel::Mathematical
        } else if self.virtualization_support && !self.security_features.is_empty() {
            SecurityLevel::HardwareAssisted
        } else if !self.security_features.is_empty() {
            SecurityLevel::SoftwareEnforced
        } else {
            SecurityLevel::Basic
        }
    }
    
    /// Add a processor feature to the capabilities
    ///
    /// This is used during hardware detection to build up the complete
    /// capability picture. Each added feature potentially enables new
    /// security guarantees or performance optimizations.
    pub fn add_processor_feature(&mut self, feature: ProcessorFeature) -> Result<(), CapabilityError> {
        if self.processor_features.len() >= 64 {
            return Err(CapabilityError::CapacityExceeded);
        }
        
        // Avoid duplicates - each feature should be listed only once
        if !self.processor_features.iter().any(|f| f == &feature) {
            self.processor_features.push(feature)
                .map_err(|_| CapabilityError::CapacityExceeded)?;
        }
        
        Ok(())
    }
    
    /// Add a security feature to the capabilities
    pub fn add_security_feature(&mut self, feature: SecurityFeature) -> Result<(), CapabilityError> {
        if self.security_features.len() >= 32 {
            return Err(CapabilityError::CapacityExceeded);
        }
        
        if !self.security_features.iter().any(|f| f == &feature) {
            self.security_features.push(feature)
                .map_err(|_| CapabilityError::CapacityExceeded)?;
        }
        
        Ok(())
    }
    
    /// Add an isolation capability to the architecture
    ///
    /// This is called during hardware initialization to register what
    /// mathematical isolation guarantees this hardware can provide.
    /// These capabilities form the foundation of CIBOS's security model.
    pub fn add_isolation_capability(&mut self, capability: IsolationCapability) -> Result<(), CapabilityError> {
        if self.isolation_capabilities.len() >= 16 {
            return Err(CapabilityError::CapacityExceeded);
        }
        
        if !self.isolation_capabilities.iter().any(|c| c == &capability) {
            self.isolation_capabilities.push(capability)
                .map_err(|_| CapabilityError::CapacityExceeded)?;
        }
        
        Ok(())
    }
}

/// Individual processor features that affect security, performance, or isolation
///
/// These features are the atomic building blocks from which we construct
/// security guarantees. Each feature represents a specific hardware capability
/// that CIBIOS can exploit for isolation, performance, or security.
///
/// The key insight is that we classify features by their security implications,
/// not just their functional capabilities. A virtualization feature is
/// important because it enables isolation guarantees, not because it's "cool".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProcessorFeature {
    // Execution Environment Features - affect how code runs and can be isolated
    
    /// 64-bit execution capability - enables larger isolated address spaces
    LongMode,
    
    /// Supervisor Mode Execution Prevention - prevents kernel code execution in user space
    /// Critical for maintaining isolation boundaries between privilege levels
    Smep,
    
    /// Supervisor Mode Access Prevention - prevents kernel access to user memory
    /// Essential for ensuring applications can't be spied on by kernel components
    Smap,
    
    /// User Mode Instruction Prevention - prevents certain instructions in user mode
    /// Helps maintain privilege separation in isolation boundaries
    Umip,
    
    // Virtualization and Isolation Features - the core of our mathematical guarantees
    
    /// Hardware virtualization support (Intel VT-x, AMD-V, ARM Virtualization)
    /// This is fundamental to creating mathematically guaranteed isolation domains
    HardwareVirtualization,
    
    /// Extended Page Tables / Second Level Address Translation
    /// Enables guest physical to host physical memory translation with isolation
    ExtendedPageTables,
    
    /// VPID/ASID support for TLB isolation
    /// Prevents applications from observing memory access patterns of others
    VirtualProcessorId,
    
    /// Unrestricted guest execution capabilities
    /// Allows isolated domains to run any code without host intervention
    UnrestrictedGuest,
    
    // Memory Protection Features - enable mathematical privacy guarantees
    
    /// NX/XD bit support - prevents code execution from data pages
    /// Essential for preventing certain classes of attacks that could break isolation
    ExecuteDisable,
    
    /// Intel Memory Protection Extensions or ARM Pointer Authentication
    /// Provides hardware-enforced bounds checking that strengthens isolation
    MemoryProtectionExtensions,
    
    /// Intel Control-flow Enforcement Technology or ARM Branch Target Instructions
    /// Prevents ROP/JOP attacks that could potentially break isolation boundaries
    ControlFlowEnforcement,
    
    /// Hardware memory encryption (Intel TME, AMD SME, ARM Memory Tagging)
    /// Provides cryptographic protection of memory contents
    MemoryEncryption,
    
    // Cryptographic Acceleration Features - improve security performance
    
    /// AES New Instructions - hardware-accelerated symmetric encryption
    AesInstructions,
    
    /// SHA Extensions - hardware-accelerated hash computation
    ShaExtensions,
    
    /// Hardware random number generator
    /// Critical for generating cryptographically secure keys for isolation
    HardwareRng,
    
    /// Cryptographic coprocessor or security extensions
    CryptoCoprocessor,
    
    // Performance Features that affect isolation overhead
    
    /// Advanced Vector Extensions - SIMD instructions that can affect crypto performance
    Avx,
    
    /// AVX2 - enhanced vector processing for cryptographic operations
    Avx2,
    
    /// AVX-512 - high-performance vector operations (mainly Intel)
    Avx512,
    
    /// ARM NEON or other SIMD extensions
    SimdExtensions,
    
    // Platform-Specific Features
    
    /// Intel Transactional Synchronization Extensions
    /// Can be used for high-performance isolation-aware synchronization
    TransactionalSynchronization,
    
    /// ARM TrustZone security extensions
    /// Provides hardware-enforced secure/non-secure world separation
    TrustZone,
    
    /// ARM Pointer Authentication
    /// Hardware-enforced control flow integrity
    PointerAuthentication,
    
    /// ARM Memory Tagging Extensions
    /// Hardware-enforced memory safety
    MemoryTagging,
    
    /// RISC-V Physical Memory Protection
    /// Hardware memory access control
    PhysicalMemoryProtection,
    
    /// Custom security extensions (platform-specific)
    CustomSecurityExtensions,
}

impl ProcessorFeature {
    /// Check if this feature contributes to isolation capabilities
    ///
    /// Not all processor features are relevant to security - some are just
    /// performance optimizations. This method helps us focus on features
    /// that actually contribute to our mathematical security guarantees.
    pub fn contributes_to_isolation(&self) -> bool {
        matches!(self, 
            ProcessorFeature::Smep |
            ProcessorFeature::Smap |
            ProcessorFeature::Umip |
            ProcessorFeature::HardwareVirtualization |
            ProcessorFeature::ExtendedPageTables |
            ProcessorFeature::VirtualProcessorId |
            ProcessorFeature::ExecuteDisable |
            ProcessorFeature::MemoryProtectionExtensions |
            ProcessorFeature::ControlFlowEnforcement |
            ProcessorFeature::MemoryEncryption |
            ProcessorFeature::TrustZone |
            ProcessorFeature::PointerAuthentication |
            ProcessorFeature::MemoryTagging |
            ProcessorFeature::PhysicalMemoryProtection |
            ProcessorFeature::CustomSecurityExtensions
        )
    }
    
    /// Check if this feature provides cryptographic acceleration
    ///
    /// Cryptographic operations are essential for maintaining isolation
    /// boundaries. Hardware acceleration can significantly improve performance
    /// without weakening security guarantees.
    pub fn provides_crypto_acceleration(&self) -> bool {
        matches!(self,
            ProcessorFeature::AesInstructions |
            ProcessorFeature::ShaExtensions |
            ProcessorFeature::HardwareRng |
            ProcessorFeature::CryptoCoprocessor
        )
    }
    
    /// Get the security impact level of this processor feature
    ///
    /// This helps us prioritize which features to enable and how to configure
    /// them for maximum security benefit.
    pub fn security_impact(&self) -> SecurityImpact {
        match self {
            ProcessorFeature::HardwareVirtualization |
            ProcessorFeature::ExtendedPageTables |
            ProcessorFeature::TrustZone => SecurityImpact::Critical,
            
            ProcessorFeature::Smep |
            ProcessorFeature::Smap |
            ProcessorFeature::MemoryEncryption |
            ProcessorFeature::ControlFlowEnforcement => SecurityImpact::High,
            
            ProcessorFeature::VirtualProcessorId |
            ProcessorFeature::ExecuteDisable |
            ProcessorFeature::MemoryProtectionExtensions => SecurityImpact::Medium,
            
            ProcessorFeature::AesInstructions |
            ProcessorFeature::ShaExtensions |
            ProcessorFeature::HardwareRng => SecurityImpact::Medium,
            
            _ => SecurityImpact::Low,
        }
    }
}

/// Security impact levels for processor features
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityImpact {
    /// Low impact - nice to have but not essential for security
    Low,
    /// Medium impact - contributes to security but system can work without it
    Medium,
    /// High impact - important for security, system should prefer to have it
    High,
    /// Critical impact - essential for mathematical security guarantees
    Critical,
}

/// Security features available on the hardware platform
///
/// These represent higher-level security capabilities that are built from
/// processor features. While processor features are atomic hardware capabilities,
/// security features represent composed capabilities that provide specific
/// security guarantees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecurityFeature {
    /// Hardware-enforced privilege separation
    /// Guarantees that user code cannot access kernel memory or resources
    HardwarePrivilegeSeparation,
    
    /// Hardware-enforced memory isolation
    /// Guarantees that processes cannot access each other's memory
    HardwareMemoryIsolation,
    
    /// Hardware-enforced execution isolation
    /// Guarantees that processes cannot observe each other's execution
    HardwareExecutionIsolation,
    
    /// Hardware-supported cryptographic operations
    /// Provides acceleration for encryption/decryption needed for privacy
    HardwareCryptographicSupport,
    
    /// Hardware random number generation
    /// Provides high-quality entropy for cryptographic key generation
    HardwareRandomGeneration,
    
    /// Trusted execution environment
    /// Provides a secure area for running sensitive code
    TrustedExecutionEnvironment,
    
    /// Hardware-enforced code integrity
    /// Prevents modification of code during execution
    HardwareCodeIntegrity,
    
    /// Hardware-enforced data integrity
    /// Detects modification of data in memory
    HardwareDataIntegrity,
    
    /// Hardware-enforced control flow integrity
    /// Prevents ROP/JOP attacks that could compromise isolation
    HardwareControlFlowIntegrity,
    
    /// Secure boot capabilities
    /// Ensures only cryptographically verified code can run
    SecureBootCapability,
    
    /// Hardware security module integration
    /// Provides secure key storage and cryptographic operations
    HardwareSecurityModule,
}

/// Isolation capabilities that can be mathematically guaranteed by hardware
///
/// This is the heart of what makes CIBOS revolutionary. Instead of relying
/// on software policies that can be bypassed, we use hardware features to
/// create mathematical guarantees that certain types of privacy violations
/// are physically impossible.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IsolationCapability {
    /// Hardware-enforced memory domains with mathematical isolation guarantees
    ///
    /// This capability means that the hardware can create memory domains where
    /// it is mathematically impossible for code in one domain to read or write
    /// memory in another domain. This is the foundation of our privacy guarantees.
    HardwareEnforcedMemoryDomains {
        /// Maximum number of simultaneously isolatable memory domains
        max_domains: u32,
        /// Granularity of memory isolation (minimum isolatable unit)
        granularity: MemoryGranularity,
        /// Whether domains can be dynamically created/destroyed
        dynamic_allocation: bool,
    },
    
    /// Hardware-enforced process isolation with scheduling guarantees
    ///
    /// Guarantees that processes cannot observe each other's execution timing,
    /// preventing side-channel attacks based on cache behavior or CPU usage patterns.
    HardwareEnforcedProcessIsolation {
        /// Maximum number of simultaneously isolated processes
        max_processes: u32,
        /// Whether CPU cache is partitioned between processes
        cache_partitioning: bool,
        /// Whether timing channels are eliminated
        timing_isolation: bool,
    },
    
    /// Hardware-enforced I/O isolation
    ///
    /// Guarantees that applications cannot monitor or interfere with each
    /// other's I/O operations, including network traffic and disk access.
    HardwareEnforcedIoIsolation {
        /// Whether network I/O is isolated between applications
        network_isolation: bool,
        /// Whether storage I/O is isolated between applications
        storage_isolation: bool,
        /// Whether peripheral access is isolated
        peripheral_isolation: bool,
    },
    
    /// Hardware-enforced cryptographic isolation
    ///
    /// Guarantees that cryptographic keys and operations are isolated,
    /// preventing applications from accessing each other's cryptographic material.
    HardwareEnforcedCryptographicIsolation {
        /// Whether keys are stored in hardware-protected storage
        hardware_key_storage: bool,
        /// Whether cryptographic operations are hardware-isolated
        operation_isolation: bool,
        /// Maximum number of isolated cryptographic contexts
        max_contexts: u32,
    },
}

impl IsolationCapability {
    /// Check if this capability includes (is more comprehensive than) another capability
    ///
    /// This is used for capability matching - when code requires a specific
    /// isolation guarantee, we check if the hardware can provide that guarantee
    /// or a stronger one.
    pub fn includes(&self, other: &IsolationCapability) -> bool {
        match (self, other) {
            (
                IsolationCapability::HardwareEnforcedMemoryDomains { max_domains: self_max, .. },
                IsolationCapability::HardwareEnforcedMemoryDomains { max_domains: other_max, .. }
            ) => self_max >= other_max,
            
            (
                IsolationCapability::HardwareEnforcedProcessIsolation { max_processes: self_max, .. },
                IsolationCapability::HardwareEnforcedProcessIsolation { max_processes: other_max, .. }
            ) => self_max >= other_max,
            
            // Exact match for other capability types
            _ => self == other,
        }
    }
    
    /// Get the security level that this isolation capability enables
    pub fn security_level(&self) -> SecurityLevel {
        match self {
            IsolationCapability::HardwareEnforcedMemoryDomains { .. } |
            IsolationCapability::HardwareEnforcedProcessIsolation { .. } |
            IsolationCapability::HardwareEnforcedCryptographicIsolation { .. } => {
                SecurityLevel::Mathematical
            }
            IsolationCapability::HardwareEnforcedIoIsolation { .. } => {
                SecurityLevel::HardwareAssisted
            }
        }
    }
}

/// Memory granularity for isolation capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MemoryGranularity {
    /// 4KB pages - standard page size
    Page4K,
    /// 2MB pages - large pages for better performance
    Page2M,
    /// 1GB pages - huge pages for very large applications
    Page1G,
    /// Custom granularity (platform-specific)
    Custom(u64),
}

/// Memory protection levels available on the platform
///
/// This represents the strength of memory protection that the hardware can
/// provide. Higher levels enable stronger mathematical guarantees about
/// memory isolation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MemoryProtectionLevel {
    /// Basic memory protection - minimal segmentation or paging
    /// Can prevent gross violations but no strong guarantees
    Basic,
    
    /// Standard paging with NX bit support
    /// Can prevent code execution from data pages
    Standard,
    
    /// Enhanced protection with SMEP/SMAP or similar
    /// Prevents kernel from accessing user memory inadvertently
    Enhanced,
    
    /// Hardware-enforced isolation with virtualization
    /// Can create mathematically guaranteed memory domains
    HardwareEnforced,
    
    /// Memory encryption with hardware key management
    /// Provides cryptographic protection of memory contents
    Encrypted,
}

/// Hardware entropy sources for random number generation
///
/// High-quality randomness is essential for cryptographic operations that
/// maintain isolation boundaries. We classify entropy sources by their
/// cryptographic quality and performance characteristics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntropySource {
    /// CPU-integrated hardware random number generator (RDRAND, etc.)
    CpuHardwareRng,
    
    /// Trusted Platform Module entropy source
    TpmEntropy,
    
    /// Hardware security module entropy source
    HsmEntropy,
    
    /// Environmental entropy (thermal, electrical noise)
    EnvironmentalEntropy,
    
    /// Timing-based entropy from hardware events
    TimingEntropy,
    
    /// Platform-specific hardware entropy source
    PlatformSpecific(u8),
}

impl EntropySource {
    /// Get the cryptographic quality assessment for this entropy source
    ///
    /// This affects how much we trust the randomness for cryptographic operations
    /// that protect isolation boundaries.
    pub fn cryptographic_quality(&self) -> EntropyQuality {
        match self {
            EntropySource::CpuHardwareRng => EntropyQuality::High,
            EntropySource::TpmEntropy => EntropyQuality::High,
            EntropySource::HsmEntropy => EntropyQuality::Excellent,
            EntropySource::EnvironmentalEntropy => EntropyQuality::Medium,
            EntropySource::TimingEntropy => EntropyQuality::Low,
            EntropySource::PlatformSpecific(_) => EntropyQuality::Medium,
        }
    }
}

/// Entropy quality levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EntropyQuality {
    /// Low quality - should not be used alone for cryptographic operations
    Low,
    /// Medium quality - acceptable when combined with other sources
    Medium,
    /// High quality - suitable for most cryptographic operations
    High,
    /// Excellent quality - meets highest cryptographic standards
    Excellent,
}

/// Hardware cryptographic acceleration capabilities
///
/// These capabilities affect the performance of cryptographic operations
/// but not their correctness. Faster crypto means we can use stronger
/// isolation mechanisms without performance penalties.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CryptoAcceleration {
    /// AES encryption/decryption acceleration
    AesAcceleration,
    
    /// SHA-family hash function acceleration
    ShaAcceleration,
    
    /// Elliptic curve cryptography acceleration
    EccAcceleration,
    
    /// RSA public key cryptography acceleration
    RsaAcceleration,
    
    /// ChaCha20/Poly1305 stream cipher acceleration
    ChaChaAcceleration,
    
    /// Blake3 hash function acceleration
    Blake3Acceleration,
    
    /// Generic cryptographic coprocessor
    GenericCryptoProcessor,
    
    /// Platform-specific acceleration
    PlatformSpecific(u8),
}

/// Security levels that can be achieved with different hardware capabilities
///
/// This is a key concept in CIBOS: we classify security not by implementation
/// details, but by the mathematical guarantees we can provide. Higher security
/// levels enable stronger privacy guarantees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// Basic security - relies on software-only mechanisms
    /// Can be bypassed by sufficiently sophisticated attacks
    Basic,
    
    /// Software-enforced security with some hardware assistance
    /// Significantly harder to bypass but not mathematically guaranteed
    SoftwareEnforced,
    
    /// Hardware-assisted security with some hardware guarantees
    /// Very difficult to bypass but may have some theoretical vulnerabilities
    HardwareAssisted,
    
    /// Mathematical security with hardware-enforced guarantees
    /// Certain classes of attacks are mathematically impossible
    Mathematical,
}

impl SecurityLevel {
    /// Check if this security level can provide specific guarantees
    pub fn provides_isolation_guarantees(&self) -> bool {
        matches!(self, SecurityLevel::HardwareAssisted | SecurityLevel::Mathematical)
    }
    
    /// Check if this security level provides mathematical guarantees
    pub fn provides_mathematical_guarantees(&self) -> bool {
        matches!(self, SecurityLevel::Mathematical)
    }
}

/// Hardware features as a coherent collection
///
/// This represents all the individual hardware features available on a platform,
/// organized for efficient querying and capability assessment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareFeatures {
    /// All available processor features
    pub features: HeaplessVec<ProcessorFeature, 64>,
    
    /// Overall capability assessment based on available features
    pub capability_level: HardwareCapabilityLevel,
}

impl HardwareFeatures {
    /// Create new hardware features collection
    pub fn new() -> Self {
        HardwareFeatures {
            features: HeaplessVec::new(),
            capability_level: HardwareCapabilityLevel::Basic,
        }
    }
    
    /// Add a hardware feature to the collection
    pub fn add_feature(&mut self, feature: ProcessorFeature) -> Result<(), CapabilityError> {
        if self.features.len() >= 64 {
            return Err(CapabilityError::CapacityExceeded);
        }
        
        if !self.features.contains(&feature) {
            self.features.push(feature)
                .map_err(|_| CapabilityError::CapacityExceeded)?;
            self.update_capability_level();
        }
        
        Ok(())
    }
    
    /// Check if a specific feature is available
    pub fn has_feature(&self, feature: ProcessorFeature) -> bool {
        self.features.contains(&feature)
    }
    
    /// Check if all features in a set are available
    pub fn has_all_features(&self, required_features: &[ProcessorFeature]) -> bool {
        required_features.iter().all(|feature| self.has_feature(*feature))
    }
    
    /// Get all features that contribute to isolation capabilities
    pub fn isolation_features(&self) -> impl Iterator<Item = &ProcessorFeature> {
        self.features.iter().filter(|f| f.contributes_to_isolation())
    }
    
    /// Get all features that provide cryptographic acceleration
    pub fn crypto_features(&self) -> impl Iterator<Item = &ProcessorFeature> {
        self.features.iter().filter(|f| f.provides_crypto_acceleration())
    }
    
    /// Update the overall capability level based on available features
    fn update_capability_level(&mut self) {
        let critical_features = self.features.iter()
            .filter(|f| f.security_impact() == SecurityImpact::Critical)
            .count();
        
        let high_features = self.features.iter()
            .filter(|f| f.security_impact() == SecurityImpact::High)
            .count();
        
        self.capability_level = if critical_features >= 2 && high_features >= 4 {
            HardwareCapabilityLevel::Advanced
        } else if critical_features >= 1 && high_features >= 2 {
            HardwareCapabilityLevel::Enhanced
        } else if high_features >= 1 {
            HardwareCapabilityLevel::Standard
        } else {
            HardwareCapabilityLevel::Basic
        };
    }
}

impl Default for HardwareFeatures {
    fn default() -> Self {
        Self::new()
    }
}

/// Hardware capability levels based on available features
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HardwareCapabilityLevel {
    /// Basic capabilities - minimal feature set
    Basic,
    /// Standard capabilities - typical modern processor
    Standard,
    /// Enhanced capabilities - high-end processor with security features
    Enhanced,
    /// Advanced capabilities - cutting-edge processor with advanced security
    Advanced,
}

/// Errors that can occur during capability management
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityError {
    /// Attempted to add more capabilities than storage allows
    CapacityExceeded,
    /// Capability configuration is invalid
    InvalidConfiguration,
    /// Required capability is not available
    CapabilityUnavailable,
    /// Capability conflict detected
    CapabilityConflict,
}

impl Display for CapabilityError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            CapabilityError::CapacityExceeded => write!(f, "Capability storage capacity exceeded"),
            CapabilityError::InvalidConfiguration => write!(f, "Invalid capability configuration"),
            CapabilityError::CapabilityUnavailable => write!(f, "Required capability not available"),
            CapabilityError::CapabilityConflict => write!(f, "Capability conflict detected"),
        }
    }
}
