// =============================================================================
// CIBIOS ARCHITECTURE MODULE ORGANIZATION - cibios/src/arch/mod.rs
// =============================================================================

//! Architecture-specific implementations for CIBIOS firmware
//! 
//! This module provides hardware-specific implementations for different
//! processor architectures, enabling universal compatibility while
//! maintaining optimal performance for each platform.

// Architecture-specific module declarations
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "x86")]
pub mod x86;

#[cfg(target_arch = "riscv64")]
pub mod riscv64;

// Architecture-specific re-exports based on compilation target
#[cfg(target_arch = "x86_64")]
pub use self::x86_64::{X86_64Runtime, X86_64Hardware, X86_64Boot, X86_64Virtualization};

#[cfg(target_arch = "aarch64")]
pub use self::aarch64::{AArch64Runtime, AArch64Hardware, AArch64Boot, AArch64TrustZone};

#[cfg(target_arch = "x86")]
pub use self::x86::{X86Runtime, X86Hardware, X86Boot};

#[cfg(target_arch = "riscv64")]
pub use self::riscv64::{RiscV64Runtime, RiscV64Hardware, RiscV64Boot};
