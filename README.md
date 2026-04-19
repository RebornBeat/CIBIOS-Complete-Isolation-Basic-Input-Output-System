# CIBIOS: Complete Isolation Basic Input/Output System
**Boot Firmware Foundation for Universal Privacy Protection**

## The Firmware Revolution: Security from Power-On

The Complete Isolation Basic Input/Output System (CIBIOS) is boot firmware that establishes isolation guarantees from the moment hardware powers on, creating the hardware foundation on which CIBOS builds its operating environment. CIBIOS implements the Hybrid Isolation Paradigm's architectural principles at the firmware layer, ensuring that the isolation properties CIBOS relies on are hardware-established before any operating system code executes.

Traditional firmware operates on trust-based models where each component must trust every other component, creating cascade failure scenarios where compromise of any element undermines entire system security. When conventional computers start, BIOS or UEFI firmware trusts the bootloader, which trusts the operating system kernel, creating dependency chains where system security depends on the trustworthiness of every individual component in sequence. Compromise at any link breaks the entire chain.

CIBIOS eliminates foundational vulnerabilities by implementing isolation principles at firmware level. Rather than depending on trust relationships, CIBIOS establishes hardware-enforced isolation boundaries, performs cryptographic or lightweight verification depending on the configured profile, and transfers control to CIBOS in a state where isolation is already active — not requested by the OS, but established by the firmware before the OS begins. CIBOS inherits isolation as a starting condition, not as something it must set up for itself.

CIBIOS is designed to boot CIBOS. These two systems are architected together as a complete stack. CIBIOS establishes the hardware foundation; CIBOS builds the execution environment on top of that foundation. They share a build system, feature flags, and architectural principles derived from HIP.

---

## HIP at the Firmware Layer

CIBIOS implements HIP's architectural principles at firmware level. The isolation properties that CIBOS relies on are established before any operating system code executes.

Before kernel execution, CIBIOS establishes:
- Memory isolation boundaries between regions
- Hardware-enforced component boundaries before drivers load
- Cryptographic verification chains where the profile requires them
- The lane memory regions that CIBOS will populate
- SMT configuration appropriate to the profile
- Hardware configuration record for CIBOS to inherit

The handoff mode — whether CIBIOS transfers control to CIBOS using cryptographic verification or lightweight handshake — is a shared build-time feature. CIBIOS and CIBOS are compiled together with matching handoff configuration, ensuring they agree on the protocol by construction rather than by runtime negotiation.

---

## CIBIOS Profiles

CIBIOS provides two build-time profiles. Profiles are Rust feature flag configurations selected at build time, not options presented during installation. The binary is already configured when built. Changing profiles requires rebuilding.

### CIBIOS Standard Profile

**Purpose:** Systems that need boot-level cryptographic verification of the operating system image. Appropriate for multi-user systems, networked systems, and any system where boot chain integrity is a security requirement.

**What Is Compiled In:**
- Cryptographic verification of the CIBOS kernel image before handoff
- Full boot component integrity verification chain
- Cryptographic entropy source for initialization randomness
- Hardware vendor features disabled unless explicitly added as additional feature flags
- Complete isolation boundary establishment before kernel execution
- SMT disabled by default

**How Handoff Works:**

CIBIOS Standard performs cryptographic verification of the CIBOS binary before transferring control. CIBIOS computes a hash of the loaded CIBOS image, verifies the hash against a signature using the public key embedded in firmware at build time, and proceeds only if verification succeeds. If verification fails, boot stops with a diagnostic message. A CIBOS binary compiled with mismatched feature flags will have a different hash and signature than what CIBIOS expects, causing boot to fail. This makes profile pairings self-enforcing.

**Appropriate Deployment Contexts:**
- Enterprise servers
- Multi-user workstations
- Network-connected personal systems
- Any system where boot integrity is a security requirement

**Pairs with CIBOS profiles:** Maximum Isolation, Balanced, Performance

### CIBIOS Lightweight Profile

**Purpose:** Systems where cryptographic boot verification overhead is inappropriate and physical security establishes the trust boundary. Appropriate for air-gapped single-user computation systems.

**What Is Compiled In:**
- Lightweight handshake transfer to CIBOS
- Minimal boot parameter verification
- Event-driven parallel hardware initialization
- Isolation boundary establishment before kernel execution
- SMT enabled by default

**What Is Not Compiled In:**
- Cryptographic signature verification of CIBOS image
- Measured boot sequence
- Attestation chain

**How Handoff Works:**

CIBIOS Lightweight loads the CIBOS kernel into memory, establishes isolation boundaries, writes hardware configuration parameters to an agreed memory location, and transfers control to the CIBOS entry point. No signatures are verified. Trust is established by the physical environment: in a physically secured single-user system, the only entity loading software onto the boot media is the trusted user.

**Why This Is Not a Security Compromise:**
A cryptographic verification chain protects against an adversary who could modify the CIBOS binary without physical access to the boot media. In a physically secured single-user air-gapped system, this adversary does not exist. Cryptographic verification in this context adds overhead without protecting against any realistic threat. Lightweight profile is correct threat modeling.

**Appropriate Deployment Contexts:**
- Air-gapped research and computation systems
- Single-user offline computation environments
- Physically secured development platforms

**Pairs with CIBOS profiles:** Compute, Performance (offline)

---

## SMT Configuration at Boot

CIBIOS configures Simultaneous Multithreading (SMT) at boot before transferring control to CIBOS. CIBOS inherits the SMT configuration established by CIBIOS.

| CIBIOS Profile | SMT Default | Reason |
|---|---|---|
| Standard | Disabled | Adversarial environments require hardware side-channel elimination |
| Lightweight | Enabled | Air-gapped environments maximize computation throughput |

SMT configuration is part of the hardware state CIBIOS establishes. The hardware configuration record written by CIBIOS includes SMT status so CIBOS can accurately report execution context count.

---

## Hardware Vendor Features: Philosophy and Security Considerations

### The Default: Native Isolation Only

By default, all CIBIOS profiles use native firmware-level isolation that:
- Operates independently of all vendor proprietary code
- Provides identical isolation guarantees across all platforms
- Can be fully audited as open-source code
- Does not activate hardware vendor stacks below firmware level

Hardware vendor features introduce proprietary code into the trust model. This is the recommended configuration for all deployments.

### Intel VT-x

Intel Management Engine operates at a privilege level below firmware. Enabling VT-x activates Intel's virtualization stack which interacts with the Management Engine. Intel's virtualization components are proprietary and cannot be fully audited. The security model becomes partially dependent on Intel's undisclosed firmware when this feature is enabled.

### AMD SVM

AMD Platform Security Processor operates below firmware level. SVM activation interacts with AMD's secure processor stack. AMD's secure processor code is proprietary and unauditable.

### ARM TrustZone

ARM Trusted Firmware gains execution privileges above the operating system when TrustZone is activated. TrustOS is proprietary ARM firmware executing in the secure world. TrustZone activation means ARM's proprietary code enforces some security boundaries alongside CIBIOS.

### When Hardware Vendor Features May Be Appropriate

Hardware vendor features may be considered when performance requirements justify the vendor trust trade-off, when specific workloads benefit significantly from hardware virtualization, and when users explicitly understand and accept the security implications. These features are never enabled by default and require explicit addition as feature flags at build time.

**Enabling hardware vendor features:**
- `hardware-vendor-vtx` — Intel VT-x (documented trust implications apply)
- `hardware-vendor-svm` — AMD SVM (documented trust implications apply)
- `hardware-vendor-trustzone` — ARM TrustZone (documented trust implications apply)

---

## Universal Hardware Support

### ARM Architecture Firmware Support

CIBIOS implements comprehensive ARM processor support enabling universal deployment across mobile devices, embedded systems, single-board computers, and ARM-based servers while providing consistent isolation guarantees regardless of ARM processor capabilities or cost.

**Mobile Device Support:** CIBIOS operates across all ARM mobile processors including older smartphones that manufacturers no longer support, extending device lifetime. Mobile firmware initialization includes power management and sensor controller initialization that maintains isolation while enabling necessary mobile functionality.

**Embedded System Support:** CIBIOS operates in IoT devices, industrial control systems, and embedded platforms with minimal resource utilization while providing complete isolation guarantees. Embedded optimization maintains isolation effectiveness within resource constraints.

**Single-Board Computer Support:** CIBIOS operates on affordable computing platforms including Raspberry Pi devices, providing privacy protection independent of hardware cost.

### x86 and x64 Architecture Firmware Support

Intel and AMD processor support provides CIBIOS compatibility across desktop computers, laptops, and servers while maintaining universal compatibility across processor generations and price ranges.

**Desktop and Laptop Support:** CIBIOS enables privacy-focused computing across all x86 hardware including older systems. Legacy hardware receives the same isolation guarantees as current hardware.

**Server Platform Support:** CIBIOS enables enterprise deployment across all server hardware. Server optimization includes support for high-memory configurations and multi-processor environments.

**Legacy Hardware Extension:** CIBIOS operates effectively on older x86 systems, extending hardware lifetime.

### RISC-V Open Architecture Foundation Firmware

RISC-V processor support ensures CIBIOS compatibility with emerging open-source processor architectures. Open-source hardware integration eliminates concerns about undisclosed surveillance features while providing optimal performance through processor-specific optimization that leverages RISC-V flexibility.

---

## Boot Sequence Design

### Event-Driven Parallel Initialization

CIBIOS initialization uses event-driven sequencing consistent with HIP's architectural principles. Each initialization step proceeds when its prerequisites signal completion, not after a fixed time delay. Steps without semantic ordering dependencies proceed in parallel.

Boot time is minimized by parallel initialization where safe. The pattern of event-driven coordination is established at firmware level and inherited by CIBOS.

### Boot Performance

**CIBIOS Standard Profile:** Boot time includes cryptographic verification time, which is bounded and predictable. Total boot time from power-on to CIBOS kernel execution is measured in seconds on modern hardware with fast storage.

**CIBIOS Lightweight Profile:** Boot time excludes cryptographic verification. Under one second from power-on to CIBOS kernel execution on modern hardware with fast storage.

---

## Isolation Establishment: The Critical Pre-Kernel Work

CIBIOS's most important function is establishing isolation boundaries before the kernel executes. The isolation properties that CIBOS relies on are not set up by CIBOS itself — they are established by CIBIOS at the hardware level during boot.

### What CIBIOS Establishes Before Kernel Handoff

**Memory Isolation Boundaries:**
CIBIOS configures the memory management hardware to enforce boundaries between memory regions. Kernel memory, application memory, firmware memory, and device memory are separated by hardware-enforced boundaries. These boundaries are in place when CIBOS receives control.

**Lane Memory Regions:**
CIBIOS reserves and initializes the memory regions that CIBOS will use for lane execution contexts. These regions are isolated at the hardware level before CIBOS creates lanes within them.

**SMT Configuration:**
CIBIOS configures SMT based on profile before CIBOS receives control.

**Hardware Configuration Record:**
CIBIOS writes a complete record of hardware configuration, memory layout, initialized boundaries, and system capabilities (including SMT status and execution context count) to a known memory location. CIBOS reads this record rather than re-detecting hardware state.

### What CIBIOS Does Not Do During Boot

CIBIOS does not load or initialize user applications. CIBIOS does not configure network interfaces beyond the minimum needed for network boot in profiles that support it. CIBIOS does not establish user profiles or authentication state. These are CIBOS responsibilities.

---

## What CIBIOS Protects Against and What It Cannot Prevent

### CIBIOS Protects Against

- Software-based attacks that attempt to substitute an unauthorized CIBOS kernel (Standard profile)
- Compromise of operating system components that attempt to undermine isolation boundaries
- Software exploitation of initialization state before isolation is established
- Unauthorized operating system modification (Standard profile only)

### CIBIOS Cannot Prevent

- Hardware-level surveillance mechanisms operating below firmware level (Intel ME, AMD PSP, etc.)
- Hardware vulnerabilities in the processor itself
- Physical tampering with hardware components after manufacturing
- Attack vectors requiring only physical access to storage media (Lightweight profile — addressed by trust model)

This is honest documentation. CIBIOS provides strong guarantees against software-based attacks. Hardware-level constraints apply to all software-enforced security systems, not uniquely to CIBIOS.

---

## The CIBIOS-CIBOS Build System Relationship

### Shared Feature Flags

Some feature flags apply to both CIBIOS and CIBOS simultaneously because they describe the handoff protocol both must agree on:

- `handoff-cryptographic` — CIBIOS verifies CIBOS signature; CIBOS provides its signature for verification
- `handoff-lightweight` — CIBIOS accepts CIBOS without cryptographic verification; CIBOS does not generate verification signature

These flags are defined at the workspace root level and automatically applied to both CIBIOS and CIBOS builds. Building the two components together with mismatched handoff flags is caught at compile time by the type system.

### Preventing Mismatched Binaries

**Standard profile prevents mismatch:** A CIBIOS Standard binary computes the hash of whatever CIBOS binary is loaded and verifies it against the expected signature. A CIBOS binary built with a different feature configuration has a different hash. Boot fails with a verification error when binaries are mismatched.

**Lightweight profile accepts any valid kernel:** Because no signature verification occurs, CIBIOS Lightweight will transfer control to any valid CIBOS binary. This is acceptable in the lightweight context because the threat model assumes the user controls boot media.

---

## Development Roadmap

**Phase 1: Core Firmware Architecture Development (Months 1 to 8)**
Core firmware development establishes foundational CIBIOS architecture including hardware initialization, isolation boundary establishment, hardware abstraction, SMT configuration, and universal compatibility across supported processor architectures. Both handoff modes implemented and validated.

**Phase 2: Isolation Establishment and Validation (Months 6 to 14)**
Comprehensive testing of isolation boundary establishment across all supported hardware platforms. Validation that isolation state is correctly inherited by CIBOS. Performance optimization of boot sequences for both profiles. Hardware vendor feature implementation for opt-in use.

**Phase 3: Multi-Platform Integration and Validation (Months 12 to 20)**
Multi-platform validation across ARM, x86, x64, and RISC-V platforms. Performance validation demonstrating boot time targets. Security validation of cryptographic verification chain. Compatibility testing with CIBOS profiles.

**Phase 4: Community Development and Production Deployment (Months 18 to 24)**
Open-source collaboration infrastructure. Community contribution frameworks. Production deployment validation. Documentation completion.

---

## Future Research: Non-Binary Substrates

CIBIOS's principles — event-driven initialization, isolation boundary establishment before OS execution, lightweight handoff — are substrate-agnostic. When non-binary hardware becomes practical, CIBIOS principles map directly to whatever initialization mechanisms that substrate requires. The semantic guarantees remain the design goal regardless of substrate.

---

## Conclusion

CIBIOS represents a fundamental reimagining of boot firmware that establishes privacy and security guarantees before the operating system begins. By implementing HIP's isolation principles at the firmware layer, CIBIOS ensures that the isolation properties CIBOS depends on are hardware-established rather than software-requested.

Two profiles serve distinct deployment contexts with appropriate security-overhead trade-offs: Standard profile for cryptographic boot verification in adversarial environments, Lightweight profile for minimal-overhead boot in physically secured single-user environments.

Universal hardware support across ARM, x86, x64, and RISC-V ensures that privacy protection is independent of hardware cost, extending the democratic access to privacy that CIBOS provides at the operating system layer down to the firmware foundation.

---

**Project Repository:** github.com/cibos/complete-isolation-bios
**Documentation:** docs.cibios.org | **Community:** community.cibios.org
**Development Status:** Core architecture development and multi-platform validation phase
**Profiles:** Standard (cryptographic handoff), Lightweight (lightweight handshake)
**Supported Architectures:** ARM, x64, x86, RISC-V with universal compatibility
**Hardware Requirements:** Any 32-bit or 64-bit processor with basic memory protection
**License:** Privacy-focused open source with strong copyleft protections and hardware freedom
