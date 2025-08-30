// CIBIOS SECURITY MODULE ORGANIZATION - cibios/src/security/mod.rs
pub mod cibios_security {
    //! Security subsystem for CIBIOS firmware
    
    use anyhow::{Context, Result as AnyhowResult};
    use serde::{Deserialize, Serialize};
    use log::{debug, error, info, warn};
    use uuid::Uuid;
    use std::sync::Arc;
    use std::collections::HashMap;
    
    // Security component exports
    pub use self::attestation::{HardwareAttestation, AttestationResult, AttestationChain};
    pub use self::secure_boot::{SecureBootChain, BootVerification, TrustedBoot};
    pub use self::key_management::{KeyManager, CryptographicKeys, KeyDerivation};
    pub use self::tamper_detection::{TamperDetection, TamperEvent, TamperResponse};
    
    // Security module declarations
    pub mod attestation;
    pub mod secure_boot;
    pub mod key_management;
    pub mod tamper_detection;
    
    /// Hardware attestation for platform verification
    #[derive(Debug)]
    pub struct HardwareAttestation {
        pub platform_identity: PlatformIdentity,
        pub attestation_chain: AttestationChain,
        pub verification_keys: Arc<VerificationKeySet>,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PlatformIdentity {
        pub platform_id: Uuid,
        pub hardware_hash: String,
        pub firmware_version: String,
        pub attestation_timestamp: chrono::DateTime<chrono::Utc>,
    }
    
    #[derive(Debug)]
    pub struct AttestationChain {
        pub chain_elements: Vec<AttestationElement>,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AttestationElement {
        pub element_type: AttestationType,
        pub measurement: Vec<u8>,
        pub signature: Vec<u8>,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum AttestationType {
        Hardware,
        Firmware,
        Configuration,
    }
    
    #[derive(Debug)]
    pub struct VerificationKeySet {
        pub signing_keys: HashMap<String, ed25519_dalek::PublicKey>,
        pub verification_keys: HashMap<String, rsa::RsaPublicKey>,
    }
}
