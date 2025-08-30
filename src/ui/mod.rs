// CIBIOS UI MODULE ORGANIZATION - cibios/src/ui/mod.rs  
pub mod cibios_ui {
    //! User interface components for CIBIOS firmware
    
    use anyhow::{Context, Result as AnyhowResult};
    use serde::{Deserialize, Serialize};
    use log::{debug, error, info, warn};
    use std::collections::HashMap;
    
    // UI component exports
    pub use self::setup::{FirmwareSetupInterface, HardwareConfigurationUI, SetupWizard};
    pub use self::boot_menu::{BootMenuInterface, BootOptions, BootSelection};
    pub use self::recovery::{RecoveryInterface, RecoveryOptions, DiagnosticsDisplay};
    pub use self::diagnostics::{DiagnosticsInterface, HardwareTestResults, SystemStatus};
    
    // UI module declarations
    pub mod setup;
    pub mod boot_menu;
    pub mod recovery;
    pub mod diagnostics;
    
    /// Main firmware setup interface for initial configuration
    #[derive(Debug)]
    pub struct FirmwareSetupInterface {
        pub hardware_detector: HardwareDetector,
        pub configuration_manager: SetupConfigurationManager,
        pub ui_renderer: FirmwareUIRenderer,
    }
    
    #[derive(Debug)]
    pub struct HardwareDetector {
        pub detected_hardware: HashMap<String, HardwareComponent>,
    }
    
    #[derive(Debug, Clone)]
    pub struct HardwareComponent {
        pub component_type: ComponentType,
        pub vendor: String,
        pub model: String,
        pub capabilities: Vec<String>,
    }
    
    #[derive(Debug, Clone)]
    pub enum ComponentType {
        Processor,
        Memory,
        Storage,
        Network,
        Display,
        Input,
    }
    
    #[derive(Debug)]
    pub struct SetupConfigurationManager {
        pub current_config: SetupConfiguration,
    }
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SetupConfiguration {
        pub authentication_method: shared::types::authentication::AuthenticationMethod,
        pub isolation_preferences: shared::types::isolation::BoundaryConfiguration,
        pub hardware_acceleration: bool,
    }
    
    #[derive(Debug)]
    pub struct FirmwareUIRenderer {
        pub display_mode: DisplayMode,
    }
    
    #[derive(Debug, Clone)]
    pub enum DisplayMode {
        Text,
        BasicGraphics,
    }
}
