use std::path::PathBuf;

pub const DEFAULT_OUT_DIR: &str = "/data/local/tmp/";
pub const OUTPUT_SUFFIX: &str = "_dumped_";
pub const DEFAULT_MIN_REGION_SIZE: u64 = 10 * 1024;
pub const DEFAULT_MAX_REGION_SIZE: u64 = 600 * 1024 * 1024;
pub const DEFAULT_FRIDA_CHUNK_SIZE: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DumpMode {
    Ptrace,
    Frida,
}

#[derive(Clone, Debug)]
pub struct FridaConfig {
    /// Optional remote `<host>:<port>` descriptor for `frida-server`.
    pub remote: Option<String>,
    /// Prefer the USB device when multiple device types are present.
    pub use_usb: bool,
    /// Spawn the target application instead of attaching to a running pid.
    pub spawn: bool,
    /// Resume the spawned process once script injection is complete.
    pub resume_after_spawn: bool,
    /// Optional filesystem path to a custom agent script.
    pub script_path: Option<PathBuf>,
    /// Chunk size when streaming DEX payloads from the agent.
    pub chunk_size: usize,
    /// Enable embedded gadget injection instead of relying on frida-server.
    pub gadget_enabled: bool,
    /// Optional port for the gadget listener.
    pub gadget_port: Option<u16>,
    /// Keep deployed gadget files after completion.
    pub gadget_keep_files: bool,
    /// Use an existing gadget shared object instead of embedded asset.
    pub gadget_library_path: Option<PathBuf>,
    /// Use an existing gadget config file instead of auto-generated one.
    pub gadget_config_path: Option<PathBuf>,
    /// Reference an already prepared gadget deployment (MCP managed).
    pub gadget_id: Option<String>,
}

impl Default for FridaConfig {
    fn default() -> Self {
        Self {
            remote: None,
            use_usb: false,
            spawn: true,
            resume_after_spawn: true,
            script_path: None,
            chunk_size: DEFAULT_FRIDA_CHUNK_SIZE,
            gadget_enabled: false,
            gadget_port: None,
            gadget_keep_files: false,
            gadget_library_path: None,
            gadget_config_path: None,
            gadget_id: None,
        }
    }
}

#[derive(Clone)]
pub struct Config {
    pub out_dir: PathBuf,
    pub wait_time: f64,
    pub dump_all: bool,
    pub fix_header: bool,
    pub scan_step: u64,
    pub min_region: u64,
    pub max_region: u64,
    pub min_dump_size: u64,
    pub signal_trigger: bool,
    pub watch_maps: bool,
    pub stage_threshold: Option<usize>,
    pub map_patterns: Vec<String>,
    pub dump_mode: DumpMode,
    pub frida: FridaConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            out_dir: PathBuf::from(DEFAULT_OUT_DIR),
            wait_time: 0.0,
            dump_all: false,
            fix_header: false,
            scan_step: 4096,
            min_region: DEFAULT_MIN_REGION_SIZE,
            max_region: DEFAULT_MAX_REGION_SIZE,
            min_dump_size: 4096,
            signal_trigger: false,
            watch_maps: false,
            stage_threshold: None,
            map_patterns: Vec::new(),
            dump_mode: DumpMode::Ptrace,
            frida: FridaConfig::default(),
        }
    }
}

impl Config {
    /// Validate configuration parameters
    ///
    /// # Returns
    /// - `Ok(())` if configuration is valid
    /// - `Err(String)` with error message if validation fails
    pub fn validate(&self) -> Result<(), String> {
        // Region size validation
        if self.min_region > self.max_region {
            return Err(format!(
                "min_region ({}) cannot exceed max_region ({})",
                self.min_region, self.max_region
            ));
        }

        if self.min_region == 0 {
            return Err("min_region must be greater than 0".to_string());
        }

        // Scan parameters
        if self.scan_step == 0 {
            return Err("scan_step must be greater than 0".to_string());
        }

        if self.min_dump_size < 0x70 {
            return Err(format!(
                "min_dump_size ({}) must be at least 0x70 (DEX header size)",
                self.min_dump_size
            ));
        }

        // Wait time
        if self.wait_time < 0.0 {
            return Err("wait_time cannot be negative".to_string());
        }

        // Stage threshold
        if let Some(threshold) = self.stage_threshold {
            if threshold == 0 {
                return Err("stage_threshold must be greater than 0 if specified".to_string());
            }
            if !self.watch_maps {
                return Err("stage_threshold requires watch_maps to be enabled".to_string());
            }
        }

        // FRIDA configuration validation
        if self.dump_mode == DumpMode::Frida {
            self.frida.validate()?;
        }

        Ok(())
    }
}

impl FridaConfig {
    /// Validate FRIDA-specific configuration
    pub fn validate(&self) -> Result<(), String> {
        // Chunk size validation
        if self.chunk_size < 4096 {
            return Err(format!(
                "frida chunk_size ({}) must be at least 4096 bytes",
                self.chunk_size
            ));
        }

        const MAX_CHUNK_SIZE: usize = 64 * 1024 * 1024;
        if self.chunk_size > MAX_CHUNK_SIZE {
            return Err(format!(
                "frida chunk_size ({}) exceeds maximum ({})",
                self.chunk_size, MAX_CHUNK_SIZE
            ));
        }

        // Gadget configuration validation
        if self.gadget_enabled {
            if let Some(port) = self.gadget_port {
                if port == 0 {
                    return Err("gadget_port cannot be 0".to_string());
                }
            }

            if self.gadget_library_path.is_some() && self.gadget_port.is_none() {
                return Err("gadget_port must be specified when using custom gadget_library_path".to_string());
            }
        }

        // Remote and USB are mutually exclusive with gadget
        if self.gadget_enabled && self.remote.is_some() {
            return Err("gadget_enabled and remote cannot be used together (gadget is local-only)".to_string());
        }

        if self.gadget_enabled && self.use_usb {
            return Err("gadget_enabled and use_usb cannot be used together (gadget is local-only)".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_is_valid() {
        let cfg = Config::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_invalid_region_sizes() {
        let mut cfg = Config::default();
        cfg.min_region = 1000;
        cfg.max_region = 500;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_zero_scan_step() {
        let mut cfg = Config::default();
        cfg.scan_step = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_negative_wait_time() {
        let mut cfg = Config::default();
        cfg.wait_time = -1.0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_stage_threshold_without_watch_maps() {
        let mut cfg = Config::default();
        cfg.stage_threshold = Some(5);
        cfg.watch_maps = false;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_frida_chunk_size_too_small() {
        let mut cfg = Config::default();
        cfg.dump_mode = DumpMode::Frida;
        cfg.frida.chunk_size = 1024;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_gadget_with_remote() {
        let mut cfg = Config::default();
        cfg.dump_mode = DumpMode::Frida;
        cfg.frida.gadget_enabled = true;
        cfg.frida.remote = Some("127.0.0.1:27042".to_string());
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_gadget_with_usb() {
        let mut cfg = Config::default();
        cfg.dump_mode = DumpMode::Frida;
        cfg.frida.gadget_enabled = true;
        cfg.frida.use_usb = true;
        assert!(cfg.validate().is_err());
    }
}
