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
