use std::path::PathBuf;

use anyhow::Result;

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

pub fn parse_config(args: &[String]) -> Result<Config> {
    parse_config_from_index(args, 1)
}

/// Parse configuration options from command-line arguments where the package name
/// resides at `package_index`.
pub fn parse_config_from_index(args: &[String], package_index: usize) -> Result<Config> {
    let mut cfg = Config::default();
    let mut dump_mode = DumpMode::Ptrace;
    let mut frida_cfg = FridaConfig::default();

    let mut i = package_index + 1;
    if let Some(arg) = args.get(i) {
        if !arg.starts_with("--") {
            cfg.wait_time = arg.parse::<f64>().unwrap_or(0.0);
            i += 1;
        }
    }

    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "--dump-all" => {
                cfg.dump_all = true;
            }
            "--fix-header" => {
                cfg.fix_header = true;
            }
            "--out" => {
                if let Some(value) = args.get(i + 1) {
                    cfg.out_dir = PathBuf::from(value);
                    i += 1;
                }
            }
            "--scan-step" => {
                if let Some(value) = args.get(i + 1) {
                    cfg.scan_step = value.parse::<u64>().unwrap_or(4096);
                    i += 1;
                }
            }
            "--min-size" => {
                if let Some(value) = args.get(i + 1) {
                    cfg.min_region = value.parse::<u64>().unwrap_or(DEFAULT_MIN_REGION_SIZE);
                    i += 1;
                }
            }
            "--max-size" => {
                if let Some(value) = args.get(i + 1) {
                    cfg.max_region = value.parse::<u64>().unwrap_or(DEFAULT_MAX_REGION_SIZE);
                    i += 1;
                }
            }
            "--min-dump-size" => {
                if let Some(value) = args.get(i + 1) {
                    cfg.min_dump_size = value.parse::<u64>().unwrap_or(4096).max(0x70);
                    i += 1;
                }
            }
            "--signal-trigger" => {
                cfg.signal_trigger = true;
            }
            "--watch-maps" => {
                cfg.watch_maps = true;
            }
            "--stage-threshold" => {
                if let Some(value) = args.get(i + 1) {
                    cfg.stage_threshold = value.parse::<usize>().ok();
                    cfg.watch_maps = true;
                    i += 1;
                }
            }
            "--map-pattern" => {
                if let Some(value) = args.get(i + 1) {
                    cfg.watch_maps = true;
                    cfg.map_patterns.push(value.to_ascii_lowercase());
                    i += 1;
                }
            }
            "--mode" => {
                if let Some(value) = args.get(i + 1) {
                    dump_mode = match value.as_str() {
                        "frida" | "FRIDA" => DumpMode::Frida,
                        "ptrace" | "PTRACE" => DumpMode::Ptrace,
                        _ => dump_mode,
                    };
                    i += 1;
                }
            }
            "--frida" => {
                dump_mode = DumpMode::Frida;
            }
            "--frida-remote" => {
                if let Some(value) = args.get(i + 1) {
                    frida_cfg.remote = Some(value.to_string());
                    i += 1;
                }
            }
            "--frida-usb" => {
                frida_cfg.use_usb = true;
            }
            "--frida-attach" => {
                frida_cfg.spawn = false;
            }
            "--frida-spawn" => {
                frida_cfg.spawn = true;
            }
            "--frida-no-resume" => {
                frida_cfg.resume_after_spawn = false;
            }
            "--frida-script" => {
                if let Some(value) = args.get(i + 1) {
                    frida_cfg.script_path = Some(PathBuf::from(value));
                    i += 1;
                }
            }
            "--frida-chunk" => {
                if let Some(value) = args.get(i + 1) {
                    if let Ok(parsed) = value.parse::<usize>() {
                        frida_cfg.chunk_size = parsed.max(4096);
                    }
                    i += 1;
                }
            }
            "--frida-gadget" => {
                frida_cfg.gadget_enabled = true;
            }
            "--frida-gadget-port" => {
                if let Some(value) = args.get(i + 1) {
                    frida_cfg.gadget_port = value.parse::<u16>().ok();
                    i += 1;
                }
            }
            "--frida-gadget-keep" => {
                frida_cfg.gadget_keep_files = true;
            }
            "--frida-gadget-path" => {
                if let Some(value) = args.get(i + 1) {
                    frida_cfg.gadget_library_path = Some(PathBuf::from(value));
                    i += 1;
                }
            }
            "--frida-gadget-config" => {
                if let Some(value) = args.get(i + 1) {
                    frida_cfg.gadget_config_path = Some(PathBuf::from(value));
                    i += 1;
                }
            }
            "--frida-gadget-id" => {
                if let Some(value) = args.get(i + 1) {
                    frida_cfg.gadget_id = Some(value.to_string());
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }

    cfg.dump_mode = dump_mode;
    cfg.frida = frida_cfg;
    Ok(cfg)
}

pub fn print_usage() {
    println!(
        "[*]  Usage :\n\
         [*]    ./drizzleDumper --mcp-server [bind_addr]\n\
         [*]    ./drizzleDumper <package_name> [wait_times(s)] [options]\n\
         [*]  Options:\n\
         [*]    --dump-all               Dump all dex/cdex found in regions\n\
         [*]    --fix-header             Recompute DEX header SHA1 & Adler32\n\
         [*]    --out <dir>              Output directory (default /data/local/tmp)\n\
         [*]    --scan-step <bytes>      Scan granularity per region (default 4096)\n\
         [*]    --min-size <bytes>       Minimum region size (default 10KiB)\n\
         [*]    --max-size <bytes>       Maximum region size (default 600MiB)\n\
         [*]    --min-dump-size <bytes>  Minimum bytes to dump per hit (default 4096, fallback to region if smaller)\n\
         [*]    --signal-trigger         Wait for SIGUSR1 to trigger dumping\n\
         [*]    --watch-maps             Monitor /proc/<pid>/maps and trigger on new dex-like regions\n\
         [*]    --stage-threshold <n>    Trigger when at least N matching regions exist (implies --watch-maps)\n\
         [*]    --map-pattern <substr>   Additional substring to watch in map paths (repeatable, implies --watch-maps)\n\
         [*]    --mode <ptrace|frida>    Choose the dumping backend (default ptrace)\n\
         [*]    --frida                  Alias for --mode frida\n\
         [*]    --frida-remote <host:port> Connect to remote frida-server instead of local device\n\
         [*]    --frida-usb              Prefer USB device when selecting a FRIDA target\n\
         [*]    --frida-spawn            Spawn the target app (default)\n\
         [*]    --frida-attach           Attach to a running process instead of spawning\n\
         [*]    --frida-no-resume        Do not resume the process after spawning\n\
         [*]    --frida-script <path>    Provide custom FRIDA agent JS script\n\
         [*]    --frida-chunk <bytes>    Chunk size when streaming DEX payloads (default 16MiB)\n\
         [*]    --frida-gadget           Inject FRIDA Gadget (no frida-server required)\n\
         [*]    --frida-gadget-port <n>  Override gadget listen port (default random)\n\
         [*]    --frida-gadget-keep      Keep gadget files on disk after dumping\n\
         [*]    --frida-gadget-path <so> Supply custom gadget shared object\n\
         [*]    --frida-gadget-config <file> Supply custom gadget config JSON\n\
         [*]    --frida-gadget-id <id>   Use gadget prepared via MCP (overrides paths/port)\n\
         [*]  Example:\n\
         [*]    ./drizzleDumper com.foo.bar 0.5 --dump-all --fix-header --out /sdcard/dumps\n\
         [*]  If success, you can find the dex file in the output directory.\n\
         [*]  Good Luck!"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_config_with_offset_matches_base() {
        let base_args = build_args(&[
            "bin",
            "com.example.app",
            "1.0",
            "--dump-all",
            "--fix-header",
            "--out",
            "/tmp/out",
            "--scan-step",
            "2048",
            "--min-size",
            "8192",
            "--max-size",
            "65536",
            "--min-dump-size",
            "512",
            "--signal-trigger",
            "--watch-maps",
            "--stage-threshold",
            "3",
            "--map-pattern",
            "classes.dex",
        ]);
        let expected = parse_config(&base_args).unwrap();

        let alt_args = build_args(&[
            "bin",
            "--placeholder",
            "com.example.app",
            "1.0",
            "--dump-all",
            "--fix-header",
            "--out",
            "/tmp/out",
            "--scan-step",
            "2048",
            "--min-size",
            "8192",
            "--max-size",
            "65536",
            "--min-dump-size",
            "512",
            "--signal-trigger",
            "--watch-maps",
            "--stage-threshold",
            "3",
            "--map-pattern",
            "classes.dex",
        ]);
        let remote = parse_config_from_index(&alt_args, 2).unwrap();

        assert_eq!(remote.wait_time, expected.wait_time);
        assert_eq!(remote.dump_all, expected.dump_all);
        assert_eq!(remote.fix_header, expected.fix_header);
        assert_eq!(remote.out_dir, expected.out_dir);
        assert_eq!(remote.scan_step, expected.scan_step);
        assert_eq!(remote.min_region, expected.min_region);
        assert_eq!(remote.max_region, expected.max_region);
        assert_eq!(remote.min_dump_size, expected.min_dump_size);
        assert_eq!(remote.signal_trigger, expected.signal_trigger);
        assert_eq!(remote.watch_maps, expected.watch_maps);
        assert_eq!(remote.stage_threshold, expected.stage_threshold);
        assert_eq!(remote.map_patterns, expected.map_patterns);
        assert_eq!(remote.dump_mode, expected.dump_mode);
        assert_eq!(remote.frida.remote, expected.frida.remote);
        assert_eq!(remote.frida.use_usb, expected.frida.use_usb);
        assert_eq!(remote.frida.spawn, expected.frida.spawn);
        assert_eq!(
            remote.frida.resume_after_spawn,
            expected.frida.resume_after_spawn
        );
        assert_eq!(remote.frida.script_path, expected.frida.script_path);
        assert_eq!(remote.frida.chunk_size, expected.frida.chunk_size);
        assert_eq!(remote.frida.gadget_enabled, expected.frida.gadget_enabled);
        assert_eq!(remote.frida.gadget_port, expected.frida.gadget_port);
        assert_eq!(
            remote.frida.gadget_keep_files,
            expected.frida.gadget_keep_files
        );
        assert_eq!(
            remote.frida.gadget_library_path,
            expected.frida.gadget_library_path
        );
        assert_eq!(
            remote.frida.gadget_config_path,
            expected.frida.gadget_config_path
        );
        assert_eq!(remote.frida.gadget_id, expected.frida.gadget_id);
    }

    #[test]
    fn parse_frida_options() {
        let args = build_args(&[
            "bin",
            "com.example.app",
            "--mode",
            "frida",
            "--frida-remote",
            "127.0.0.1:27042",
            "--frida-usb",
            "--frida-attach",
            "--frida-no-resume",
            "--frida-script",
            "/tmp/script.js",
            "--frida-chunk",
            "1048576",
            "--frida-gadget",
            "--frida-gadget-port",
            "34567",
            "--frida-gadget-keep",
            "--frida-gadget-path",
            "/tmp/gadget.so",
            "--frida-gadget-config",
            "/tmp/gadget.config",
            "--frida-gadget-id",
            "demo-id",
        ]);

        let cfg = parse_config(&args).unwrap();
        assert_eq!(cfg.dump_mode, DumpMode::Frida);
        assert_eq!(cfg.frida.remote.as_deref(), Some("127.0.0.1:27042"));
        assert!(cfg.frida.use_usb);
        assert!(!cfg.frida.spawn);
        assert!(!cfg.frida.resume_after_spawn);
        assert_eq!(cfg.frida.script_path, Some(PathBuf::from("/tmp/script.js")));
        assert_eq!(cfg.frida.chunk_size, 1_048_576);
        assert!(cfg.frida.gadget_enabled);
        assert_eq!(cfg.frida.gadget_port, Some(34_567));
        assert!(cfg.frida.gadget_keep_files);
        assert_eq!(
            cfg.frida.gadget_library_path,
            Some(PathBuf::from("/tmp/gadget.so"))
        );
        assert_eq!(
            cfg.frida.gadget_config_path,
            Some(PathBuf::from("/tmp/gadget.config"))
        );
        assert_eq!(cfg.frida.gadget_id.as_deref(), Some("demo-id"));
    }
}
