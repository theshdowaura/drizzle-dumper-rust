use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};

use crate::config::{Config, DumpMode, FridaConfig};

#[derive(Parser, Debug)]
#[command(
    name = "drizzleDumper",
    about = "Android DEX dumper with ptrace and Frida helpers",
    version,
    propagate_version = true,
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Dump DEX/CDEX regions from a running Android package.
    Dump(DumpCommand),
    /// Run the drizzleDumper MCP server for remote workflows.
    McpServer(McpServerCommand),
}

#[derive(Args, Debug, Clone)]
pub struct McpServerCommand {
    /// Address to bind, defaults to 0.0.0.0:45831.
    #[arg(value_name = "BIND", default_value = "0.0.0.0:45831")]
    pub bind: String,
}

#[derive(Args, Debug, Clone)]
pub struct DumpCommand {
    /// Android application package name to target.
    pub package: String,

    /// Optional wait time before scanning/attaching (seconds).
    #[arg(value_name = "WAIT", value_parser = clap::value_parser!(f64))]
    pub wait: Option<f64>,

    /// Dump all matching DEX/CDEX regions regardless of heuristics.
    #[arg(long, action = ArgAction::SetTrue)]
    pub dump_all: bool,

    /// Recompute DEX header hashes for dumped artifacts.
    #[arg(long, action = ArgAction::SetTrue)]
    pub fix_header: bool,

    /// Output directory for artifacts.
    #[arg(long = "out", value_name = "DIR")]
    pub out_dir: Option<PathBuf>,

    /// Scan step size (bytes) for region scanning.
    #[arg(long = "scan-step", value_name = "BYTES")]
    pub scan_step: Option<u64>,

    /// Minimum region size (bytes) to consider.
    #[arg(long = "min-size", value_name = "BYTES")]
    pub min_size: Option<u64>,

    /// Maximum region size (bytes) to consider.
    #[arg(long = "max-size", value_name = "BYTES")]
    pub max_size: Option<u64>,

    /// Minimum dump size (bytes) for extracted payloads.
    #[arg(long = "min-dump-size", value_name = "BYTES")]
    pub min_dump_size: Option<u64>,

    /// Wait for SIGUSR1 to trigger dumping instead of immediate scan.
    #[arg(long = "signal-trigger", action = ArgAction::SetTrue)]
    pub signal_trigger: bool,

    /// Enable live map watching for new matching regions.
    #[arg(long = "watch-maps", action = ArgAction::SetTrue)]
    pub watch_maps: bool,

    /// Trigger when at least N matching regions are present.
    #[arg(long = "stage-threshold", value_name = "COUNT")]
    pub stage_threshold: Option<usize>,

    /// Additional map path substring(s) to track when watching maps.
    #[arg(long = "map-pattern", value_name = "PATTERN")]
    pub map_pattern: Vec<String>,

    /// Select dumping backend (ptrace or frida).
    #[arg(long = "mode", value_enum)]
    pub mode: Option<DumpBackend>,

    /// Shortcut for `--mode frida`.
    #[arg(long = "frida", action = ArgAction::SetTrue, conflicts_with = "mode")]
    pub frida_alias: bool,

    /// Remote frida-server host:port.
    #[arg(long = "frida-remote", value_name = "HOST:PORT")]
    pub frida_remote: Option<String>,

    /// Prefer USB-connected devices when selecting target.
    #[arg(long = "frida-usb", action = ArgAction::SetTrue)]
    pub frida_usb: bool,

    /// Force spawning the target application before hooking.
    #[arg(long = "frida-spawn", action = ArgAction::SetTrue, conflicts_with = "frida_attach")]
    pub frida_spawn: bool,

    /// Attach to an already-running process instead of spawning.
    #[arg(long = "frida-attach", action = ArgAction::SetTrue)]
    pub frida_attach: bool,

    /// Do not resume the spawned process automatically.
    #[arg(long = "frida-no-resume", action = ArgAction::SetTrue)]
    pub frida_no_resume: bool,

    /// Path to a custom Frida agent JavaScript file.
    #[arg(long = "frida-script", value_name = "PATH")]
    pub frida_script: Option<PathBuf>,

    /// Chunk size when streaming payloads from Frida gadget (bytes).
    #[arg(long = "frida-chunk", value_name = "BYTES")]
    pub frida_chunk: Option<usize>,

    /// Enable Frida gadget deployment workflow.
    #[arg(long = "frida-gadget", action = ArgAction::SetTrue)]
    pub frida_gadget: bool,

    /// Override Frida gadget listener port.
    #[arg(long = "frida-gadget-port", value_name = "PORT")]
    pub frida_gadget_port: Option<u16>,

    /// Keep deployed gadget files on disk after completion.
    #[arg(long = "frida-gadget-keep", action = ArgAction::SetTrue)]
    pub frida_gadget_keep: bool,

    /// Use an existing gadget shared object instead of bundled asset.
    #[arg(long = "frida-gadget-path", value_name = "PATH")]
    pub frida_gadget_path: Option<PathBuf>,

    /// Use an existing gadget config instead of auto-generated one.
    #[arg(long = "frida-gadget-config", value_name = "PATH")]
    pub frida_gadget_config: Option<PathBuf>,

    /// Reference an MCP-managed gadget deployment by identifier.
    #[arg(long = "frida-gadget-id", value_name = "ID")]
    pub frida_gadget_id: Option<String>,

    /// Seconds to wait for gadget listener readiness.
    #[arg(long = "frida-gadget-timeout", value_name = "SECONDS")]
    pub frida_gadget_timeout: Option<u64>,

    /// Milliseconds of silence before FRIDA session auto-exits.
    #[arg(long = "frida-quiet-ms", value_name = "MILLIS")]
    pub frida_quiet_ms: Option<u64>,

    /// Indicate that a system-wide Zygisk module will load the gadget.
    #[arg(long = "zygisk", action = ArgAction::SetTrue)]
    pub zygisk: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "lower")]
pub enum DumpBackend {
    Ptrace,
    Frida,
}

impl DumpBackend {
    fn into_dump_mode(self) -> DumpMode {
        match self {
            DumpBackend::Ptrace => DumpMode::Ptrace,
            DumpBackend::Frida => DumpMode::Frida,
        }
    }
}

impl DumpCommand {
    pub fn to_config(&self) -> Config {
        let mut cfg = Config::default();
        cfg.wait_time = self.wait.unwrap_or(0.0);
        cfg.dump_all = self.dump_all;
        cfg.fix_header = self.fix_header;

        if let Some(dir) = &self.out_dir {
            cfg.out_dir = dir.clone();
        }
        if let Some(step) = self.scan_step {
            cfg.scan_step = step;
        }
        if let Some(min) = self.min_size {
            cfg.min_region = min;
        }
        if let Some(max) = self.max_size {
            cfg.max_region = max;
        }
        if let Some(min_dump) = self.min_dump_size {
            cfg.min_dump_size = min_dump.max(0x70);
        }

        cfg.signal_trigger = self.signal_trigger;

        if self.watch_maps || self.stage_threshold.is_some() || !self.map_pattern.is_empty() {
            cfg.watch_maps = true;
        }

        cfg.stage_threshold = self.stage_threshold;
        cfg.map_patterns = self
            .map_pattern
            .iter()
            .map(|p| p.to_ascii_lowercase())
            .collect();

        let mut dump_mode = self.mode.unwrap_or(DumpBackend::Ptrace).into_dump_mode();
        if self.frida_alias {
            dump_mode = DumpMode::Frida;
        }
        if self.zygisk {
            dump_mode = DumpMode::Frida;
        }
        cfg.dump_mode = dump_mode;

        let mut frida_cfg = FridaConfig::default();
        frida_cfg.remote = self.frida_remote.clone();
        frida_cfg.use_usb = self.frida_usb;

        if self.frida_attach {
            frida_cfg.spawn = false;
        } else if self.frida_spawn {
            frida_cfg.spawn = true;
        }

        if self.frida_no_resume {
            frida_cfg.resume_after_spawn = false;
        }

        frida_cfg.script_path = self.frida_script.clone();
        if let Some(chunk) = self.frida_chunk {
            frida_cfg.chunk_size = chunk.max(4096);
        }

        frida_cfg.gadget_enabled = self.frida_gadget;
        frida_cfg.gadget_port = self.frida_gadget_port;
        frida_cfg.gadget_keep_files = self.frida_gadget_keep;
        frida_cfg.gadget_library_path = self.frida_gadget_path.clone();
        frida_cfg.gadget_config_path = self.frida_gadget_config.clone();
        frida_cfg.gadget_id = self.frida_gadget_id.clone();
        if let Some(timeout) = self.frida_gadget_timeout {
            frida_cfg.gadget_ready_timeout = timeout;
        }
        if let Some(quiet) = self.frida_quiet_ms {
            frida_cfg.quiet_after_complete_ms = quiet;
        }

        cfg.frida = frida_cfg;
        cfg.zygisk_enabled = self.zygisk;
        cfg
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use clap::Parser;

    fn parse_dump(args: &[&str]) -> (DumpCommand, Config) {
        let mut argv = vec!["drizzle", "dump"];
        argv.extend(args);
        let cli = Cli::try_parse_from(&argv).expect("parse dump command");
        match cli.command {
            Commands::Dump(cmd) => {
                let cfg = cmd.to_config();
                (cmd, cfg)
            }
            _ => panic!("expected dump command"),
        }
    }

    #[test]
    fn dump_options_map_into_config() {
        let (_, cfg) = parse_dump(&[
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

        assert_eq!(cfg.wait_time, 1.0);
        assert!(cfg.dump_all);
        assert!(cfg.fix_header);
        assert_eq!(cfg.out_dir, PathBuf::from("/tmp/out"));
        assert_eq!(cfg.scan_step, 2048);
        assert_eq!(cfg.min_region, 8192);
        assert_eq!(cfg.max_region, 65_536);
        assert_eq!(cfg.min_dump_size, 0x200.max(0x70));
        assert!(cfg.signal_trigger);
        assert!(cfg.watch_maps);
        assert_eq!(cfg.stage_threshold, Some(3));
        assert_eq!(cfg.map_patterns, vec!["classes.dex".to_string()]);
        assert!(!cfg.zygisk_enabled);
    }

    #[test]
    fn frida_flags_configure_frida_mode() {
        let (cmd, cfg) = parse_dump(&[
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
            "1024",
            "--frida-gadget",
            "--frida-gadget-port",
            "34567",
            "--frida-gadget-keep",
            "--frida-gadget-path",
            "/tmp/gadget.so",
            "--frida-gadget-config",
            "/tmp/gadget.json",
            "--frida-gadget-id",
            "demo-id",
            "--frida-gadget-timeout",
            "15",
            "--frida-quiet-ms",
            "5000",
        ]);

        assert_eq!(cmd.wait, None);
        assert_eq!(cfg.dump_mode, DumpMode::Frida);
        assert_eq!(cfg.frida.remote.as_deref(), Some("127.0.0.1:27042"));
        assert!(cfg.frida.use_usb);
        assert!(!cfg.frida.spawn);
        assert!(!cfg.frida.resume_after_spawn);
        assert_eq!(cfg.frida.script_path, Some(PathBuf::from("/tmp/script.js")));
        assert_eq!(cfg.frida.chunk_size, 4096.max(1024));
        assert!(cfg.frida.gadget_enabled);
        assert_eq!(cfg.frida.gadget_port, Some(34_567));
        assert!(cfg.frida.gadget_keep_files);
        assert_eq!(
            cfg.frida.gadget_library_path,
            Some(PathBuf::from("/tmp/gadget.so"))
        );
        assert_eq!(
            cfg.frida.gadget_config_path,
            Some(PathBuf::from("/tmp/gadget.json"))
        );
        assert_eq!(cfg.frida.gadget_id.as_deref(), Some("demo-id"));
        assert_eq!(cfg.frida.gadget_ready_timeout, 15);
        assert_eq!(cfg.frida.quiet_after_complete_ms, 5000);
        assert!(!cfg.zygisk_enabled);
    }

    #[test]
    fn frida_alias_switches_mode() {
        let (_, cfg) = parse_dump(&["com.example.app", "--frida"]);
        assert_eq!(cfg.dump_mode, DumpMode::Frida);
    }

    #[test]
    fn zygisk_flag_sets_config() {
        let (_, cfg) = parse_dump(&["com.example.app", "--zygisk"]);
        assert!(cfg.zygisk_enabled);
        assert_eq!(cfg.dump_mode, DumpMode::Frida);
    }
}
