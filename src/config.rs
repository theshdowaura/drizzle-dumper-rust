use std::path::PathBuf;

use anyhow::Result;

pub const DEFAULT_OUT_DIR: &str = "/data/local/tmp/";
pub const OUTPUT_SUFFIX: &str = "_dumped_";
pub const DEFAULT_MIN_REGION_SIZE: u64 = 10 * 1024;
pub const DEFAULT_MAX_REGION_SIZE: u64 = 600 * 1024 * 1024;

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
            _ => {}
        }
        i += 1;
    }

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
    }
}
