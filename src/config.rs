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
    let wait_time = if args.len() >= 3 && !args[2].starts_with("--") {
        args[2].parse::<f64>().unwrap_or(0.0)
    } else {
        0.0
    };

    let mut cfg = Config::default();
    cfg.wait_time = wait_time;

    let mut i = 2;
    while i < args.len() {
        let a = &args[i];
        if a == "--dump-all" {
            cfg.dump_all = true;
        } else if a == "--fix-header" {
            cfg.fix_header = true;
        } else if a == "--out" && i + 1 < args.len() {
            cfg.out_dir = PathBuf::from(&args[i + 1]);
            i += 1;
        } else if a == "--scan-step" && i + 1 < args.len() {
            cfg.scan_step = args[i + 1].parse::<u64>().unwrap_or(4096);
            i += 1;
        } else if a == "--min-size" && i + 1 < args.len() {
            cfg.min_region = args[i + 1]
                .parse::<u64>()
                .unwrap_or(DEFAULT_MIN_REGION_SIZE);
            i += 1;
        } else if a == "--max-size" && i + 1 < args.len() {
            cfg.max_region = args[i + 1]
                .parse::<u64>()
                .unwrap_or(DEFAULT_MAX_REGION_SIZE);
            i += 1;
        } else if a == "--min-dump-size" && i + 1 < args.len() {
            cfg.min_dump_size = args[i + 1].parse::<u64>().unwrap_or(4096).max(0x70);
            i += 1;
        } else if a == "--signal-trigger" {
            cfg.signal_trigger = true;
        } else if a == "--watch-maps" {
            cfg.watch_maps = true;
        } else if a == "--stage-threshold" && i + 1 < args.len() {
            cfg.stage_threshold = args[i + 1].parse::<usize>().ok();
            cfg.watch_maps = true;
            i += 1;
        } else if a == "--map-pattern" && i + 1 < args.len() {
            cfg.watch_maps = true;
            cfg.map_patterns.push(args[i + 1].to_ascii_lowercase());
            i += 1;
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
