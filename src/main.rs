use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use mcp_protocol_sdk::{
    core::{error::McpError, tool::ToolHandler},
    protocol::types::{Content, ToolResult},
    server::McpServer,
    transport::websocket::WebSocketServerTransport,
};
use nix::libc::{EFAULT, EIO, EPERM};
use nix::sys::ptrace;
use nix::sys::signal::{self, SigHandler, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{getuid, Pid};
use procfs::process::{all_processes, MMPermissions, MMapPath, MemoryMap, Process};
use serde_json::{json, Value};
use sha1::{Digest, Sha1};
use tokio::signal as tokio_signal;
use tokio::{runtime::Builder as TokioRuntimeBuilder, sync::Mutex, task};

const DEFAULT_OUT_DIR: &str = "/data/local/tmp/";
const SUFFIX: &str = "_dumped_";
const DEFAULT_MIN_REGION_SIZE: u64 = 10 * 1024;
const DEFAULT_MAX_REGION_SIZE: u64 = 600 * 1024 * 1024;

static TRIGGER_DUMP: AtomicBool = AtomicBool::new(false);

#[derive(Clone)]
struct Config {
    out_dir: PathBuf,
    wait_time: f64,
    dump_all: bool,
    fix_header: bool,
    scan_step: u64,
    min_region: u64,
    max_region: u64,
    min_dump_size: u64,
    signal_trigger: bool,
    watch_maps: bool,
    stage_threshold: Option<usize>,
    map_patterns: Vec<String>,
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

#[derive(Debug)]
struct MapTriggerEvent {
    matches: usize,
    triggered_by_threshold: bool,
}

#[derive(Default)]
struct MapWatcher {
    last_count: usize,
}

impl MapWatcher {
    fn reset(&mut self) {
        self.last_count = 0;
    }

    fn observe(&mut self, pid: i32, cfg: &Config) -> Result<Option<MapTriggerEvent>> {
        let process = Process::new(pid)?;
        let maps = process.maps()?;
        let matches = maps
            .iter()
            .filter(|m| map_is_relevant(m, &cfg.map_patterns))
            .count();

        let threshold_crossed = cfg
            .stage_threshold
            .map_or(false, |th| self.last_count < th && matches >= th);
        let incremented = matches > self.last_count;

        self.last_count = matches;

        if threshold_crossed || incremented {
            Ok(Some(MapTriggerEvent {
                matches,
                triggered_by_threshold: threshold_crossed,
            }))
        } else {
            Ok(None)
        }
    }

    fn backoff(&mut self, stage: usize) {
        self.last_count = stage.saturating_sub(1);
    }
}

fn map_is_relevant(map: &MemoryMap, extra_patterns: &[String]) -> bool {
    let path = match &map.pathname {
        MMapPath::Path(p) => p.to_string_lossy().to_ascii_lowercase(),
        _ => return false,
    };

    if path.contains(".dex")
        || path.contains(".cdex")
        || path.contains(".odex")
        || path.contains(".vdex")
        || path.contains(".jar")
        || path.contains(".apk")
    {
        return true;
    }

    extra_patterns
        .iter()
        .any(|pattern| !pattern.is_empty() && path.contains(pattern))
}

extern "C" fn handle_sigusr1(_: nix::libc::c_int) {
    TRIGGER_DUMP.store(true, Ordering::SeqCst);
}

fn setup_signal_handler() -> Result<()> {
    unsafe {
        signal::signal(Signal::SIGUSR1, SigHandler::Handler(handle_sigusr1))
            .context("register SIGUSR1 handler")?;
    }
    Ok(())
}

fn run_dump_workflow(package_name: &str, cfg: &Config) -> Result<Vec<PathBuf>> {
    println!(
        "[*]  Try to Find {}{}",
        package_name,
        if cfg.wait_time > 0.0 {
            format!(" (poll interval {}s)", cfg.wait_time)
        } else {
            String::new()
        }
    );

    if cfg.signal_trigger {
        setup_signal_handler()?;
        TRIGGER_DUMP.store(false, Ordering::SeqCst);
        println!(
            "[*]  Signal trigger armed. Send `kill -SIGUSR1 {}` when ready.",
            std::process::id()
        );
    }

    if cfg.watch_maps {
        if let Some(threshold) = cfg.stage_threshold {
            println!("[*]  Map watcher threshold: at least {threshold} matching regions.");
        }
        if !cfg.map_patterns.is_empty() {
            println!(
                "[*]  Map watcher extra patterns: {}",
                cfg.map_patterns.join(", ")
            );
        }
    }

    let mut map_watcher = MapWatcher::default();
    let mut known_pid: Option<i32> = None;

    loop {
        if cfg.wait_time > 0.0 {
            thread::sleep(Duration::from_secs_f64(cfg.wait_time));
        } else if cfg.signal_trigger || cfg.watch_maps {
            thread::sleep(Duration::from_millis(200));
        }

        let pid_opt = match find_process_pid(package_name) {
            Ok(pid) => pid,
            Err(err) => {
                eprintln!("[!]  Failed to enumerate processes: {err:?}");
                continue;
            }
        };

        let pid = match pid_opt {
            Some(pid) => pid,
            None => {
                if known_pid.take().is_some() {
                    map_watcher.reset();
                }
                continue;
            }
        };

        if Some(pid) != known_pid {
            println!("[*]  Target pid is {pid}");
            map_watcher.reset();
            known_pid = Some(pid);
        }

        let mut map_event: Option<MapTriggerEvent> = None;
        if cfg.watch_maps {
            match map_watcher.observe(pid, cfg) {
                Ok(event) => {
                    map_event = event;
                }
                Err(err) => {
                    eprintln!("[!]  Failed to inspect process maps: {err:?}");
                    continue;
                }
            }
        }

        let signal_fired = cfg.signal_trigger && TRIGGER_DUMP.load(Ordering::SeqCst);
        let should_attempt = if cfg.signal_trigger || cfg.watch_maps {
            (cfg.signal_trigger && signal_fired) || (cfg.watch_maps && map_event.is_some())
        } else {
            true
        };

        if !should_attempt {
            continue;
        }

        let clone_pid = match find_clone_thread(pid) {
            Ok(Some(tid)) => tid,
            Ok(None) => continue,
            Err(err) => {
                eprintln!("[!]  Failed to enumerate threads: {err:?}");
                continue;
            }
        };

        println!("[*]  Using tid {} for dumping", clone_pid);

        if signal_fired {
            TRIGGER_DUMP.store(false, Ordering::SeqCst);
            println!("[*]  SIGUSR1 trigger received; attempting dump");
        }

        if let Some(event) = &map_event {
            let suffix = if event.triggered_by_threshold {
                cfg.stage_threshold
                    .map(|th| format!(" (>= threshold {th})"))
                    .unwrap_or_else(String::new)
            } else {
                " (new dex-like region detected)".to_string()
            };
            println!("[*]  Map watcher stage {}{}", event.matches, suffix);
        }

        match try_dump_dex(package_name, clone_pid, cfg) {
            Ok(paths) if !paths.is_empty() => {
                for p in &paths {
                    println!("[+]  dex dump into {}", p.display());
                }
                println!("[*]  Done.\n");
                return Ok(paths);
            }
            Ok(_) => {
                println!("[*]  The magic was Not Found!");
                if let Some(event) = &map_event {
                    map_watcher.backoff(event.matches);
                }
                if cfg.wait_time <= 0.0 && !cfg.signal_trigger && !cfg.watch_maps {
                    return Ok(Vec::new());
                }
            }
            Err(err) => {
                eprintln!("[!]  Error while dumping: {err:?}");
                if let Some(event) = &map_event {
                    map_watcher.backoff(event.matches);
                }
                if cfg.wait_time <= 0.0 && !cfg.signal_trigger && !cfg.watch_maps {
                    return Err(err);
                }
            }
        }
    }
}

struct DumpTool {
    guard: Mutex<()>,
}

impl Default for DumpTool {
    fn default() -> Self {
        Self {
            guard: Mutex::new(()),
        }
    }
}

#[async_trait]
impl ToolHandler for DumpTool {
    async fn call(&self, arguments: HashMap<String, Value>) -> Result<ToolResult, McpError> {
        let _lock = self.guard.lock().await;

        let package = arguments
            .get("package")
            .and_then(Value::as_str)
            .ok_or_else(|| McpError::validation("missing required string parameter `package`") )?
            .to_string();

        let cfg = config_from_tool_arguments(&arguments)?;

        let join = task::spawn_blocking(move || run_dump_workflow(&package, &cfg))
            .await
            .map_err(|err| McpError::internal(format!("dump task join error: {err}")))?;

        let paths = join.map_err(|err| McpError::internal(err.to_string()))?;

        let message = if paths.is_empty() {
            "No dex/cdex regions dumped. Check server logs for details.".to_string()
        } else {
            let rendered = paths
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join("\n- ");
            format!("Dumped {} file(s):\n- {}", paths.len(), rendered)
        };

        Ok(ToolResult {
            content: vec![Content::text(message)],
            is_error: None,
            structured_content: None,
            meta: None,
        })
    }
}

fn parse_bool(name: &str, value: &Value) -> Result<bool, McpError> {
    value
        .as_bool()
        .ok_or_else(|| McpError::validation(format!("`{name}` must be a boolean")))
}

fn parse_u64(name: &str, value: &Value) -> Result<u64, McpError> {
    value
        .as_u64()
        .or_else(|| value.as_f64().map(|v| v.max(0.0) as u64))
        .ok_or_else(|| McpError::validation(format!("`{name}` must be a positive number")))
}

fn parse_f64(name: &str, value: &Value) -> Result<f64, McpError> {
    value
        .as_f64()
        .ok_or_else(|| McpError::validation(format!("`{name}` must be a number")))
}

fn parse_string(name: &str, value: &Value) -> Result<String, McpError> {
    value
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| McpError::validation(format!("`{name}` must be a string")))
}

fn config_from_tool_arguments(arguments: &HashMap<String, Value>) -> Result<Config, McpError> {
    let mut cfg = Config::default();

    if let Some(wait) = arguments.get("wait_time") {
        cfg.wait_time = parse_f64("wait_time", wait)?;
    }
    if let Some(out_dir) = arguments.get("out_dir") {
        cfg.out_dir = PathBuf::from(parse_string("out_dir", out_dir)?);
    }
    if let Some(dump_all) = arguments.get("dump_all") {
        cfg.dump_all = parse_bool("dump_all", dump_all)?;
    }
    if let Some(fix) = arguments.get("fix_header") {
        cfg.fix_header = parse_bool("fix_header", fix)?;
    }
    if let Some(step) = arguments.get("scan_step") {
        cfg.scan_step = parse_u64("scan_step", step)?;
    }
    if let Some(min_region) = arguments
        .get("min_size")
        .or_else(|| arguments.get("min_region"))
    {
        cfg.min_region = parse_u64("min_size", min_region)?;
    }
    if let Some(max_region) = arguments
        .get("max_size")
        .or_else(|| arguments.get("max_region"))
    {
        cfg.max_region = parse_u64("max_size", max_region)?;
    }
    if let Some(min_dump) = arguments.get("min_dump_size") {
        cfg.min_dump_size = parse_u64("min_dump_size", min_dump)?.max(0x70);
    }
    if let Some(signal_trigger) = arguments.get("signal_trigger") {
        cfg.signal_trigger = parse_bool("signal_trigger", signal_trigger)?;
    }
    if let Some(watch_maps) = arguments.get("watch_maps") {
        cfg.watch_maps = parse_bool("watch_maps", watch_maps)?;
    }
    if let Some(stage_threshold) = arguments.get("stage_threshold") {
        cfg.stage_threshold = Some(parse_u64("stage_threshold", stage_threshold)? as usize);
        cfg.watch_maps = true;
    }
    if let Some(patterns) = arguments.get("map_patterns") {
        match patterns {
            Value::String(single) => {
                let pattern = single.trim();
                if !pattern.is_empty() {
                    cfg.map_patterns.push(pattern.to_ascii_lowercase());
                }
            }
            Value::Array(items) => {
                for item in items {
                    let s = item
                        .as_str()
                        .ok_or_else(|| {
                            McpError::validation("`map_patterns` entries must be strings")
                        })?
                        .trim();
                    if !s.is_empty() {
                        cfg.map_patterns.push(s.to_ascii_lowercase());
                    }
                }
            }
            _ => {
                return Err(McpError::validation(
                    "`map_patterns` must be a string or array of strings",
                ))
            }
        }
        if !cfg.map_patterns.is_empty() {
            cfg.watch_maps = true;
        }
    }

    Ok(cfg)
}

fn run_mcp_server(bind: &str) -> Result<()> {
    let bind = bind.to_string();
    let runtime = TokioRuntimeBuilder::new_multi_thread()
        .enable_all()
        .build()
        .context("construct tokio runtime for MCP server")?;
    runtime.block_on(run_mcp_server_async(bind))
}

async fn run_mcp_server_async(bind: String) -> Result<()> {
    if !getuid().is_root() {
        println!(
            "[MCP]  Warning: drizzleDumper server is not running as root; dumps will likely fail."
        );
    }

    let mut server = McpServer::new(
        "drizzle-dumper".to_string(),
        env!("CARGO_PKG_VERSION").to_string(),
    );

    server
        .add_tool(
            "dump_dex".to_string(),
            Some("Dump DEX/CDEX regions for a running package".to_string()),
            json!({
                "type": "object",
                "properties": {
                    "package": {
                        "type": "string",
                        "description": "Process name / package to attach to"
                    },
                    "wait_time": {
                        "type": "number",
                        "description": "Polling interval in seconds"
                    },
                    "out_dir": {
                        "type": "string",
                        "description": "Output directory for dump files"
                    },
                    "dump_all": {"type": "boolean"},
                    "fix_header": {"type": "boolean"},
                    "scan_step": {"type": "integer", "minimum": 1},
                    "min_size": {"type": "integer", "minimum": 1},
                    "max_size": {"type": "integer", "minimum": 1},
                    "min_dump_size": {"type": "integer", "minimum": 1},
                    "signal_trigger": {"type": "boolean"},
                    "watch_maps": {"type": "boolean"},
                    "stage_threshold": {"type": "integer", "minimum": 1},
                    "map_patterns": {
                        "oneOf": [
                            {"type": "string"},
                            {
                                "type": "array",
                                "items": {"type": "string"}
                            }
                        ]
                    }
                },
                "required": ["package"]
            }),
            DumpTool::default(),
        )
        .await
        .context("register dump_dex tool")?;

    let transport = WebSocketServerTransport::new(bind.as_str());
    server
        .start(transport)
        .await
        .context("start MCP websocket server")?;

    println!("[MCP]  drizzleDumper MCP server listening on ws://{bind}");
    println!("[MCP]  Press Ctrl+C to stop the server.");

    tokio_signal::ctrl_c()
        .await
        .context("wait for Ctrl+C to stop MCP server")?;

    server.stop().await.context("stop MCP server")?;

    Ok(())
}

fn main() -> Result<()> {
    println!("[>>>]  This is drizzleDumper (Rust) [<<<]");
    println!("[>>>]    rewritten by Codex       [<<<]");
    println!("[>>>]        2025.10              [<<<]");

    let args: Vec<String> = env::args().collect();
    if args.len() <= 1 {
        print_usage();
        return Ok(());
    }
    if args[1] == "--mcp-server" {
        let bind = args.get(2).map(|s| s.as_str()).unwrap_or("0.0.0.0:45831");
        return run_mcp_server(bind);
    }

    if !getuid().is_root() {
        println!("[*]  Device Not root!");
        return Ok(());
    }

    let package_name = &args[1];
    let cfg = parse_config(&args)?;
    let _ = run_dump_workflow(package_name, &cfg)?;
    Ok(())
}

fn print_usage() {
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

fn parse_config(args: &[String]) -> Result<Config> {
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

fn find_process_pid(package_name: &str) -> Result<Option<i32>> {
    for proc_entry in all_processes().context("iterating over /proc")? {
        let process = match proc_entry {
            Ok(proc) => proc,
            Err(_) => continue,
        };

        let proc_pid = process.pid;
        if proc_pid == std::process::id() as i32 {
            continue;
        }

        if let Ok(cmdline) = process.cmdline() {
            if let Some(first) = cmdline.first() {
                if first == package_name {
                    return Ok(Some(proc_pid));
                }
            }
        }
    }
    Ok(None)
}

fn find_clone_thread(pid: i32) -> Result<Option<i32>> {
    let mut max_tid: Option<i32> = None;
    let task_dir = format!("/proc/{pid}/task");

    for entry in
        fs::read_dir(&task_dir).with_context(|| format!("opening thread dir {task_dir}"))?
    {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let name = entry.file_name();
        let tid = name
            .to_str()
            .and_then(|s| s.parse::<i32>().ok())
            .unwrap_or_default();
        if tid > 0 {
            max_tid = Some(max_tid.map_or(tid, |current| current.max(tid)));
        }
    }
    Ok(max_tid)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MagicKind {
    Dex,
    Cdex,
}

struct DumpHit {
    base: u64,
    reported_size: Option<u64>,
    kind: MagicKind,
    buffer: Vec<u8>,
}

fn try_dump_dex(package_name: &str, tid: i32, cfg: &Config) -> Result<Vec<PathBuf>> {
    let pid = Pid::from_raw(tid);
    let mut guard = PtracedGuard::attach(pid)?;

    let mut mem =
        File::open(format!("/proc/{}/mem", tid)).with_context(|| "opening /proc/<tid>/mem")?;

    let process = Process::new(tid).with_context(|| format!("reading /proc/{tid}/maps"))?;
    let maps = process
        .maps()
        .with_context(|| format!("parsing /proc/{tid}/maps"))?;

    let mut dumped_paths = Vec::<PathBuf>::new();
    let mut seen_bases = HashSet::<u64>::new();

    for map in maps {
        if !map.perms.contains(MMPermissions::READ) {
            continue;
        }

        let region_start = map.address.0;
        let region_end = map.address.1;
        if region_end <= region_start {
            continue;
        }
        let region_len = region_end - region_start;
        if region_len < cfg.min_region || region_len > cfg.max_region {
            continue;
        }

        let path_hint = match &map.pathname {
            MMapPath::Path(p) => p.to_string_lossy().into_owned(),
            other => format!("{other:?}"),
        };
        let prefer = path_hint.contains("dex")
            || path_hint.contains(".jar")
            || path_hint.contains("odex")
            || path_hint.contains("dalvik")
            || path_hint.contains("apk");

        if let Ok(hits) = scan_region_for_magic(
            &mut mem,
            region_start,
            region_len,
            cfg,
            prefer,
        ) {
            for mut hit in hits {
                if seen_bases.contains(&hit.base) {
                    continue;
                }
                seen_bases.insert(hit.base);

                if cfg.fix_header
                    && hit.kind == MagicKind::Dex
                    && hit.reported_size == Some(hit.buffer.len() as u64)
                {
                    fix_dex_header_inplace(&mut hit.buffer);
                }

                let output_path = build_output_path(
                    package_name,
                    &cfg.out_dir,
                    hit.base,
                    hit.kind,
                );
                write_dump(&output_path, &hit.buffer).with_context(|| "writing dump file")?;
                append_manifest(
                    &cfg.out_dir,
                    tid,
                    hit.base,
                    hit.buffer.len() as u64,
                    hit.kind,
                    &output_path,
                    &path_hint,
                    hit.reported_size,
                )?;
                dumped_paths.push(output_path);

                if !cfg.dump_all {
                    guard.detach();
                    return Ok(dumped_paths);
                }
            }
        }
    }

    guard.detach();
    Ok(dumped_paths)
}

fn scan_region_for_magic(
    mem: &mut File,
    start: u64,
    region_len: u64,
    cfg: &Config,
    _prefer: bool,
) -> Result<Vec<DumpHit>> {
    let region_end = start + region_len;
    let mut hits = Vec::<DumpHit>::new();

    for off in [0u64, 8u64] {
        if let Some(hit) = try_read_at(mem, start + off, region_end - (start + off), cfg)? {
            hits.push(hit);
        }
    }
    let mut pos = start;
    const CHUNK: usize = 4096;
    let mut buf = vec![0u8; CHUNK];

    while pos < region_end {
        let read_len = std::cmp::min(CHUNK as u64, region_end - pos) as usize;
        mem.seek(SeekFrom::Start(pos)).ok();
        if mem.read_exact(&mut buf[..read_len]).is_err() {
            pos = pos.saturating_add(cfg.scan_step.max(1));
            continue;
        }
        let window = &buf[..read_len];
        let mut i = 0usize;
        while i + 8 <= window.len() {
            if &window[i..i + 4] == b"dex\n" || &window[i..i + 4] == b"cdex" {
                if let Some(hit) =
                    try_read_at(mem, pos + i as u64, region_end - (pos + i as u64), cfg)?
                {
                    hits.push(hit);
                }
                i += 16;
                continue;
            }
            i += 1;
        }
        pos = pos.saturating_add(cfg.scan_step.max(1));
    }
    Ok(hits)
}

fn try_read_at(mem: &mut File, base: u64, available: u64, cfg: &Config) -> Result<Option<DumpHit>> {
    if available < 0x40 {
        return Ok(None);
    }
    let mut header = [0u8; 0x70];
    if mem.seek(SeekFrom::Start(base)).is_err() {
        return Ok(None);
    }
    if let Err(err) = mem.read_exact(&mut header) {
        if err.kind() == io::ErrorKind::UnexpectedEof || should_skip_io_error(&err) {
            return Ok(None);
        } else {
            return Err(err).context("read dex header");
        }
    }

    let kind = match magic_kind(&header) {
        Some(k) => k,
        None => return Ok(None),
    };

    let mut header_size = read_u32_le(&header, 0x20) as u64;
    if header_size == 0 || header_size > available {
        for off in [0x24usize, 0x28usize] {
            header_size = read_u32_le(&header, off) as u64;
            if header_size > 0 && header_size <= available {
                break;
            }
        }
    }
    let header_opt = if header_size > 0 && header_size <= available {
        Some(header_size)
    } else {
        None
    };

    let mut read_len = header_opt.unwrap_or(available);
    if read_len < cfg.min_dump_size {
        read_len = available;
    }

    let mut buffer = vec![0u8; read_len as usize];
    if mem.seek(SeekFrom::Start(base)).is_err() {
        return Ok(None);
    }
    if let Err(err) = mem.read_exact(&mut buffer) {
        if err.kind() == io::ErrorKind::UnexpectedEof || should_skip_io_error(&err) {
            return Ok(None);
        } else {
            return Err(err).context("read full dex/cdex from memory");
        }
    }

    Ok(Some(DumpHit {
        base,
        reported_size: header_opt,
        kind,
        buffer,
    }))
}

fn read_u32_le(h: &[u8], off: usize) -> u32 {
    if h.len() >= off + 4 {
        u32::from_le_bytes([h[off], h[off + 1], h[off + 2], h[off + 3]])
    } else {
        0
    }
}

fn magic_kind(header: &[u8]) -> Option<MagicKind> {
    if header.len() < 8 {
        return None;
    }
    if &header[0..4] == b"dex\n"
        && header[4..7]
            .iter()
            .all(|c| *c == b'\0' || c.is_ascii_digit())
    {
        return Some(MagicKind::Dex);
    }
    if &header[0..4] == b"cdex" && header[4] == b'\n' {
        return Some(MagicKind::Cdex);
    }
    None
}

fn build_output_path(
    package_name: &str,
    out_dir: &PathBuf,
    region_start: u64,
    kind: MagicKind,
) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let ext = match kind {
        MagicKind::Dex => "dex",
        MagicKind::Cdex => "cdex",
    };
    let file_name = format!("{package_name}{SUFFIX}{:x}_{ts}.{ext}", region_start);
    out_dir.join(file_name)
}

fn write_dump(path: &PathBuf, buffer: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("ensuring directory {}", parent.display()))?;
    }
    let mut file = File::create(path)?;
    file.write_all(buffer)?;
    Ok(())
}

fn append_manifest(
    out_dir: &PathBuf,
    tid: i32,
    base: u64,
    size: u64,
    kind: MagicKind,
    out_path: &PathBuf,
    map_path_hint: &str,
    reported_size: Option<u64>,
) -> Result<()> {
    let manifest = out_dir.join("dump_manifest.csv");
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&manifest)?;
    let kind_s = match kind {
        MagicKind::Dex => "DEX",
        MagicKind::Cdex => "CDEX",
    };
    let reported_col = reported_size
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());
    writeln!(
        f,
        "{tid},{base:#x},{size},{kind_s},{},\"{}\",\"{}\"",
        reported_col,
        out_path.display(),
        map_path_hint.replace('"', "'")
    )?;
    Ok(())
}

struct PtracedGuard {
    pid: Pid,
    attached: bool,
}

impl PtracedGuard {
    fn attach(pid: Pid) -> Result<Self> {
        ptrace::attach(pid).with_context(|| format!("ptrace attach {}", pid))?;
        match waitpid(pid, None)? {
            WaitStatus::Stopped(_, _) => Ok(Self {
                pid,
                attached: true,
            }),
            other => Err(anyhow!("unexpected wait status: {other:?}")),
        }
    }
    fn detach(&mut self) {
        if self.attached {
            let _ = ptrace::detach(self.pid, None);
            self.attached = false;
        }
    }
}

impl Drop for PtracedGuard {
    fn drop(&mut self) {
        self.detach();
    }
}

fn should_skip_io_error(err: &io::Error) -> bool {
    match err.raw_os_error() {
        Some(code) if code == EIO || code == EFAULT || code == EPERM => true,
        _ => false,
    }
}

fn fix_dex_header_inplace(buf: &mut [u8]) {
    if buf.len() < 0x70 {
        return;
    }
    if !matches!(magic_kind(&buf[..8]), Some(MagicKind::Dex)) {
        return;
    }

    let mut hasher = Sha1::new();
    if buf.len() > 0x20 {
        hasher.update(&buf[0x20..]);
        let digest = hasher.finalize();
        buf[0x0C..0x20].copy_from_slice(&digest[..20]);
    }

    let ad = adler32(&buf[0x0C..]);
    buf[0x08..0x0C].copy_from_slice(&ad.to_le_bytes());
}

fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65_521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &x in data {
        a = (a + x as u32) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}
