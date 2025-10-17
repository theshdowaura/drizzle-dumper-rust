use std::collections::HashSet;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use nix::libc::{EFAULT, EIO, EPERM};
use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{getuid, Pid};
use procfs::process::{all_processes, MMPermissions, MMapPath, Process};
use sha1::{Digest, Sha1};

const DEFAULT_OUT_DIR: &str = "/data/local/tmp/";
const SUFFIX: &str = "_dumped_";
const DEFAULT_MIN_REGION_SIZE: u64 = 10 * 1024;
const DEFAULT_MAX_REGION_SIZE: u64 = 600 * 1024 * 1024;

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
    if !getuid().is_root() {
        println!("[*]  Device Not root!");
        return Ok(());
    }

    let package_name = &args[1];
    let cfg = parse_config(&args)?;

    println!(
        "[*]  Try to Find {}{}",
        package_name,
        if cfg.wait_time > 0.0 {
            format!(" (poll interval {}s)", cfg.wait_time)
        } else {
            String::new()
        }
    );

    loop {
        if cfg.wait_time > 0.0 {
            thread::sleep(Duration::from_secs_f64(cfg.wait_time));
        }

        let pid = match find_process_pid(package_name) {
            Ok(Some(pid)) => pid,
            Ok(None) => continue,
            Err(err) => {
                eprintln!("[!]  Failed to enumerate processes: {err:?}");
                continue;
            }
        };
        println!("[*]  pid is {}", pid);

        let clone_pid = match find_clone_thread(pid) {
            Ok(Some(tid)) => tid,
            Ok(None) => continue,
            Err(err) => {
                eprintln!("[!]  Failed to enumerate threads: {err:?}");
                continue;
            }
        };
        println!("[*]  clone pid is {}", clone_pid);

        match try_dump_dex(package_name, clone_pid, &cfg) {
            Ok(paths) if !paths.is_empty() => {
                for p in &paths {
                    println!("[+]  dex dump into {}", p.display());
                }
                println!("[*]  Done.\n");
                break;
            }
            Ok(_) => {
                println!("[*]  The magic was Not Found!");
                if cfg.wait_time <= 0.0 {
                    break;
                }
            }
            Err(err) => {
                eprintln!("[!]  Error while dumping: {err:?}");
                if cfg.wait_time <= 0.0 {
                    break;
                }
            }
        }
    }

    Ok(())
}

fn print_usage() {
    println!(
        "[*]  Usage : ./drizzleDumper <package_name> [wait_times(s)] [options]\n\
         [*]  Options:\n\
         [*]    --dump-all               Dump all dex/cdex found in regions\n\
         [*]    --fix-header             Recompute DEX header SHA1 & Adler32\n\
         [*]    --out <dir>              Output directory (default /data/local/tmp)\n\
         [*]    --scan-step <bytes>      Scan granularity per region (default 4096)\n\
         [*]    --min-size <bytes>       Minimum region size (default 10KiB)\n\
         [*]    --max-size <bytes>       Maximum region size (default 600MiB)\n\
         [*]    --min-dump-size <bytes>  Minimum bytes to dump per hit (default 4096, fallback to region if smaller)\n\
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
    let mut cfg = Config {
        out_dir: PathBuf::from(DEFAULT_OUT_DIR),
        wait_time,
        dump_all: false,
        fix_header: false,
        scan_step: 4096,
        min_region: DEFAULT_MIN_REGION_SIZE,
        max_region: DEFAULT_MAX_REGION_SIZE,
        min_dump_size: 4096,
    };
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
            cfg.min_region = args[i + 1].parse::<u64>().unwrap_or(DEFAULT_MIN_REGION_SIZE);
            i += 1;
        } else if a == "--max-size" && i + 1 < args.len() {
            cfg.max_region = args[i + 1].parse::<u64>().unwrap_or(DEFAULT_MAX_REGION_SIZE);
            i += 1;
        } else if a == "--min-dump-size" && i + 1 < args.len() {
            cfg.min_dump_size = args[i + 1]
                .parse::<u64>()
                .unwrap_or(4096)
                .max(0x70);
            i += 1;
        }
        i += 1;
    }
    Ok(cfg)
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

    let mut mem = File::open(format!("/proc/{}/mem", tid))
        .with_context(|| "opening /proc/<tid>/mem")?;

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
    if &header[0..4] == b"dex\n" && header[4..7].iter().all(|c| *c == b'\0' || c.is_ascii_digit()) {
        return Some(MagicKind::Dex);
    }
    if &header[0..4] == b"cdex" && header[4] == b'\n' {
        return Some(MagicKind::Cdex);
    }
    None
}

fn build_output_path(package_name: &str, out_dir: &PathBuf, region_start: u64, kind: MagicKind) -> PathBuf {
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
    let mut f = OpenOptions::new().create(true).append(true).open(&manifest)?;
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
