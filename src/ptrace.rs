use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use nix::libc::{EFAULT, EIO, EPERM};
use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use procfs::process::{MMPermissions, MMapPath, Process};
use sha1::{Digest, Sha1};

use crate::config::{Config, OUTPUT_SUFFIX};

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

pub fn try_dump_dex(package_name: &str, tid: i32, cfg: &Config) -> Result<Vec<PathBuf>> {
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
    let header_opt = if header_size > 0 and ...