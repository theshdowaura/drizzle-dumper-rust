use std::io::{self, Read, Seek, SeekFrom};

use anyhow::Context;
use nix::libc::{EFAULT, EIO, EPERM};

use crate::config::Config;

pub(super) const HEADER_LEN: usize = 0x70;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MagicKind {
    Dex,
    Cdex,
}

pub(super) struct DumpHit {
    pub(super) base: u64,
    pub(super) reported_size: Option<u64>,
    pub(super) kind: MagicKind,
    pub(super) buffer: Vec<u8>,
}

pub(super) fn scan_region(
    mem: &mut std::fs::File,
    start: u64,
    len: u64,
    cfg: &Config,
) -> anyhow::Result<Vec<DumpHit>> {
    let end = start + len;
    let mut hits = Vec::<DumpHit>::new();

    for &offset in &[0u64, 8] {
        if let Some(hit) = try_read(mem, start + offset, end - (start + offset), cfg)? {
            hits.push(hit);
        }
    }

    const CHUNK: usize = 4096;
    let mut buf = vec![0u8; CHUNK];
    let mut pos = start;

    while pos < end {
        let remain = end - pos;
        let read_len = remain.min(CHUNK as u64) as usize;
        mem.seek(SeekFrom::Start(pos)).ok();
        if mem.read_exact(&mut buf[..read_len]).is_err() {
            pos = pos.saturating_add(cfg.scan_step.max(1));
            continue;
        }

        let window = &buf[..read_len];
        let mut idx = 0usize;
        while idx + 8 <= window.len() {
            if &window[idx..idx + 4] == b"dex\n" || &window[idx..idx + 4] == b"cdex" {
                if let Some(hit) = try_read(mem, pos + idx as u64, end - (pos + idx as u64), cfg)?
                {
                    hits.push(hit);
                }
                idx += 16;
            } else {
                idx += 1;
            }
        }

        pos = pos.saturating_add(cfg.scan_step.max(1));
    }

    Ok(hits)
}

pub(super) fn magic_kind(header: &[u8]) -> Option<MagicKind> {
    if header.len() < 5 {
        return None;
    }
    if &header[0..4] == b"dex\n"
        && header[4..7]
            .iter()
            .all(|c| *c == b'\0' || c.is_ascii_digit())
    {
        return Some(MagicKind::Dex);
    }
    if &header[0..4] == b"cdex" && header.get(4) == Some(&b'\n') {
        return Some(MagicKind::Cdex);
    }
    None
}

fn try_read(
    mem: &mut std::fs::File,
    base: u64,
    available: u64,
    cfg: &Config,
) -> anyhow::Result<Option<DumpHit>> {
    if available < HEADER_LEN as u64 {
        return Ok(None);
    }

    let mut header = [0u8; HEADER_LEN];
    if mem.seek(SeekFrom::Start(base)).is_err() {
        return Ok(None);
    }
    if let Err(err) = mem.read_exact(&mut header) {
        if err.kind() == io::ErrorKind::UnexpectedEof || should_skip(&err) {
            return Ok(None);
        } else {
            return Err(err).context("read dex header");
        }
    }

    let kind = match magic_kind(&header) {
        Some(k) => k,
        None => return Ok(None),
    };

    let mut declared = read_u32(&header, 0x20) as u64;
    if declared == 0 || declared > available {
        for off in [0x24usize, 0x28] {
            declared = read_u32(&header, off) as u64;
            if declared > 0 && declared <= available {
                break;
            }
        }
    }
    let reported = if declared > 0 && declared <= available {
        Some(declared)
    } else {
        None
    };

    let mut read_len = reported.unwrap_or(available);
    if read_len < cfg.min_dump_size {
        read_len = available;
    }

    let mut buffer = vec![0u8; read_len as usize];
    if mem.seek(SeekFrom::Start(base)).is_err() {
        return Ok(None);
    }
    if let Err(err) = mem.read_exact(&mut buffer) {
        if err.kind() == io::ErrorKind::UnexpectedEof || should_skip(&err) {
            return Ok(None);
        } else {
            return Err(err).context("read full region");
        }
    }

    Ok(Some(DumpHit {
        base,
        reported_size: reported,
        kind,
        buffer,
    }))
}

fn read_u32(buf: &[u8], offset: usize) -> u32 {
    if buf.len() >= offset + 4 {
        u32::from_le_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ])
    } else {
        0
    }
}

fn should_skip(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(code) if code == EIO || code == EFAULT || code == EPERM)
}
