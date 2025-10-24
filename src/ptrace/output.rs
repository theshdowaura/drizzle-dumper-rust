use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use sha1::{Digest, Sha1};

use crate::config::OUTPUT_SUFFIX;

use super::scanner::MagicKind;

pub(super) fn build_output_path(
    package: &str,
    out_dir: &PathBuf,
    base: u64,
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
    let file = format!("{package}{OUTPUT_SUFFIX}{base:x}_{ts}.{ext}");
    out_dir.join(file)
}

pub(super) fn write_dump(path: &PathBuf, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = File::create(path)?;
    file.write_all(data)?;
    Ok(())
}

pub(super) fn append_manifest(
    out_dir: &PathBuf,
    tid: i32,
    base: u64,
    size: u64,
    kind: MagicKind,
    out_path: &PathBuf,
    map_hint: &str,
    reported_size: Option<u64>,
) -> Result<()> {
    let manifest = out_dir.join("dump_manifest.csv");
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&manifest)?;
    let kind_str = match kind {
        MagicKind::Dex => "DEX",
        MagicKind::Cdex => "CDEX",
    };
    let reported = reported_size
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());
    writeln!(
        file,
        "{tid},{base:#x},{size},{kind_str},{},\"{}\",\"{}\"",
        reported,
        out_path.display(),
        map_hint.replace('"', "'")
    )?;
    Ok(())
}

pub(super) fn fix_dex_header(buffer: &mut [u8]) {
    if !matches!(super::scanner::magic_kind(buffer), Some(MagicKind::Dex)) {
        return;
    }
    if buffer.len() > 0x20 {
        let mut hasher = Sha1::new();
        hasher.update(&buffer[0x20..]);
        buffer[0x0C..0x20].copy_from_slice(&hasher.finalize()[..20]);
    }
    let checksum = adler32(&buffer[0x0C..]);
    buffer[0x08..0x0C].copy_from_slice(&checksum.to_le_bytes());
}

fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65_521;
    let mut a = 1u32;
    let mut b = 0u32;
    for &byte in data {
        a = (a + byte as u32) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}
