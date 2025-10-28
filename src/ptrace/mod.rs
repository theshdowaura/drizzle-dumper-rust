mod guard;
mod output;
#[cfg(feature = "frida")]
mod remote;
mod scanner;

use std::collections::HashSet;
use std::path::PathBuf;

use anyhow::{Context, Result};
use procfs::process::{MMPermissions, MMapPath, Process};

use crate::config::Config;

use guard::PtracedGuard;
use output::{append_manifest, build_output_path, fix_dex_header, write_dump};
#[cfg(feature = "frida")]
pub use remote::inject_library;
use scanner::{scan_region, MagicKind};

pub fn try_dump_dex(package_name: &str, tid: i32, cfg: &Config) -> Result<Vec<PathBuf>> {
    let mut guard = PtracedGuard::attach(tid)?;
    let mut mem =
        std::fs::File::open(format!("/proc/{tid}/mem")).context("open /proc/<tid>/mem")?;
    let maps = Process::new(tid).context("create proc entry")?.maps()?;

    let mut dumped_paths = Vec::<PathBuf>::new();
    let mut seen = HashSet::<u64>::new();

    for map in maps {
        if !map.perms.contains(MMPermissions::READ) {
            continue;
        }
        let (start, end) = map.address;
        if end <= start {
            continue;
        }
        let len = end - start;
        if len < cfg.min_region || len > cfg.max_region {
            continue;
        }

        let hint = match &map.pathname {
            MMapPath::Path(p) => p.to_string_lossy().into_owned(),
            other => format!("{other:?}"),
        };

        if let Ok(hits) = scan_region(&mut mem, start, len, cfg) {
            for mut hit in hits {
                if !seen.insert(hit.base) {
                    continue;
                }

                if cfg.fix_header
                    && matches!(hit.kind, MagicKind::Dex)
                    && hit.reported_size == Some(hit.buffer.len() as u64)
                {
                    fix_dex_header(&mut hit.buffer);
                }

                let output = build_output_path(package_name, &cfg.out_dir, hit.base, hit.kind);
                write_dump(&output, &hit.buffer)?;
                append_manifest(
                    &cfg.out_dir,
                    tid,
                    hit.base,
                    hit.buffer.len() as u64,
                    hit.kind,
                    &output,
                    &hint,
                    hit.reported_size,
                )?;
                dumped_paths.push(output);

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
