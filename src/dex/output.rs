//! DEX file output and manifest management

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;

use super::kind::DexKind;

/// Suffix added to output filenames
const OUTPUT_SUFFIX: &str = "_dumped_";

/// Build output file path for a dumped DEX file
///
/// # Arguments
/// * `package` - Android package name
/// * `out_dir` - Output directory
/// * `base` - Memory address where DEX was found
/// * `kind` - DEX file type
///
/// # Returns
/// Path in format: `{out_dir}/{package}_dumped_{base:x}_{timestamp}.{ext}`
pub fn build_output_path(
    package: &str,
    out_dir: &PathBuf,
    base: u64,
    kind: DexKind,
) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let ext = kind.extension();
    let file = format!("{package}{OUTPUT_SUFFIX}{base:x}_{ts}.{ext}");
    out_dir.join(file)
}

/// Write DEX data to file
///
/// # Arguments
/// * `path` - Destination file path
/// * `data` - DEX file contents
///
/// # Returns
/// `Ok(())` on success, error otherwise
///
/// # Notes
/// - Creates parent directories if needed
/// - Overwrites existing file
pub fn write_dump(path: &PathBuf, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = File::create(path)?;
    file.write_all(data)?;
    Ok(())
}

/// Append dump information to CSV manifest
///
/// # Arguments
/// * `out_dir` - Directory containing manifest (creates `dump_manifest.csv`)
/// * `pid` - Process/thread ID
/// * `base` - Memory address
/// * `size` - Actual dumped size (bytes)
/// * `kind` - DEX file type
/// * `out_path` - Path to dumped file
/// * `map_hint` - Description from /proc/pid/maps or FRIDA
/// * `reported_size` - Size declared in DEX header (if available)
///
/// # CSV Format
/// ```text
/// {pid},{base:#x},{size},{kind},{reported_size},"{out_path}","{map_hint}"
/// ```
pub fn append_manifest(
    out_dir: &PathBuf,
    pid: i32,
    base: u64,
    size: u64,
    kind: DexKind,
    out_path: &PathBuf,
    map_hint: &str,
    reported_size: Option<u64>,
) -> Result<()> {
    let manifest = out_dir.join("dump_manifest.csv");
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&manifest)?;

    let kind_str = kind.as_str();
    let reported = reported_size
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());

    writeln!(
        file,
        "{pid},{base:#x},{size},{kind_str},{reported},\"{}\",\"{}\"",
        out_path.display(),
        map_hint.replace('"', "'")
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_build_output_path() {
        let out_dir = PathBuf::from("/tmp");
        let path = build_output_path("com.example", &out_dir, 0xDEADBEEF, DexKind::Dex);

        let filename = path.file_name().unwrap().to_string_lossy();
        assert!(filename.starts_with("com.example_dumped_deadbeef_"));
        assert!(filename.ends_with(".dex"));
    }

    #[test]
    fn test_write_dump() -> Result<()> {
        let temp = TempDir::new()?;
        let path = temp.path().join("test.dex");

        let data = b"dex\n035\0test data";
        write_dump(&path, data)?;

        let contents = fs::read(&path)?;
        assert_eq!(contents, data);

        Ok(())
    }

    #[test]
    fn test_write_dump_creates_parent() -> Result<()> {
        let temp = TempDir::new()?;
        let path = temp.path().join("subdir").join("test.dex");

        write_dump(&path, b"data")?;
        assert!(path.exists());

        Ok(())
    }

    #[test]
    fn test_append_manifest() -> Result<()> {
        let temp = TempDir::new()?;
        let manifest = temp.path().join("dump_manifest.csv");

        append_manifest(
            &temp.path().to_path_buf(),
            12345,
            0xDEADBEEF,
            1024,
            DexKind::Dex,
            &PathBuf::from("/data/out.dex"),
            "/system/framework/classes.dex",
            Some(2048),
        )?;

        let contents = fs::read_to_string(&manifest)?;
        assert!(contents.contains("12345"));
        assert!(contents.contains("0xdeadbeef"));
        assert!(contents.contains("1024"));
        assert!(contents.contains("DEX"));
        assert!(contents.contains("2048"));
        assert!(contents.contains("/data/out.dex"));

        Ok(())
    }
}
