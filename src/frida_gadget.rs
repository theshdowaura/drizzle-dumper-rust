#[cfg(feature = "frida")]
use std::fs::{self, File};
#[cfg(feature = "frida")]
use std::io::{Read, Write};
#[cfg(feature = "frida")]
use std::net::{IpAddr, Ipv4Addr, TcpStream};
#[cfg(feature = "frida")]
use std::path::{Path, PathBuf};
#[cfg(feature = "frida")]
use std::thread;
#[cfg(feature = "frida")]
use std::time::{Duration, Instant};

#[cfg(feature = "frida")]
use anyhow::Context;
use anyhow::{bail, Result};
#[cfg(feature = "frida")]
use rand::Rng;

use crate::config::{Config, FridaConfig};

#[cfg(feature = "frida")]
pub struct GadgetDeployment {
    pub port: u16,
    pub library_path: PathBuf,
    pub config_path: PathBuf,
    keep_files: bool,
}

#[cfg(feature = "frida")]
impl GadgetDeployment {
    pub fn cleanup(&self) {
        if self.keep_files {
            return;
        }
        if let Some(parent) = self.library_path.parent() {
            let _ = fs::remove_dir_all(parent);
        } else {
            let _ = fs::remove_file(&self.library_path);
            let _ = fs::remove_file(&self.config_path);
        }
    }

    pub fn keep_files(&self) -> bool {
        self.keep_files
    }
}

#[cfg(feature = "frida")]
impl Drop for GadgetDeployment {
    fn drop(&mut self) {
        self.cleanup();
    }
}

#[cfg(feature = "frida")]
pub fn prepare_gadget(cfg: &Config) -> Result<GadgetDeployment> {
    ensure_supported_arch()?;

    let frida_cfg = &cfg.frida;
    if !frida_cfg.gadget_enabled {
        bail!("gadget mode not enabled");
    }

    let base_dir = cfg
        .out_dir
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/data/local/tmp"));
    let gadget_dir = base_dir.join("drizzle_gadget");
    fs::create_dir_all(&gadget_dir).context("create gadget directory")?;

    let port = frida_cfg
        .gadget_port
        .unwrap_or_else(|| rand::thread_rng().gen_range(28000..40000));
    let suffix = format!("{:x}", rand::random::<u32>());
    let run_dir = gadget_dir.join(format!("run-{suffix}"));
    fs::create_dir_all(&run_dir).context("create gadget run directory")?;
    let lib_path = run_dir.join("frida-gadget.so");
    let cfg_path = run_dir.join("frida-gadget.config");

    materialize_library(frida_cfg, &lib_path)?;
    materialize_config(frida_cfg, &cfg_path, port)?;

    set_permissions(&lib_path)?;
    set_permissions(&cfg_path)?;

    Ok(GadgetDeployment {
        port,
        library_path: lib_path,
        config_path: cfg_path,
        keep_files: frida_cfg.gadget_keep_files,
    })
}

#[cfg(feature = "frida")]
pub fn wait_for_gadget(port: u16, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if TcpStream::connect((IpAddr::V4(Ipv4Addr::LOCALHOST), port)).is_ok() {
            return Ok(());
        }
        if Instant::now() > deadline {
            bail!("gadget did not start listening within {:?}", timeout);
        }
        thread::sleep(Duration::from_millis(200));
    }
}

#[cfg(feature = "frida")]
fn materialize_library(cfg: &FridaConfig, target: &Path) -> Result<()> {
    if let Some(custom) = &cfg.gadget_library_path {
        fs::copy(custom, target)
            .with_context(|| format!("copy gadget library from {}", custom.display()))?;
        return Ok(());
    }

    if let Some(bytes) = embedded::gadget_blob()? {
        let mut file = File::create(target)?;
        file.write_all(bytes)?;
        Ok(())
    } else {
        bail!("no gadget asset embedded; provide --frida-gadget-path <so>");
    }
}

#[cfg(feature = "frida")]
fn materialize_config(cfg: &FridaConfig, target: &Path, port: u16) -> Result<()> {
    if let Some(custom) = &cfg.gadget_config_path {
        fs::copy(custom, target)
            .with_context(|| format!("copy gadget config {}", custom.display()))?;
        return Ok(());
    }

    let template = format!(
        r#"{{
  "interaction": {{
    "type": "script"
  }},
  "listen": ["127.0.0.1:{port}"]
}}
"#
    );
    fs::write(target, template)?;
    Ok(())
}

#[cfg(feature = "frida")]
fn set_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(feature = "frida")]
fn ensure_supported_arch() -> Result<()> {
    match std::env::consts::ARCH {
        "aarch64" => Ok(()),
        other => bail!("gadget injection currently only supports aarch64, found {other}"),
    }
}

#[cfg(feature = "frida")]
mod embedded {
    use super::*;

    #[cfg(feature = "frida-gadget-bundle")]
    pub fn gadget_blob() -> Result<&'static [u8]> {
        #[cfg(target_arch = "aarch64")]
        {
            Ok(include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/assets/frida/arm64/libfrida-gadget.so"
            )))
        }

        #[cfg(not(target_arch = "aarch64"))]
        {
            bail!("gadget bundle only available for aarch64");
        }
    }

    #[cfg(not(feature = "frida-gadget-bundle"))]
    pub fn gadget_blob() -> Result<&'static [u8]> {
        Err(anyhow::anyhow!(
            "embedded gadget not available; enable feature `frida-gadget-bundle` or provide --frida-gadget-path"
        ))
    }
}

#[cfg(not(feature = "frida"))]
pub fn prepare_gadget(_cfg: &Config) -> Result<()> {
    bail!("compile with `--features frida` to use gadget mode");
}

#[cfg(not(feature = "frida"))]
pub fn wait_for_gadget(_port: u16, _timeout: Duration) -> Result<()> {
    bail!("compile with `--features frida` to use gadget mode");
}
