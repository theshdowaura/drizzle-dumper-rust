use anyhow::{bail, Result};
use std::path::PathBuf;

use crate::config::Config;

pub fn run_frida_workflow(package_name: &str, cfg: &Config) -> Result<Vec<PathBuf>> {
    #[cfg(feature = "frida")]
    {
        inner::run_frida_workflow(package_name, cfg)
    }

    #[cfg(not(feature = "frida"))]
    {
        let _ = package_name;
        let _ = cfg;
        bail!(
            "FRIDA hook dumper is disabled. Rebuild drizzleDumper with `--features frida` \
             to enable FRIDA-based extraction."
        );
    }
}

#[cfg(feature = "frida")]
mod inner {
    use super::*;
    use std::collections::{hash_map::Entry, HashMap};
    use std::convert::TryFrom;
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::thread;
    use std::time::{Duration, Instant};

    use anyhow::{anyhow, bail, Context};
    use frida::{
        Device, DeviceManager, DeviceType, Frida, Message, MessageSend, ScriptHandler,
        ScriptOption, SpawnOptions,
    };
    use serde::Deserialize;
    use sha1::{Digest, Sha1};

    use crate::config::OUTPUT_SUFFIX;
    use crate::frida_gadget::{prepare_gadget, wait_for_gadget, GadgetDeployment};
    use crate::ptrace::inject_library;
    use crate::workflow::{find_clone_thread, find_process_pid};

    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    const WAIT_FOR_AGENT_READY: Duration = Duration::from_secs(20);
    const EVENT_POLL_INTERVAL: Duration = Duration::from_millis(250);
    const THREAD_DISCOVERY_RETRIES: usize = 50;
    const THREAD_DISCOVERY_INTERVAL: Duration = Duration::from_millis(50);

    enum GadgetContext {
        Managed(GadgetDeployment),
        External {
            library_path: PathBuf,
            config_path: Option<PathBuf>,
            port: u16,
        },
        Zygisk {
            port: u16,
        },
    }

    impl GadgetContext {
        fn library_path(&self) -> Option<&Path> {
            match self {
                GadgetContext::Managed(dep) => Some(dep.library_path.as_path()),
                GadgetContext::External { library_path, .. } => Some(library_path.as_path()),
                GadgetContext::Zygisk { .. } => None,
            }
        }

        fn config_path(&self) -> Option<&Path> {
            match self {
                GadgetContext::Managed(dep) => Some(dep.config_path.as_path()),
                GadgetContext::External { config_path, .. } => config_path.as_deref(),
                GadgetContext::Zygisk { .. } => None,
            }
        }

        fn port(&self) -> u16 {
            match self {
                GadgetContext::Managed(dep) => dep.port,
                GadgetContext::External { port, .. } => *port,
                GadgetContext::Zygisk { port } => *port,
            }
        }

        fn needs_injection(&self) -> bool {
            !matches!(self, GadgetContext::Zygisk { .. })
        }
    }

    pub(super) fn run_frida_workflow(package_name: &str, cfg: &Config) -> Result<Vec<PathBuf>> {
        let frida_ctx = unsafe { Frida::obtain() };
        let manager = DeviceManager::obtain(&frida_ctx);

        let gadget = if cfg.zygisk_enabled {
            let port = cfg.frida.gadget_port.unwrap_or(27_042);
            Some(GadgetContext::Zygisk { port })
        } else if let Some(path) = cfg.frida.gadget_library_path.as_ref() {
            let port = cfg
                .frida
                .gadget_port
                .ok_or_else(|| anyhow!("frida gadget port required when using gadget id/path"))?;
            Some(GadgetContext::External {
                library_path: path.clone(),
                config_path: cfg.frida.gadget_config_path.clone(),
                port,
            })
        } else if cfg.frida.gadget_enabled && cfg.frida.remote.is_none() && !cfg.frida.use_usb {
            Some(GadgetContext::Managed(prepare_gadget(cfg)?))
        } else {
            None
        };

        let spawn_mode = cfg.frida.spawn;
        let mut spawn_device = if spawn_mode {
            Some(select_device(&manager, cfg).context("select FRIDA device for spawn/resume")?)
        } else {
            None
        };

        let mut spawn_pid: Option<u32> = None;
        let target_pid = if spawn_mode {
            let options = SpawnOptions::default();
            let dev = spawn_device
                .as_mut()
                .ok_or_else(|| anyhow!("spawn device unavailable"))?;
            let pid = dev
                .spawn(package_name, &options)
                .with_context(|| format!("spawn {package_name} via FRIDA"))?;
            spawn_pid = Some(pid);
            pid
        } else {
            let pid = find_process_pid(package_name)?
                .ok_or_else(|| anyhow!("process {package_name} not found to attach"))?;
            u32::try_from(pid).context("convert pid to u32")?
        };
        let pid_i32 = i32::try_from(target_pid).unwrap_or(i32::MAX);

        if let Some(ctx) = gadget.as_ref() {
            let gadget_wait = Duration::from_secs(cfg.frida.gadget_ready_timeout);
            if ctx.needs_injection() {
                let tid = wait_for_injectable_thread(pid_i32)
                    .with_context(|| format!("locate thread for pid {pid_i32}"))?;
                let prev_env = std::env::var_os("FRIDA_GADGET_CONFIG");
                if let Some(config) = ctx.config_path() {
                    std::env::set_var("FRIDA_GADGET_CONFIG", config);
                }
                if let Some(path) = ctx.library_path() {
                    inject_library(tid, path).context("inject gadget library")?;
                } else {
                    bail!("gadget context missing library path");
                }
                wait_for_gadget(ctx.port(), gadget_wait).context("wait gadget listener")?;
                match (ctx.config_path(), prev_env) {
                    (_, Some(prev)) => std::env::set_var("FRIDA_GADGET_CONFIG", prev),
                    (Some(_), None) => std::env::remove_var("FRIDA_GADGET_CONFIG"),
                    _ => {}
                }
            } else {
                println!(
                    "[*]  Waiting for Zygisk gadget on port {} (timeout {}s)…",
                    ctx.port(),
                    cfg.frida.gadget_ready_timeout
                );
                wait_for_gadget(ctx.port(), gadget_wait).context("wait gadget listener")?;
            }
        }

        let device = if let Some(ctx) = gadget.as_ref() {
            manager
                .get_remote_device(&format!("127.0.0.1:{}", ctx.port()))
                .context("connect gadget device")?
        } else {
            select_device(&manager, cfg).context("select FRIDA device for attach")?
        };

        let session = device
            .attach(target_pid)
            .with_context(|| format!("attach to pid {target_pid}"))?;

        let script_source = if let Some(path) = cfg.frida.script_path.as_ref() {
            std::fs::read_to_string(path)
                .with_context(|| format!("read FRIDA agent script {}", path.display()))?
        } else {
            build_agent_script(cfg.frida.chunk_size)
        };

        let mut script_options = ScriptOption::default();
        let mut script = session
            .create_script(&script_source, &mut script_options)
            .context("create FRIDA script")?;

        let (sender, receiver) = mpsc::channel();
        script
            .handle_message(ChannelHandler { sender })
            .context("register script message handler")?;
        script.load().context("load FRIDA script")?;

        let quiet_after = if cfg.frida.quiet_after_complete_ms == 0 {
            None
        } else {
            Some(Duration::from_millis(cfg.frida.quiet_after_complete_ms))
        };

        let mut resume_pending = spawn_pid.is_some() && cfg.frida.resume_after_spawn;
        let mut aggregator = DexAggregator::new(package_name, cfg, pid_i32);
        let mut agent_ready = false;
        let ready_deadline = Instant::now() + WAIT_FOR_AGENT_READY;
        let mut last_event = Instant::now();

        loop {
            match receiver.recv_timeout(EVENT_POLL_INTERVAL) {
                Ok(event) => {
                    last_event = Instant::now();
                    match event {
                        AgentEvent::Ready => {
                            agent_ready = true;
                            if resume_pending {
                                if let Some(pid) = spawn_pid {
                                    if let Some(spawner) = spawn_device.as_ref() {
                                        spawner.resume(pid).context("resume spawned process")?;
                                    } else {
                                        device.resume(pid).context("resume spawned process")?;
                                    }
                                }
                                resume_pending = false;
                            }
                            println!("[*]  FRIDA agent is active; awaiting Dex loads…");
                        }
                        AgentEvent::DexChunk(chunk) => {
                            aggregator.ingest_chunk(chunk)?;
                        }
                        AgentEvent::DexComplete(complete) => {
                            if let Some(path) = aggregator.complete(complete)? {
                                println!("[+]  FRIDA dumped dex -> {}", path.display());
                                if !cfg.dump_all {
                                    break;
                                }
                            }
                        }
                        AgentEvent::HookError(msg) => {
                            eprintln!("[!]  FRIDA hook error: {msg}");
                        }
                        AgentEvent::AgentError(msg) => {
                            eprintln!("[!]  Agent runtime error: {msg}");
                        }
                        AgentEvent::Log { level, message } => {
                            println!("[FRIDA][{level}] {message}");
                        }
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    if !agent_ready && Instant::now() > ready_deadline {
                        bail!("FRIDA agent failed to report ready within allotted time");
                    }
                    if agent_ready && aggregator.has_output() && aggregator.is_drained() {
                        if let Some(window) = quiet_after {
                            if Instant::now().duration_since(last_event) > window {
                                break;
                            }
                        }
                    }
                    continue;
                }
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }

        script.unload().ok();
        session.detach().ok();
        Ok(aggregator.into_outputs())
    }

    fn wait_for_injectable_thread(pid: i32) -> Result<i32> {
        for _ in 0..THREAD_DISCOVERY_RETRIES {
            if let Some(tid) = find_clone_thread(pid)? {
                return Ok(tid);
            }
            thread::sleep(THREAD_DISCOVERY_INTERVAL);
        }
        bail!("no thread found for pid {pid} to inject gadget");
    }

    fn select_device<'a>(manager: &'a DeviceManager, cfg: &Config) -> Result<Device<'a>> {
        if let Some(remote) = cfg.frida.remote.as_ref() {
            return manager
                .get_remote_device(remote)
                .with_context(|| format!("connect remote device {remote}"));
        }
        if cfg.frida.use_usb {
            if let Ok(device) = manager.get_device_by_type(DeviceType::USB) {
                return Ok(device);
            }
        }
        manager
            .get_local_device()
            .context("obtain local FRIDA device")
    }

    struct ChannelHandler {
        sender: mpsc::Sender<AgentEvent>,
    }

    impl ScriptHandler for ChannelHandler {
        fn on_message(&mut self, message: &Message, data: Option<Vec<u8>>) {
            let _ = match message {
                Message::Send(payload) => self.handle_send(payload, data),
                Message::Log(log) => {
                    let level = format!("{:?}", log.level);
                    let msg = log.payload.clone();
                    self.sender.send(AgentEvent::Log {
                        level,
                        message: msg,
                    })
                }
                Message::Error(err) => self
                    .sender
                    .send(AgentEvent::AgentError(err.description.clone())),
                Message::Other(value) => self.sender.send(AgentEvent::AgentError(format!(
                    "unexpected message: {value}"
                ))),
            };
        }
    }

    impl ChannelHandler {
        fn handle_send(
            &mut self,
            payload: &MessageSend,
            data: Option<Vec<u8>>,
        ) -> Result<(), mpsc::SendError<AgentEvent>> {
            let json = payload.payload.returns.clone();
            match serde_json::from_value::<AgentPayload>(json) {
                Ok(agent_payload) => self.route_agent_payload(agent_payload, data),
                Err(err) => self.sender.send(AgentEvent::AgentError(format!(
                    "malformed agent payload: {err}"
                ))),
            }
        }

        fn route_agent_payload(
            &mut self,
            payload: AgentPayload,
            data: Option<Vec<u8>>,
        ) -> Result<(), mpsc::SendError<AgentEvent>> {
            match payload.event.as_str() {
                "agent-ready" => self.sender.send(AgentEvent::Ready),
                "dex-chunk" => {
                    if let Some(bytes) = data {
                        self.sender.send(AgentEvent::DexChunk(DexChunk {
                            key: payload.key.unwrap_or_default(),
                            size: payload.size.unwrap_or(0),
                            offset: payload.offset.unwrap_or(0),
                            data: bytes,
                            symbol: payload.symbol,
                            location: payload.location,
                            magic: payload.magic,
                        }))
                    } else {
                        self.sender.send(AgentEvent::AgentError(
                            "dex-chunk missing binary payload".to_string(),
                        ))
                    }
                }
                "dex-complete" => self.sender.send(AgentEvent::DexComplete(DexComplete {
                    key: payload.key.unwrap_or_default(),
                    size: payload.size.unwrap_or(0),
                    symbol: payload.symbol,
                    location: payload.location,
                    magic: payload.magic,
                    reported: payload.reported,
                })),
                "hook-error" => self
                    .sender
                    .send(AgentEvent::HookError(payload.message.unwrap_or_default())),
                "agent-error" => self.sender.send(AgentEvent::AgentError(
                    payload
                        .message
                        .unwrap_or_else(|| "unspecified agent error".to_string()),
                )),
                other => self.sender.send(AgentEvent::AgentError(format!(
                    "unknown agent event: {other}"
                ))),
            }
        }
    }

    #[derive(Debug, Deserialize)]
    struct AgentPayload {
        event: String,
        key: Option<String>,
        size: Option<u64>,
        offset: Option<u64>,
        symbol: Option<String>,
        location: Option<String>,
        message: Option<String>,
        magic: Option<String>,
        reported: Option<u64>,
    }

    enum AgentEvent {
        Ready,
        DexChunk(DexChunk),
        DexComplete(DexComplete),
        HookError(String),
        AgentError(String),
        Log { level: String, message: String },
    }

    struct DexChunk {
        key: String,
        size: u64,
        offset: u64,
        data: Vec<u8>,
        symbol: Option<String>,
        location: Option<String>,
        magic: Option<String>,
    }

    struct DexComplete {
        key: String,
        size: u64,
        symbol: Option<String>,
        location: Option<String>,
        magic: Option<String>,
        reported: Option<u64>,
    }

    struct DexAssembly {
        base: u64,
        expected: usize,
        received: usize,
        buffer: Vec<u8>,
        symbol: Option<String>,
        location: Option<String>,
        magic: Option<String>,
        reported: Option<u64>,
    }

    impl DexAssembly {
        fn new(
            key: &str,
            size: u64,
            symbol: Option<String>,
            location: Option<String>,
            magic: Option<String>,
        ) -> Result<Self> {
            let base = parse_pointer(key)?;
            let expected = size
                .try_into()
                .map_err(|_| anyhow!("DEX size {size} does not fit into usize"))?;
            let buffer = vec![0u8; expected];
            let reported = if size > 0 { Some(size) } else { None };
            Ok(Self {
                base,
                expected,
                received: 0,
                buffer,
                symbol,
                location,
                magic,
                reported,
            })
        }

        fn ingest(&mut self, offset: u64, data: Vec<u8>) -> Result<()> {
            let offset = offset
                .try_into()
                .map_err(|_| anyhow!("chunk offset {offset} does not fit"))?;
            let end = offset + data.len();
            if end > self.buffer.len() {
                self.buffer.resize(end, 0);
                self.expected = self.buffer.len();
            }
            self.buffer[offset..end].copy_from_slice(&data);
            self.received = self.received.max(end);
            Ok(())
        }

        fn merge_chunk_meta(&mut self, chunk: &DexChunk) {
            if self.symbol.is_none() {
                self.symbol = chunk.symbol.clone();
            }
            if self.location.is_none() {
                self.location = chunk.location.clone();
            }
            if self.magic.is_none() {
                self.magic = chunk.magic.clone();
            }
            if self.reported.is_none() && chunk.size > 0 {
                self.reported = Some(chunk.size);
            }
        }

        fn merge_complete_meta(&mut self, complete: &DexComplete) {
            if self.symbol.is_none() {
                self.symbol = complete.symbol.clone();
            }
            if self.location.is_none() {
                self.location = complete.location.clone();
            }
            if self.magic.is_none() {
                self.magic = complete.magic.clone();
            }
            if complete.size > 0 {
                self.reported = Some(complete.size);
            }
            if let Some(reported) = complete.reported {
                self.reported = Some(reported);
            }
        }

        fn complete(mut self, package: &str, cfg: &Config, pid: i32) -> Result<Option<PathBuf>> {
            if self.received == 0 {
                return Ok(None);
            }
            self.buffer.truncate(self.received);
            let kind = detect_dex_kind(&self.buffer)
                .or_else(|| self.magic.as_deref().and_then(DexKind::from_magic))
                .ok_or_else(|| anyhow!("unknown dex magic"))?;
            if cfg.fix_header && matches!(kind, DexKind::Dex) && self.buffer.len() == self.expected
            {
                fix_dex_header(&mut self.buffer);
            }
            let output = build_output_path(package, &cfg.out_dir, self.base, kind);
            write_dump(&output, &self.buffer)?;
            let reported = self.reported.unwrap_or(self.buffer.len() as u64);
            append_manifest(
                &cfg.out_dir,
                pid,
                self.base,
                self.buffer.len() as u64,
                kind,
                &output,
                &self
                    .location
                    .or(self.symbol.clone())
                    .unwrap_or_else(|| "FRIDA".to_string()),
                Some(reported),
            )?;
            Ok(Some(output))
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum DexKind {
        Dex,
        Cdex,
    }

    impl DexKind {
        fn from_magic(magic: &str) -> Option<Self> {
            match magic {
                "dex\n" => Some(DexKind::Dex),
                "cdex" => Some(DexKind::Cdex),
                _ => None,
            }
        }
    }

    struct DexAggregator<'a> {
        package: &'a str,
        cfg: &'a Config,
        pid: i32,
        assemblies: HashMap<String, DexAssembly>,
        outputs: Vec<PathBuf>,
    }

    impl<'a> DexAggregator<'a> {
        fn new(package: &'a str, cfg: &'a Config, pid: i32) -> Self {
            Self {
                package,
                cfg,
                pid,
                assemblies: HashMap::new(),
                outputs: Vec::new(),
            }
        }

        fn ingest_chunk(&mut self, chunk: DexChunk) -> Result<()> {
            let entry = self.assemblies.entry(chunk.key.clone());
            let assembly = match entry {
                Entry::Occupied(occ) => occ.into_mut(),
                Entry::Vacant(vac) => {
                    let assembly = DexAssembly::new(
                        &chunk.key,
                        chunk.size,
                        chunk.symbol.clone(),
                        chunk.location.clone(),
                        chunk.magic.clone(),
                    )?;
                    vac.insert(assembly)
                }
            };
            assembly.merge_chunk_meta(&chunk);
            assembly.ingest(chunk.offset, chunk.data)
        }

        fn complete(&mut self, complete: DexComplete) -> Result<Option<PathBuf>> {
            if let Some(mut assembly) = self.assemblies.remove(&complete.key) {
                assembly.merge_complete_meta(&complete);
                if let Some(path) = assembly.complete(self.package, self.cfg, self.pid)? {
                    self.outputs.push(path.clone());
                    return Ok(Some(path));
                }
            }
            Ok(None)
        }

        fn is_drained(&self) -> bool {
            self.assemblies
                .values()
                .all(|asm| asm.received >= asm.expected)
        }

        fn has_output(&self) -> bool {
            !self.outputs.is_empty()
        }

        fn into_outputs(self) -> Vec<PathBuf> {
            self.outputs
        }
    }

    fn parse_pointer(text: &str) -> Result<u64> {
        let trimmed = text.trim_start_matches("0x");
        u64::from_str_radix(trimmed, 16).with_context(|| format!("parse pointer {text}"))
    }

    fn build_agent_script(chunk_size: usize) -> String {
        AGENT_TEMPLATE.replace("__CHUNK_SIZE__", &chunk_size.to_string())
    }

    fn detect_dex_kind(header: &[u8]) -> Option<DexKind> {
        if header.len() < 5 {
            return None;
        }
        if &header[0..4] == b"dex\n"
            && header[4..7]
                .iter()
                .all(|c| *c == b'\0' || c.is_ascii_digit())
        {
            return Some(DexKind::Dex);
        }
        if &header[0..4] == b"cdex" && header.get(4) == Some(&b'\n') {
            return Some(DexKind::Cdex);
        }
        None
    }

    fn build_output_path(package: &str, out_dir: &PathBuf, base: u64, kind: DexKind) -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let ext = match kind {
            DexKind::Dex => "dex",
            DexKind::Cdex => "cdex",
        };
        let file = format!("{package}{OUTPUT_SUFFIX}{base:x}_{ts}.{ext}");
        out_dir.join(file)
    }

    fn write_dump(path: &PathBuf, data: &[u8]) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = fs::File::create(path)?;
        file.write_all(data)?;
        Ok(())
    }

    fn append_manifest(
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
        let kind_str = match kind {
            DexKind::Dex => "DEX",
            DexKind::Cdex => "CDEX",
        };
        let reported = reported_size
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string());
        writeln!(
            file,
            "{pid},{base:#x},{size},{kind_str},{},\"{}\",\"{}\"",
            reported,
            out_path.display(),
            map_hint.replace('"', "'"),
        )?;
        Ok(())
    }

    fn fix_dex_header(buffer: &mut [u8]) {
        if !matches!(detect_dex_kind(buffer), Some(DexKind::Dex)) {
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

    const AGENT_TEMPLATE: &str = r#"
'use strict';

const chunkSize = __CHUNK_SIZE__;
const observed = new Set();

const HOOK_SPECS = [
  {
    name: 'DexFile::OpenCommon',
    tokens: ['DexFile::OpenCommon'],
    pairs: [[2, 3], [3, 4]],
  },
  {
    name: 'DexFile::OpenMemory',
    tokens: ['DexFile::OpenMemory'],
    pairs: [[1, 2], [2, 3]],
  },
  {
    name: 'DexFile::DexFile',
    tokens: ['DexFile::DexFile'],
    pairs: [[1, 2], [2, 3]],
  }
];

function readPointerSize(arg) {
  try {
    return parseInt(arg.toString(), 16);
  } catch (e) {
    return 0;
  }
}

function isDex(ptr) {
  if (!ptr || ptr.isNull()) {
    return false;
  }
  try {
    const magic = Memory.readUtf8String(ptr, 4);
    return magic === 'dex\\n' || magic === 'cdex';
  } catch (e) {
    return false;
  }
}

function resolveDex(args, pairs) {
  for (let i = 0; i < pairs.length; i++) {
    const [baseIndex, sizeIndex] = pairs[i];
    const basePtr = args[baseIndex];
    if (!basePtr || !isDex(basePtr)) {
      continue;
    }
    let size = 0;
    if (typeof sizeIndex === 'number') {
      const candidate = args[sizeIndex];
      if (candidate) {
        size = readPointerSize(candidate);
      }
    }
    if (!size || size <= 0) {
      size = Memory.readU32(basePtr.add(0x20));
    }
    if (size && size > 0x200) {
      return { base: basePtr, size: size };
    }
  }
  for (let idx = 0; idx < 6; idx++) {
    const ptr = args[idx];
    if (ptr && isDex(ptr)) {
      const size = Memory.readU32(ptr.add(0x20));
      if (size) {
        return { base: ptr, size: size };
      }
    }
  }
  return null;
}

function dumpDex(meta) {
  const key = meta.base.toString();
  if (observed.has(key)) {
    return;
  }
  observed.add(key);

  let size = meta.size;
  if (!size || size <= 0) {
    size = Memory.readU32(meta.base.add(0x20));
  }
  if (!size || size <= 0) {
    return;
  }

  const magic = Memory.readUtf8String(meta.base, 4);
  let offset = 0;
  while (offset < size) {
    const length = Math.min(chunkSize, size - offset);
    const buffer = Memory.readByteArray(meta.base.add(offset), length);
    send({
      event: 'dex-chunk',
      key: key,
      size: size,
      offset: offset,
      symbol: meta.symbol,
      location: meta.location,
      magic: magic,
    }, buffer);
    offset += length;
  }
  send({
    event: 'dex-complete',
    key: key,
    size: size,
    symbol: meta.symbol,
    location: meta.location,
    magic: magic,
  });
}

function hookSymbol(spec) {
  const symbols = Module.enumerateSymbolsSync('libart.so').filter(function (sym) {
    return spec.tokens.some(function (token) {
      return sym.name.indexOf(token) !== -1;
    });
  });

  symbols.forEach(function (sym) {
    Interceptor.attach(sym.address, {
      onEnter: function (args) {
        this.meta = resolveDex(args, spec.pairs);
        if (this.meta) {
          this.meta.symbol = sym.name;
          try {
            if (args[0] && args[0].readCString) {
              this.meta.location = args[0].readCString();
            } else if (args[1] && args[1].readCString) {
              this.meta.location = args[1].readCString();
            }
          } catch (e) {
            this.meta.location = null;
          }
        }
      },
      onLeave: function () {
        if (this.meta) {
          dumpDex(this.meta);
        }
      }
    });
  });
}

try {
  HOOK_SPECS.forEach(hookSymbol);
  send({ event: 'agent-ready' });
} catch (e) {
  send({ event: 'agent-error', message: e.message });
}
"#;
}
