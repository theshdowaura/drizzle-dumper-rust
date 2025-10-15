use std::env;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{getuid, Pid};
use procfs::process::{all_processes, Process};

const STATIC_SAFE_LOCATION: &str = "/data/local/tmp/";
const SUFFIX: &str = "_dumped_";
const MIN_REGION_SIZE: u64 = 10 * 1024;
const MAX_REGION_SIZE: u64 = 600 * 1024 * 1024;

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
    let wait_time = parse_wait_time(&args).unwrap_or(0.0);

    println!(
        "[*]  Try to Find {}{}",
        package_name,
        if wait_time > 0.0 {
            format!(" (poll interval {}s)", wait_time)
        } else {
            String::new()
        }
    );

    loop {
        if wait_time > 0.0 {
            thread::sleep(Duration::from_secs_f64(wait_time));
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

        match try_dump_dex(package_name, clone_pid) {
            Ok(Some(path)) => {
                println!("[+]  dex dump into {}", path.display());
                println!("[*]  Done.\n");
                break;
            }
            Ok(None) => {
                println!("[*]  The magic was Not Found!");
            }
            Err(err) => {
                eprintln!("[!]  Error while dumping: {err:?}");
            }
        }
    }

    Ok(())
}

fn print_usage() {
    println!(
        "[*]  Usage : ./drizzleDumper package_name wait_times(s)\n\
         [*]  The wait_times(s) means how long between the two scans, default 0s\n\
         [*]  If success, you can find the dex file in /data/local/tmp\n\
         [*]  Good Luck!"
    );
}

fn parse_wait_time(args: &[String]) -> Option<f64> {
    if args.len() >= 3 {
        args[2].parse::<f64>().ok()
    } else {
        None
    }
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

    for entry in fs::read_dir(&task_dir)
        .with_context(|| format!("opening thread dir {task_dir}"))?
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

fn try_dump_dex(package_name: &str, tid: i32) -> Result<Option<PathBuf>> {
    let pid = Pid::from_raw(tid);
    let mut guard = PtracedGuard::attach(pid)?;

    let mut mem =
        File::open(format!("/proc/{}/mem", tid)).with_context(|| "opening /proc/<tid>/mem")?;

    let process = Process::new(tid).with_context(|| format!("reading /proc/{tid}/maps"))?;
    let maps = process.maps().with_context(|| format!("parsing /proc/{tid}/maps"))?;

    for map in maps {
        if !map.perms.contains('r') {
            continue;
        }

        let region_start = map.address.0;
        let region_end = map.address.1;
        if region_end <= region_start {
            continue;
        }
        let region_len = region_end - region_start;
        if region_len < MIN_REGION_SIZE || region_len > MAX_REGION_SIZE {
            continue;
        }

        if let Some(buf) = inspect_region(&mut mem, region_start, region_len)
            .context("inspecting memory region")?
        {
            let output_path = build_output_path(package_name, region_start);
            write_dump(&output_path, &buf).with_context(|| "writing dump file")?;
            guard.detach();
            return Ok(Some(output_path));
        }
    }

    guard.detach();
    Ok(None)
}

fn inspect_region(mem: &mut File, start: u64, region_len: u64) -> Result<Option<Vec<u8>>> {
    const OFFSETS: [u64; 2] = [0, 8];

    for offset in OFFSETS {
        if region_len <= offset {
            continue;
        }
        if let Some(buf) = read_dex_from(mem, start + offset, region_len - offset)? {
            return Ok(Some(buf));
        }
    }

    Ok(None)
}

fn read_dex_from(mem: &mut File, base: u64, available: u64) -> Result<Option<Vec<u8>>> {
    let mut header = [0u8; 0x70];
    mem.seek(SeekFrom::Start(base))
        .with_context(|| format!("seek to 0x{base:x}"))?;

    if let Err(err) = mem.read_exact(&mut header) {
        if err.kind() == io::ErrorKind::UnexpectedEof {
            return Ok(None);
        } else {
            return Err(err).context("read dex header");
        }
    }

    if !is_dex_magic(&header[..8]) {
        return Ok(None);
    }

    let file_size = u32::from_le_bytes(header[0x20..0x24].try_into().unwrap()) as u64;
    if file_size == 0 || file_size > available {
        return Ok(None);
    }

    let mut buffer = vec![0u8; file_size as usize];
    mem.seek(SeekFrom::Start(base))
        .with_context(|| format!("seek to 0x{base:x} for full dump"))?;
    mem.read_exact(&mut buffer)
        .context("read full dex from memory")?;
    Ok(Some(buffer))
}

fn is_dex_magic(magic: &[u8]) -> bool {
    magic.len() >= 4
        && &magic[0..4] == b"dex\n"
        && magic[4..7]
            .iter()
            .all(|c| (*c == b'\0') || (c.is_ascii_digit()))
}

fn build_output_path(package_name: &str, region_start: u64) -> PathBuf {
    let file_name = format!("{package_name}{SUFFIX}{region_start:x}.dex");
    PathBuf::from(format!("{STATIC_SAFE_LOCATION}{file_name}"))
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
