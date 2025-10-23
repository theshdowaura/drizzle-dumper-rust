use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use procfs::process::{all_processes, MMapPath, MemoryMap, Process};

use crate::config::Config;
use crate::ptrace::try_dump_dex;
use crate::signals::{
    clear_trigger_flag, install_sigusr1_handler, is_triggered, reset_trigger_flag,
};

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

pub fn run_dump_workflow(package_name: &str, cfg: &Config) -> Result<Vec<PathBuf>> {
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
        install_sigusr1_handler()?;
        reset_trigger_flag();
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
                Ok(event) => map_event = event,
                Err(err) => {
                    eprintln!("[!]  Failed to inspect process maps: {err:?}");
                    continue;
                }
            }
        }

        let signal_fired = cfg.signal_trigger && is_triggered();
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
            clear_trigger_flag();
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
