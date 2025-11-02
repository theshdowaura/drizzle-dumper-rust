use std::{fs, path::PathBuf, thread, time::Duration};

use anyhow::{Context, Result};
use procfs::process::{all_processes, MMapPath, MemoryMap, Process};

use crate::config::{Config, DumpMode};
use crate::ptrace::try_dump_dex;
use crate::signals::{
    clear_trigger_flag, install_sigusr1_handler, is_triggered, reset_trigger_flag,
};

pub fn run_dump_workflow(package_name: &str, cfg: &Config) -> Result<Vec<PathBuf>> {
    if matches!(cfg.dump_mode, DumpMode::Frida) {
        return crate::frida_hook::run_frida_workflow(package_name, cfg);
    }

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

    let mut watcher = MapWatcher::default();
    let mut cached_pid: Option<i32> = None;

    loop {
        if cfg.wait_time > 0.0 {
            thread::sleep(Duration::from_secs_f64(cfg.wait_time));
        } else if cfg.signal_trigger || cfg.watch_maps {
            thread::sleep(Duration::from_millis(200));
        }

        let pid = match find_process_pid(package_name) {
            Ok(Some(pid)) => pid,
            Ok(None) => {
                if cached_pid.take().is_some() {
                    watcher.reset();
                }
                continue;
            }
            Err(err) => {
                eprintln!("[!]  Failed to enumerate processes: {err:?}");
                continue;
            }
        };

        if cached_pid != Some(pid) {
            println!("[*]  Target pid is {pid}");
            watcher.reset();
            cached_pid = Some(pid);
        }

        let event = if cfg.watch_maps {
            match watcher.observe(pid, cfg) {
                Ok(ev) => ev,
                Err(err) => {
                    eprintln!("[!]  Failed to inspect process maps: {err:?}");
                    continue;
                }
            }
        } else {
            None
        };

        let triggered = cfg.signal_trigger && is_triggered();
        if !(cfg.signal_trigger || cfg.watch_maps) || triggered || event.is_some() {
            let clone_tid = match find_clone_thread(pid) {
                Ok(Some(tid)) => tid,
                Ok(None) => continue,
                Err(err) => {
                    eprintln!("[!]  Failed to enumerate threads: {err:?}");
                    continue;
                }
            };

            println!("[*]  Using tid {} for dumping", clone_tid);
            if triggered {
                clear_trigger_flag();
                println!("[*]  SIGUSR1 trigger received; attempting dump");
            }

            if let Some(stage) = &event {
                let extra = if stage.triggered_by_threshold {
                    cfg.stage_threshold
                        .map(|th| format!(" (>= threshold {th})"))
                        .unwrap_or_default()
                } else {
                    " (new dex-like region detected)".to_string()
                };
                println!("[*]  Map watcher stage {}{}", stage.matches, extra);
            }

            match try_dump_dex(package_name, clone_tid, cfg) {
                Ok(paths) if !paths.is_empty() => {
                    for path in &paths {
                        println!("[+]  dex dump into {}", path.display());
                    }
                    println!("[*]  Done.\n");
                    return Ok(paths);
                }
                Ok(_) => {
                    println!("[*]  The magic was Not Found!");
                    if let Some(stage) = &event {
                        watcher.backoff(stage.matches);
                    }
                    if cfg.wait_time <= 0.0 && !cfg.signal_trigger && !cfg.watch_maps {
                        return Ok(Vec::new());
                    }
                }
                Err(err) => {
                    eprintln!("[!]  Error while dumping: {err:?}");
                    if let Some(stage) = &event {
                        watcher.backoff(stage.matches);
                    }
                    if cfg.wait_time <= 0.0 && !cfg.signal_trigger && !cfg.watch_maps {
                        return Err(err);
                    }
                }
            }
        }
    }
}

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
        let increased = matches > self.last_count;
        self.last_count = matches;

        if threshold_crossed || increased {
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

pub(crate) fn find_process_pid(package_name: &str) -> Result<Option<i32>> {
    for entry in all_processes().context("iterate /proc")? {
        let process = match entry {
            Ok(p) => p,
            Err(_) => continue,
        };
        if process.pid == std::process::id() as i32 {
            continue;
        }
        if let Ok(cmdline) = process.cmdline() {
            if let Some(first) = cmdline.first() {
                if first == package_name {
                    return Ok(Some(process.pid));
                }
            }
        }
    }
    Ok(None)
}

pub(crate) fn find_clone_thread(pid: i32) -> Result<Option<i32>> {
    let mut max_tid: Option<i32> = None;
    let task_dir = format!("/proc/{pid}/task");
    for entry in fs::read_dir(&task_dir).with_context(|| format!("open {task_dir}"))? {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let tid = entry
            .file_name()
            .to_string_lossy()
            .parse::<i32>()
            .unwrap_or_default();
        if tid > 0 {
            max_tid = Some(match max_tid {
                Some(current) => current.max(tid),
                None => tid,
            });
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
