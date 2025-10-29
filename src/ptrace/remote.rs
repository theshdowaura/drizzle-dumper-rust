use anyhow::{bail, Context, Result};
use std::path::Path;

#[cfg(target_arch = "aarch64")]
mod imp {
    use super::*;
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};

    use goblin::elf::{note::NT_PRSTATUS, Elf};
    use nix::libc;
    use nix::sys::ptrace;
    use nix::sys::wait::{waitpid, WaitStatus};
    use nix::unistd::Pid;
    use procfs::process::{MMapPath, Process};

    pub(crate) fn inject_library(tid: i32, library: &Path) -> Result<()> {
        let pid = Pid::from_raw(tid);
        let mut proc = RemoteProcess::attach(pid)?;

        let dlopen_addr = resolve_remote_symbol(pid, "libdl.so", "dlopen")
            .or_else(|_| resolve_remote_symbol(pid, "libdl_android.so", "dlopen"))
            .context("resolve remote dlopen")?;

        let flags = libc::RTLD_NOW | libc::RTLD_GLOBAL;
        let cstr_addr = proc.write_cstring(library)?;
        proc.call_function(dlopen_addr, &[cstr_addr, flags as u64, 0, 0, 0, 0])?;
        Ok(())
    }

    struct RemoteProcess {
        pid: Pid,
        regs_backup: UserPtRegs,
        mem: File,
    }

    impl RemoteProcess {
        fn attach(pid: Pid) -> Result<Self> {
            ptrace::attach(pid).with_context(|| format!("ptrace attach {pid}"))?;
            match waitpid(pid, None)? {
                WaitStatus::Stopped(_, _) => {}
                other => bail!("unexpected wait status {other:?}"),
            }
            let regs = getregs(pid)?;
            let mem = OpenOptions::new()
                .read(true)
                .write(true)
                .open(format!("/proc/{}/mem", pid))
                .context("open /proc/pid/mem")?;
            Ok(Self {
                pid,
                regs_backup: regs,
                mem,
            })
        }

        fn call_function(&mut self, func: u64, args: &[u64]) -> Result<u64> {
            let mut regs = getregs(self.pid)?;
            let backup = regs;

            let stack = (regs.sp - 0x400) & !0xf;
            let trampoline = stack - 0x10;
            let mut orig = [0u8; 4];
            self.read_exact(trampoline, &mut orig)?;
            self.write_bytes(trampoline, &TRAP_INSTRUCTION)?;

            regs.sp = stack;
            regs.set_lr(trampoline);
            regs.pc = func;

            for (idx, value) in args.iter().enumerate() {
                regs.set_x(idx, *value);
            }

            setregs(self.pid, &regs)?;
            ptrace::cont(self.pid, None)?;

            loop {
                match waitpid(self.pid, None)? {
                    WaitStatus::Stopped(_, nix::sys::signal::Signal::SIGTRAP) => break,
                    WaitStatus::Stopped(_, _) => ptrace::cont(self.pid, None)?,
                    other => bail!("unexpected wait status {other:?} during call"),
                }
            }

            let result_regs = getregs(self.pid)?;
            setregs(self.pid, &backup)?;
            self.write_bytes(trampoline, &orig)?;

            Ok(result_regs.x(0))
        }

        fn write_cstring(&mut self, path: &Path) -> Result<u64> {
            let bytes = path
                .to_str()
                .ok_or_else(|| anyhow!("library path must be utf-8"))?
                .as_bytes();
            let len = bytes.len() + 1;

            let mut regs = getregs(self.pid)?;
            let addr = (regs.sp - (len as u64 + 0x20)) & !0xf;
            regs.sp = addr;
            setregs(self.pid, &regs)?;

            let mut buf = Vec::with_capacity(len);
            buf.extend_from_slice(bytes);
            buf.push(0);
            self.write_bytes(addr, &buf)?;
            Ok(addr)
        }

        fn write_bytes(&mut self, addr: u64, data: &[u8]) -> Result<()> {
            self.mem
                .seek(SeekFrom::Start(addr))
                .context("seek remote mem")?;
            self.mem.write_all(data).context("write remote mem")
        }

        fn read_exact(&mut self, addr: u64, buf: &mut [u8]) -> Result<()> {
            self.mem
                .seek(SeekFrom::Start(addr))
                .context("seek remote mem")?;
            self.mem.read_exact(buf).context("read remote mem")
        }
    }

    impl Drop for RemoteProcess {
        fn drop(&mut self) {
            let _ = setregs(self.pid, &self.regs_backup);
            let _ = ptrace::detach(self.pid, None);
        }
    }

    fn resolve_remote_symbol(pid: Pid, hint: &str, symbol: &str) -> Result<u64> {
        let process = Process::new(pid.as_raw()).context("proc entry")?;
        for map in process.maps()? {
            let path = match &map.pathname {
                MMapPath::Path(p) => p,
                _ => continue,
            };
            if !path
                .file_name()
                .and_then(|s| s.to_str())
                .map(|n| n.contains(hint))
                .unwrap_or(false)
            {
                continue;
            }

            let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)?;
            let elf = Elf::parse(&buffer).context("parse elf")?;
            if let Some((_, sym)) = elf
                .dynsyms
                .iter()
                .enumerate()
                .find(|(idx, _)| elf.dynstrtab.get_at(*idx) == Some(symbol))
            {
                let addr = map.address.0 + sym.st_value;
                return Ok(addr);
            }
        }
        Err(anyhow!("symbol {symbol} not found in {hint}"))
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct UserPtRegs {
        regs: [u64; 31],
        sp: u64,
        pc: u64,
        pstate: u64,
    }

    impl UserPtRegs {
        fn set_x(&mut self, idx: usize, value: u64) {
            if idx < self.regs.len() {
                self.regs[idx] = value;
            }
        }

        fn x(&self, idx: usize) -> u64 {
            self.regs.get(idx).copied().unwrap_or(0)
        }

        fn set_lr(&mut self, value: u64) {
            self.set_x(30, value);
        }
    }

    fn getregs(pid: Pid) -> Result<UserPtRegs> {
        unsafe {
            let mut iov = libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: std::mem::size_of::<UserPtRegs>(),
            };
            let mut regs = std::mem::MaybeUninit::<UserPtRegs>::uninit();
            iov.iov_base = regs.as_mut_ptr() as *mut _;
            iov.iov_len = std::mem::size_of::<UserPtRegs>();
            let ret = libc::ptrace(
                libc::PTRACE_GETREGSET,
                pid.as_raw(),
                NT_PRSTATUS as *mut libc::c_void,
                &mut iov as *mut _ as *mut libc::c_void,
            );
            if ret != 0 {
                bail!("ptrace getregs failed: {}", std::io::Error::last_os_error());
            }
            Ok(regs.assume_init())
        }
    }

    fn setregs(pid: Pid, regs: &UserPtRegs) -> Result<()> {
        unsafe {
            let mut iov = libc::iovec {
                iov_base: regs as *const _ as *mut _,
                iov_len: std::mem::size_of::<UserPtRegs>(),
            };
            let ret = libc::ptrace(
                libc::PTRACE_SETREGSET,
                pid.as_raw(),
                NT_PRSTATUS as *mut libc::c_void,
                &mut iov as *mut _ as *mut libc::c_void,
            );
            if ret != 0 {
                bail!("ptrace setregs failed: {}", std::io::Error::last_os_error());
            }
            Ok(())
        }
    }

    const TRAP_INSTRUCTION: [u8; 4] = 0x00d03dd4u32.to_le_bytes();
}

#[cfg(target_arch = "aarch64")]
pub(crate) use imp::inject_library;

#[cfg(not(target_arch = "aarch64"))]
pub(crate) fn inject_library(_tid: i32, _library: &Path) -> Result<()> {
    bail!("gadget injection only supported on aarch64 builds")
}
