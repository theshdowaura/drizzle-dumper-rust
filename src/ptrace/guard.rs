use anyhow::{anyhow, Context, Result};
use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;

pub(super) struct PtracedGuard {
    pid: Pid,
    attached: bool,
}

impl PtracedGuard {
    pub(super) fn attach(tid: i32) -> Result<Self> {
        let pid = Pid::from_raw(tid);
        ptrace::attach(pid).with_context(|| format!("ptrace attach {pid}"))?;
        match waitpid(pid, None)? {
            WaitStatus::Stopped(_, _) => Ok(Self {
                pid,
                attached: true,
            }),
            other => Err(anyhow!("unexpected wait status: {other:?}")),
        }
    }

    pub(super) fn detach(&mut self) {
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
