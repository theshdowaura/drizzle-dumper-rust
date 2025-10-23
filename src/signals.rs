use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use nix::libc;
use nix::sys::signal::{self, SigHandler, Signal};

static TRIGGER_DUMP: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_sigusr1(_: libc::c_int) {
    TRIGGER_DUMP.store(true, Ordering::SeqCst);
}

pub fn install_sigusr1_handler() -> Result<()> {
    unsafe {
        signal::signal(Signal::SIGUSR1, SigHandler::Handler(handle_sigusr1))?;
    }
    Ok(())
}

pub fn reset_trigger_flag() {
    TRIGGER_DUMP.store(false, Ordering::SeqCst);
}

pub fn is_triggered() -> bool {
    TRIGGER_DUMP.load(Ordering::SeqCst)
}

pub fn clear_trigger_flag() {
    TRIGGER_DUMP.store(false, Ordering::SeqCst);
}
