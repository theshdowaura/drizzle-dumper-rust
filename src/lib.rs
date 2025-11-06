#[cfg(all(target_arch = "aarch64", target_os = "android"))]
mod clear_cache;
pub mod cli;
pub mod config;
pub mod dex;
pub mod error;
pub mod frida_gadget;
pub mod frida_hook;
pub mod mcp;
#[path = "ptrace/mod.rs"]
pub mod ptrace;
pub mod signals;
pub mod workflow;

pub use config::Config;
pub use error::{DumperError, Result};
pub use mcp::run_mcp_server;
pub use workflow::run_dump_workflow;
