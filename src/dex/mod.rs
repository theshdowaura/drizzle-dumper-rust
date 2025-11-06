//! DEX file handling utilities
//!
//! This module provides common functionality for working with Android DEX files:
//! - Magic number detection (DEX/CDEX)
//! - Header validation and repair
//! - File output and manifest generation

mod header;
mod kind;
mod output;

pub use header::fix_dex_header;
pub use kind::{DexKind, detect_dex_kind};
pub use output::{build_output_path, write_dump, append_manifest};

/// DEX file header size (standard)
pub const HEADER_SIZE: usize = 0x70;

/// Minimum valid DEX file size
pub const MIN_DEX_SIZE: u64 = HEADER_SIZE as u64;
