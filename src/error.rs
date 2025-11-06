//! Unified error handling for drizzleDumper
//!
//! This module defines domain-specific error types that provide better
//! context and debugging information than generic `anyhow::Error`.

use std::io;
use thiserror::Error;

/// Main error type for drizzleDumper operations
#[derive(Debug, Error)]
pub enum DumperError {
    /// Process with given package name was not found
    #[error("Process '{0}' not found")]
    ProcessNotFound(String),

    /// Failed to find any threads for the target process
    #[error("No threads found for process {0}")]
    NoThreadsFound(i32),

    /// Failed to attach to target process/thread
    #[error("Failed to attach to PID {pid}: {source}")]
    AttachFailed {
        pid: i32,
        #[source]
        source: anyhow::Error,
    },

    /// Memory access error during scanning
    #[error("Memory access error at address {addr:#x}: {source}")]
    MemoryAccessError {
        addr: u64,
        #[source]
        source: io::Error,
    },

    /// Invalid DEX magic number detected
    #[error("Invalid DEX magic at address {addr:#x}")]
    InvalidDexMagic { addr: u64 },

    /// DEX file size mismatch
    #[error("DEX size mismatch at {addr:#x}: declared {declared}, available {available}")]
    SizeMismatch {
        addr: u64,
        declared: u64,
        available: u64,
    },

    /// FRIDA-related errors
    #[error("FRIDA error: {0}")]
    FridaError(String),

    /// FRIDA agent timeout
    #[error("FRIDA agent did not respond within {timeout_secs}s")]
    FridaAgentTimeout { timeout_secs: u64 },

    /// FRIDA gadget errors
    #[error("Gadget error: {0}")]
    GadgetError(String),

    /// Gadget deployment not found
    #[error("Gadget deployment '{0}' not found")]
    GadgetNotFound(String),

    /// Configuration validation error
    #[error("Invalid configuration: {0}")]
    ConfigError(String),

    /// File I/O error
    #[error("File I/O error for '{path}': {source}")]
    IoError {
        path: String,
        #[source]
        source: io::Error,
    },

    /// Permission denied (e.g., not running as root)
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Feature not enabled
    #[error("Feature '{0}' not enabled at compile time")]
    FeatureNotEnabled(String),

    /// MCP protocol errors
    #[error("MCP error: {0}")]
    McpError(String),

    /// Authentication failure
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Generic error for cases not covered above
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Result type alias for drizzleDumper operations
pub type Result<T> = std::result::Result<T, DumperError>;

impl DumperError {
    /// Check if this error indicates a permission issue
    pub fn is_permission_error(&self) -> bool {
        matches!(self, DumperError::PermissionDenied(_))
    }

    /// Check if this error is recoverable (can retry)
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            DumperError::MemoryAccessError { .. }
                | DumperError::FridaAgentTimeout { .. }
                | DumperError::ProcessNotFound(_)
        )
    }

    /// Get a user-friendly error message
    pub fn user_message(&self) -> String {
        match self {
            DumperError::PermissionDenied(_) => {
                "This operation requires root privileges. Try running with 'su'.".to_string()
            }
            DumperError::FeatureNotEnabled(feat) => {
                format!("This feature requires rebuilding with '--features {}'", feat)
            }
            DumperError::ProcessNotFound(pkg) => {
                format!("Process '{}' not running. Start the app first.", pkg)
            }
            _ => self.to_string(),
        }
    }
}

/// Convert IO errors with path context
impl DumperError {
    pub fn from_io_error(path: impl Into<String>, error: io::Error) -> Self {
        DumperError::IoError {
            path: path.into(),
            source: error,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = DumperError::ProcessNotFound("com.example".to_string());
        assert_eq!(err.to_string(), "Process 'com.example' not found");
    }

    #[test]
    fn test_is_permission_error() {
        let err = DumperError::PermissionDenied("root required".to_string());
        assert!(err.is_permission_error());

        let err = DumperError::ProcessNotFound("test".to_string());
        assert!(!err.is_permission_error());
    }

    #[test]
    fn test_is_recoverable() {
        let err = DumperError::ProcessNotFound("test".to_string());
        assert!(err.is_recoverable());

        let err = DumperError::ConfigError("invalid".to_string());
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_user_message() {
        let err = DumperError::PermissionDenied("test".to_string());
        assert!(err.user_message().contains("root"));

        let err = DumperError::FeatureNotEnabled("frida".to_string());
        assert!(err.user_message().contains("--features frida"));
    }
}
