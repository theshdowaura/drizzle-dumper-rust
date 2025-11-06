//! DEX file type detection

/// Represents the type of DEX file
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DexKind {
    /// Standard DEX format (dex\n035)
    Dex,
    /// Compact DEX format (cdex)
    Cdex,
}

impl DexKind {
    /// Returns the file extension for this DEX kind
    pub fn extension(&self) -> &'static str {
        match self {
            DexKind::Dex => "dex",
            DexKind::Cdex => "cdex",
        }
    }

    /// Returns the string representation for manifest output
    pub fn as_str(&self) -> &'static str {
        match self {
            DexKind::Dex => "DEX",
            DexKind::Cdex => "CDEX",
        }
    }

    /// Parse DEX kind from magic string
    pub fn from_magic(magic: &str) -> Option<Self> {
        match magic {
            "dex\n" => Some(DexKind::Dex),
            "cdex" => Some(DexKind::Cdex),
            _ => None,
        }
    }
}

/// Detect DEX file type from header bytes
///
/// # Arguments
/// * `header` - First few bytes of the file (at least 5 bytes recommended)
///
/// # Returns
/// - `Some(DexKind::Dex)` if standard DEX format detected
/// - `Some(DexKind::Cdex)` if compact DEX format detected
/// - `None` if not a valid DEX file
pub fn detect_dex_kind(header: &[u8]) -> Option<DexKind> {
    if header.len() < 5 {
        return None;
    }

    // Check for standard DEX format: "dex\n" followed by version digits
    if &header[0..4] == b"dex\n"
        && header[4..7]
            .iter()
            .all(|c| *c == b'\0' || c.is_ascii_digit())
    {
        return Some(DexKind::Dex);
    }

    // Check for compact DEX format: "cdex\n"
    if &header[0..4] == b"cdex" && header.get(4) == Some(&b'\n') {
        return Some(DexKind::Cdex);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_standard_dex() {
        let header = b"dex\n035\0extra bytes";
        assert_eq!(detect_dex_kind(header), Some(DexKind::Dex));
    }

    #[test]
    fn test_detect_compact_dex() {
        let header = b"cdex\nextra bytes";
        assert_eq!(detect_dex_kind(header), Some(DexKind::Cdex));
    }

    #[test]
    fn test_invalid_magic() {
        let header = b"invalid";
        assert_eq!(detect_dex_kind(header), None);
    }

    #[test]
    fn test_too_short() {
        let header = b"dex";
        assert_eq!(detect_dex_kind(header), None);
    }

    #[test]
    fn test_from_magic() {
        assert_eq!(DexKind::from_magic("dex\n"), Some(DexKind::Dex));
        assert_eq!(DexKind::from_magic("cdex"), Some(DexKind::Cdex));
        assert_eq!(DexKind::from_magic("invalid"), None);
    }

    #[test]
    fn test_extension() {
        assert_eq!(DexKind::Dex.extension(), "dex");
        assert_eq!(DexKind::Cdex.extension(), "cdex");
    }
}
