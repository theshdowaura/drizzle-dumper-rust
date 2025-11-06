//! DEX header manipulation and repair

use sha1::{Digest, Sha1};

use super::kind::{DexKind, detect_dex_kind};

/// DEX header offsets
const CHECKSUM_OFFSET: usize = 0x08;
const SIGNATURE_OFFSET: usize = 0x0C;
const SIGNATURE_END: usize = 0x20;

/// Recompute and fix DEX header checksum and signature
///
/// This function updates the Adler-32 checksum (at offset 0x08) and
/// SHA-1 signature (at offset 0x0C-0x1F) for a standard DEX file.
///
/// # Arguments
/// * `buffer` - Mutable slice containing the complete DEX file
///
/// # Behavior
/// - Only processes standard DEX format (not CDEX)
/// - Requires buffer length > 0x20 (32 bytes)
/// - Updates in-place: checksum at 0x08, signature at 0x0C-0x1F
pub fn fix_dex_header(buffer: &mut [u8]) {
    // Only fix standard DEX format
    if !matches!(detect_dex_kind(buffer), Some(DexKind::Dex)) {
        return;
    }

    // Need at least signature end offset
    if buffer.len() <= SIGNATURE_END {
        return;
    }

    // Compute SHA-1 signature over everything after offset 0x20
    let mut hasher = Sha1::new();
    hasher.update(&buffer[SIGNATURE_END..]);
    let signature = hasher.finalize();

    // Update signature field
    buffer[SIGNATURE_OFFSET..SIGNATURE_END].copy_from_slice(&signature[..20]);

    // Compute Adler-32 checksum over everything after offset 0x0C
    let checksum = adler32(&buffer[SIGNATURE_OFFSET..]);

    // Update checksum field
    buffer[CHECKSUM_OFFSET..SIGNATURE_OFFSET].copy_from_slice(&checksum.to_le_bytes());
}

/// Compute Adler-32 checksum (as used in DEX files)
///
/// # Arguments
/// * `data` - Byte slice to checksum
///
/// # Returns
/// 32-bit Adler-32 checksum in little-endian format
fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65_521;
    let mut a = 1u32;
    let mut b = 0u32;

    for &byte in data {
        a = (a + byte as u32) % MOD;
        b = (b + a) % MOD;
    }

    (b << 16) | a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adler32_empty() {
        assert_eq!(adler32(&[]), 1);
    }

    #[test]
    fn test_adler32_known_value() {
        // "Wikipedia" has a known Adler-32 of 0x11E60398
        let data = b"Wikipedia";
        assert_eq!(adler32(data), 0x11E60398);
    }

    #[test]
    fn test_fix_dex_header_too_short() {
        let mut buffer = vec![0u8; 0x10];
        buffer[0..4].copy_from_slice(b"dex\n");

        let original = buffer.clone();
        fix_dex_header(&mut buffer);

        // Should not modify if too short
        assert_eq!(buffer, original);
    }

    #[test]
    fn test_fix_dex_header_not_dex() {
        let mut buffer = vec![0u8; 0x100];
        buffer[0..4].copy_from_slice(b"cdex");

        let checksum_before = u32::from_le_bytes([
            buffer[0x08], buffer[0x09], buffer[0x0A], buffer[0x0B]
        ]);

        fix_dex_header(&mut buffer);

        let checksum_after = u32::from_le_bytes([
            buffer[0x08], buffer[0x09], buffer[0x0A], buffer[0x0B]
        ]);

        // Should not modify CDEX
        assert_eq!(checksum_before, checksum_after);
    }

    #[test]
    fn test_fix_dex_header_valid() {
        let mut buffer = vec![0u8; 0x100];
        buffer[0..4].copy_from_slice(b"dex\n");
        buffer[4..7].copy_from_slice(b"035");

        // Fill with some data
        for i in 0x20..buffer.len() {
            buffer[i] = (i % 256) as u8;
        }

        fix_dex_header(&mut buffer);

        // Verify checksum was written
        let checksum = u32::from_le_bytes([
            buffer[0x08], buffer[0x09], buffer[0x0A], buffer[0x0B]
        ]);
        assert_ne!(checksum, 0);

        // Verify signature was written (non-zero)
        let signature_sum: u32 = buffer[0x0C..0x20].iter().map(|&b| b as u32).sum();
        assert_ne!(signature_sum, 0);
    }
}
