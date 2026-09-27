//! Current Windows personality ACP: single-byte Windows 1252 with best fit.
//!
//! Convert the whole command line BEFORE narrow argument parsing: best-fit
//! U+FF02 becomes a syntactically active quote. Never use a reverse generic
//! CP1252 table: Microsoft's Windows MBTABLE includes five control mappings
//! that the older Unicode vendor table marks undefined.
//!
//! Supplementary/unpaired UTF-16 units each yield default 0x3F. This explicit
//! profile's native replacement cardinality is unknown (register S4).

#[path = "codepage_data.rs"]
mod data;

/// O(N log 698) time, O(N) output bytes for N UTF-16 units. No normalization,
/// UTF-8 intermediary, surrogate replacement expansion, or silent truncation.
pub(super) fn encode(units: &[u16]) -> Vec<u8> {
    units
        .iter()
        .map(|unit| {
            data::ENCODE
                .binary_search_by_key(unit, |entry| entry.0)
                .map(|index| data::ENCODE[index].1)
                .unwrap_or(b'?')
        })
        .collect()
}

/// O(N) time/output units; Windows-specific MBTABLE is total over all bytes.
pub(super) fn decode(bytes: &[u8]) -> Vec<u16> {
    bytes
        .iter()
        .map(|&byte| data::DECODE[byte as usize])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primary_windows_bestfit_examples_change_narrow_parse_syntax() {
        assert_eq!(
            encode(&[0x0100, 0xFF02, 0x2010, 0x221E, 0x20AC]),
            b"A\"-8\x80"
        );
        let raw = "p \u{ff02}two words\u{ff02}"
            .encode_utf16()
            .collect::<Vec<_>>();
        let narrow = encode(&raw).into_iter().map(u16::from).collect::<Vec<_>>();
        let arguments = super::super::parse::arguments(&narrow);
        assert_eq!(arguments.len(), 2);
        assert_eq!(
            arguments[1].units,
            "two words".encode_utf16().collect::<Vec<_>>()
        );
        assert_eq!(super::super::parse::arguments(&raw).len(), 3);
    }

    #[test]
    fn all_windows_decode_bytes_roundtrip_and_controls_are_not_undefined() {
        let bytes = (0..=255).collect::<Vec<u8>>();
        assert_eq!(encode(&decode(&bytes)), bytes);
        assert_eq!(
            decode(&[0x81, 0x8D, 0x8F, 0x90, 0x9D]),
            [0x81, 0x8D, 0x8F, 0x90, 0x9D]
        );
        assert!(data::ENCODE.windows(2).all(|pair| pair[0].0 < pair[1].0));
    }

    #[test]
    fn supplementary_and_unpaired_units_use_explicit_default_profile() {
        assert_eq!(encode(&[0xD83D, 0xDE00, 0xD800, 0xDC00, 0x4E00]), b"?????");
        assert_eq!(encode(&[0, 0xFFFF]), [0, b'?']);
    }
}
