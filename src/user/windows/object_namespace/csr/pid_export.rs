//! The measured native AMD64 readonly PID export, without executing host code.
use std::ops::Range;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Globals {
    pub(crate) pid: u64,
    pub(crate) flag: u64,
}

/// Decode the two RIP-relative loads after checking the complete20-byte body.
/// Every code/data span must belong to the selected loaded module. O(1).
pub(crate) fn decode(code: &[u8], entry: u64, module: Range<u64>) -> Option<Globals> {
    let code = code.get(..20)?;
    if module.start >= module.end
        || entry < module.start
        || entry.checked_add(20)? > module.end
        || code[..3] != [0x48, 0x8B, 0x05]
        || code[7..11] != [0x33, 0xC9, 0x38, 0x0D]
        || code[15..20] != [0x48, 0x0F, 0x45, 0xC1, 0xC3]
    {
        return None;
    }
    let relative = |offset: u64, bytes: &[u8]| {
        let displacement = i32::from_le_bytes(bytes.try_into().ok()?) as i64;
        entry.checked_add(offset)?.checked_add_signed(displacement)
    };
    let pid = relative(7, &code[3..7])?;
    let flag = relative(15, &code[11..15])?;
    if pid < module.start || pid.checked_add(8)? > module.end || !module.contains(&flag) {
        return None;
    }
    Some(Globals { pid, flag })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_export_replays_both_independently_verified_native_amd64_captures() {
        let captures: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../docs/specifications/windows/native-session-csr-connect/profiles-v3.json"
        ))
        .unwrap();
        for row in captures["projections"].as_array().unwrap() {
            let text = row["code_hex"].as_str().unwrap();
            let code: Vec<_> = (0..text.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
                .collect();
            let entry = row["entry"].as_u64().unwrap();
            // This deliberately minimal test range encloses the observed spans;
            // native acquisition separately obtains the actual PE image extent.
            let module =
                row["module"].as_u64().unwrap()..row["minimum_enclosing_end"].as_u64().unwrap();
            assert_eq!(
                decode(&code, entry, module.clone()),
                Some(Globals {
                    pid: row["pid_address"].as_u64().unwrap(),
                    flag: row["flag_address"].as_u64().unwrap(),
                })
            );
            assert_eq!(
                decode(
                    &code,
                    entry,
                    module.start..row["pid_address"].as_u64().unwrap() + 7
                ),
                None
            );
        }
    }

    #[test]
    fn pid_export_checks_signed_operands_and_every_span_before_reading_globals() {
        let mut code = [0; 20];
        code[..3].copy_from_slice(&[0x48, 0x8B, 0x05]);
        code[3..7].copy_from_slice(&(-263i32).to_le_bytes());
        code[7..11].copy_from_slice(&[0x33, 0xC9, 0x38, 0x0D]);
        code[11..15].copy_from_slice(&512i32.to_le_bytes());
        code[15..].copy_from_slice(&[0x48, 0x0F, 0x45, 0xC1, 0xC3]);
        assert_eq!(
            decode(&code, 0x1100, 0x1000..0x1400),
            Some(Globals {
                pid: 0x1000,
                flag: 0x130F
            })
        );
        assert_eq!(decode(&code, 0x1100, 0x1001..0x1400), None);
        assert_eq!(decode(&code, 0x1100, 0x1000..0x130F), None);
        assert_eq!(decode(&code[..19], 0x1100, 0x1000..0x1400), None);
        for index in [0, 1, 2, 7, 8, 9, 10, 15, 16, 17, 18, 19] {
            let mut altered = code;
            altered[index] ^= 1;
            assert_eq!(decode(&altered, 0x1100, 0x1000..0x1400), None);
        }
        assert_eq!(decode(&code, 0, 0..u64::MAX), None);
        assert_eq!(decode(&code, u64::MAX - 19, 0..u64::MAX), None);
    }
}
