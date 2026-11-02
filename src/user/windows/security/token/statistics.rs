//! Pointer-free TOKEN_STATISTICS, owned by the exact captured token subject.

pub(crate) const BYTES: usize = 56;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Statistics([u8; BYTES]);

impl Statistics {
    #[cfg(any(windows, test))]
    pub(crate) fn selected(bytes: [u8; BYTES]) -> Option<Self> {
        let value = Self(bytes);
        match value.token_type() {
            1 => Some(value),
            2 if value.word(28) <= 3 => Some(value),
            _ => None,
        }
    }

    fn word(&self, at: usize) -> u32 {
        u32::from_le_bytes(self.0[at..at + 4].try_into().unwrap())
    }

    pub(crate) fn token_type(&self) -> u32 {
        self.word(24)
    }

    #[cfg(any(windows, test))]
    pub(crate) fn matches_counts(&self, groups: usize, privileges: usize) -> bool {
        u32::try_from(groups).ok() == Some(self.word(40))
            && u32::try_from(privileges).ok() == Some(self.word(44))
    }

    pub(crate) fn bytes(&self) -> &[u8; BYTES] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(kind: u32, level: u32) -> [u8; BYTES] {
        let mut b = std::array::from_fn(|i| (i * 37 + 19) as u8);
        for (at, value) in [(24, kind), (28, level), (40, 4), (44, 28)] {
            b[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        b
    }

    fn store(words: &mut [u64; 7], bytes: &[u8; BYTES]) {
        for (word, chunk) in words.iter_mut().zip(bytes.chunks_exact(8)) {
            *word = u64::from_ne_bytes(chunk.try_into().unwrap());
        }
    }

    #[test]
    fn token_statistics_preserves_every_byte_and_checks_subject_counts() {
        for (kind, level) in [(1, u32::MAX), (2, 0), (2, 1), (2, 2), (2, 3)] {
            let raw = record(kind, level);
            let value = Statistics::selected(raw).unwrap();
            assert_eq!(value.bytes(), &raw);
            assert_eq!(value.token_type(), kind);
            assert!(value.matches_counts(4, 28));
            assert!(!value.matches_counts(3, 28));
            assert!(!value.matches_counts(4, 27));
            assert!(!value.matches_counts(usize::MAX, usize::MAX));
        }
        for (kind, level) in [(0, 0), (3, 0), (2, 4), (2, u32::MAX)] {
            assert!(Statistics::selected(record(kind, level)).is_none());
        }
    }

    #[test]
    fn token_statistics_capture_uses_two_aligned_oppositely_initialized_records() {
        let raw = record(1, 0);
        let mut calls = 0;
        let value = capture_with(|words, got| {
            assert_eq!(words.as_ptr() as usize % 8, 0);
            assert!(words.iter().all(|w| *w
                == if calls == 0 {
                    0xa5a5a5a5a5a5a5a5
                } else {
                    0x5a5a5a5a5a5a5a5a
                }));
            calls += 1;
            store(words, &raw);
            *got = BYTES as u32;
            0
        })
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(value.bytes(), &raw);
    }

    #[test]
    fn token_statistics_capture_rejects_errors_and_wrong_returned_lengths() {
        for (status, got) in [
            (0, 0),
            (0, 55),
            (0, 57),
            (0, u32::MAX),
            (0xc0000022u32 as i32, 56),
        ] {
            let mut calls = 0;
            assert!(
                capture_with(|_, returned| {
                    calls += 1;
                    *returned = got;
                    status
                })
                .is_err()
            );
            assert_eq!(calls, 1);
        }
    }

    #[test]
    fn token_statistics_capture_rejects_undefined_or_changing_bytes() {
        for undefined in [false, true] {
            let mut calls = 0;
            assert!(
                capture_with(|words, got| {
                    calls += 1;
                    let mut raw = record(1, 0);
                    raw[0] = calls;
                    if undefined {
                        words[..6].fill(0);
                    } else {
                        store(words, &raw);
                    }
                    *got = BYTES as u32;
                    0
                })
                .is_err()
            );
            assert_eq!(calls, 2);
        }
    }
}

/// O(1) time/storage: two fixed, aligned, oppositely initialized samples.
/// No guest argument or allocation proportional to a guest length enters here.
#[cfg(any(windows, test))]
pub(crate) fn capture_with(
    mut query: impl FnMut(&mut [u64; 7], &mut u32) -> i32,
) -> Result<Statistics, String> {
    let mut first = [u64::from_ne_bytes([0xa5; 8]); 7];
    let mut second = [u64::from_ne_bytes([0x5a; 8]); 7];
    for words in [&mut first, &mut second] {
        let mut got = 0;
        let status = query(words, &mut got);
        if status != 0 || got != BYTES as u32 {
            return Err(format!(
                "native TokenStatistics capture status={status:#010x}, returned={got}; expected={BYTES}"
            ));
        }
    }
    if first != second {
        return Err("native TokenStatistics changed or left undefined bytes".into());
    }
    let bytes = std::array::from_fn(|i| first[i / 8].to_ne_bytes()[i % 8]);
    Statistics::selected(bytes)
        .ok_or_else(|| "native TokenStatistics has an unsupported token type or level".into())
}
