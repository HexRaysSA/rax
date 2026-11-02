//! Bounded, immutable native SystemCodeIntegrityPoliciesFullInformation bytes.
//! No guest arguments reach the acquisition query.

#[cfg(windows)]
pub(super) fn capture() -> Result<std::sync::Arc<[u8]>, String> {
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQuerySystemInformation(
            class: u32,
            output: *mut std::ffi::c_void,
            bytes: u32,
            returned: *mut u32,
        ) -> i32;
    }
    capture_with(|data, returned| {
        let output = if data.is_empty() {
            std::ptr::null_mut()
        } else {
            data.as_mut_ptr().cast()
        };
        // SAFETY: fixed read-only class189 and private initialized storage,
        // aligned to eight bytes, bounded by MAX_BYTES, with an exclusive
        // ULONG result. Both destinations live for this synchronous query.
        // No guest class, pointer or requested length is forwarded.
        unsafe { NtQuerySystemInformation(189, output, data.len() as u32, returned) }
    })
    .map(std::sync::Arc::from)
}

#[cfg(not(windows))]
pub(super) fn capture() -> Result<std::sync::Arc<[u8]>, String> {
    Err("native code integrity policies require a Windows host".into())
}

#[cfg(any(windows, test))]
const MAX_BYTES: usize = 16 << 20;
#[cfg(any(windows, test))]
const LENGTH_MISMATCH: i32 = 0xc000_0004_u32 as i32;

#[cfg(any(windows, test))]
struct Aligned {
    words: Vec<u64>,
    bytes: usize,
}

#[cfg(any(windows, test))]
impl Aligned {
    fn new(bytes: usize, poison: u8) -> Result<Self, String> {
        let count = bytes.div_ceil(8);
        let mut words = Vec::new();
        words.try_reserve_exact(count).map_err(|e| {
            format!("native SystemCodeIntegrityPoliciesFullInformation capture allocation: {e}")
        })?;
        words.resize(count, u64::from_ne_bytes([poison; 8]));
        Ok(Self { words, bytes })
    }

    fn bytes(&mut self) -> &mut [u8] {
        // SAFETY: initialized exclusive u64 storage has eight-byte alignment;
        // the bounded byte window cannot exceed its allocation or lifetime.
        unsafe { std::slice::from_raw_parts_mut(self.words.as_mut_ptr().cast(), self.bytes) }
    }
}

#[cfg(any(windows, test))]
fn capture_with(mut query: impl FnMut(&mut [u8], &mut u32) -> i32) -> Result<Vec<u8>, String> {
    for _ in 0..3 {
        let mut required = 0;
        let status = query(&mut [], &mut required);
        if status != LENGTH_MISMATCH || required == 0 || required as usize > MAX_BYTES {
            return Err(format!(
                "native SystemCodeIntegrityPoliciesFullInformation size query status={status:#010x}, required={required}; cap={MAX_BYTES}"
            ));
        }
        let length = required as usize;
        let mut first = Aligned::new(length, 0xa5)?;
        let mut got = 0;
        let status = query(first.bytes(), &mut got);
        if status == LENGTH_MISMATCH || status == 0 && got != required {
            continue;
        }
        if status != 0 {
            return Err(format!(
                "native SystemCodeIntegrityPoliciesFullInformation capture status={status:#010x}, returned={got}"
            ));
        }
        let mut second = Aligned::new(length, 0x5a)?;
        let mut got = 0;
        let status = query(second.bytes(), &mut got);
        if status == LENGTH_MISMATCH || status == 0 && got != required {
            continue;
        }
        if status != 0 {
            return Err(format!(
                "native SystemCodeIntegrityPoliciesFullInformation verification status={status:#010x}, returned={got}"
            ));
        }
        if first.bytes() == second.bytes() {
            return Ok(first.bytes().to_vec());
        }
    }
    Err("native SystemCodeIntegrityPoliciesFullInformation size or bytes changed, or bytes remained undefined during bounded capture".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_bound_precedes_any_data_allocation_or_query() {
        for required in [0, MAX_BYTES as u32 + 1, u32::MAX] {
            let mut calls = 0;
            assert!(
                capture_with(|data, returned| {
                    calls += 1;
                    assert!(data.is_empty());
                    *returned = required;
                    LENGTH_MISMATCH
                })
                .is_err()
            );
            assert_eq!(calls, 1);
        }
    }

    #[test]
    fn odd_sized_bytes_are_aligned_defined_and_exact() {
        let record: Vec<_> = (0..8193).map(|i| ((i * 37 + 19) % 256) as u8).collect();
        let mut calls = 0;
        let result = capture_with(|data, returned| {
            calls += 1;
            *returned = record.len() as u32;
            if data.is_empty() {
                return LENGTH_MISMATCH;
            }
            assert_eq!(data.as_ptr() as usize % 8, 0);
            assert_eq!(data.len(), record.len());
            data.copy_from_slice(&record);
            0
        })
        .unwrap();
        assert_eq!(result, record);
        assert_eq!(calls, 3);
    }

    #[test]
    fn undefined_tail_exhausts_the_bounded_pair_attempts() {
        let mut calls = 0;
        let result = capture_with(|data, returned| {
            calls += 1;
            *returned = 32;
            if data.is_empty() {
                return LENGTH_MISMATCH;
            }
            data[..31].fill(0);
            0
        });
        assert!(result.unwrap_err().contains("undefined"));
        assert_eq!(calls, 9);
    }

    #[test]
    fn changing_bytes_never_publish_a_sample() {
        let mut calls = 0;
        assert!(
            capture_with(|data, returned| {
                calls += 1;
                *returned = 8;
                if data.is_empty() {
                    return LENGTH_MISMATCH;
                }
                data.fill(calls);
                0
            })
            .is_err()
        );
        assert_eq!(calls, 9);
    }

    #[test]
    fn racing_size_restarts_with_an_independent_probe() {
        let mut calls = 0;
        let result = capture_with(|data, returned| {
            calls += 1;
            *returned = if calls == 1 { 8 } else { 16 };
            if data.len() < *returned as usize {
                return LENGTH_MISMATCH;
            }
            data.fill(0x37);
            0
        })
        .unwrap();
        assert_eq!(result, [0x37; 16]);
        assert_eq!(calls, 5);
    }

    #[test]
    fn native_errors_remain_explicit() {
        let result = capture_with(|_, _| 0xc000_0003_u32 as i32);
        assert!(result.unwrap_err().contains("c0000003"));
    }

    #[test]
    fn successful_queries_with_wrong_lengths_do_not_publish() {
        let mut calls = 0;
        assert!(
            capture_with(|data, returned| {
                calls += 1;
                *returned = if data.is_empty() { 8 } else { 0 };
                if data.is_empty() { LENGTH_MISMATCH } else { 0 }
            })
            .is_err()
        );
        assert_eq!(calls, 6);
    }
}
