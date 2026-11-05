//! Pure fixed-width transformations used by indivisible MMIO transactions.
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[path = "shift.rs"]
mod shift;
pub use shift::MmioShift;

/// A scalar MMIO read/modify/write transformation. Even an unsuccessful
/// comparison writes the old value back, matching x86 CMPXCHG bus semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MmioRmwOp {
    Exchange(u64),
    CompareExchange {
        expected: u64,
        replacement: u64,
    },
    Add {
        value: u64,
        carry: bool,
    },
    Subtract {
        value: u64,
        borrow: bool,
    },
    And(u64),
    Or(u64),
    Xor(u64),
    Not,
    Negate,
    BitSet(u8),
    BitReset(u8),
    BitComplement(u8),
    Shift {
        kind: MmioShift,
        count: u8,
        carry: bool,
    },
}

impl MmioRmwOp {
    /// Admit the complete descriptor before invoking a device callback.
    pub fn validate(self, size: u8) -> Result<()> {
        if !matches!(size, 1 | 2 | 4 | 8) {
            return Err(Error::InvalidConfig("invalid scalar MMIO RMW width".into()));
        }
        if let Self::Shift {
            kind, carry: true, ..
        } = self
            && !matches!(
                kind,
                MmioShift::RotateCarryLeft | MmioShift::RotateCarryRight
            )
        {
            return Err(Error::InvalidConfig(
                "non-carry MMIO shift has a carry input".into(),
            ));
        }
        if let Self::BitSet(bit) | Self::BitReset(bit) | Self::BitComplement(bit) = self {
            if u32::from(bit) >= u32::from(size) * 8 {
                return Err(Error::InvalidConfig(
                    "MMIO RMW bit exceeds operand width".into(),
                ));
            }
        }
        Ok(())
    }

    /// Transform one little-endian operand. Time and space are O(1), with an
    /// eight-byte maximum operand; rejection leaves the buffer unchanged.
    pub fn apply(self, bytes: &mut [u8]) -> Result<()> {
        let size = u8::try_from(bytes.len())
            .map_err(|_| Error::InvalidConfig("invalid scalar MMIO RMW length".into()))?;
        self.validate(size)?;
        let mut raw = [0; 8];
        raw[..bytes.len()].copy_from_slice(bytes);
        let old = u64::from_le_bytes(raw);
        let mask = u64::MAX >> (64 - u32::from(size) * 8);
        let value = match self {
            Self::Exchange(value) => value,
            Self::CompareExchange {
                expected,
                replacement,
            } => {
                if old == expected & mask {
                    replacement
                } else {
                    old
                }
            }
            Self::Add { value, carry } => old.wrapping_add(value).wrapping_add(u64::from(carry)),
            Self::Subtract { value, borrow } => {
                old.wrapping_sub(value).wrapping_sub(u64::from(borrow))
            }
            Self::And(value) => old & value,
            Self::Or(value) => old | value,
            Self::Xor(value) => old ^ value,
            Self::Not => !old,
            Self::Negate => old.wrapping_neg(),
            Self::BitSet(bit) => old | (1u64 << bit),
            Self::BitReset(bit) => old & !(1u64 << bit),
            Self::BitComplement(bit) => old ^ (1u64 << bit),
            Self::Shift { kind, count, carry } => kind.apply(old, size, count, carry),
        };
        bytes.copy_from_slice(&value.to_le_bytes()[..usize::from(size)]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::bus::{MmioBus, MmioDevice, MmioRange, SharedMmioDevice};
    use std::sync::{Arc, Barrier, Mutex, TryLockError, Weak};

    struct Register {
        value: u64,
        log: Arc<Mutex<Vec<(bool, Vec<u8>)>>>,
        owner: Weak<Mutex<Register>>,
    }
    impl Register {
        fn check_lock(&self) {
            if let Some(owner) = self.owner.upgrade() {
                assert!(matches!(owner.try_lock(), Err(TryLockError::WouldBlock)));
            }
        }
    }
    impl MmioDevice for Register {
        fn read(&mut self, _: u64, data: &mut [u8]) {
            self.check_lock();
            data.copy_from_slice(&self.value.to_le_bytes()[..data.len()]);
            self.log.lock().unwrap().push((false, data.to_vec()));
            std::thread::yield_now();
        }
        fn write(&mut self, _: u64, data: &[u8]) {
            self.check_lock();
            let mut bytes = self.value.to_le_bytes();
            bytes[..data.len()].copy_from_slice(data);
            self.value = u64::from_le_bytes(bytes);
            self.log.lock().unwrap().push((true, data.to_vec()));
        }
    }

    #[test]
    fn transform_boundaries_use_fixed_width_wrapping_and_preserve_rejected_inputs() {
        for size in [1u8, 2, 4, 8] {
            let width = usize::from(size);
            let mut value = vec![0xff; width];
            MmioRmwOp::Add {
                value: 0,
                carry: true,
            }
            .apply(&mut value)
            .unwrap();
            assert_eq!(value, vec![0; width]);
            MmioRmwOp::Subtract {
                value: 0,
                borrow: true,
            }
            .apply(&mut value)
            .unwrap();
            assert_eq!(value, vec![0xff; width]);
            MmioRmwOp::Negate.apply(&mut value).unwrap();
            assert_eq!(value[0], 1);
            assert!(value[1..].iter().all(|b| *b == 0));
            let before = value.clone();
            assert!(MmioRmwOp::BitSet(size * 8).apply(&mut value).is_err());
            assert_eq!(value, before);
        }
        for width in [0, 3, 5, 9, 256] {
            let mut value = vec![0xa5; width];
            assert!(MmioRmwOp::Not.apply(&mut value).is_err());
            assert_eq!(value, vec![0xa5; width]);
        }
    }

    #[test]
    fn unsuccessful_compare_still_performs_exactly_one_write_cycle() {
        for expected in [0x1234u64, 0x5678] {
            let log = Arc::new(Mutex::new(Vec::new()));
            let mut device = Register {
                value: 0x1234,
                log: log.clone(),
                owner: Weak::new(),
            };
            let old = device
                .read_modify_write(
                    0,
                    2,
                    MmioRmwOp::CompareExchange {
                        expected,
                        replacement: 0xabcd,
                    },
                )
                .unwrap();
            assert_eq!(old, 0x1234u16.to_le_bytes());
            let new = if expected == 0x1234 {
                0xabcdu16
            } else {
                0x1234
            };
            assert_eq!(device.value, u64::from(new));
            assert_eq!(
                *log.lock().unwrap(),
                vec![(false, old), (true, new.to_le_bytes().to_vec())]
            );
        }
    }

    #[test]
    fn shared_adapters_hold_one_guard_across_both_callbacks_and_release_it_on_return() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let device = Arc::new(Mutex::new(Register {
            value: 0,
            log: log.clone(),
            owner: Weak::new(),
        }));
        device.lock().unwrap().owner = Arc::downgrade(&device);
        let barrier = Arc::new(Barrier::new(3));
        let workers: Vec<_> = (0..2)
            .map(|_| {
                let device = device.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let mut adapter = SharedMmioDevice::new(device.clone());
                    barrier.wait();
                    for _ in 0..1000 {
                        adapter
                            .read_modify_write(
                                0,
                                8,
                                MmioRmwOp::Add {
                                    value: 1,
                                    carry: false,
                                },
                            )
                            .unwrap();
                        // No model guard escapes the completed transaction.
                        // Another worker can own it now, so check only its final
                        // availability after both workers join below.
                    }
                })
            })
            .collect();
        barrier.wait();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(device.try_lock().unwrap().value, 2000);
        let log = log.lock().unwrap();
        assert_eq!(log.len(), 4000);
        for pair in log.chunks_exact(2) {
            assert!(!pair[0].0 && pair[1].0);
        }
    }

    #[test]
    fn bus_admission_rejects_cross_mapping_and_invalid_descriptors_before_callbacks() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut bus = MmioBus::new();
        bus.register(
            MmioRange {
                base: 0x1000,
                len: 8,
            },
            Box::new(Register {
                value: 0x1234,
                log: log.clone(),
                owner: Weak::new(),
            }),
        )
        .unwrap();
        assert!(bus.read_modify_write(0x1007, 2, MmioRmwOp::Not).is_err());
        assert!(bus.read_modify_write(u64::MAX, 2, MmioRmwOp::Not).is_err());
        assert!(
            bus.read_modify_write(0x1000, 1, MmioRmwOp::BitSet(8))
                .is_err()
        );
        assert!(log.lock().unwrap().is_empty());
        let old = bus
            .read_modify_write(0x1000, 2, MmioRmwOp::Exchange(0x5678))
            .unwrap();
        assert_eq!(old, [0x34, 0x12]);
        assert_eq!(log.lock().unwrap().len(), 2);
        assert_eq!(
            bus.read_modify_write(0x2000, 4, MmioRmwOp::Not).unwrap(),
            [0xff; 4]
        );
        assert_eq!(log.lock().unwrap().len(), 2);
    }

    #[test]
    fn poisoned_shared_model_fails_before_any_read_or_write_callback() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let device = Arc::new(Mutex::new(Register {
            value: 7,
            log: log.clone(),
            owner: Weak::new(),
        }));
        let worker_device = device.clone();
        assert!(
            std::thread::spawn(move || {
                let _guard = worker_device.lock().unwrap();
                panic!("intentional model-lock poisoning");
            })
            .join()
            .is_err()
        );
        let mut adapter = SharedMmioDevice::new(device);
        assert!(
            adapter
                .read_modify_write(0, 4, MmioRmwOp::Exchange(8))
                .is_err()
        );
        assert!(log.lock().unwrap().is_empty());
    }
}
