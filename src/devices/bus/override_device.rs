//! A CPU-local window can replace the legacy BSP view for one transaction.
//! Scope exit, error and unwind all restore the original device owner.
use super::{MmioBus, MmioDevice, MmioRange};
use crate::error::{Error, Result};

struct Restore<'a> {
    bus: &'a mut MmioBus,
    index: usize,
    original: Option<Box<dyn MmioDevice>>,
}
impl Drop for Restore<'_> {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            self.bus.devices[self.index].1 = original;
        }
    }
}
impl MmioBus {
    /// Fixed registration geometry remains unchanged, including split points
    /// and RMW ownership. The callback must not alter bus registration.
    pub(crate) fn with_device_override<T>(
        &mut self,
        range: MmioRange,
        device: Box<dyn MmioDevice>,
        operation: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        let index = self
            .devices
            .iter()
            .position(|(r, _)| r.base == range.base && r.len == range.len)
            .ok_or_else(|| {
                Error::InvalidConfig("CPU-local MMIO window is not registered".into())
            })?;
        let original = std::mem::replace(&mut self.devices[index].1, device);
        let restore = Restore {
            bus: self,
            index,
            original: Some(original),
        };
        operation(restore.bus)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    struct Probe(usize, Arc<AtomicUsize>);
    impl MmioDevice for Probe {
        fn read(&mut self, _: u64, bytes: &mut [u8]) {
            bytes.fill(self.0 as u8);
            self.1.fetch_add(1, Ordering::SeqCst);
        }
        fn write(&mut self, _: u64, _: &[u8]) {
            self.1.fetch_add(1, Ordering::SeqCst);
        }
    }
    #[test]
    fn every_override_outcome_restores_the_original_owner() {
        let range = MmioRange {
            base: 0x1000,
            len: 0x1000,
        };
        let original = Arc::new(AtomicUsize::new(0));
        let temporary = Arc::new(AtomicUsize::new(0));
        let mut bus = MmioBus::new();
        bus.register(range, Box::new(Probe(1, original.clone())))
            .unwrap();
        for error in [false, true] {
            let result =
                bus.with_device_override(range, Box::new(Probe(2, temporary.clone())), |bus| {
                    let mut data = [0; 4];
                    bus.read(0x1000, &mut data)?;
                    assert_eq!(data, [2; 4]);
                    if error {
                        Err(Error::Emulator("owned callback failure".into()))
                    } else {
                        Ok(())
                    }
                });
            assert_eq!(result.is_err(), error);
            let mut data = [0; 4];
            bus.read(0x1000, &mut data).unwrap();
            assert_eq!(data, [1; 4]);
        }
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: Result<()> =
                bus.with_device_override(range, Box::new(Probe(2, temporary.clone())), |_| {
                    panic!("owned unwind fixture")
                });
        }));
        assert!(unwind.is_err());
        let mut data = [0; 4];
        bus.read(0x1000, &mut data).unwrap();
        assert_eq!(data, [1; 4]);
        assert_eq!(original.load(Ordering::SeqCst), 3);
        assert_eq!(temporary.load(Ordering::SeqCst), 2);
    }
}
