//! Software GSI publication shares the PC bus/checkpoint controller identity.
//! There is no detached assertion queue: both levels reach the same model.
use crate::devices::ioapic::{IOAPIC_NUM_RTE, IoApic};
use crate::error::{Error, Result};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

#[derive(Default)]
pub(super) struct SoftwareIoApic {
    controller: OnceLock<Arc<Mutex<IoApic>>>,
}

pub(super) struct Source<'a> {
    gsi: u8,
    controller: MutexGuard<'a, IoApic>,
}

impl Source<'_> {
    pub(super) fn set_level(&mut self, asserted: bool) {
        self.controller.set_irq(self.gsi, asserted);
    }
}

impl SoftwareIoApic {
    pub(super) fn bind(&self, controller: Arc<Mutex<IoApic>>) -> Result<()> {
        if let Err(controller) = self.controller.set(controller) {
            if !Arc::ptr_eq(self.require_bound()?, &controller) {
                return Err(Error::InvalidConfig(
                    "software I/O APIC is already bound to another controller".into(),
                ));
            }
        }
        Ok(())
    }

    pub(super) fn require_bound(&self) -> Result<&Arc<Mutex<IoApic>>> {
        self.controller.get().ok_or_else(|| {
            Error::InvalidConfig("software GSI publication requires a bound I/O APIC".into())
        })
    }

    /// Hold the validated controller source before entering native exclusion.
    /// This matches PC checkpoint capture: controller -> native writer boundary.
    pub(super) fn source(&self, gsi: u32) -> Result<Source<'_>> {
        if gsi >= IOAPIC_NUM_RTE as u32 {
            return Err(Error::InvalidConfig(format!(
                "software GSI {gsi} exceeds I/O APIC pins"
            )));
        }
        let controller = self
            .require_bound()?
            .lock()
            .map_err(|_| Error::Emulator("software I/O APIC source lock poisoned".into()))?;
        Ok(Source {
            gsi: gsi as u8,
            controller,
        })
    }

    /// One normalized GSI assertion level. The model owns edge detection,
    /// masking and remote IRR; publication performs no CPU or bus callbacks.
    pub(super) fn set_irq_line(&self, gsi: u32, asserted: bool) -> Result<()> {
        self.source(gsi)?.set_level(asserted);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::bus::MmioDevice;

    fn controller(level: bool) -> Arc<Mutex<IoApic>> {
        let mut ioapic = IoApic::new();
        ioapic.write(0xfec0_0000, &[0x38]); // GSI20 low redirection word.
        let low = 0x51u32 | (u32::from(level) << 15);
        ioapic.write(0xfec0_0010, &low.to_le_bytes());
        Arc::new(Mutex::new(ioapic))
    }

    #[test]
    fn binding_is_idempotent_for_the_same_identity_and_rejects_replacement() {
        let source = SoftwareIoApic::default();
        assert!(source.set_irq_line(20, true).is_err());
        let original = controller(true);
        source.bind(original.clone()).unwrap();
        source.bind(original.clone()).unwrap();
        let replacement = controller(true);
        assert!(source.bind(replacement.clone()).is_err());
        source.set_irq_line(20, true).unwrap();
        assert_eq!(original.lock().unwrap().pending().len(), 1);
        assert!(replacement.lock().unwrap().pending().is_empty());
    }

    #[test]
    fn both_source_levels_reach_the_shared_edge_and_level_models() {
        for level in [false, true] {
            let source = SoftwareIoApic::default();
            let model = controller(level);
            source.bind(model.clone()).unwrap();
            source.set_irq_line(20, true).unwrap();
            source.set_irq_line(20, true).unwrap();
            assert_eq!(model.lock().unwrap().pending().len(), 1);
            source.set_irq_line(20, false).unwrap();
            assert_eq!(model.lock().unwrap().pending().len(), usize::from(!level));
            model.lock().unwrap().take_pending();
            source.set_irq_line(20, true).unwrap();
            assert_eq!(model.lock().unwrap().pending().len(), 1);
        }
    }

    #[test]
    fn abandoned_native_admission_cannot_publish_a_source_transition() {
        let source = SoftwareIoApic::default();
        let model = controller(true);
        source.bind(model.clone()).unwrap();
        let held = source.source(20).unwrap();
        drop(held); // Native exclusion/readiness can reject before publication.
        assert!(model.lock().unwrap().pending().is_empty());
        source.set_irq_line(20, true).unwrap();
        assert_eq!(model.lock().unwrap().pending().len(), 1);
        let held = source.source(20).unwrap();
        drop(held);
        assert_eq!(model.lock().unwrap().pending().len(), 1);
        source.set_irq_line(20, false).unwrap();
        assert!(model.lock().unwrap().pending().is_empty());
    }

    #[test]
    fn invalid_gsis_and_poisoned_models_return_errors_without_source_effects() {
        let source = SoftwareIoApic::default();
        let model = controller(true);
        source.bind(model.clone()).unwrap();
        for gsi in [IOAPIC_NUM_RTE as u32, 256, u32::MAX] {
            for asserted in [false, true] {
                assert!(source.set_irq_line(gsi, asserted).is_err());
                assert!(model.lock().unwrap().pending().is_empty());
            }
        }
        let held = model.clone();
        assert!(
            std::thread::spawn(move || {
                let _guard = held.lock().unwrap();
                panic!("poison source controller for publication failure");
            })
            .join()
            .is_err()
        );
        assert!(source.set_irq_line(20, true).is_err());
    }
}
