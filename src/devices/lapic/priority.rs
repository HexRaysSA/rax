//! Shared TPR access without reacquiring an already-held controller lock.
//! A snapshot clone freezes a value; an explicit handle clone shares identity.
//! Writers still require the VMM's stopped CPU/controller publication boundary.
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Public CR8 imports preserve unrepresented subclass bits when the class is
/// unchanged. An explicit MOV-to-CR8 separately clears the subclass.
pub(crate) fn import_value(current: u32, cr8: u64) -> Option<u32> {
    if current > 255 || cr8 > 15 {
        return None;
    }
    Some(if u64::from(current >> 4) == cr8 {
        current
    } else {
        (cr8 << 4) as u32
    })
}
use std::sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
};

#[derive(Clone)]
pub(crate) struct PriorityHandle(Arc<AtomicU32>);
impl PriorityHandle {
    pub(crate) fn load(&self) -> u32 {
        self.0.load(Ordering::SeqCst)
    }
    pub(crate) fn store(&self, value: u32) {
        self.0.store(value, Ordering::SeqCst);
    }
}

pub(crate) struct TaskPriority(PriorityHandle);
impl TaskPriority {
    pub(crate) fn new(value: u32) -> Self {
        Self(PriorityHandle(Arc::new(AtomicU32::new(value))))
    }
    pub(crate) fn load(&self) -> u32 {
        self.0.load()
    }
    pub(crate) fn store(&self, value: u32) {
        self.0.store(value);
    }
    pub(crate) fn handle(&self) -> PriorityHandle {
        self.0.clone()
    }
    /// Replace a frozen value while retaining handles already given to CPUs.
    pub(crate) fn restore_from(&mut self, saved: &Self) {
        self.store(saved.load());
    }
}
impl Clone for TaskPriority {
    fn clone(&self) -> Self {
        Self::new(self.load())
    }
}
// Preserve the existing positional u32 wire field exactly. No Arc/atomic
// representation, host address or synchronization state enters a checkpoint.
impl Serialize for TaskPriority {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.load().serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for TaskPriority {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        u32::deserialize(deserializer).map(Self::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_projection_import_preserves_same_class_subclass_and_rejects_invalid_bits() {
        for tpr in 0..=255 {
            for class in 0..16 {
                assert_eq!(
                    import_value(tpr, class),
                    Some(if u64::from(tpr >> 4) == class {
                        tpr
                    } else {
                        (class << 4) as u32
                    })
                );
            }
        }
        assert_eq!(import_value(256, 0), None);
        assert_eq!(import_value(0, 16), None);
    }
    #[test]
    fn explicit_handles_share_but_snapshot_clones_freeze_values() {
        let live = TaskPriority::new(0xa7);
        let handle = live.handle();
        let saved = live.clone();
        handle.store(0xb0);
        assert_eq!(live.load(), 0xb0);
        assert_eq!(saved.load(), 0xa7);
    }
    #[test]
    fn wire_bytes_match_the_previous_u32_field_and_restore_keeps_identity() {
        for value in [0, 0x5f, 0xff, u32::MAX] {
            let original = crate::codec::serialize(&value).unwrap();
            let mut live: TaskPriority = crate::codec::deserialize(&original).unwrap();
            let handle = live.handle();
            assert_eq!(crate::codec::serialize(&live).unwrap(), original);
            live.restore_from(&TaskPriority::new(0xa7));
            assert_eq!(handle.load(), 0xa7);
        }
    }

    #[test]
    fn ppr_keeps_tpr_subclass_only_when_its_class_exceeds_the_in_service_class() {
        use super::super::LocalApic;
        for tpr in 0..=255u32 {
            for in_service in 0..16u8 {
                let mut model = LocalApic::new(0);
                model.write_register(0x80, tpr);
                if in_service != 0 {
                    model.ack_interrupt((in_service << 4) | 15);
                }
                // Intel SDM086 Vol.3A12.8.3.1: equal classes are model-specific;
                // this profile consistently selects a zero PPR subclass there.
                let expected = if tpr >> 4 > u32::from(in_service) {
                    tpr
                } else {
                    u32::from(in_service) << 4
                };
                assert_eq!(model.read_register(0xa0), expected);
            }
        }
    }
}
