//! Shared timer LVT/MSR ownership without taking a controller lock in a CPU.
//! The bounded state lock never spans native calls, callbacks or allocation.
//! Controller snapshots clone values; explicitly cloned handles share identity.
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::sync::{Arc, Mutex, MutexGuard};

const MODE: u32 = 3 << 17;
const DEADLINE: u32 = 2 << 17;
const MASK: u32 = 1 << 16;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Image {
    pub(crate) lvt: u32,
    pub(crate) deadline: u64,
    pub(crate) pending: [u64; 4],
}

impl Image {
    pub(crate) const BYTES: usize = 44;

    pub(crate) fn encode(self) -> [u8; Self::BYTES] {
        let mut bytes = [0; Self::BYTES];
        bytes[..4].copy_from_slice(&self.lvt.to_le_bytes());
        bytes[4..12].copy_from_slice(&self.deadline.to_le_bytes());
        for (index, word) in self.pending.into_iter().enumerate() {
            bytes[12 + index * 8..20 + index * 8].copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::BYTES {
            return None;
        }
        let mut image = Self {
            lvt: u32::from_le_bytes(bytes[..4].try_into().ok()?),
            deadline: u64::from_le_bytes(bytes[4..12].try_into().ok()?),
            pending: [0; 4],
        };
        for (index, word) in image.pending.iter_mut().enumerate() {
            *word = u64::from_le_bytes(bytes[12 + index * 8..20 + index * 8].try_into().ok()?);
        }
        image.valid().then_some(image)
    }

    pub(crate) fn valid(&self) -> bool {
        self.deadline == 0 || self.lvt & MODE == DEADLINE
    }

    pub(crate) fn is_quiescent(&self) -> bool {
        self.deadline == 0 && self.pending == [0; 4]
    }
}

#[derive(Clone)]
pub(crate) struct Handle(Arc<Mutex<Image>>);

impl Handle {
    fn state(&self) -> MutexGuard<'_, Image> {
        // No user code or fallible operation runs under this lock. Every
        // mutation below is a bounded scalar/array operation without a panic
        // path; recovering a poisoned guard cannot expose a partial mutation.
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn snapshot(&self) -> Image {
        *self.state()
    }

    pub(crate) fn restore(&self, image: Image) {
        *self.state() = image;
    }

    pub(crate) fn read(&self) -> u64 {
        self.state().deadline
    }

    pub(crate) fn write(&self, value: u64) {
        let mut state = self.state();
        if state.lvt & MODE == DEADLINE {
            state.deadline = value;
        }
    }

    /// Intel SDM086 Vol.3A12.5.4.1 uses an unsigned comparison, not modular
    /// half-range ordering. Expiry disarms even a masked timer. Raised vectors
    /// remain owned here until the controller transfers them into its IRR.
    pub(crate) fn expire(&self, now: u64) {
        let mut state = self.state();
        if state.deadline == 0 || now < state.deadline {
            return;
        }
        state.deadline = 0;
        if state.lvt & MASK == 0 {
            let vector = (state.lvt & 0xff) as usize;
            state.pending[vector / 64] |= 1u64 << (vector % 64);
        }
    }

    pub(crate) fn take_pending(&self) -> [u64; 4] {
        std::mem::take(&mut self.state().pending)
    }
}

pub(crate) struct TimerLvt(Handle);

impl TimerLvt {
    pub(crate) fn new(lvt: u32) -> Self {
        Self(Handle(Arc::new(Mutex::new(Image {
            lvt,
            ..Image::default()
        }))))
    }

    pub(crate) fn value(&self) -> u32 {
        self.0.state().lvt
    }

    pub(crate) fn write(&self, value: u32) {
        let mut state = self.0.state();
        if state.lvt & MODE != value & MODE {
            state.deadline = 0;
        }
        state.lvt = value;
    }

    pub(crate) fn handle(&self) -> Handle {
        self.0.clone()
    }

    pub(crate) fn restore_from(&self, other: &Self) {
        self.0.restore(other.0.snapshot());
    }
}

impl Clone for TimerLvt {
    fn clone(&self) -> Self {
        Self(Handle(Arc::new(Mutex::new(self.0.snapshot()))))
    }
}

// Keep the legacy positional LVT u32 byte-for-byte. Complete execution and
// native CPU extensions transport the deadline and outstanding vector bitmap.
impl Serialize for TimerLvt {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.value().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TimerLvt {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        u32::deserialize(deserializer).map(Self::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deadline_mode_owns_all_64_bits_and_mode_changes_disarm_it() {
        let timer = TimerLvt::new(0x51);
        let msr = timer.handle();
        for mode in [0, 1, 2, 3] {
            timer.write((mode << 17) | 0x51);
            for value in [0, 1, 1 << 63, u64::MAX] {
                msr.write(value);
                assert_eq!(msr.read(), if mode == 2 { value } else { 0 });
            }
        }
        timer.write(DEADLINE | 0x51);
        msr.write(u64::MAX);
        timer.write(DEADLINE | MASK | 0x61);
        assert_eq!(msr.read(), u64::MAX, "mask/vector changes retain the arm");
        timer.write(0x51);
        assert_eq!(msr.read(), 0);
        timer.write(DEADLINE | 0x51);
        assert_eq!(msr.read(), 0);
    }

    #[test]
    fn expiry_uses_unsigned_tsc_order_and_masked_expiry_does_not_reappear() {
        for masked in [false, true] {
            let timer = TimerLvt::new(DEADLINE | 0x51 | if masked { MASK } else { 0 });
            let msr = timer.handle();
            msr.write(u64::MAX);
            msr.expire(u64::MAX - 1);
            assert_eq!(msr.read(), u64::MAX);
            msr.expire(u64::MAX);
            assert_eq!(msr.read(), 0);
            let mut expected = [0; 4];
            if !masked {
                expected[1] = 1 << 17;
            }
            assert_eq!(msr.take_pending(), expected);
            timer.write(DEADLINE | 0x51);
            msr.expire(u64::MAX);
            assert_eq!(msr.take_pending(), [0; 4]);
            msr.write(1);
            msr.expire(1 << 63);
            assert_eq!(msr.read(), 0, "unsigned comparison across half range");
        }
    }

    #[test]
    fn expired_vectors_coalesce_without_losing_distinct_vectors_or_identity() {
        let timer = TimerLvt::new(DEADLINE | 0x51);
        let msr = timer.handle();
        for vector in [0x51, 0x61, 0x51] {
            timer.write(DEADLINE | vector);
            msr.write(1);
            msr.expire(1);
        }
        let saved = timer.clone();
        let frozen = saved.handle().snapshot();
        assert_eq!(msr.take_pending()[1], (1 << 17) | (1 << 33));
        assert_eq!(saved.handle().snapshot(), frozen);
        timer.restore_from(&saved);
        assert_eq!(msr.snapshot(), frozen);
        assert_eq!(
            crate::codec::serialize(&timer).unwrap(),
            crate::codec::serialize(&(DEADLINE | 0x51)).unwrap()
        );
    }
}
