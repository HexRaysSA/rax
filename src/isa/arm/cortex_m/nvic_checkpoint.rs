//! Fixed-size controller image admission; no MMIO register replay.
use super::{MAX_INTERRUPTS, Nvic};

impl Nvic {
    pub(crate) fn validate_checkpoint(&self, target: &Self) -> crate::error::Result<()> {
        if self.num_interrupts != target.num_interrupts
            || self.priority_bits != target.priority_bits
            || self.num_interrupts > MAX_INTERRUPTS
            || !(2..=8).contains(&self.priority_bits)
            || self.priority_group > 7
            || self.current_exception >= 512
        {
            return Err(crate::error::Error::InvalidConfig(
                "Cortex-M checkpoint NVIC profile or fields differ".into(),
            ));
        }
        Ok(())
    }
}

pub(super) mod priorities {
    use super::MAX_INTERRUPTS;
    use serde::de::{Error, SeqAccess, Visitor};
    use serde::ser::SerializeTuple;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &[u8; MAX_INTERRUPTS], s: S) -> Result<S::Ok, S::Error> {
        let mut tuple = s.serialize_tuple(MAX_INTERRUPTS)?;
        for byte in value {
            tuple.serialize_element(byte)?;
        }
        tuple.end()
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; MAX_INTERRUPTS], D::Error> {
        struct Fixed;
        impl<'de> Visitor<'de> for Fixed {
            type Value = [u8; MAX_INTERRUPTS];
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{MAX_INTERRUPTS} priority bytes")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                let mut out = [0; MAX_INTERRUPTS];
                for (i, byte) in out.iter_mut().enumerate() {
                    *byte = a
                        .next_element()?
                        .ok_or_else(|| A::Error::invalid_length(i, &self))?;
                }
                Ok(out)
            }
        }
        d.deserialize_tuple(MAX_INTERRUPTS, Fixed)
    }
}
