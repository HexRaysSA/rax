//! Wire representation of optional feature bits in private ARM contexts.

pub(super) mod feature_bits {
    use crate::isa::arm::common::features::ArmFeatures;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        features: &ArmFeatures,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(features.bits())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<ArmFeatures, D::Error> {
        let bits = u64::deserialize(deserializer)?;
        ArmFeatures::from_bits(bits)
            .ok_or_else(|| serde::de::Error::custom("unknown ARM feature bits"))
    }
}
