//! Selected optional arithmetic capabilities for positive oracle cases.
use rax::isa::arm::{AArch64Config, ArmFeatures};

pub(super) fn config() -> AArch64Config {
    let mut config = AArch64Config::v8_2();
    config.features.insert(ArmFeatures::FP16 | ArmFeatures::FHM);
    config
}
