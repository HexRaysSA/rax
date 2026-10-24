//! Serialization adapters kept outside the standalone QARMA reference module.

use super::pauth::{PauthAlgorithm, PauthConfig, PauthProfile};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Serialize, Deserialize)]
#[serde(remote = "PauthAlgorithm")]
enum Algorithm {
    Qarma3,
    Qarma5,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "PauthProfile")]
enum Profile {
    Base,
    Pauth2,
    Fpac,
    FpacCombine,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "PauthConfig")]
struct Config {
    algorithm: PauthAlgorithm,
    profile: PauthProfile,
}

macro_rules! serialization_adapter {
    ($value:ty, $wire:ident) => {
        impl Serialize for $value {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                $wire::serialize(self, serializer)
            }
        }

        impl<'de> Deserialize<'de> for $value {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                $wire::deserialize(deserializer)
            }
        }
    };
}

serialization_adapter!(PauthAlgorithm, Algorithm);
serialization_adapter!(PauthProfile, Profile);
serialization_adapter!(PauthConfig, Config);
