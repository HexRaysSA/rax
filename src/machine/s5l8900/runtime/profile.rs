//! Effective guest-affecting diagnostics, distinct from host logging/sink owners.
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Serialize, Deserialize)]
pub(super) struct GuestProfile {
    #[serde(deserialize_with = "key")]
    pub(super) gid_key: Option<Vec<u8>>,
    pub(super) logical0_page: Option<u32>,
    pub(super) no_sparse_vfl_mask: bool,
    pub(super) no_security_seed: bool,
    pub(super) guid_probe_score: Option<u32>,
}
fn key<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Option<Vec<u8>>, D::Error> {
    #[derive(Deserialize)]
    struct Key(#[serde(deserialize_with = "bytes")] Vec<u8>);
    fn bytes<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
        crate::devices::checkpoint_serde::vector::<u8, D, 32>(d)
    }
    Option::<Key>::deserialize(d).map(|v| v.map(|v| v.0))
}
fn decode_key(value: &str) -> Option<Vec<u8>> {
    let value = value.trim().trim_start_matches("0x").as_bytes();
    if !matches!(value.len(), 32 | 48 | 64) {
        return None;
    }
    fn digit(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    value
        .chunks_exact(2)
        .map(|p| Some((digit(p[0])? << 4) | digit(p[1])?))
        .collect()
}
impl GuestProfile {
    pub(super) fn from_environment() -> Self {
        Self {
            gid_key: std::env::var("RAX_S5L_GID_KEY")
                .ok()
                .and_then(|v| decode_key(&v)),
            logical0_page: std::env::var("RAX_S5L_LOGICAL0_PAGE")
                .ok()
                .and_then(|v| v.parse().ok()),
            no_sparse_vfl_mask: std::env::var("RAX_S5L_NO_SPARSE_VFL_MASK").is_ok(),
            no_security_seed: std::env::var("RAX_S5L_NO_SECURITY_SEED").is_ok(),
            guid_probe_score: std::env::var_os("RAX_S5L_GUID_PROBE_SCORE").map(|_| {
                std::env::var("RAX_S5L_GUID_PROBE_SCORE")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(50_000)
            }),
        }
    }
    pub(super) fn validate(&self) -> Result<()> {
        if self
            .gid_key
            .as_ref()
            .is_some_and(|v| !matches!(v.len(), 16 | 24 | 32))
        {
            return Err(Error::InvalidConfig(
                "S5L effective GID key length is invalid".into(),
            ));
        }
        Ok(())
    }
}
impl super::S5L8900Vcpu {
    pub(super) fn effective_guest_profile(&self) -> std::borrow::Cow<'_, GuestProfile> {
        match &self.guest_profile {
            Some(p) => std::borrow::Cow::Borrowed(p),
            None => std::borrow::Cow::Owned(GuestProfile::from_environment()),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn effective_gid_admission_handles_lengths_ascii_and_utf8_without_panics() {
        for len in [16, 24, 32] {
            assert_eq!(decode_key(&"a5".repeat(len)), Some(vec![0xa5; len]));
        }
        for value in [
            "0é0",
            "éé",
            "00",
            "",
            "0x",
            &"gg".repeat(16),
            &"a5".repeat(33),
        ] {
            assert!(decode_key(value).is_none());
        }
        assert_eq!(
            decode_key(&format!(" 0x{} ", "A5".repeat(16))),
            Some(vec![0xa5; 16])
        );
    }
}
