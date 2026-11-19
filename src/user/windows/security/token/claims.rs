//! Observed empty claim sets for the user and device on a selected token.

pub(crate) const TOKEN_USER_CLAIMS: u32 = 33;
pub(crate) const TOKEN_DEVICE_CLAIMS: u32 = 34;

/// CLAIM_SECURITY_ATTRIBUTES_INFORMATION version 1 with no attributes.
pub(crate) const EMPTY_RECORD: [u8; 16] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct EmptyClaims {
    pub(crate) user: bool,
    pub(crate) device: bool,
}
