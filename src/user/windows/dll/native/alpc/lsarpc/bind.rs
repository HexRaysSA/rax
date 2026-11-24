//! Local RPC transfer-syntax negotiation for the selected LSARPC endpoint.

use super::exchange::{Response, put_word, word};
use crate::user::windows::objects::LsarpcInterface;

pub(super) const BIND: u32 = 1;
const BIND_BYTES: usize = 72;
pub(super) const NDR32: u32 = 1;
pub(super) const NDR64: u32 = 2;
const SYNTAX_MASK: u32 = 7;
const RPC_S_UNKNOWN_IF: u32 = 1717;
const RPC_S_PROTOCOL_ERROR: u32 = 1728;
const RPC_S_UNSUPPORTED_TRANS_SYN: u32 = 1730;
const FAULT: u32 = 2;
const FAULT_BYTES: usize = 20;
const LSARPC_INTERFACE: [u8; 20] = [
    0x78, 0x57, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab, 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
    0, 0, 0, 0,
];

const POLICY_LOOKUP_INTERFACE: [u8; 20] = [
    0x29, 0x07, 0x8a, 0xfb, 0x04, 0x2d, 0x58, 0x46, 0xbe, 0x93, 0x27, 0xb4, 0xad, 0x55, 0x3f, 0xac,
    1, 0, 0, 0,
];

const SSPI_INTERFACE: [u8; 20] = [
    0xc8, 0xad, 0x32, 0x4f, 0x52, 0x60, 0x04, 0x4a, 0x87, 0x01, 0x29, 0x3c, 0xcf, 0x20, 0x96, 0xf0,
    1, 0, 0, 0,
];

pub(super) fn response(
    interface: LsarpcInterface,
    payload: &[u8],
    request_type: u16,
) -> Option<Response> {
    if payload.len() != BIND_BYTES || !matches!(request_type, 0 | 0x4000) {
        return None;
    }
    let expected = match interface {
        LsarpcInterface::Policy => LSARPC_INTERFACE,
        LsarpcInterface::PolicyLookup => POLICY_LOOKUP_INTERFACE,
        LsarpcInterface::Sspi => SSPI_INTERFACE,
    };
    let negotiated = if payload[12..32] == expected {
        match word(payload, 32) & SYNTAX_MASK {
            1 | 5 => Ok(NDR32),
            2 | 3 | 6 => Ok(NDR64),
            4 => Err(RPC_S_UNSUPPORTED_TRANS_SYN),
            _ => Err(RPC_S_PROTOCOL_ERROR),
        }
    } else {
        Err(RPC_S_UNKNOWN_IF)
    };
    Some(match negotiated {
        Ok(syntax) => {
            let mut body = payload.to_vec();
            put_word(&mut body, 8, 0);
            put_word(&mut body, 32, syntax);
            Response {
                body,
                request_type,
                transfer_syntax: Some(syntax),
                policy: Default::default(),
            }
        }
        Err(status) => {
            let mut body = vec![0; FAULT_BYTES];
            put_word(&mut body, 0, FAULT);
            put_word(&mut body, 8, status);
            body[16..].copy_from_slice(&payload[16..20]);
            Response {
                body,
                request_type: 0,
                transfer_syntax: None,
                policy: Default::default(),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_lookup_negotiates_ndr64_without_aliasing_the_other_lsarpc_interface() {
        let mut payload = [0; BIND_BYTES];
        put_word(&mut payload, 0, BIND);
        put_word(&mut payload, 12, 0xfb8a_0729);
        put_word(&mut payload, 16, 0x4658_2d04);
        put_word(&mut payload, 20, 0xb427_93be);
        put_word(&mut payload, 24, 0xac3f_55ad);
        put_word(&mut payload, 28, 1);
        put_word(&mut payload, 32, 3);

        let accepted = response(LsarpcInterface::PolicyLookup, &payload, 0x4000).unwrap();
        assert_eq!(accepted.transfer_syntax, Some(NDR64));
        assert_eq!(accepted.request_type, 0x4000);
        put_word(&mut payload, 32, NDR64);
        assert_eq!(accepted.body, payload);

        let rejected = response(LsarpcInterface::Policy, &payload, 0x4000).unwrap();
        assert_eq!(rejected.transfer_syntax, None);
        assert_eq!(word(&rejected.body, 8), RPC_S_UNKNOWN_IF);

        put_word(&mut payload, 28, 0);
        let rejected = response(LsarpcInterface::PolicyLookup, &payload, 0x4000).unwrap();
        assert_eq!(rejected.transfer_syntax, None);
        assert_eq!(word(&rejected.body, 8), RPC_S_UNKNOWN_IF);
    }

    #[test]
    fn sspi_bind_is_distinct_from_both_policy_interfaces() {
        let mut payload = [0; BIND_BYTES];
        put_word(&mut payload, 0, BIND);
        for (offset, value) in [
            (12, 0x4f32_adc8),
            (16, 0x4a04_6052),
            (20, 0x3c29_0187),
            (24, 0xf096_20cf),
            (28, 1),
        ] {
            put_word(&mut payload, offset, value);
        }
        for (offer, selected) in [(1, NDR32), (3, NDR64)] {
            put_word(&mut payload, 32, offer);
            let reply = response(LsarpcInterface::Sspi, &payload, 0x4000).unwrap();
            assert_eq!(reply.transfer_syntax, Some(selected));
            assert_eq!(word(&reply.body, 32), selected);
        }
        for policy in [LsarpcInterface::Policy, LsarpcInterface::PolicyLookup] {
            let rejected = response(policy, &payload, 0x4000).unwrap();
            assert_eq!(rejected.transfer_syntax, None);
            assert_eq!(word(&rejected.body, 8), RPC_S_UNKNOWN_IF);
        }
        put_word(&mut payload, 28, 2);
        let rejected = response(LsarpcInterface::Sspi, &payload, 0x4000).unwrap();
        assert_eq!(rejected.transfer_syntax, None);
        assert_eq!(word(&rejected.body, 8), RPC_S_UNKNOWN_IF);
    }
}
