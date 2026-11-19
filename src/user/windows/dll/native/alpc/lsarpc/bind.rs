//! Local RPC transfer-syntax negotiation for the selected LSARPC endpoint.

use super::exchange::{Response, put_word, word};

pub(super) const BIND: u32 = 1;
const BIND_BYTES: usize = 72;
const NDR: u32 = 1;
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

pub(super) fn response(payload: &[u8], request_type: u16) -> Option<Response> {
    if payload.len() != BIND_BYTES || !matches!(request_type, 0 | 0x4000) {
        return None;
    }
    let negotiated = if payload[12..32] == LSARPC_INTERFACE {
        match word(payload, 32) & SYNTAX_MASK {
            1 | 5 => Ok(NDR),
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
