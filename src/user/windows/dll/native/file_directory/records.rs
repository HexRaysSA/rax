//! Pointer-free directory record geometry shared by every host adapter.
use super::{Checked, Completion, Ctx, Layout};
use crate::user::windows::nt::status::{STATUS_BUFFER_OVERFLOW, STATUS_SUCCESS};

pub(super) fn validate(c: &Ctx, layout: Layout, completion: &Completion) -> Checked<()> {
    let Some(information) = completion.information else {
        return Ok(());
    };
    let information = usize::try_from(information)
        .ok()
        .filter(|&size| size <= completion.bytes.len())
        .ok_or_else(|| c.unsupported("native directory result exceeded private output"))?;
    if information == 0 || !matches!(completion.code, STATUS_SUCCESS | STATUS_BUFFER_OVERFLOW) {
        return Ok(());
    }
    let mut at = 0usize;
    loop {
        let end = at
            .checked_add(layout.name)
            .filter(|&end| end <= information)
            .ok_or_else(|| c.unsupported("native directory record has a truncated fixed prefix"))?;
        let raw = &completion.bytes[at..end];
        let next = u32::from_le_bytes(raw[..4].try_into().unwrap()) as usize;
        let name_bytes =
            u32::from_le_bytes(raw[layout.length..layout.length + 4].try_into().unwrap()) as usize;
        if name_bytes % 2 != 0 {
            return Err(c
                .unsupported("native directory filename has odd byte length")
                .into());
        }
        let full = end
            .checked_add(name_bytes)
            .ok_or_else(|| c.unsupported("native directory record length overflow"))?;
        if full > information
            && !(at == 0 && next == 0 && completion.code == STATUS_BUFFER_OVERFLOW)
        {
            return Err(c
                .unsupported("native directory filename exceeds completed result")
                .into());
        }
        if next == 0 {
            return Ok(());
        }
        if next % layout.alignment as usize != 0 || next < layout.name + name_bytes {
            return Err(c
                .unsupported("native directory next-entry offset is invalid")
                .into());
        }
        at = at
            .checked_add(next)
            .filter(|&at| at < information)
            .ok_or_else(|| c.unsupported("native directory next-entry offset exceeds result"))?;
    }
}
