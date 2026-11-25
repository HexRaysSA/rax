//! Fixed-size NT file information returned through a separate I/O status block.

use super::super::named_object::{Checked, Failure, finish_with, status};
use super::super::query::probe_write;
use super::attributes;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::{
    STATUS_DATATYPE_MISALIGNMENT, STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_INFO_CLASS,
    STATUS_INVALID_PARAMETER, STATUS_SUCCESS,
};

#[derive(Clone, Copy)]
pub(super) struct Layout {
    #[cfg(windows)]
    pub(super) class: u32,
    pub(super) bytes: u32,
    alignment: u64,
}

impl Layout {
    fn of(class: u32) -> Option<Self> {
        let (bytes, alignment) = match class {
            68 => (72, 8),  // FileStatInformation
            70 => (96, 8),  // FileStatLxInformation
            71 => (4, 4),   // FileCaseSensitiveInformation
            77 => (104, 8), // FileStatBasicInformation
            _ => return None,
        };
        Some(Self {
            #[cfg(windows)]
            class,
            bytes,
            alignment,
        })
    }
}

pub(super) struct Completion {
    pub(super) code: u32,
    pub(super) information: Option<u32>,
    pub(super) data: [u8; 104],
}

pub(in super::super) fn query(c: &mut Ctx) -> ApiResult {
    let mut publishing = false;
    let result = checked(c, &mut publishing);
    finish_with(c, result, publishing)
}

fn checked(c: &mut Ctx, publishing: &mut bool) -> Checked<u32> {
    let (attrs, io, output, length, class) =
        (c.ptr(0)?, c.ptr(1)?, c.ptr(2)?, c.u32(3)?, c.u32(4)?);
    let Some(layout) = Layout::of(class) else {
        // Native by-name dispatch distinguishes recognized file classes
        // that are inapplicable here from unrecognized class numbers.
        return status(match class {
            4..=9
            | 14
            | 16..=18
            | 21..=26
            | 28
            | 29
            | 32..=35
            | 41
            | 43..=49
            | 51
            | 53..=55
            | 58
            | 59
            | 62
            | 67
            | 74..=76
            | 82 => STATUS_INVALID_PARAMETER,
            _ => STATUS_INVALID_INFO_CLASS,
        });
    };
    if length < layout.bytes {
        return status(STATUS_INFO_LENGTH_MISMATCH);
    }

    let wow = c.arch() == WinArch::X86;
    let captured = if wow {
        Some(attributes::capture(c, attrs, true)?)
    } else {
        None
    };
    probe_write(c, io, 4)?;
    let alignment = if wow { 4 } else { layout.alignment };
    if output % alignment != 0 {
        return status(STATUS_DATATYPE_MISALIGNMENT);
    }
    probe_write(c, output, length as usize)?;

    let completion = match execute(c, attrs, captured, layout) {
        Ok(completion) => completion,
        Err(Failure::Status(code)) => Completion {
            code,
            information: Some(0),
            data: [0; 104],
        },
        Err(error) => return Err(error),
    };
    *publishing = true;
    if completion.code == STATUS_SUCCESS {
        c.mem()
            .wr(output, &completion.data[..layout.bytes as usize])?;
    }
    if let Some(information) = completion.information {
        let width = c.psize();
        c.mem().wptr(io, width, u64::from(completion.code))?;
        c.mem().wptr(io + width, width, u64::from(information))?;
    }
    Ok(completion.code)
}

fn execute(
    c: &Ctx,
    address: u64,
    captured: Option<Option<attributes::Attributes>>,
    layout: Layout,
) -> Checked<Completion> {
    let attrs = match captured {
        Some(attrs) => attrs,
        None => attributes::capture(c, address, false)?,
    };
    let Some(attrs) = attrs else {
        return status(STATUS_INVALID_PARAMETER);
    };
    let name = attributes::validate(c, &attrs)?;
    #[cfg(windows)]
    return super::metadata::by_name(c, &attrs, name.as_deref(), layout);
    #[cfg(not(windows))]
    {
        let _ = (name, layout);
        Err(c
            .unsupported("NtQueryInformationByName requires a Windows host")
            .into())
    }
}
