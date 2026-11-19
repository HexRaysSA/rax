//! Guest-side Win32u lookup over the captured stock resource cache.
use super::{Availability, Mem, Outcome, Proc, Thread, failure, query_error};
use crate::user::windows::gui::cursor_icons::{Catalog, MODULE};
use crate::user::windows::memory::MemFault;
use crate::user::windows::nt::error::{
    ERROR_INVALID_NAME, ERROR_INVALID_PARAMETER, ERROR_NOACCESS,
};
use crate::user::windows::nt::status::{
    STATUS_ACCESS_VIOLATION, STATUS_GUARD_PAGE_VIOLATION, STATUS_INVALID_PARAMETER,
    STATUS_OBJECT_NAME_INVALID,
};

const ERROR_INVALID_CURSOR_HANDLE: u32 = 1402;
const USER_PROBE: u64 = 0x7fff_ffff_0000;

struct Name {
    length: u16,
    maximum: u16,
    buffer: u64,
}

impl Name {
    fn read(mem: &impl Mem, address: u64) -> Result<Self, MemFault> {
        let mut bytes = [0; 16];
        mem.rd(address, &mut bytes)?;
        Ok(Self {
            length: u16::from_le_bytes([bytes[0], bytes[1]]),
            maximum: u16::from_le_bytes([bytes[2], bytes[3]]),
            buffer: u64::from_le_bytes(bytes[8..].try_into().expect("native name pointer")),
        })
    }

    fn valid_length(&self) -> bool {
        self.length <= self.maximum && self.length % 2 == 0
    }
}

#[derive(Debug)]
enum Rejection {
    Miss,
    Fault { fault: MemFault, report: bool },
    Error { error: u32, status: Option<u32> },
}

fn reported(fault: MemFault) -> Rejection {
    Rejection::Fault {
        fault,
        report: true,
    }
}

fn silent(fault: MemFault) -> Rejection {
    Rejection::Fault {
        fault,
        report: false,
    }
}

fn lookup(
    mem: &impl Mem,
    catalog: &Catalog,
    upcase: &[u16],
    [module, resource, request]: [u64; 3],
) -> Result<u32, Rejection> {
    // Capturing a supplied module can fault before either other argument.
    // Null and empty names are rejected later, after validating any handle.
    let module = if module == 0 {
        None
    } else {
        let module = Name::read(mem, module).map_err(reported)?;
        if !module.valid_length() {
            return Err(Rejection::Error {
                error: ERROR_NOACCESS,
                status: Some(STATUS_ACCESS_VIOLATION),
            });
        }
        if module.buffer == 0 {
            None
        } else {
            Some(
                mem.wunits(module.buffer, usize::from(module.length / 2))
                    .map_err(reported)?,
            )
        }
    };

    let resource = Name::read(mem, resource).map_err(silent)?;
    let ordinal = match u16::try_from(resource.buffer) {
        Ok(ordinal) => Some(ordinal),
        Err(_) if !resource.valid_length() || resource.buffer >= USER_PROBE => {
            return Err(Rejection::Miss);
        }
        Err(_) => {
            if resource.length != 0 {
                mem.bytes(resource.buffer, usize::from(resource.length))
                    .map_err(silent)?;
            }
            None
        }
    };

    let mut bytes = [0; 24];
    mem.rd(request, &mut bytes).map_err(reported)?;
    let word =
        |offset| u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("request DWORD"));
    let low_hint = word(0);
    let hint = if low_hint == 0 && word(4) == 0 {
        None
    } else {
        Some(catalog.hint(low_hint).ok_or(Rejection::Error {
            error: ERROR_INVALID_CURSOR_HANDLE,
            status: None,
        })?)
    };
    let module = module.ok_or(Rejection::Error {
        error: ERROR_INVALID_PARAMETER,
        status: Some(STATUS_INVALID_PARAMETER),
    })?;
    if module.is_empty() {
        return Err(Rejection::Error {
            error: ERROR_INVALID_NAME,
            status: Some(STATUS_OBJECT_NAME_INVALID),
        });
    }
    if !module
        .iter()
        .map(|&unit| upcase[usize::from(unit)])
        .eq(MODULE)
    {
        return Ok(0);
    }
    Ok(catalog.find(ordinal, word(8), [word(12), word(16), word(20)], hint))
}

pub(super) fn complete(p: &mut Proc, t: &Thread, arguments: [u64; 3]) -> Result<u64, Outcome> {
    let Some(Availability::Available(inputs)) = p.native.as_ref().map(|runtime| &runtime.gui)
    else {
        return Err(failure(
            "cursor/icon lookup requires selected native GUI inputs",
        ));
    };
    let catalog = inputs.cursor_icons.as_ref().map_err(|reason| {
        failure(format!(
            "selected GUI cursor/icon cache is unavailable: {reason}"
        ))
    })?;
    let upcase = p.registry.upcase_table();
    if upcase.len() != 65_536 {
        return Err(failure(
            "cursor/icon lookup requires the installed case table",
        ));
    }
    match lookup(&p.space, catalog, &upcase, arguments) {
        Ok(handle) => Ok(u64::from(handle)),
        Err(Rejection::Miss) => Ok(0),
        Err(Rejection::Error { error, status }) => query_error(p, t, error, status),
        Err(Rejection::Fault { fault, report }) => {
            let guard = p.vm.take_guard(fault.addr);
            if !report {
                return Ok(0);
            }
            if guard {
                query_error(
                    p,
                    t,
                    STATUS_GUARD_PAGE_VIOLATION,
                    Some(STATUS_GUARD_PAGE_VIOLATION),
                )
            } else {
                query_error(p, t, ERROR_NOACCESS, Some(STATUS_ACCESS_VIOLATION))
            }
        }
    }
}
