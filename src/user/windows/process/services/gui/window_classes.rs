//! Native 64-bit Win32u class entry points using guest-owned USER objects.

use super::{
    Availability, Mem, MemoryAccessKind, Outcome, Proc, Thread, WinArch, failure, query_error,
    windows,
};
use crate::user::windows::gui::window_classes::{
    CS_GLOBALCLASS, DEFAULT_IME_CURSOR, Definition, MENU_BYTES, Name, RECORD_BYTES,
};
use crate::user::windows::memory::MemFault;
use crate::user::windows::nt::error::{
    ERROR_INVALID_NAME, ERROR_INVALID_PARAMETER, ERROR_NOACCESS,
};
use crate::user::windows::nt::status::{
    STATUS_ACCESS_VIOLATION, STATUS_GUARD_PAGE_VIOLATION, STATUS_OBJECT_NAME_INVALID,
};

const ERROR_INVALID_FLAGS: u32 = 1004;
const ERROR_CLASS_DOES_NOT_EXIST: u32 = 1411;
const CLASS_STYLE_MASK: u32 = 0x37bff;
const CLASS_FLAGS_MASK: u32 = 0xc2;
const ANSI_PROCEDURE: u32 = 2;

enum Rejection {
    Fault(MemFault),
    Error(u32, Option<u32>),
    Unsupported(&'static str),
}

impl From<MemFault> for Rejection {
    fn from(fault: MemFault) -> Self {
        Self::Fault(fault)
    }
}

impl Rejection {
    fn invalid_memory() -> Self {
        Self::Error(ERROR_NOACCESS, Some(STATUS_ACCESS_VIOLATION))
    }

    fn report(self, p: &mut Proc, t: &Thread) -> Result<u64, Outcome> {
        match self {
            Self::Fault(fault) if p.vm.take_guard(fault.addr) => query_error(
                p,
                t,
                STATUS_GUARD_PAGE_VIOLATION,
                Some(STATUS_GUARD_PAGE_VIOLATION),
            ),
            Self::Fault(_) => query_error(p, t, ERROR_NOACCESS, Some(STATUS_ACCESS_VIOLATION)),
            Self::Error(error, status) => query_error(p, t, error, status),
            Self::Unsupported(reason) => Err(failure(reason)),
        }
    }
}

fn dword(record: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(record[offset..offset + 4].try_into().expect("class DWORD"))
}

fn qword(record: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(record[offset..offset + 8].try_into().expect("class QWORD"))
}

struct Counted {
    bytes: usize,
    buffer: u64,
}

impl Counted {
    fn read(mem: &impl Mem, address: u64) -> Result<Self, Rejection> {
        let mut record = [0; 16];
        mem.rd(address, &mut record)?;
        let bytes = u16::from_le_bytes([record[0], record[1]]) as usize;
        let capacity = u16::from_le_bytes([record[2], record[3]]) as usize;
        if bytes % 2 != 0 || bytes > capacity {
            return Err(Rejection::invalid_memory());
        }
        Ok(Self {
            bytes,
            buffer: qword(&record, 8),
        })
    }

    fn class_name(&self, mem: &impl Mem) -> Result<Name, Rejection> {
        if self.bytes == 0
            && let Ok(ordinal @ 1..) = u16::try_from(self.buffer)
        {
            return Ok(Name::Ordinal(ordinal));
        }
        if self.bytes > 255 * 2 {
            return Err(Rejection::Error(ERROR_INVALID_PARAMETER, None));
        }
        Ok(Name::Counted(mem.wunits(self.buffer, self.bytes / 2)?))
    }
}

fn class_name(mem: &impl Mem, descriptor: u64) -> Result<Option<Name>, Rejection> {
    if descriptor == 0 {
        return Ok(None);
    }
    Ok(Some(Counted::read(mem, descriptor)?.class_name(mem)?))
}

fn empty(name: &Name) -> bool {
    matches!(name, Name::Counted(units) if units.is_empty())
}

fn require_case_table(upcase: &[u16]) -> Result<(), Outcome> {
    if upcase.len() != 65_536 {
        return Err(failure("window classes require the installed case table"));
    }
    Ok(())
}

fn registration(
    p: &Proc,
    [class, primary, version, menu, function, flags, wow]: [u64; 7],
) -> Result<Option<(Name, Name, Definition)>, Rejection> {
    let flags = flags as u32;
    if flags & !CLASS_FLAGS_MASK != 0 {
        return Err(Rejection::Error(ERROR_INVALID_FLAGS, None));
    }
    match function as u16 {
        0 | 0x29a | 0x29b | 0x29e | 0x2a0..=0x2b8 => {}
        // Reserved IDs within the function range are rejected before probing
        // any caller record, with the same error as an invalid resource.
        0x29c | 0x29d | 0x29f => return Err(Rejection::Error(ERROR_INVALID_PARAMETER, None)),
        _ => return Ok(None),
    }
    if wow != 0 {
        return Err(Rejection::Unsupported(
            "WOW class registration data is unavailable",
        ));
    }

    let mem = &p.space;
    let mut record = [0; RECORD_BYTES];
    mem.rd(class, &mut record)?;
    let primary = class_name(mem, primary)?;
    let version = class_name(mem, version)?;
    let mut menu_record = [0; MENU_BYTES];
    mem.rd(menu, &mut menu_record)?;
    let counted_menu = Counted::read(mem, qword(&menu_record, 16))?;
    if counted_menu.bytes != 0 {
        mem.probe(
            counted_menu.buffer,
            counted_menu.bytes,
            MemoryAccessKind::Read,
        )
        .map_err(|fault| MemFault {
            addr: fault.address,
            write: false,
        })?;
    }

    let (Some(primary), Some(version)) = (primary, version) else {
        return Ok(None);
    };
    if empty(&version) {
        return Err(Rejection::Error(
            ERROR_INVALID_NAME,
            Some(STATUS_OBJECT_NAME_INVALID),
        ));
    }
    if empty(&primary) {
        return Ok(None);
    }
    let class_extra = dword(&record, 16) as i32;
    if class_extra < 0 {
        return Err(Rejection::Error(ERROR_INVALID_PARAMETER, None));
    }
    // The kernel rejects an allocation whose header cannot fit in a signed
    // byte count. Class extra bytes have no guest mapping until consumed.
    if class_extra == i32::MAX {
        return Ok(None);
    }

    let handles = [qword(&record, 32), qword(&record, 40), qword(&record, 72)];
    if handles.iter().any(|&handle| handle != 0) {
        let Some(Availability::Available(inputs)) = p.native.as_ref().map(|runtime| &runtime.gui)
        else {
            return Err(Rejection::Unsupported(
                "window class GUI inputs are unavailable",
            ));
        };
        let catalog = inputs.cursor_icons.as_ref().map_err(|_| {
            Rejection::Unsupported("window class cursor/icon inputs are unavailable")
        })?;
        if handles.iter().any(|&handle| {
            handle != 0
                && u32::try_from(handle)
                    .ok()
                    .and_then(|value| catalog.hint(value))
                    .is_none()
        }) {
            return Err(Rejection::Error(ERROR_INVALID_PARAMETER, None));
        }
    }

    let style = dword(&record, 4) & CLASS_STYLE_MASK;
    record[4..8].copy_from_slice(&style.to_le_bytes());
    // The native query returns menu information through a separate client
    // output, and publishes neither caller's class-name pointer.
    record[56..72].fill(0);
    Ok(Some((
        primary,
        version,
        Definition {
            record,
            menu: [qword(&menu_record, 0), qword(&menu_record, 8)],
            ansi_procedure: flags & ANSI_PROCEDURE != 0,
            ime_ansi_procedure: None,
        },
    )))
}

pub(super) fn register(p: &mut Proc, t: &Thread, arguments: [u64; 7]) -> Result<u64, Outcome> {
    let (primary, version, mut definition) = match registration(p, arguments) {
        Ok(Some(registration)) => registration,
        Ok(None) => return Ok(0),
        Err(error) => return error.report(p, t),
    };
    let upcase = p.registry.upcase_table();
    require_case_table(&upcase)?;
    if p.arch == WinArch::Arm64
        && arguments[4] as u16 == windows::FNID_IME
        && arguments[5] as u32 == 0x40
        && primary.is_default_ime(&upcase)
        && version.is_default_ime(&upcase)
        && user_module(p)
            .or_else(|| windows::default_ime_user_module(p))
            .is_some_and(|user| definition.module() == user)
        && definition.procedure() == windows::ime_procedure(p, false)?
    {
        definition.ime_ansi_procedure = Some(windows::ime_procedure(p, true)?);
        definition.record[40..48].copy_from_slice(&DEFAULT_IME_CURSOR.to_le_bytes());
    }
    match p
        .gui
        .register_class(&upcase, &primary, &version, definition)
    {
        Ok(atom) => Ok(u64::from(atom)),
        Err(error) => query_error(p, t, error, None),
    }
}

fn required_name(mem: &impl Mem, descriptor: u64) -> Result<Name, Rejection> {
    let name = Counted::read(mem, descriptor)?.class_name(mem)?;
    if empty(&name) {
        Err(Rejection::Error(
            ERROR_CLASS_DOES_NOT_EXIST,
            Some(STATUS_OBJECT_NAME_INVALID),
        ))
    } else {
        Ok(name)
    }
}

fn probe_output(p: &Proc, address: u64, len: usize) -> Result<(), MemFault> {
    p.space
        .probe(address, len, MemoryAccessKind::Write)
        .map_err(|fault| MemFault {
            addr: fault.address,
            write: true,
        })
}

pub(super) fn user_module(p: &Proc) -> Option<u64> {
    p.modules
        .by_name("user32.dll")
        .map(|index| p.modules.list[index].base)
}

pub(super) fn get(
    p: &mut Proc,
    t: &Thread,
    [module, descriptor, class_out, menu_out, ansi]: [u64; 5],
) -> Result<u64, Outcome> {
    let upcase = p.registry.upcase_table();
    require_case_table(&upcase)?;
    let operation = || -> Result<u64, Rejection> {
        probe_output(p, class_out, RECORD_BYTES)?;
        probe_output(p, menu_out, 8)?;
        let name = required_name(&p.space, descriptor)?;
        let user = user_module(p);
        let Some(class) = p.gui.class(&upcase, &name, module, user) else {
            return Err(Rejection::Error(ERROR_CLASS_DOES_NOT_EXIST, None));
        };
        let definition = &class.definition;
        let ansi = ansi as u32 != 0;
        let mut record = definition.record;
        if let Some(ansi_procedure) = definition.ime_ansi_procedure {
            let style = dword(&record, 4) & !CS_GLOBALCLASS;
            record[4..8].copy_from_slice(&style.to_le_bytes());
            if ansi {
                record[8..16].copy_from_slice(&ansi_procedure.to_le_bytes());
            }
        } else if ansi != definition.ansi_procedure && definition.procedure() != 0 {
            return Err(Rejection::Unsupported(
                "window class procedure encoding conversion is unavailable",
            ));
        }
        let user = if user.is_none() && definition.ime_ansi_procedure.is_some() {
            windows::default_ime_user_module(p)
        } else {
            user
        };
        let client_module = if Some(module) == user { 0 } else { module };
        record[24..32].copy_from_slice(&client_module.to_le_bytes());
        let menu = definition.menu[if ansi { 0 } else { 1 }];
        p.space.wr(class_out + 4, &record[4..])?;
        p.space.w64(menu_out, menu)?;
        Ok(u64::from(class.public_atom))
    };
    match operation() {
        Ok(value) => Ok(value),
        Err(error) => error.report(p, t),
    }
}

pub(super) fn unregister(
    p: &mut Proc,
    t: &Thread,
    [descriptor, module, menu_out]: [u64; 3],
) -> Result<u64, Outcome> {
    let name = match required_name(&p.space, descriptor) {
        Ok(name) => name,
        Err(error) => return error.report(p, t),
    };
    let upcase = p.registry.upcase_table();
    require_case_table(&upcase)?;
    let user = user_module(p);
    let definition = match p.gui.unregister_class(&upcase, &name, module, user) {
        Ok(definition) => definition,
        Err(error) => return query_error(p, t, error, None),
    };
    if menu_out != 0 {
        let mut menu = [0; 24];
        menu[..8].copy_from_slice(&definition.menu[0].to_le_bytes());
        menu[8..16].copy_from_slice(&definition.menu[1].to_le_bytes());
        // Once removed, the native service returns success even on an output
        // fault. The class and its atom references remain retired.
        if let Err(fault) = p.space.wr(menu_out, &menu) {
            p.vm.take_guard(fault.addr);
        }
    }
    Ok(1)
}
