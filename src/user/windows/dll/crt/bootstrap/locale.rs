//! Exact _configthreadlocale flag transitions from the pinned SDK source.

use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::sync::Wait;

use super::super::{invalid, state};
use super::{RuntimeKind, runtime, with_ptd};

// The locale critical section is separate from address waits and the CRT exit lock.
const LOCALE_WAIT_KEY: u128 = 1 << 126;

pub(super) fn lock(c: &mut Ctx) -> ApiResult {
    let owner = &mut c.p.crt.runtimes[RuntimeKind::Ucrt.index()]
        .bootstrap
        .locale_lock;
    let count = match *owner {
        Some((tid, _)) if tid != c.t.tid => {
            return Flow::block(
                Wait::Address {
                    key: LOCALE_WAIT_KEY,
                    deadline: None,
                },
                |c, _| lock(c),
            );
        }
        Some((_, count)) => count
            .checked_add(1)
            .ok_or_else(|| ApiErr::Internal("UCRT locale lock recursion exhausted".into()))?,
        None => 1,
    };
    *owner = Some((c.t.tid, count));
    Flow::void()
}

pub(super) fn unlock(c: &mut Ctx) -> ApiResult {
    let owner = &mut c.p.crt.runtimes[RuntimeKind::Ucrt.index()]
        .bootstrap
        .locale_lock;
    match *owner {
        Some((tid, 1)) if tid == c.t.tid => {
            *owner = None;
            c.p.sync.wake(LOCALE_WAIT_KEY, usize::MAX);
        }
        Some((tid, count)) if tid == c.t.tid => *owner = Some((tid, count - 1)),
        _ => {
            return Err(ApiErr::Internal(
                "UCRT locale lock released by non-owner".into(),
            ));
        }
    }
    Flow::void()
}

/// The built-in CRT provides the startup C locale. Unavailable locale
/// requests return NULL and leave that locale in effect.
pub(super) fn set(c: &mut Ctx) -> ApiResult {
    let category = c.u32(0)?;
    let name = c.ptr(1)?;
    if category > 5 || (name != 0 && c.mem().cstr(name, 2)? != b"C") {
        return Flow::ret(0);
    }
    Flow::ret(classic_data(c)?)
}

pub(super) fn codepage(_: &mut Ctx) -> ApiResult {
    // Native initial locinfo has both CTYPE and COLLATE code pages set to CP_ACP (0).
    Flow::ret(0)
}

pub(super) fn mb_cur_max(_: &mut Ctx) -> ApiResult {
    Flow::ret(1)
}

pub(super) fn names(c: &mut Ctx) -> ApiResult {
    Flow::ret(classic_data(c)? + NAMES_OFFSET as u64)
}

pub(super) fn ctype(c: &mut Ctx) -> ApiResult {
    Flow::ret(classic_data(c)? + CTYPE_OFFSET as u64)
}

const NAMES_OFFSET: usize = 8;
const CTYPE_OFFSET: usize = 64 + 128 * 2;

fn classic_data(c: &mut Ctx) -> Result<u64, ApiErr> {
    let kind = RuntimeKind::Ucrt;
    let cached = c.p.crt.runtimes[kind.index()].bootstrap.classic_locale_data;
    if cached != 0 {
        return Ok(cached);
    }
    // C string, six null locale-name pointers, then a biased ushort table
    // covering signed char indexes and the complete unsigned byte domain.
    let mut bytes = [0; CTYPE_OFFSET + 256 * 2];
    bytes[0] = b'C';
    for n in 0..=127u8 {
        let flags = u16::from(n.is_ascii_uppercase())
            | (u16::from(n.is_ascii_lowercase()) << 1)
            | (u16::from(n.is_ascii_digit()) << 2)
            | (u16::from(n.is_ascii_whitespace() || n == 0x0b) << 3)
            | (u16::from(n.is_ascii_punctuation()) << 4)
            | (u16::from(n.is_ascii_control()) << 5)
            | (u16::from(n == b' ') << 6)
            | (u16::from(n.is_ascii_hexdigit()) << 7);
        let at = CTYPE_OFFSET + usize::from(n) * 2;
        bytes[at..at + 2].copy_from_slice(&flags.to_le_bytes());
    }
    let heap = state::ensure_heap(c, kind)?;
    let address =
        c.p.heaps
            .alloc(&mut c.p.vm, heap, bytes.len() as u64, false)
            .ok_or_else(|| ApiErr::Internal("UCRT cannot allocate C locale data".into()))?;
    if let Err(fault) = c.mem().wr(address, &bytes) {
        let _ = c.p.heaps.free(heap, address);
        return Err(fault.into());
    }
    c.p.crt.runtimes[kind.index()].bootstrap.classic_locale_data = address;
    Ok(address)
}

pub(super) fn configure(c: &mut Ctx) -> ApiResult {
    let kind = runtime(c)?;
    if c.arch() == WinArch::X86 {
        // The pinned x86 body calls getptd before loading the stack formal.
        with_ptd(c, kind, Box::new(move |c, _| decode_ready(c, kind)))
    } else {
        // Win64 bodies capture the register formal before getptd.
        decode(c, kind)
    }
}

fn decode_ready(c: &mut Ctx, kind: RuntimeKind) -> ApiResult {
    match c.arg(0) {
        Ok(value) => selected(c, kind, value as i32),
        Err(fault) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| decode_ready(c, kind)),
        }),
    }
}

fn decode(c: &mut Ctx, kind: RuntimeKind) -> ApiResult {
    match c.arg(0) {
        Ok(value) => with_ptd(
            c,
            kind,
            Box::new(move |c, _| selected(c, kind, value as i32)),
        ),
        Err(fault) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| decode(c, kind)),
        }),
    }
}

fn selected(c: &mut Ctx, kind: RuntimeKind, mode: i32) -> ApiResult {
    let runtime = &mut c.p.crt.runtimes[kind.index()];
    let flags = &mut runtime
        .contexts
        .get_mut(&c.t.tid)
        .ok_or_else(|| ApiErr::Internal("CRT locale PTD disappeared after establishment".into()))?
        .locale_flags;
    let previous = if *flags & 2 == 0 { 2 } else { 1 };
    match mode {
        0 => {}
        1 => *flags |= 2,
        2 => *flags &= !2,
        -1 => runtime.bootstrap.global_locale_status = u32::MAX,
        _ => return invalid_mode(c, kind),
    }
    Flow::ret(previous)
}

fn invalid_mode(c: &mut Ctx, kind: RuntimeKind) -> ApiResult {
    // SDK _VALIDATE_RETURN's errno write precedes the invalid handler. A
    // returning handler's own errno mutation must not be overwritten.
    match state::set_errno(c, kind, 22) {
        Ok(()) => invalid_callback(c, kind),
        Err(ApiErr::Fault(fault)) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| invalid_mode(c, kind)),
        }),
        Err(error) => Err(error),
    }
}

fn invalid_callback(c: &mut Ctx, kind: RuntimeKind) -> ApiResult {
    match invalid::invoke(
        c,
        kind,
        [0; 5],
        Box::new(|_, _| Flow::ret(u64::from(u32::MAX))),
    ) {
        Ok(Flow::Call { target, args, then }) => Ok(Flow::CallChecked { target, args, then }),
        Err(ApiErr::Fault(fault)) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| invalid_callback(c, kind)),
        }),
        other => other,
    }
}
