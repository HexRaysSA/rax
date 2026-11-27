//! UCRT buffer formatting in the guest C locale.

use std::iter::Peekable;
use std::slice::Iter;

use crate::user::windows::hle::{
    ApiErr, ApiResult, Arg::*, Conv::Cdecl, Ctx, Export, Flow, VaList,
};
use crate::user::windows::memory::{Mem, MemFault};

use super::super::{RuntimeKind, invalid, state};

pub(crate) static UCRT_BUFFER_FORMAT_EXPORTS: &[Export] = &[Export::func(
    "__stdio_common_vsprintf",
    Cdecl,
    &[I64, Ptr, Ptr, Ptr, Ptr, Ptr],
    vsprintf,
)];

pub(crate) static UCRT_WIDE_BUFFER_FORMAT_EXPORTS: &[Export] = &[
    Export::func(
        "__stdio_common_vswprintf",
        Cdecl,
        &[I64, Ptr, Ptr, Ptr, Ptr, Ptr],
        vswprintf,
    ),
    Export::forward(
        "_o___stdio_common_vswprintf",
        "ucrtbase.__stdio_common_vswprintf",
    ),
];

const LEGACY_TERMINATION: u64 = 1;
const STANDARD_SNPRINTF: u64 = 2;
const LEGACY_WIDE_SPECIFIERS: u64 = 4;
const STRING_LIMIT: usize = 1 << 20;

fn invalid_parameter(c: &mut Ctx) -> ApiResult {
    state::set_errno(c, RuntimeKind::Ucrt, 22)?;
    invalid::invoke(c, RuntimeKind::Ucrt, [0; 5], Box::new(|_, _| result(-1)))
}

fn result(value: i32) -> ApiResult {
    Flow::ret(u64::from(value as u32))
}

struct Output {
    base: u64,
    capacity: u64,
    count: u64,
    wide: bool,
}

impl Output {
    fn address(&self, c: &Ctx, offset: u64) -> Result<u64, MemFault> {
        offset
            .checked_mul(if self.wide { 2 } else { 1 })
            .and_then(|offset| self.base.checked_add(offset))
            .filter(|&address| c.arch().ptr(address) == address)
            .ok_or(MemFault {
                addr: u64::MAX,
                write: true,
            })
    }

    fn write(&mut self, c: &Ctx, bytes: &[u8]) -> Result<(), ApiErr> {
        let size = self
            .capacity
            .saturating_sub(self.count)
            .min(bytes.len() as u64);
        if size != 0 {
            let at = self.address(c, self.count)?;
            let bytes = &bytes[..size as usize];
            if self.wide {
                let units: Vec<u16> = bytes.iter().map(|&byte| u16::from(byte)).collect();
                c.mem().put_wunits(at, &units)?;
            } else {
                c.mem().wr(at, bytes)?;
            }
        }
        self.count += bytes.len() as u64;
        Ok(())
    }

    fn write_wide(&mut self, c: &Ctx, units: &[u16]) -> Result<(), ApiErr> {
        let size = self
            .capacity
            .saturating_sub(self.count)
            .min(units.len() as u64);
        if size != 0 {
            let at = self.address(c, self.count)?;
            match &units[..size as usize] {
                [unit] => c.mem().w16(at, *unit)?,
                units => c.mem().put_wunits(at, units)?,
            }
        }
        self.count += units.len() as u64;
        Ok(())
    }

    fn pad(&mut self, c: &Ctx, byte: u8, count: u64) -> Result<(), ApiErr> {
        let written = count.min(self.capacity.saturating_sub(self.count));
        let mut remaining = written;
        let bytes = [byte; 256];
        while remaining != 0 {
            let size = remaining.min(bytes.len() as u64);
            self.write(c, &bytes[..size as usize])?;
            remaining -= size;
        }
        self.count += count - written;
        Ok(())
    }
}

#[derive(Clone)]
struct Format<'a>(Peekable<std::iter::Copied<Iter<'a, u16>>>);

impl Format<'_> {
    fn peek(&mut self) -> Option<u8> {
        u8::try_from(*self.0.peek()?).ok()
    }

    fn next(&mut self) -> Option<u8> {
        self.0.next().map(|unit| u8::try_from(unit).unwrap_or(0xff))
    }

    fn take(&mut self, byte: u8) -> bool {
        self.0.next_if_eq(&u16::from(byte)).is_some()
    }
}

enum Text<'a> {
    Bytes(&'a [u8]),
    Wide(&'a [u16]),
}

impl Text<'_> {
    fn len(&self) -> usize {
        match self {
            Self::Bytes(bytes) => bytes.len(),
            Self::Wide(units) => units.len(),
        }
    }

    fn write(self, c: &Ctx, out: &mut Output) -> Result<(), ApiErr> {
        match self {
            Self::Bytes(bytes) => out.write(c, bytes),
            Self::Wide(units) => out.write_wide(c, units),
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq)]
enum Length {
    Byte,
    Short,
    #[default]
    Int,
    Long,
    WideChar,
    Wide,
    Pointer,
}

#[derive(Default)]
struct Spec {
    left: bool,
    zero: bool,
    alternate: bool,
    sign: Option<u8>,
    width: u64,
    precision: Option<u64>,
    length: Length,
}

fn decimal(format: &mut Format<'_>) -> u64 {
    let mut value = 0u64;
    while let Some(byte @ b'0'..=b'9') = format.peek() {
        format.next();
        value = (value * 10 + u64::from(byte - b'0')).min(i32::MAX as u64);
    }
    value
}

impl Spec {
    fn read(c: &Ctx, format: &mut Format<'_>, va: &mut VaList) -> Result<Self, ApiErr> {
        let mut spec = Self::default();
        loop {
            match format.peek() {
                Some(b'-') => spec.left = true,
                Some(b'0') => spec.zero = true,
                Some(b'#') => spec.alternate = true,
                Some(b'+') => spec.sign = Some(b'+'),
                Some(b' ') if spec.sign != Some(b'+') => spec.sign = Some(b' '),
                Some(b' ') => (),
                _ => break,
            }
            format.next();
        }
        spec.width = if format.take(b'*') {
            let width = c.va_next(va, false)? as i32;
            spec.left |= width < 0;
            u64::from(width.unsigned_abs())
        } else {
            decimal(format)
        };
        if format.take(b'.') {
            spec.precision = if format.take(b'*') {
                u64::try_from(c.va_next(va, false)? as i32).ok()
            } else {
                Some(decimal(format))
            };
        }
        spec.length = match format.peek() {
            Some(b'h') => {
                format.next();
                if format.take(b'h') {
                    Length::Byte
                } else {
                    Length::Short
                }
            }
            Some(b'l') => {
                format.next();
                if format.take(b'l') {
                    Length::Wide
                } else {
                    Length::Long
                }
            }
            Some(b'w') => {
                format.next();
                Length::WideChar
            }
            Some(b'j') => {
                format.next();
                Length::Wide
            }
            Some(b'z' | b't') => {
                format.next();
                Length::Pointer
            }
            Some(b'I') => {
                format.next();
                let mut suffix = format.clone();
                match (suffix.next(), suffix.next()) {
                    (Some(b'6'), Some(b'4')) => {
                        *format = suffix;
                        Length::Wide
                    }
                    (Some(b'3'), Some(b'2')) => {
                        *format = suffix;
                        Length::Int
                    }
                    _ => Length::Pointer,
                }
            }
            _ => Length::Int,
        };
        Ok(spec)
    }

    fn emit(
        &self,
        c: &Ctx,
        out: &mut Output,
        text: Text<'_>,
        prefix: &[u8],
        leading_zeros: u64,
        zero_pad: bool,
    ) -> Result<(), ApiErr> {
        let extra = self
            .width
            .saturating_sub(text.len() as u64 + prefix.len() as u64 + leading_zeros);
        if !self.left && !zero_pad {
            out.pad(c, b' ', extra)?;
        }
        out.write(c, prefix)?;
        out.pad(
            c,
            b'0',
            leading_zeros + if !self.left && zero_pad { extra } else { 0 },
        )?;
        text.write(c, out)?;
        if self.left {
            out.pad(c, b' ', extra)?;
        }
        Ok(())
    }

    fn integer(&self, c: &Ctx, out: &mut Output, va: &mut VaList, ty: u8) -> Result<(), ApiErr> {
        let ptr = ty == b'p';
        let width = match self.length {
            _ if ptr => c.psize() * 8,
            Length::Byte => 8,
            Length::Short => 16,
            Length::Int | Length::Long | Length::WideChar => 32,
            Length::Wide => 64,
            Length::Pointer => c.psize() * 8,
        };
        let value = c.va_next(va, width == 64)?;
        let shift = 64 - width;
        let narrow = (value << shift) >> shift;
        let signed = matches!(ty, b'd' | b'i');
        let signed_value = ((value << shift) as i64) >> shift;
        let magnitude = if signed {
            signed_value.unsigned_abs()
        } else {
            narrow
        };
        let digits = match ty {
            b'x' => format!("{magnitude:x}"),
            b'X' | b'p' => format!("{magnitude:X}"),
            b'o' => format!("{magnitude:o}"),
            _ => magnitude.to_string(),
        };
        let precision = if ptr {
            Some(c.psize() * 2)
        } else {
            self.precision
        };
        let bytes = if magnitude == 0 && precision == Some(0) {
            &[][..]
        } else {
            digits.as_bytes()
        };
        let mut zeroes = precision.unwrap_or(0).saturating_sub(bytes.len() as u64);
        let sign = if signed_value < 0 {
            Some(b'-')
        } else {
            self.sign
        };
        let prefix: &[u8] = if signed {
            sign.as_slice()
        } else if self.alternate && magnitude != 0 && ty == b'x' {
            b"0x"
        } else if self.alternate && magnitude != 0 && ty == b'X' {
            b"0X"
        } else {
            &[]
        };
        if self.alternate && ty == b'o' && zeroes == 0 && bytes.first() != Some(&b'0') {
            zeroes = 1;
        }
        self.emit(
            c,
            out,
            Text::Bytes(bytes),
            prefix,
            zeroes,
            self.zero && precision.is_none(),
        )
    }
}

fn vsprintf(c: &mut Ctx) -> ApiResult {
    format_buffer(c, false)
}

fn vswprintf(c: &mut Ctx) -> ApiResult {
    format_buffer(c, true)
}

fn format_buffer(c: &mut Ctx, wide: bool) -> ApiResult {
    let options = c.arg(0)?;
    let base = c.ptr(1)?;
    let capacity = c.ptr(2)?;
    let format = c.ptr(3)?;
    if format == 0 || (base == 0 && capacity != 0) {
        return invalid_parameter(c);
    }
    if c.ptr(4)? != 0 {
        return Err(c.unsupported("UCRT buffer formatting with an explicit locale"));
    }
    let source = if wide {
        c.mem().wstr(format, STRING_LIMIT)?
    } else {
        c.mem()
            .cstr(format, STRING_LIMIT)?
            .into_iter()
            .map(u16::from)
            .collect()
    };
    if source.len() == STRING_LIMIT {
        return Err(c.unsupported("UCRT format exceeds the portable string limit"));
    }
    let mut format = Format(source.iter().copied().peekable());
    let mut va = c.va_list(5)?;
    let mut out = Output {
        base,
        capacity,
        count: 0,
        wide,
    };
    let legacy = options & LEGACY_TERMINATION != 0;
    let standard = options & STANDARD_SNPRINTF != 0;
    let count_through = standard || base == 0;
    while (count_through || out.count <= capacity)
        && let Some(unit) = format.0.next()
    {
        if unit != u16::from(b'%') || format.take(b'%') {
            if wide {
                out.write_wide(c, &[unit])?;
            } else {
                out.write(c, &[unit as u8])?;
            }
            continue;
        }
        let spec = Spec::read(c, &mut format, &mut va)?;
        match format.next() {
            Some(ty @ (b'd' | b'i' | b'u' | b'x' | b'X' | b'o' | b'p')) => {
                spec.integer(c, &mut out, &mut va, ty)?;
            }
            Some(ty @ (b's' | b'S' | b'c' | b'C')) => {
                let read_wide = match spec.length {
                    Length::Long | Length::WideChar => true,
                    Length::Short => false,
                    Length::Int if wide && options & LEGACY_WIDE_SPECIFIERS != 0 => {
                        ty.is_ascii_lowercase()
                    }
                    Length::Int => ty.is_ascii_uppercase(),
                    _ => return Err(c.unsupported("UCRT string argument length modifier")),
                };
                if read_wide && !wide {
                    return Err(c.unsupported("UCRT wide string conversion to a byte buffer"));
                }
                let arg = c.va_next(&mut va, false)?;
                if ty.eq_ignore_ascii_case(&b'c') {
                    if read_wide {
                        spec.emit(c, &mut out, Text::Wide(&[arg as u16]), &[], 0, false)?;
                    } else {
                        spec.emit(c, &mut out, Text::Bytes(&[arg as u8]), &[], 0, false)?;
                    }
                    continue;
                }
                let address = c.arch().ptr(arg);
                let limit = spec.precision.unwrap_or(u64::MAX);
                let bounded = limit.min(STRING_LIMIT as u64) as usize;
                if read_wide && address != 0 {
                    let units = c.mem().wstr(address, bounded)?;
                    check_string_limit(c, units.len(), limit)?;
                    spec.emit(c, &mut out, Text::Wide(&units), &[], 0, false)?;
                } else {
                    let bytes = if address == 0 {
                        b"(null)"[..limit.min(6) as usize].to_vec()
                    } else {
                        c.mem().cstr(address, bounded)?
                    };
                    check_string_limit(c, bytes.len(), limit)?;
                    spec.emit(c, &mut out, Text::Bytes(&bytes), &[], 0, false)?;
                }
            }
            None | Some(b'n') => return invalid_parameter(c),
            Some(ty) => {
                return Err(
                    c.unsupported(format!("UCRT buffer format conversion %{}", char::from(ty)))
                );
            }
        }
    }
    let used = out.count.min(capacity);
    let fits = out.count < capacity;
    if capacity != 0 && (fits || !legacy) {
        let at = out.address(c, used.min(capacity - 1))?;
        if wide {
            c.mem().w16(at, 0)?;
        } else {
            c.mem().w8(at, 0)?;
        }
    }
    if !fits && base != 0 {
        if legacy && out.count > capacity {
            return result(-1);
        }
        if !legacy && !standard {
            return result(if capacity == 0 { -1 } else { -2 });
        }
    }
    match i32::try_from(out.count) {
        Ok(count) => result(count),
        Err(_) => {
            state::set_errno(c, RuntimeKind::Ucrt, 132)?;
            result(-1)
        }
    }
}

fn check_string_limit(c: &Ctx, len: usize, limit: u64) -> Result<(), ApiErr> {
    if len == STRING_LIMIT && limit > STRING_LIMIT as u64 {
        return Err(c.unsupported("UCRT string argument exceeds the portable string limit"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::windows::dll::crt::tests::{area, int, invoke, run};

    const NAME: &str = "__stdio_common_vsprintf";

    #[test]
    fn wide_buffer_counts_utf16_units_and_preserves_the_private_alias() {
        run(|c| {
            let at = area(c);
            let fmt = at + 64;
            let text = at + 128;
            let args = at + 192;
            let name = "__stdio_common_vswprintf";
            let format: Vec<u16> = "λ:%4s:%08X".encode_utf16().collect();
            let value: Vec<u16> = "😀".encode_utf16().collect();
            c.mem().put_wstr(fmt, &format).unwrap();
            c.mem().put_wstr(text, &value).unwrap();
            c.mem().wptr(args, c.psize(), text).unwrap();
            c.mem().wptr(args + c.psize(), c.psize(), 0x2a).unwrap();
            let expected: Vec<u16> = "λ:  😀:0000002A".encode_utf16().collect();
            assert_eq!(
                int(invoke(
                    c,
                    RuntimeKind::Ucrt,
                    name,
                    &[6, at, 20, fmt, 0, args]
                )),
                expected.len() as u64
            );
            assert_eq!(c.mem().wstr(at, 20).unwrap(), expected);
            let canonical = c.entry_pc;
            let dll = c.p.modules.by_name("ucrtbase.dll").unwrap();
            let alias = crate::user::windows::loader::SymRef::Name(
                b"_o___stdio_common_vswprintf".to_vec(),
                None,
            );
            assert_eq!(
                crate::user::windows::loader::lookup(c.p, dll, &alias).unwrap(),
                Some(canonical)
            );
            c.mem().w16(at + 8, 0xfeed).unwrap();
            assert_eq!(
                int(invoke(
                    c,
                    RuntimeKind::Ucrt,
                    name,
                    &[6, at, 4, fmt, 0, args]
                )),
                expected.len() as u64
            );
            assert_eq!(
                c.mem().wunits(at, 5).unwrap(),
                [0x3bb, 0x3a, 0x20, 0, 0xfeed]
            );
        });
    }

    #[test]
    fn formats_guest_va_list_across_abis() {
        run(|c| {
            let at = area(c);
            let format = at + 64;
            let text = at + 128;
            let args = at + 192;
            c.mem().put_cstr(format, b"%*.*s:%#06x:%I64d:%%").unwrap();
            c.mem().put_cstr(text, b"abcde").unwrap();
            let slot = c.psize();
            for (i, arg) in [(-5i32) as u32 as u64, 3, text, 0x2a]
                .into_iter()
                .enumerate()
            {
                c.mem().wptr(args + i as u64 * slot, slot, arg).unwrap();
            }
            c.mem().w64(args + 4 * slot, i64::MIN as u64).unwrap();
            let expected = b"abc  :0x002a:-9223372036854775808:%";
            assert_eq!(
                int(invoke(
                    c,
                    RuntimeKind::Ucrt,
                    NAME,
                    &[2, at, 64, format, 0, args]
                )),
                expected.len() as u64
            );
            assert_eq!(c.mem().cstr(at, 64).unwrap(), expected);
        });
    }

    #[test]
    fn distinguishes_count_query_and_termination_policies() {
        run(|c| {
            let at = area(c);
            let format = at + 64;
            c.mem().put_cstr(format, b"hello").unwrap();
            for (flags, out, count, status, expected) in [
                (2, at, 3, 5u32, &b"he\0!"[..]),
                (1, at, 3, u32::MAX, &b"hel!"[..]),
                (1, at, 5, 5, &b"hell"[..]),
                (0, at, 3, (-2i32) as u32, &b"he\0!"[..]),
                (2, 0, 0, 5, &b"!!!!"[..]),
            ] {
                c.mem().wr(at, b"!!!!").unwrap();
                assert_eq!(
                    int(invoke(
                        c,
                        RuntimeKind::Ucrt,
                        NAME,
                        &[flags, out, count, format, 0, 0]
                    )),
                    u64::from(status)
                );
                assert_eq!(c.mem().bytes(at, 4).unwrap(), expected);
            }
        });
    }
}
