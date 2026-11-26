//! Win32 queries of the current guest process environment block.
use super::super::hle::{ApiResult, Arg::*, Conv::Stdcall, Ctx, Export, Flow};
use super::super::memory::Mem;
use super::super::nt::{error::*, status_to_error};
use super::{crt::startup, path_strings::ordinal_uppercase};

pub(super) static EXPORTS: &[Export] = &[
    Export::func(
        "GetEnvironmentVariableA",
        Stdcall,
        &[Ptr, Ptr, I32],
        get_ansi,
    ),
    Export::func(
        "GetEnvironmentVariableW",
        Stdcall,
        &[Ptr, Ptr, I32],
        get_wide,
    ),
];

fn get_ansi(c: &mut Ctx) -> ApiResult {
    get(c, false)
}

fn get_wide(c: &mut Ctx) -> ApiResult {
    get(c, true)
}

fn get(c: &mut Ctx, wide: bool) -> ApiResult {
    let (name, out, capacity) = (c.ptr(0)?, c.ptr(1)?, c.u32(2)? as usize);
    if name == 0 {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    const NAME_LIMIT: usize = 32_767;
    let name = if wide {
        c.mem().wstr(name, NAME_LIMIT)?
    } else {
        startup::decode_process_ansi(&c.mem().cstr(name, NAME_LIMIT)?)
    };
    if name.is_empty() || name.len() == NAME_LIMIT {
        return c.fail(ERROR_ENVVAR_NOT_FOUND, 0);
    }
    let environment = match startup::environment(c.p) {
        Ok(environment) => environment,
        Err(error) => return c.fail(status_to_error(error.status), 0),
    };
    let table = c.p.registry.upcase_table();
    let fold = |&unit| ordinal_uppercase(unit, &table);
    let value = environment.iter().find_map(|entry| {
        let skip_equal = usize::from(entry.first() == Some(&(b'=' as u16)));
        let separator = entry[skip_equal..]
            .iter()
            .position(|&unit| unit == b'=' as u16)?
            + skip_equal;
        let key = &entry[..separator];
        (key.len() == name.len() && key.iter().map(fold).eq(name.iter().map(fold)))
            .then_some(&entry[separator + 1..])
    });
    let Some(value) = value else {
        return c.fail(ERROR_ENVVAR_NOT_FOUND, 0);
    };
    let written = if wide {
        if capacity <= value.len() {
            return Flow::ret(value.len() as u64 + 1);
        }
        c.mem().put_wstr(out, value)?;
        value.len()
    } else {
        let bytes = startup::encode_process_ansi(value);
        if capacity <= bytes.len() {
            return Flow::ret(bytes.len() as u64 + 1);
        }
        c.mem().put_cstr(out, &bytes)?;
        bytes.len()
    };
    if written == 0 {
        c.set_last_error(0)?;
    }
    Flow::ret(written as u64)
}
