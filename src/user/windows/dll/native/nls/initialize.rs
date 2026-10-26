//! Original NLS initialization outputs, including measured WoW64 partial copies.
use super::*;
use crate::user::windows::dll::native::query::write_guard_result;

pub(crate) fn initialize(c: &mut Ctx) -> ApiResult {
    let result = checked(c);
    match write_guard_result(c, result) {
        Err(ApiErr::Fault(_)) => Flow::ret(STATUS_ACCESS_VIOLATION.into()),
        result => result,
    }
}

fn checked(c: &mut Ctx) -> ApiResult {
    if !crate::user::windows::nls::supports_startup_profile(&c.p.cfg.version) {
        return Err(c.unsupported("NtInitializeNlsFiles native build profile is unmeasured"));
    }
    // The measured builds ignore the declared casing-size/version outputs,
    // including NULL, invalid, readonly and guarded addresses. Do not visit them.
    let (output, locale_output) = (c.ptr(0)?, c.ptr(1)?);
    let wow = c.arch() == WinArch::X86;
    if wow {
        // WoW64's first capture validates readability, not writability. A later
        // readonly pointer store fails after the locale copy and native mapping.
        c.mem().u32(output)?;
    } else {
        probe_write(c, output, 8)?;
    }
    probe_write(c, locale_output, 4)?;
    let selected =
        c.p.nls
            .as_ref()
            .and_then(|nls| nls.initialize())
            .cloned()
            .ok_or_else(|| {
                c.unsupported("NtInitializeNlsFiles immutable initialization data was not selected")
            })?;
    let length = selected.bytes.len() as u64;
    let base = match c.p.vm.reserve(
        None,
        length,
        prot::READONLY,
        AllocKind::Mapped,
        false,
        Some("installed locale.nls initialization".into()),
    ) {
        Ok(base) => base,
        Err(error) => return Flow::ret(error.status().into()),
    };
    if let Err(error) = c.p.vm.commit(base, length, prot::READWRITE) {
        let _ = c.p.vm.release(base);
        return Flow::ret(error.status().into());
    }
    if let Err(error) = c.mem().wr(base, &selected.bytes) {
        let _ = c.p.vm.release(base);
        return Err(error.into());
    }
    if let Err(error) =
        c.p.vm
            .protect(base, length, prot::READONLY)
            .and_then(|_| c.p.vm.seal_nls_view(base))
    {
        let _ = c.p.vm.release(base);
        return Flow::ret(error.status().into());
    }
    // Native controls enumerate locale.nls mappings before/after each call:
    // a WoW64 late pointer-copy fault retains the already mapped view. It stays
    // owned by the guest VM, charged to its budget, and can be explicitly unmapped.
    // Aliases observe native64 base-then-locale versus WoW64 locale-then-base.
    if wow {
        c.mem().w32(locale_output, selected.locale)?;
        c.write_ptr(output, base)?;
    } else {
        c.write_ptr(output, base)?;
        c.mem().w32(locale_output, selected.locale)?;
    }
    Flow::ret(STATUS_SUCCESS.into())
}
