//! Kernel architecture metadata is independent of a process's execution ISA.

use super::Proc;
use crate::user::windows::arch::WinArch;
use crate::user::windows::nt::status::STATUS_NOT_SUPPORTED;

pub(crate) fn native_arch(p: &Proc) -> Result<WinArch, u32> {
    if let Some(native) = &p.native {
        return native
            .object_namespace
            .native_machine
            .and_then(WinArch::from_machine)
            .filter(|arch| arch.is64())
            .ok_or(STATUS_NOT_SUPPORTED);
    }
    // The synthetic x86 process uses the same IA-32e compatibility CPU as
    // WoW64, over a virtual AMD64 kernel. No host architecture is consulted.
    Ok(if p.arch == WinArch::X86 {
        WinArch::X64
    } else {
        p.arch
    })
}

pub(crate) fn x86_signature(value: u32) -> (u16, u16) {
    let family = (value >> 8) & 15;
    let level = family + if family == 15 { (value >> 20) & 255 } else { 0 };
    let model = ((value >> 4) & 15)
        | if matches!(family, 6 | 15) {
            ((value >> 16) & 15) << 4
        } else {
            0
        };
    (level as u16, ((model << 8) | (value & 15)) as u16)
}
