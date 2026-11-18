//! Transfers to addresses of guest-owned WoW64 processes.
use super::{
    query::{probe_write, write_guard_result},
    write_memory::copy,
};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{CURRENT_PROCESS, CURRENT_THREAD, Object};
use crate::user::windows::process::{Proc, wow64::wide_process_memory};
use crate::user::windows::{layout, memory::Mem};

const PROCESS_VM_READ: u32 = 0x10;
const PROCESS_VM_WRITE: u32 = 0x20;

pub(super) fn selected(c: &Ctx) -> Result<(), ApiErr> {
    if c.arch() != WinArch::X86
        || !c
            .p
            .wow64
            .as_ref()
            .is_some_and(|state| wide_process_memory(Some(state.machine), state.kernel))
    {
        return Err(c.unsupported("unmeasured native-width WoW64 process-memory profile"));
    }
    Ok(())
}

pub(super) fn read(c: &mut Ctx) -> ApiResult {
    let result = transfer(c, Transfer::Read, 8);
    write_guard_result(c, result)
}

pub(super) fn write(c: &mut Ctx) -> ApiResult {
    let result = transfer(c, Transfer::Write, 8);
    write_guard_result(c, result)
}

pub(super) fn write_x86(c: &mut Ctx) -> ApiResult {
    let result = transfer(c, Transfer::Write, 4);
    write_guard_result(c, result)
}

#[derive(Clone, Copy)]
enum Transfer {
    Read,
    Write,
}

impl Transfer {
    fn access(self) -> u32 {
        match self {
            Self::Read => PROCESS_VM_READ,
            Self::Write => PROCESS_VM_WRITE,
        }
    }

    fn copy(self, caller: &Proc, buffer: u64, target: &Proc, address: u64, length: u64) -> u64 {
        match self {
            Self::Read => copy(&target.space, address, &caller.space, buffer, length),
            Self::Write => copy(&caller.space, buffer, &target.space, address, length),
        }
    }
}

fn transfer(c: &mut Ctx, direction: Transfer, width: u64) -> ApiResult {
    selected(c)?;
    let (handle, address, buffer, length, returned) =
        (c.ptr(0)?, c.arg(1)?, c.ptr(2)?, c.arg(3)?, c.ptr(4)?);
    if width == 8
        && ![address, buffer]
            .into_iter()
            .all(|start| valid_range(start, length))
    {
        return Flow::ret(STATUS_ACCESS_VIOLATION.into());
    }
    if returned != 0 {
        probe_write(c, returned, width as usize)?;
    }
    let (status, count) = if length == 0 {
        (STATUS_SUCCESS, 0)
    } else {
        match target_process(c, handle, direction.access(), width) {
            Ok(pid) => {
                let copy = |target: &Proc| direction.copy(c.p, buffer, target, address, length);
                let copied = if pid == c.p.pid {
                    Some(copy(c.p))
                } else if c.p.children.basic(pid).is_some() {
                    c.p.children.with_process(pid, |child| copy(child))
                } else {
                    return Err(
                        c.unsupported("native-width WoW64 transfer outside the guest family")
                    );
                };
                match copied {
                    Some(count) if count == length => (STATUS_SUCCESS, count),
                    Some(count) => (STATUS_PARTIAL_COPY, count),
                    None => (STATUS_PROCESS_IS_TERMINATING, 0),
                }
            }
            Err(status) => (status, 0),
        }
    };
    if returned != 0 {
        c.mem().wptr(returned, width, count)?;
    }
    Flow::ret(status.into())
}

pub(super) fn user_limit() -> u64 {
    layout::user_limit(WinArch::Arm64, true)
}

fn valid_range(start: u64, length: u64) -> bool {
    let limit = user_limit();
    start < limit && start.checked_add(length).is_some_and(|end| end <= limit)
}

fn target_process(c: &Ctx, handle: u64, access: u32, width: u64) -> Result<u32, u32> {
    if width == 4 && handle == c.arch().ptr(CURRENT_PROCESS) {
        return Ok(c.p.pid);
    }
    match c.p.objects.get(handle) {
        Some(Object::Process { pid, .. }) => {
            if c.p.objects.access(handle).unwrap_or(0) & access == 0 {
                return Err(STATUS_ACCESS_DENIED);
            }
            Ok(*pid)
        }
        object if width == 4 && (object.is_some() || handle == c.arch().ptr(CURRENT_THREAD)) => {
            Err(STATUS_OBJECT_TYPE_MISMATCH)
        }
        _ => Err(STATUS_INVALID_HANDLE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::mm::{AddressSpace, SpaceConfig};
    use crate::user::windows::memory::{VirtualMemory, VmError, mem, prot};

    #[test]
    fn wow64_wide_memory_reserves_high_pages_without_changing_32_bit_placement() {
        let space = AddressSpace::new(SpaceConfig {
            va_limit: user_limit(),
            arena_bytes: 2 << 20,
            reserved_phys: vec![],
        })
        .unwrap();
        let x86_limit = layout::user_limit(WinArch::X86, true);
        let mut vm = VirtualMemory::new(space.clone(), 0x10000, x86_limit);
        let hint = Some(0x1_0000_f117);
        let flags = mem::RESERVE | mem::COMMIT;
        assert!(matches!(
            vm.allocate(hint, 0x11d8, flags, prot::READWRITE),
            Err(VmError::Conflicting)
        ));
        let (base, size) = vm
            .allocate_wow64(hint, 0x11d8, flags, prot::READWRITE)
            .unwrap();
        assert_eq!((base, size), (0x1_0000_0000, 0x11000));
        assert_eq!(vm.high(), x86_limit);
        assert!(
            vm.find_free(0x1000, 0x10000, base, user_limit(), false)
                .is_none()
        );
        assert_eq!(vm.committed_bytes(), size);
        space.w64(base, 0x6174_6164_2078_6172).unwrap();
        assert_eq!(space.u64(base).unwrap(), 0x6174_6164_2078_6172);
        assert!(matches!(
            vm.allocate_wow64(hint, 0x11d8, flags, prot::READWRITE),
            Err(VmError::Conflicting)
        ));
        let (low, size) = vm
            .allocate_wow64(None, 0x11d8, mem::COMMIT, prot::READWRITE)
            .unwrap();
        assert!(low < x86_limit);
        assert_eq!(size, 0x2000);
    }

    #[test]
    fn wow64_wide_memory_checks_native_width_ranges_without_truncation() {
        let limit = user_limit();
        assert!(valid_range(0x1_0000_0000, 8));
        assert!(valid_range(limit - 8, 8));
        assert!(!valid_range(limit - 7, 8));
        assert!(!valid_range(limit, 0));
        assert!(!valid_range(u64::MAX - 1, 8));
        assert!(!valid_range(0x10000, u64::MAX));
    }
}
