//! CFG memory request output stores through the actual NT dispatch adapters.
use super::{arguments, fixture, handle_stop, stop};
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::dispatch::Outcome;
use crate::user::windows::memory::{Mem, mem, prot};
use crate::user::windows::nt::status::{STATUS_INVALID_PARAMETER_4, STATUS_SUCCESS};

#[test]
fn cfg_protect_preserves_targets_and_publishes_native_old_protection_stores() {
    for arch in WinArch::ALL {
        for (protection, expected, previous) in [
            (
                prot::EXECUTE_READWRITE | prot::TARGETS_NO_UPDATE,
                STATUS_SUCCESS,
                prot::EXECUTE_READWRITE,
            ),
            (
                prot::READWRITE | prot::TARGETS_NO_UPDATE,
                STATUS_INVALID_PARAMETER_4,
                prot::NOACCESS,
            ),
        ] {
            let (mut process, mut thread) = fixture(arch, "NtProtectVirtualMemory", 0x50);
            let p = process.state_mut();
            let scratch =
                p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                    .unwrap()
                    .0;
            let base =
                p.vm.allocate(
                    None,
                    PAGE_SIZE,
                    mem::RESERVE | mem::COMMIT,
                    prot::EXECUTE_READWRITE | prot::TARGETS_INVALID,
                )
                .unwrap()
                .0;
            p.space.wptr(scratch, arch.ptr_size(), base).unwrap();
            p.space
                .wptr(scratch + 16, arch.ptr_size(), PAGE_SIZE)
                .unwrap();
            p.space.w32(scratch + 32, 0xabab_abab).unwrap();
            arguments(
                p,
                &mut thread,
                &[
                    arch.ptr(u64::MAX),
                    scratch,
                    scratch + 16,
                    protection.into(),
                    scratch + 32,
                ],
            );
            if arch != WinArch::Arm64 {
                thread.cpu.set_gpr(0, 0x50);
            }
            let result = if arch == WinArch::X86 {
                crate::user::windows::process::services::wow64(p, &mut thread, 0x1234_0000)
            } else {
                handle_stop(p, &mut thread, stop(arch, 0x50))
            };
            assert_eq!(result, Outcome::Continue);
            assert_eq!(thread.cpu.gpr(0), u64::from(expected));
            assert_eq!(p.space.u32(scratch + 32).unwrap(), previous);
            assert_eq!(p.space.ptr(scratch, arch.ptr_size()).unwrap(), base);
            assert_eq!(
                p.space.ptr(scratch + 16, arch.ptr_size()).unwrap(),
                PAGE_SIZE
            );
            assert_eq!(p.vm.query(base).unwrap().protect, prot::EXECUTE_READWRITE);
            assert!(!p.vm.valid_call_target(base));
            assert!(thread.frames.is_empty());
        }
    }
}
