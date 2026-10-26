//! Native NLS initialization: independent output, mapping and failure evidence.
use super::nls_tests::{arguments, dispatch};
use super::*;
use crate::user::windows::nt::status::*;
use std::sync::Arc;

#[path = "nls_initialize_replay_tests.rs"]
mod replay;

fn setup(arch: WinArch, build: u32) -> (super::super::super::super::WindowsProcess, Thread, u64) {
    let (mut process, thread) = fixture(arch, "NtInitializeNlsFiles", 0x12);
    let p = process.state_mut();
    let cfg = Arc::make_mut(&mut p.cfg);
    cfg.version.major = 10;
    cfg.version.minor = 0;
    cfg.version.build = build;
    let base =
        p.vm.allocate(None, 16384, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap()
            .0;
    p.space.wr(base, &vec![0xA5; 16384]).unwrap();
    p.vm.protect(base + 4096, 4096, prot::READONLY).unwrap();
    p.vm.protect(base + 8192, 4096, prot::NOACCESS).unwrap();
    p.vm.protect(base + 12288, 4096, prot::READWRITE | prot::GUARD)
        .unwrap();
    p.nls = Some(
        crate::user::windows::nls::Nls::new(vec![])
            .unwrap()
            .with_initialize(0x409, vec![0x53; 864256])
            .unwrap(),
    );
    (process, thread, base)
}

fn invoke(p: &mut Proc, t: &mut Thread, args: &[u64]) -> Outcome {
    arguments(p, t, args);
    dispatch(p, t)
}

fn pointer(p: &Proc, address: u64) -> u64 {
    if p.arch == WinArch::X86 {
        p.space.u32(address).unwrap().into()
    } else {
        p.space.u64(address).unwrap()
    }
}

#[test]
fn native_nls_initialize_mapping_is_distinct_readonly_owned_and_unmaps_by_interior() {
    for (arch, build) in WinArch::ALL
        .into_iter()
        .flat_map(|arch| [29683, 29695].map(|build| (arch, build)))
    {
        let (mut process, mut thread, base) = setup(arch, build);
        let p = process.state_mut();
        let initial = p.vm.committed_bytes();
        let args = [base + 1, base + 17, 0, u64::MAX];
        assert_eq!(invoke(p, &mut thread, &args), Outcome::Continue);
        assert_eq!(thread.cpu.gpr(0), 0);
        assert_eq!(p.space.u32(base + 17).unwrap(), 0x409);
        let first = pointer(p, base + 1);
        assert_eq!(p.vm.query(first).unwrap().kind, mem::MAPPED);
        assert_eq!(p.vm.query(first).unwrap().protect, prot::READONLY);
        assert_eq!(p.vm.query(first).unwrap().size, 864256);
        assert_eq!(p.space.bytes(first, 864256).unwrap(), vec![0x53; 864256]);
        assert_eq!(p.vm.committed_bytes(), initial + 864256);
        assert_eq!(
            p.vm.free(first, 0, mem::RELEASE),
            Err(crate::user::windows::memory::VmError::CannotDeleteSection)
        );
        for protection in [
            prot::NOACCESS,
            prot::READWRITE,
            prot::WRITECOPY,
            prot::EXECUTE,
            prot::EXECUTE_READ,
            prot::EXECUTE_READWRITE,
            prot::EXECUTE_WRITECOPY,
            prot::READONLY | prot::GUARD,
            prot::READWRITE | prot::GUARD,
        ] {
            assert_eq!(
                p.vm.protect(first, 4096, protection).unwrap_err().status(),
                STATUS_INVALID_PAGE_PROTECTION
            );
            assert_eq!(p.vm.query(first).unwrap().protect, prot::READONLY);
        }
        assert_eq!(
            p.vm.protect(first, 4096, prot::READONLY),
            Ok(prot::READONLY)
        );
        assert_eq!(
            p.vm.decommit(first, 4096).unwrap_err().status(),
            STATUS_UNABLE_TO_DELETE_SECTION
        );
        assert_eq!(invoke(p, &mut thread, &args), Outcome::Continue);
        let second = pointer(p, base + 1);
        assert_ne!(first, second);
        assert_eq!(p.vm.committed_bytes(), initial + 2 * 864256);
        let count = p.vm.allocations().count();
        let module = p.modules.nt_services.as_ref().unwrap().0;
        p.modules.nt_services = Some((module, table(arch, "NtUnmapViewOfSection", 0x12)));
        assert_eq!(
            invoke(p, &mut thread, &[arch.ptr(u64::MAX), first + 4095]),
            Outcome::Continue
        );
        assert_eq!(thread.cpu.gpr(0), 0);
        assert_eq!(p.vm.allocations().count(), count - 1);
        assert_eq!(p.vm.query(first).unwrap().state, mem::FREE);
        assert_eq!(p.vm.committed_bytes(), initial + 864256);
        assert!(p.space.u32(second).is_ok());
        p.vm.release(second).unwrap();
        assert_eq!(p.vm.committed_bytes(), initial);
    }
}

#[test]
fn native_nls_initialize_unselected_or_unmeasured_profile_publishes_no_mapping_or_output() {
    for arch in WinArch::ALL {
        for (major, minor, build, missing) in [
            (10, 0, 29683, true),
            (10, 0, 29695, true),
            (10, 0, 29682, false),
            (10, 0, 29684, false),
            (10, 0, 29694, false),
            (10, 0, 29696, false),
            (10, 1, 29695, false),
            (11, 0, 29695, false),
        ] {
            let (mut process, mut thread, base) = setup(arch, build);
            let p = process.state_mut();
            let cfg = Arc::make_mut(&mut p.cfg);
            cfg.version.major = major;
            cfg.version.minor = minor;
            if missing {
                p.nls = None;
            }
            let before = p.vm.allocations().count();
            let charge = p.vm.committed_bytes();
            assert!(matches!(
                invoke(p, &mut thread, &[base + 256, base + 288, 0, 0]),
                Outcome::Fail(_)
            ));
            assert_eq!(p.space.bytes(base + 256, 144).unwrap(), vec![0xA5; 144]);
            assert_eq!(p.vm.allocations().count(), before);
            assert_eq!(p.vm.committed_bytes(), charge);
        }
    }
}

#[test]
fn native_nls_initialize_export_abi_matches_original_x86_ret12_without_shadowing() {
    for arch in WinArch::ALL {
        let api = crate::user::windows::dll::nt_service("NtInitializeNlsFiles", arch).unwrap();
        assert_eq!(api.args.len(), if arch == WinArch::X86 { 3 } else { 4 });
    }
}
