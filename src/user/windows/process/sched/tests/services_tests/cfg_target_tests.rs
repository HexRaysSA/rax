//! Independent native class2 observations replay through all guest syscall ABIs.
use super::memory_prefetch_tests::enter;
use super::{Proc, WinArch, fixture};
use crate::error::MemoryAccessKind;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::hle::dispatch::Outcome;
use crate::user::windows::layout;
use crate::user::windows::memory::{Mem, mem, prot};
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;

#[path = "cfg_target_tests/inputs.rs"]
mod inputs;
#[path = "cfg_target_tests/publication.rs"]
mod publication;
#[path = "cfg_target_tests/replay.rs"]
mod replay;

#[cfg(windows)]
#[path = "cfg_target_tests/installed.rs"]
mod installed;

const SERVICE: u32 = 0x1b0;
const LAST_ERROR: u32 = 0x1234_5678;

#[test]
fn cfg_target_reserved_and_decommitted_service_calls_preserve_commitment_and_fetch_rights() {
    for arch in WinArch::ALL {
        for case in [
            "uncommitted-exec-target",
            "decommitted-exec-target",
            "uncommitted-rw-nearby-exec",
        ] {
            let (mut process, mut thread) = fixture(arch, "NtSetInformationVirtualMemory", SERVICE);
            let p = process.state_mut();
            let setup = inputs::prepare(p, case);
            let committed = p.vm.committed_bytes();
            assert_eq!(enter(p, &mut thread, setup.args), Outcome::Continue);
            assert_eq!(thread.cpu.gpr(0), 0, "{arch}/{case}");
            assert!(p.vm.valid_call_target(setup.target));
            assert!(!p.vm.accessible(setup.target, MemoryAccessKind::Fetch));
            assert_eq!(p.vm.committed_bytes(), committed);
            assert_eq!(p.vm.query(setup.target).unwrap().state, mem::RESERVE);
        }
    }
}

#[test]
fn cfg_target_capture_does_not_forward_or_modify_foreign_processes() {
    for arch in WinArch::ALL {
        let (mut process, mut thread) = fixture(arch, "NtSetInformationVirtualMemory", SERVICE);
        let p = process.state_mut();
        let mut setup = inputs::prepare(p, "valid");
        let object = p.objects.create(Object::Process {
            pid: p.pid + 4,
            exit_code: None,
        });
        setup.args[0] = p.objects.open_access(object, false, 8).unwrap().into();
        let committed = p.vm.committed_bytes();
        assert!(
            matches!(enter(p, &mut thread, setup.args), Outcome::Fail(ref message)
            if message.contains("for another process"))
        );
        assert!(!p.vm.valid_call_target(setup.target));
        assert_eq!(p.vm.committed_bytes(), committed);
    }
}

#[test]
fn cfg_target_policy_rejection_precedes_first_target_publication() {
    // Native constant-leaf controls on ARM64 Windows, translated x64: a later
    // export/XFG policy rejection leaves the first target unregistered.
    for (flags, expected) in [(4, STATUS_ACCESS_DENIED), (8, STATUS_NOT_SUPPORTED)] {
        let (mut process, mut thread) =
            fixture(WinArch::X64, "NtSetInformationVirtualMemory", SERVICE);
        let p = process.state_mut();
        super::system_processor_tests::kernel_profile(p, 0xaa64);
        let version = &mut p.native.as_mut().unwrap().version;
        version.major = 10;
        version.minor = 0;
        version.build = 29698;
        let setup = inputs::prepare(p, "entries-2");
        p.space
            .w64(setup.buffers[2].1 + 3 * p.arch.ptr_size(), flags)
            .unwrap();
        assert_eq!(enter(p, &mut thread, setup.args), Outcome::Continue);
        assert_eq!(thread.cpu.gpr(0), u64::from(expected));
        assert_eq!(p.space.u32(setup.buffers[3].1).unwrap(), 0);
        assert!(!p.vm.valid_call_target(setup.target));
    }
}
