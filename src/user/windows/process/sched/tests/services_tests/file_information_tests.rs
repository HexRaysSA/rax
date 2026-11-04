//! Independent native fixed-record and caller-memory controls, all guest ABIs.
use super::*;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{Object, StdStream};

#[path = "file_information_tests/replay.rs"]
mod replay;
#[path = "file_information_tests/retained.rs"]
mod retained;

#[cfg(windows)]
#[path = "file_information_tests/installed.rs"]
mod installed;

fn setup(arch: WinArch) -> (super::super::super::super::WindowsProcess, Thread, u64) {
    let (mut process, thread) = fixture(arch, "NtQueryInformationFile", 0x11);
    let p = process.state_mut();
    let base =
        p.vm.allocate(
            None,
            6 * PAGE_SIZE,
            mem::RESERVE | mem::COMMIT,
            prot::READWRITE,
        )
        .unwrap()
        .0;
    (process, thread, base)
}

fn invoke(p: &mut Proc, t: &mut Thread, args: &[u64]) -> u32 {
    super::nls_tests::arguments(p, t, args);
    if p.arch != WinArch::Arm64 {
        t.cpu.set_gpr(0, 0x11);
    }
    let sp = t.cpu.sp();
    let result = if p.arch == WinArch::X86 {
        super::super::super::super::services::wow64(p, t, 0x1234_0000)
    } else {
        handle_stop(p, t, stop(p.arch, 0x11))
    };
    assert_eq!(result, Outcome::Continue, "{} args={args:x?}", p.arch);
    assert_eq!(t.cpu.pc(), 0x1234_0004);
    assert_eq!(t.cpu.sp(), sp + if p.arch == WinArch::X86 { 4 } else { 0 });
    assert!(t.frames.is_empty());
    t.cpu.set_sp(sp);
    t.cpu.gpr(0) as u32
}

#[test]
fn file_information_reduced_handle_grants_and_last_error_are_independent_of_shared_objects() {
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        p.space
            .wr(base, &vec![0xA5; 6 * PAGE_SIZE as usize])
            .unwrap();
        let id = p.objects.create(Object::Console(StdStream::In));
        let all = p.objects.open_access(id, false, 0x12019f).unwrap();
        let attributes = p.objects.open_access(id, false, 0x80).unwrap();
        let error = t.teb + crate::user::windows::layout::offsets(arch).teb_last_error;
        p.space.w32(error, 0x12345678).unwrap();
        for (h, grant) in [(all, 0x12019f), (attributes, 0x80)] {
            assert_eq!(
                invoke(p, &mut t, &[u64::from(h), base, base + 64, 4, 8]),
                STATUS_SUCCESS
            );
            assert_eq!(p.space.u32(base + 64).unwrap(), grant);
        }
        assert_eq!(
            invoke(p, &mut t, &[u64::from(attributes), base, base + 64, 4, 43]),
            STATUS_ACCESS_DENIED
        );
        assert_eq!(
            invoke(p, &mut t, &[u64::from(attributes), base, base + 64, 8, 14]),
            STATUS_SUCCESS
        );
        assert_eq!(p.space.u64(base + 64).unwrap(), 0);
        assert_eq!(p.space.u32(error).unwrap(), 0x12345678);
    }
}
