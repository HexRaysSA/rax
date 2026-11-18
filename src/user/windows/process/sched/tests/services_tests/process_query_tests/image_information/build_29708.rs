//! Class 37 write and guard behavior on ARM64 Windows build 29708.
use super::*;
use serde::Deserialize;

#[derive(Deserialize)]
struct Corpus {
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Case {
    protection: u32,
    fitting: u64,
    status: u32,
    return_length: u32,
    observed_protection: u32,
    written_bytes: usize,
}

#[test]
fn native_process_image_information_build29708_replays_arm64_copy_groups() {
    replay(
        WinArch::Arm64,
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-process-image-information/local-29708-arm64-copy.json"
        )),
        68,
    );
}

#[test]
fn native_process_image_information_build29708_replays_wow64_copy() {
    replay(
        WinArch::X86,
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-process-image-information/local-29708-wow64-copy.json"
        )),
        85,
    );
}

fn replay(arch: WinArch, json: &str, expected_cases: usize) {
    let capture: Corpus = serde_json::from_str(json).unwrap();
    assert_eq!(capture.cases.len(), expected_cases);
    let width = if arch == WinArch::X86 { 48 } else { 64 };
    let (mut process, mut thread, scratch) = setup(arch);
    let stack = thread.cpu.sp();
    let p = process.state_mut();
    super::replay::kernel_profile(p, 29708, 0xAA64);
    let success = scratch + 96;
    let current = arch.ptr(u64::MAX);
    arguments(p, &mut thread, current, 37, scratch, width, success);
    assert_eq!(dispatch(p, &mut thread), Outcome::Continue);
    assert_eq!(thread.cpu.gpr(0), 0);
    assert_eq!(p.space.u32(success).unwrap(), width);
    let expected = p.space.bytes(scratch, width as usize).unwrap();
    for case in capture.cases {
        let (base, _) =
            p.vm.allocate(
                None,
                2 * PAGE_SIZE,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE,
            )
            .unwrap();
        let next = base + PAGE_SIZE;
        let output = next - case.fitting;
        let mut populated = [0xA5; 64];
        let populated = &mut populated[..width as usize];
        p.space.wr(output, populated).unwrap();
        p.space.w32(success, 0xD4D4_D4D4).unwrap();
        p.vm.protect(next, PAGE_SIZE, case.protection).unwrap();
        thread.cpu.set_sp(stack);
        arguments(p, &mut thread, current, 37, output, width, success);
        assert_eq!(dispatch(p, &mut thread), Outcome::Continue);
        assert_eq!(thread.cpu.gpr(0), u64::from(case.status), "{case:?}");
        assert_eq!(
            p.space.u32(success).unwrap(),
            case.return_length,
            "{case:?}"
        );
        assert_eq!(
            p.vm.query(next).unwrap().protect,
            case.observed_protection,
            "{case:?}"
        );
        p.vm.protect(next, PAGE_SIZE, prot::READWRITE).unwrap();
        populated[..case.written_bytes].copy_from_slice(&expected[..case.written_bytes]);
        assert_eq!(
            p.space.bytes(output, width as usize).unwrap().as_slice(),
            &*populated,
            "{case:?}"
        );
        p.vm.release(base).unwrap();
    }
}
