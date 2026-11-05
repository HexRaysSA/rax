use super::*;
use crate::user::image::pe::hybrid::{CodeRange, HybridMetadata};
use crate::user::windows::arch::{CpuStop, InstructionRoute};
use crate::user::windows::context::RegContext;

fn process_and_thread(kind: CodeKind) -> (WindowsProcess, Thread, u64, u64) {
    let input = include_bytes!("../../../../tests/fixtures/user/windows/bin/x64/smoke.exe");
    let config = WindowsConfig::embedded("C:\\helper-test.exe", vec![], vec![], 4096).unwrap();
    let mut process = WindowsProcess::spawn_image(config, input.to_vec()).unwrap();
    let p = process.state_mut();
    let tid = *p.threads.keys().next().unwrap();
    let mut thread = p.threads.remove(&tid).unwrap();
    let target = p.modules.list[0].entry;
    let base = p.modules.list[0].base;
    let exit = base + 0x1100;
    p.vm.poke(target, &0xd503_201fu32.to_le_bytes()).unwrap();
    thread.cpu.set_pc(target);
    assert!(matches!(
        thread
            .cpu
            .run_routed(1, |_, _, _| Ok(InstructionRoute::ResumeArm64)),
        CpuStop::Yield
    ));
    p.modules.list[0].hybrid = Some(Arc::new(HybridMetadata {
        version: 2,
        code: vec![
            CodeRange {
                start: 0x1000,
                end: 0x1100,
                kind,
            },
            CodeRange {
                start: 0x1100,
                end: 0x1200,
                kind: CodeKind::Arm64Ec,
            },
        ],
        entries: Vec::new(),
        redirections: Vec::new(),
        dispatch_slots: [0; 8],
        alternate_entry: 0,
    }));
    (process, thread, target, exit)
}

#[test]
fn early_direct_and_indirect_checkers_use_their_distinct_target_registers() {
    for index in 2..=4 {
        for kind in [CodeKind::Amd64, CodeKind::Arm64Ec, CodeKind::Arm64] {
            let (mut process, mut thread, target, exit) = process_and_thread(kind);
            let p = process.state_mut();
            // The early direct checker takes X9. Indirect and CFG checkers
            // take X11, as specified by the ARM64EC call-checker ABI.
            thread
                .cpu
                .set_call_gpr(9, if index == 2 { target } else { 0xdead });
            thread
                .cpu
                .set_call_gpr(11, if index == 2 { 0xbeef } else { target });
            thread.cpu.set_call_gpr(10, exit);
            thread.cpu.set_call_gpr(30, target + 0x80);
            for n in 0..9 {
                thread.cpu.set_call_gpr(n, 0x1234_0000 + n as u64);
            }
            assert_eq!(
                helper(p, &mut thread, index),
                Outcome::Continue,
                "slot={index} kind={kind:?}"
            );
            assert_eq!(thread.cpu.pc(), target + 0x80);
            assert_eq!(thread.cpu.instruction_arch(), WinArch::Arm64);
            if kind == CodeKind::Amd64 {
                assert_eq!(thread.cpu.call_gpr(9), target);
                assert_eq!(thread.cpu.call_gpr(11), exit);
            } else {
                assert_eq!(thread.cpu.call_gpr(11), target);
            }
            for n in 0..9 {
                assert_eq!(thread.cpu.call_gpr(n), 0x1234_0000 + n as u64);
            }
        }
    }
}

#[test]
fn cfg_and_unknown_targets_fail_without_mutating_the_context() {
    for guarded in [false, true] {
        let (mut process, mut thread, target, exit) = process_and_thread(CodeKind::Amd64);
        let p = process.state_mut();
        p.modules.arm64ec_cfg = guarded;
        thread
            .cpu
            .set_call_gpr(11, if guarded { target } else { 0xdead });
        thread.cpu.set_call_gpr(10, exit);
        let before = RegContext::capture(&thread.cpu);
        assert!(matches!(helper(p, &mut thread, 4), Outcome::Fail(_)));
        assert_eq!(RegContext::capture(&thread.cpu).bytes(), before.bytes());
    }
}

#[test]
fn exit_pushes_the_arm64_link_and_preserves_amd64_argument_carriers() {
    let (mut process, mut thread, target, _) = process_and_thread(CodeKind::Amd64);
    let p = process.state_mut();
    let sp = thread.cpu.sp();
    thread.cpu.set_call_gpr(0, 0x1122);
    thread.cpu.set_call_gpr(1, 0x3344);
    thread.cpu.set_call_gpr(9, target);
    thread.cpu.set_call_gpr(30, target + 0x80);
    assert_eq!(helper(p, &mut thread, 0), Outcome::Continue);
    assert_eq!(thread.cpu.instruction_arch(), WinArch::X64);
    assert_eq!(thread.cpu.pc(), target);
    assert_eq!(thread.cpu.sp(), sp - 8);
    assert_eq!(p.space.u64(sp - 8).unwrap(), target + 0x80);
    assert_eq!(thread.cpu.gpr(1), 0x1122);
    assert_eq!(thread.cpu.gpr(2), 0x3344);
}
