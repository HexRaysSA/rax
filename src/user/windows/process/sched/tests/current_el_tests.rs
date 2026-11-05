//! Native Windows ARM64 CurrentEL compatibility at the scheduler boundary.
use super::*;

fn instruction(arch: WinArch, word: u32) -> (Proc, Thread, u64) {
    let mut p = process(arch);
    let (pc, _) =
        p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap();
    p.space.w32(pc, word).unwrap();
    p.vm.protect(pc, PAGE_SIZE, prot::EXECUTE_READ).unwrap();
    let mut t = thread(&mut p, 8);
    t.cpu.set_pc(pc);
    (p, t, pc)
}

#[test]
fn windows_current_el_read_retires_all_destinations_and_preserves_context() {
    for rt in 0..32 {
        let word = 0xD538_4240 | rt;
        let (mut p, mut t, pc) = instruction(WinArch::Arm64, word);
        for n in 0..31 {
            t.cpu.set_gpr(n, 0x1234_5678_9000_0000 + n as u64);
        }
        t.cpu.set_teb(t.teb);
        t.cpu.a64_mut().unwrap().core_mut().set_nzcv_bits(0b1011);
        let before = (0..31).map(|n| t.cpu.gpr(n)).collect::<Vec<_>>();
        let sp = t.cpu.sp();
        let stop = t.cpu.run(1);
        assert!(matches!(stop, CpuStop::Undefined { pc: at, .. } if at == pc));
        assert_eq!(
            handle_stop(&mut p, &mut t, stop),
            Outcome::Continue,
            "rt={rt}"
        );
        assert_eq!(t.cpu.pc(), pc + 4, "rt={rt}");
        for (n, expected) in before.into_iter().enumerate() {
            let expected = if n == rt as usize && n != 18 {
                0
            } else {
                expected
            };
            assert_eq!(t.cpu.gpr(n), expected, "rt={rt} x{n}");
        }
        assert_eq!(t.cpu.sp(), sp);
        assert_eq!(t.cpu.a64().unwrap().core().nzcv_bits(), 0b1011);
        assert_eq!(p.space.u32(pc).unwrap(), word);
        assert!(t.frames.is_empty());
        assert!(p.failure.is_none());
    }
}

#[test]
fn windows_current_el_uses_arm64_registers_inside_an_amd64_ec_process() {
    use crate::user::windows::arch::InstructionRoute;
    for rt in 0..32 {
        let (mut p, mut t, pc) = instruction(WinArch::X64, 0xD538_4240 | rt);
        for n in 0..16 {
            t.cpu.set_gpr(n, 0x1234_5678_9000_0000 + n as u64);
        }
        // Restore a valid stack after populating the AMD64 context carriers.
        t.cpu.set_sp(0x1234_0000);
        t.cpu.set_teb(t.teb);
        let stop = t
            .cpu
            .run_routed(1, |_, _, _| Ok(InstructionRoute::ResumeArm64));
        assert!(matches!(stop, CpuStop::Undefined { pc: at, .. } if at == pc));
        assert_eq!(t.cpu.arch(), WinArch::X64);
        assert_eq!(t.cpu.instruction_arch(), WinArch::Arm64);
        let before = (0..31).map(|n| t.cpu.call_gpr(n)).collect::<Vec<_>>();
        let sp = t.cpu.sp();
        assert_eq!(
            handle_stop(&mut p, &mut t, stop),
            Outcome::Continue,
            "rt={rt}"
        );
        assert_eq!(t.cpu.pc(), pc + 4);
        assert_eq!(t.cpu.sp(), sp);
        for (n, expected) in before.into_iter().enumerate() {
            let expected = if n == rt as usize && n != 18 {
                0
            } else {
                expected
            };
            assert_eq!(t.cpu.call_gpr(n), expected, "rt={rt} x{n}");
        }
        assert!(t.frames.is_empty());
        assert!(p.failure.is_none());
    }
}

#[test]
fn windows_current_el_compatibility_does_not_admit_other_privileged_instructions() {
    for word in [
        0xD538_1000, // MRS X0,SCTLR_EL1.
        0xD538_2000, // MRS X0,TTBR0_EL1.
        0xD538_4200, // MRS X0,SPSel.
        0xD538_4100, // MRS X0,SP_EL0.
        0xD518_4240, // MSR CurrentEL,X0 (reserved write).
        0,           // UDF #0.
    ] {
        let (mut p, mut t, pc) = instruction(WinArch::Arm64, word);
        let stop = t.cpu.run(1);
        assert!(matches!(stop, CpuStop::Undefined { pc: at, .. } if at == pc));
        assert_eq!(
            handle_stop(&mut p, &mut t, stop),
            Outcome::ProcessTerminate(STATUS_ILLEGAL_INSTRUCTION),
            "word={word:#010x}"
        );
        assert_eq!(t.cpu.pc(), pc);
    }
}

#[test]
fn shared_arm64_core_still_rejects_current_el_at_el0_for_every_destination() {
    for rt in 0..32 {
        let (_p, mut t, pc) = instruction(WinArch::Arm64, 0xD538_4240 | rt);
        t.cpu.set_gpr(0, 0xDEAD_BEEF);
        assert!(matches!(t.cpu.run(1), CpuStop::Undefined { pc: at, .. } if at == pc));
        assert_eq!(t.cpu.pc(), pc);
        assert_eq!(t.cpu.gpr(0), 0xDEAD_BEEF);
    }
}

#[test]
fn windows_current_el_requires_matching_arm64_pc_and_executable_instruction() {
    for arch in WinArch::ALL {
        let (mut p, mut t, pc) = instruction(arch, 0xD538_4240);
        t.cpu.set_gpr(0, 0x1234);
        if arch != WinArch::Arm64 {
            assert!(!windows_current_el(&p, &mut t, pc));
            assert_eq!(t.cpu.gpr(0), 0x1234);
            assert_eq!(t.cpu.pc(), pc);
            continue;
        }
        assert!(!windows_current_el(&p, &mut t, pc + 4)); // Stale stop.
        t.cpu.set_pc(pc + 1);
        assert!(!windows_current_el(&p, &mut t, pc + 1)); // Misalignment.
        t.cpu.set_pc(0xDEAD_0000);
        assert!(!windows_current_el(&p, &mut t, 0xDEAD_0000)); // Unmapped.
        t.cpu.set_pc(pc);
        p.vm.protect(pc, PAGE_SIZE, prot::READONLY).unwrap();
        assert!(!windows_current_el(&p, &mut t, pc)); // Readable, not executable.
        assert_eq!(t.cpu.gpr(0), 0x1234);
        assert_eq!(t.cpu.pc(), pc);
        p.vm.protect(pc, PAGE_SIZE, prot::EXECUTE_READ | prot::GUARD)
            .unwrap();
        assert!(!windows_current_el(&p, &mut t, pc));
        assert_eq!(
            p.vm.query(pc).unwrap().protect,
            prot::EXECUTE_READ | prot::GUARD
        );
        assert_eq!(t.cpu.gpr(0), 0x1234);
        assert_eq!(t.cpu.pc(), pc);
    }
}

#[test]
fn windows_current_el_consumes_one_scheduler_turn_and_resumes_at_next_instruction() {
    let (mut p, t, pc) = instruction(WinArch::Arm64, 0xD538_4250);
    Arc::make_mut(&mut p.cfg).slice_insns = 1;
    p.threads.insert(t.tid, t);
    let mut scheduler = Scheduler::default();
    let cancel = AtomicBool::new(false);
    assert_eq!(
        scheduler.run_slice(&mut p, 1, &cancel),
        RunStatus::BudgetExhausted
    );
    assert_eq!(p.threads[&8].cpu.pc(), pc + 4);
    assert!(p.threads[&8].frames.is_empty());
    assert_eq!(
        scheduler.run_slice(&mut p, 1, &cancel),
        RunStatus::Complete(ExitStatus::Exited(STATUS_ILLEGAL_INSTRUCTION))
    );
}
