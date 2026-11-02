//! Private capture and clock regression witnesses against the actual S5L owner.
use super::*;

fn mapped_cpu() -> S5L8900Vcpu {
    let mem = Arc::new(
        GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(IBOOT_BASE as u64), 0x4000)]).unwrap(),
    );
    let code = [0xe1a0_0000u32; 4]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
    mem.write_slice(&code, GuestAddress(IBOOT_BASE as u64))
        .unwrap();
    let mut cpu = S5L8900Vcpu::new(0, mem);
    cpu.cpu.regs[15] = IBOOT_BASE;
    cpu.bridge.inner.borrow_mut().nand = S5lNand::new(None);
    cpu
}

#[test]
fn platform_declares_and_captures_required_private_state() {
    let cpu = mapped_cpu();
    assert!(cpu.required_private_checkpoint_kind().is_some());
    assert!(cpu.capture_backend_context().unwrap().is_some());
}

#[test]
fn deterministic_timer_profile_wraps_without_host_panic_during_live_and_idle_entry() {
    for halted in [false, true] {
        let mut cpu = mapped_cpu();
        cpu.det_timer = 1;
        cpu.timer_mul = u64::MAX;
        cpu.timer_irq_clock = 1;
        cpu.timer_irq_interval = 1;
        cpu.timer_irq = false;
        cpu.cpu.is_halted = halted;
        let exit = cpu.step_insn().unwrap();
        // The computed ticks wrap; the existing device keeps the greater
        // value sampled before/after the idle advance (MAX-1 versus MAX-2).
        assert_eq!(
            cpu.bridge.inner.borrow().timer.debug_state().0,
            u64::MAX - 1
        );
        assert_eq!(cpu.insn_count, u64::from(!halted));
        if halted {
            assert!(matches!(exit, Some(VcpuExit::Hlt)));
        } else {
            assert!(exit.is_none());
        }
    }
}

#[test]
fn public_register_projection_roundtrips_fp_spsr_and_mmu_fields() {
    let mut cpu = mapped_cpu();
    let CpuState::Aarch32(mut state) = cpu.get_state().unwrap() else {
        panic!()
    };
    state.regs.r[0] = 0x12345678;
    state.regs.fpscr = 0x0040001f;
    state.regs.s[0] = 0x7fc01234;
    state.regs.d_high[0] = 0x0123456789abcdef;
    state.regs.cpsr = (state.regs.cpsr & !31) | 0x13;
    state.regs.spsr = 0x60000013;
    state.sregs.ttbr0 = 0x80004000;
    state.sregs.ttbr1 = 0x81008000;
    state.sregs.dacr = 0xabcdef01;
    state.sregs.contextidr = 0x98765432;
    cpu.set_state(&CpuState::Aarch32(state.clone())).unwrap();
    let CpuState::Aarch32(actual) = cpu.get_state().unwrap() else {
        panic!()
    };
    assert_eq!(actual.regs.r, state.regs.r);
    assert_eq!(actual.regs.s, state.regs.s);
    assert_eq!(actual.regs.d_high, state.regs.d_high);
    assert_eq!(actual.regs.fpscr, state.regs.fpscr);
    assert_eq!(actual.regs.spsr, state.regs.spsr);
    assert_eq!(actual.sregs.ttbr0, state.sregs.ttbr0);
    assert_eq!(actual.sregs.ttbr1, state.sregs.ttbr1);
    assert_eq!(actual.sregs.dacr, state.sregs.dacr);
    assert_eq!(actual.sregs.contextidr, state.sregs.contextidr);
}
