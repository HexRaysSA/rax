use super::*;

#[test]
fn user_fp_denial_is_an_el0_event_without_vectoring_or_retirement() {
    for instruction in [0x1e22_2820, 0x3dc0_0020, 0x3d80_0020] {
        let (mut cpu, _) = user_vcpu(&[instruction]);
        let CpuState::Aarch64(mut saved) = cpu.get_state().unwrap() else {
            panic!()
        };
        saved.regs.x[1] = DATA;
        saved.sregs.execution.as_mut().unwrap().sysregs.el1.cpacr = 0;
        cpu.set_state(&CpuState::Aarch64(saved)).unwrap();
        assert!(matches!(
            cpu.step_insn(),
            Err(Error::GuestEvent { vector: 7 })
        ));
        assert_eq!(cpu.instruction_count(), 0);
        assert_eq!(cpu.current_pc(), CODE);
        assert_eq!(state(&cpu).regs.pstate & 0x1f, 0);
        assert_eq!(
            cpu.take_user_trap(),
            Some(A64UserTrap::Exception {
                ec: 7,
                iss: 0,
                pc: CODE
            })
        );
        let CpuState::Aarch64(mut saved) = cpu.get_state().unwrap() else {
            panic!()
        };
        saved.sregs.execution.as_mut().unwrap().sysregs.el1.cpacr = 3 << 20;
        cpu.set_state(&CpuState::Aarch64(saved)).unwrap();
        assert!(cpu.step_insn().unwrap().is_none());
        assert_eq!(cpu.instruction_count(), 1);
        assert_eq!(cpu.current_pc(), CODE + 4);
    }
}
