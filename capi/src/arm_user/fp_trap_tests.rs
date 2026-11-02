use super::*;

#[test]
fn selected_user_fp_trap_uses_existing_exception_record_without_retirement() {
    let memory = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap());
    memory
        .write_slice(&0xee810a02u32.to_le_bytes(), GuestAddress(0x100))
        .unwrap();
    let mut cpu = ArmUserVcpu::new(
        memory,
        Arc::new(RegionTranslation::new(vec![(
            0,
            0x4000,
            crate::RAX_PROT_READ | crate::RAX_PROT_EXEC,
        )])),
        false,
    );
    // The public C API keeps its default nontrapping profile; this exercises
    // the adapter contract if trusted engine metadata selects optional support.
    cpu.cpu.core_mut().vfp.mvfr0 |= 1 << 12;
    cpu.cpu.core_mut().vfp.fpscr = Fpscr::from_bits(0x100);
    cpu.cpu.set_pc(0x100);
    assert!(matches!(
        cpu.step_insn().unwrap(),
        Some(VcpuExit::Exception(0x28))
    ));
    assert_eq!(cpu.instruction_count(), 0);
    assert_eq!(cpu.current_pc(), 0x100);
    assert!(matches!(
        cpu.trap,
        Some(UserTrap::Exception {
            vector: 0x28,
            pc: 0x100,
            return_pc: 0x100,
            syndrome: Some(0x800001),
            software: false,
            undefined: false
        })
    ));
}
