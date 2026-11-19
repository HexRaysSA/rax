//! Missing platform ownership must reject before any native publication.
use super::*;

#[test]
#[ignore = "requires physical Apple Silicon and com.apple.security.hypervisor entitlement"]
fn native_automatic_checkpoint_records_uart_spi_after_read_and_write() {
    // Both guests stop with PSCI SYSTEM_OFF after the first UART access.
    for (access, initial_mask, expected_level) in [
        (0x3940_00e6u32, 16u32, false), // LDRB W6, [X7] consumes the last byte.
        (0xb900_38eau32, 0, true),      // STR W10, [X7,#0x38] unmasks RX.
    ] {
        let fixture = Fixture::new();
        let mut vm = Vmm::new_resume(fixture.config(1)).unwrap();
        let program = [access, 0x5280_0100, 0x72b0_8000, 0xd400_0002];
        for (index, word) in program.into_iter().enumerate() {
            vm.guest_mem
                .memory()
                .write_slice(&word.to_le_bytes(), GuestAddress(CODE + index as u64 * 4))
                .unwrap();
        }
        publish_native_code(&vm.guest_mem, CODE, program.len() * 4);
        vm.mmio_bus
            .write(UART + 0x38, &initial_mask.to_le_bytes())
            .unwrap();
        vm.pl011
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .queue_input(&[0x7b]);

        let CpuState::Aarch64(mut cpu) = vm.vcpus[0].get_state().unwrap() else {
            unreachable!();
        };
        cpu.regs.pc = CODE;
        cpu.regs.pstate = 0x3c5;
        cpu.regs.x[7] = UART;
        cpu.regs.x[10] = 16;
        vm.vcpus[0].set_state(&CpuState::Aarch64(cpu)).unwrap();

        // Native host slices do not report guest retirement. Arm a checkpoint
        // at the first completed MMIO exit using the coordinator's existing count.
        vm.coordinator.retired = 7;
        let schedule = SnapshotConfig {
            at_instructions: vec![7],
            output_dir: fixture
                .checkpoint
                .parent()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            prefix: fixture
                .checkpoint
                .file_stem()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            ..SnapshotConfig::default()
        };
        let path = std::path::PathBuf::from(schedule.filename(7));
        vm.snapshot_config = Some(schedule);
        let result = vm.run();
        let loaded = SnapshotBundle::load(&path);
        let _ = std::fs::remove_file(&path);
        result.unwrap();
        let loaded = loaded.unwrap();

        assert_eq!(loaded.base().instruction_count, 7);
        let context = Context::decode(
            &loaded.backend_contexts().unwrap().entries()[0]
                .as_ref()
                .unwrap()
                .data,
        )
        .unwrap();
        assert_eq!(context.public.regs.pc, CODE + 4);
        if !expected_level {
            assert_eq!(context.public.regs.x[6], 0x7b);
        }
        let global = GlobalContext::decode(&loaded.vm_context().unwrap().data).unwrap();
        assert_eq!(global.irq_levels, [(33, expected_level)], "{access:#010x}");
        let mut uart = Pl011::new();
        uart.restore_checkpoint(loaded.execution().unwrap().pl011.clone().unwrap());
        assert_eq!(uart.irq_pending(), expected_level);
    }
}

#[test]
#[ignore = "requires physical Apple Silicon and com.apple.security.hypervisor entitlement"]
fn native_missing_uart_rejects_before_cpu_ram_and_device_publication() {
    for count in [1, 2, 4] {
        let fixture = Fixture::new();
        let mut target = Vmm::new_resume(fixture.config(count)).unwrap();
        target
            .pl011
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .queue_input(&[0xab]);
        let mut incoming = target.take_snapshot_bundle(0).unwrap();
        let mut execution = incoming.take_execution().unwrap();
        execution.pl011 = None;
        incoming = incoming.with_execution(execution).unwrap();
        // The target is still unentered, so missing UART ownership is the
        // admission failure under test, rather than the SDK's entry restriction.
        for cpu in &mut target.vcpus {
            let CpuState::Aarch64(mut state) = cpu.get_state().unwrap() else {
                panic!()
            };
            state.regs.x[20] = 0xcafe_0000 + u64::from(cpu.id());
            cpu.set_state(&CpuState::Aarch64(state)).unwrap();
        }
        target
            .guest_mem
            .memory()
            .write_slice(&[0x5a; 16], GuestAddress(CODE))
            .unwrap();
        target
            .pl011
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .queue_input(&[0xcd, 0xef]);
        let cpus = private_states(&target);
        let uart = target
            .pl011
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .checkpoint()
            .unwrap();
        let coordinator = (
            target.coordinator.cursor,
            target.coordinator.retired,
            target.coordinator.online.clone(),
        );
        let result = target.restore_snapshot_bundle(&incoming);
        let error = result.expect_err("native restore accepted an absent UART image");
        assert!(error.to_string().contains("PL011"), "{error}");
        assert_eq!(private_states(&target), cpus);
        assert_eq!(
            target
                .pl011
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .checkpoint()
                .unwrap(),
            uart
        );
        assert_eq!(
            (
                target.coordinator.cursor,
                target.coordinator.retired,
                target.coordinator.online.clone(),
            ),
            coordinator
        );
        let mut memory = [0; 16];
        target
            .guest_mem
            .memory()
            .read_slice(&mut memory, GuestAddress(CODE))
            .unwrap();
        assert_eq!(memory, [0x5a; 16]);
    }
}
