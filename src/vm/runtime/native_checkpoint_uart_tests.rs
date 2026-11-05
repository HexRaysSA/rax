//! Missing platform ownership must reject before any native publication.
use super::*;

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
