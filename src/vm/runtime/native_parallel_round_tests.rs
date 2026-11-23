//! Physical Apple Silicon coverage for posted entry and VMM round dispatch.
use super::*;
use std::time::Duration;

const SLOTS: u64 = CODE + 0x1000;
const MASK: u64 = UART + 0x38;
const STORE_PC: u64 = CODE + 36;
const PROGRAM: [u32; 12] = [
    0x5280_0029, // MOV W9,#1
    0x889f_fc09, // STLR W9,[X0]
    0xaa01_03e4, // MOV X4,X1
    0xaa02_03e5, // MOV X5,X2
    0x88df_fc8a, // LDAR W10,[X4]
    0x34ff_ffea, // CBZ W10,.-4
    0x9101_0084, // ADD X4,X4,#64
    0xf100_04a5, // SUBS X5,X5,#1
    0x54ff_ff81, // B.NE .-16
    0xb900_0060, // STR W0,[X3]
    0xd503_207f, // WFI
    0x17ff_ffff, // B .-4
];

fn install_guest(vm: &mut Vmm, count: u8) {
    let code: Vec<_> = PROGRAM.into_iter().flat_map(u32::to_le_bytes).collect();
    let memory = vm.guest_mem.memory();
    memory.write_slice(&code, GuestAddress(CODE)).unwrap();
    memory
        .write_slice(&[0; 4 * 64], GuestAddress(SLOTS))
        .unwrap();
    publish_native_code(&vm.guest_mem, CODE, code.len());
    for cpu in &mut vm.vcpus {
        let CpuState::Aarch64(mut state) = cpu.get_state().unwrap() else {
            unreachable!();
        };
        state.regs.pc = CODE;
        state.regs.pstate = 0x3c5;
        state.regs.x[0] = SLOTS + 64 * u64::from(cpu.id());
        state.regs.x[1] = SLOTS;
        state.regs.x[2] = u64::from(count);
        state.regs.x[3] = MASK;
        cpu.set_state(&CpuState::Aarch64(state)).unwrap();
    }
}

fn verify_store(exit: &VcpuExit, cpu: usize) {
    let VcpuExit::MmioWrite { addr, data } = exit else {
        panic!("CPU {cpu} did not reach its report: {exit:?}");
    };
    assert_eq!(*addr, MASK);
    assert_eq!(
        data.as_slice(),
        (SLOTS as u32 + 64 * cpu as u32).to_le_bytes()
    );
}

#[test]
#[ignore = "requires physical Apple Silicon and com.apple.security.hypervisor entitlement"]
fn native_aarch64_parallel_rounds_preserve_owner_and_device_frontiers() {
    let fixture = Fixture::new();
    for count in [2, 4] {
        let mut config = fixture.config(count);
        config.hvf_parallel_vcpus = true;
        config.validate().unwrap();
        let mut vm = Vmm::new_resume(config).unwrap();
        psci::boot_native_secondaries(&mut vm);
        install_guest(&mut vm, count);

        assert!(
            vm.vcpus[0]
                .post_host_slice(Duration::from_millis(1))
                .is_err()
        );
        assert!(vm.vm.checkpoint_boundary().is_ok());
        // Every guest waits for its peers in the same posted entry. A backend
        // that runs owners serially cannot return every store in this cohort.
        let limit = Duration::from_millis(250);
        vm.vcpus[0].post_host_slice(limit).unwrap();
        assert!(vm.vcpus[0].get_state().is_err());
        assert!(vm.vcpus[0].post_host_slice(limit).is_err());
        assert!(matches!(
            vm.vm.checkpoint_boundary(),
            Err(error) if error.to_string().contains("must be collected")
        ));
        for cpu in &mut vm.vcpus[1..] {
            cpu.post_host_slice(limit).unwrap();
        }
        assert!(vm.vm.checkpoint_boundary().is_err());
        for (id, cpu) in vm.vcpus.iter_mut().enumerate() {
            let exit = cpu
                .collect_host_slice()
                .unwrap()
                .unwrap_or_else(|| panic!("CPU {id} yielded with {count} CPUs posted"));
            verify_store(&exit, id);
            assert_eq!(cpu.current_pc(), STORE_PC);
            assert!(cpu.collect_host_slice().is_err());
            cpu.complete_io_out().unwrap();
            assert_eq!(cpu.current_pc(), STORE_PC + 4);
        }
        assert!(vm.vm.checkpoint_boundary().is_ok());

        // Exercise the configured VMM path, including real PL011 dispatch.
        install_guest(&mut vm, count);
        let mut reports = vec![false; usize::from(count)];
        let mut turns = Vec::new();
        let mut pending = Vec::new();
        for _ in 0..32 {
            vm.execute_native_round(&mut turns, &mut pending).unwrap();
            for turn in &turns {
                if matches!(turn.exit, VcpuExit::MmioWrite { .. }) {
                    verify_store(&turn.exit, turn.cpu_index);
                    assert!(!std::mem::replace(&mut reports[turn.cpu_index], true));
                }
            }
            assert!(!vm.apply_native_round(&mut turns).unwrap());
            if reports.iter().all(|reported| *reported) {
                break;
            }
        }
        assert!(reports.iter().all(|reported| *reported), "{reports:?}");
        assert_eq!(vm.coordinator.retired, 0);

        // Dropping a CPU drains its own pending entry before taking the
        // exclusive teardown boundary. Other CPUs retain usable owners.
        vm.vcpus[0].post_host_slice(limit).unwrap();
        drop(vm.vcpus.remove(0));
        assert!(vm.vm.checkpoint_boundary().is_ok());
        assert!(vm.vcpus[0].run_host_slice(limit).is_ok());
    }
}
