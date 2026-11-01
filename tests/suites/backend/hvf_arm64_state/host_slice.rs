#[path = "../../../../src/backend/hvf/arm64_slice.rs"]
mod policy;

use policy::{Cancellation, KICK_PERIOD, validate_interval};
use std::sync::{Arc, Barrier};
use std::time::Duration;

#[test]
fn interval_admission_covers_worker_resolution_and_checked_clock_range() {
    for limit in [
        Duration::ZERO,
        Duration::from_nanos(1),
        Duration::from_nanos(4_999_999),
        Duration::MAX,
    ] {
        assert!(validate_interval(limit).is_err(), "{limit:?}");
    }
    for limit in [
        KICK_PERIOD,
        Duration::from_millis(10),
        Duration::from_nanos(u64::MAX),
    ] {
        assert_eq!(validate_interval(limit), Ok(()));
    }
}

#[test]
fn successful_cancellation_does_not_change_readiness() {
    let state = Cancellation::default();
    for _ in 0..16 {
        state.record(0);
        assert_eq!(state.ready(), Ok(()));
    }
}

#[test]
fn first_sdk_failure_survives_later_success_and_different_errors() {
    for error in [1, -1, i32::MIN, i32::MAX, 0xfae9_4003u32 as i32] {
        let state = Cancellation::default();
        state.record(error);
        for next in [0, 2, -2, 0] {
            state.record(next);
            assert_eq!(state.ready(), Err(error));
        }
    }
}

#[test]
fn concurrent_failures_publish_one_stable_nonzero_sdk_result() {
    let state = Arc::new(Cancellation::default());
    let start = Arc::new(Barrier::new(9));
    let workers = (1..=8)
        .map(|error| {
            let state = state.clone();
            let start = start.clone();
            std::thread::spawn(move || {
                start.wait();
                state.record(-error);
                state.record(0);
            })
        })
        .collect::<Vec<_>>();
    start.wait();
    for worker in workers {
        worker.join().unwrap();
    }
    let first = state.ready().unwrap_err();
    assert!((-8..=-1).contains(&first));
    state.record(123);
    assert_eq!(state.ready(), Err(first));
}

#[cfg(all(target_os = "macos", target_arch = "aarch64", feature = "hvf"))]
mod physical {
    use super::*;
    use rax::backend::hvf::{HvfArm64Backend, HvfArm64Vm};
    use rax::backend::{Backend, Vm};
    use rax::vm::memory::GuestMemoryWrapper;
    use rax::vm::vcpu::{CpuState, VCpu, VcpuExit};
    use std::sync::Mutex;

    static SERIAL: Mutex<()> = Mutex::new(());
    // LLVM MC independently checks these words in the group encoding evidence.
    const BUSY: [u32; 3] = [0xd280_0020, 0xf900_0020, 0x1400_0000];
    const SYSTEM_OFF: [u32; 4] = [0x5280_0100, 0x72b0_8000, 0xd400_0002, 0x1400_0000];
    const INPUT: [u32; 3] = [0xf940_0020, 0xf900_0040, 0x1400_0000];

    fn fixture(words: &[u32]) -> (Box<dyn Vm>, GuestMemoryWrapper) {
        let backend = HvfArm64Backend::new().unwrap();
        let vm = backend.create_vm().unwrap();
        let memory = GuestMemoryWrapper::new(0x4000).unwrap();
        let mut image = vec![0u8; 0x4000];
        for (chunk, word) in image.chunks_exact_mut(4).zip(words) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        memory.write_all(&image).unwrap();
        vm.as_any()
            .downcast_ref::<HvfArm64Vm>()
            .unwrap()
            .register_memory(&memory, 0, 0x4000)
            .unwrap();
        (vm, memory)
    }

    fn cpu(vm: &dyn Vm, memory: &GuestMemoryWrapper, id: u32) -> Box<dyn VCpu> {
        let mut cpu = vm
            .create_vcpu(id, Arc::new(memory.memory().clone()))
            .unwrap();
        let mut public = cpu.get_state().unwrap();
        let CpuState::Aarch64(state) = &mut public else {
            panic!("wrong native architecture");
        };
        state.regs.pc = 0;
        state.regs.pstate = 0x3c5;
        state.regs.sp = 0x4000;
        state.regs.x[1] = 0x1000 + u64::from(id) * 8;
        state.sregs.sctlr_el1 &= !((1 << 25) | (1 << 12) | (1 << 2) | 1);
        state.sregs.cntp_ctl_el0 = 0;
        state.sregs.cntv_ctl_el0 = 0;
        cpu.set_state(&public).unwrap();
        cpu
    }

    #[test]
    #[ignore = "requires physical Apple Silicon and signed Hypervisor executable"]
    fn two_and_four_actual_native_cpus_yield_without_guest_halt_or_retirement() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for count in [2, 4] {
            let (vm, memory) = fixture(&BUSY);
            let mut cpus = (0..count)
                .map(|id| cpu(vm.as_ref(), &memory, id))
                .collect::<Vec<_>>();
            for _ in 0..8 {
                for cpu in &mut cpus {
                    assert!(cpu.supports_host_slices());
                    assert!(
                        cpu.run_host_slice(Duration::from_millis(10))
                            .unwrap()
                            .is_none()
                    );
                    assert_eq!(cpu.instruction_count(), 0);
                }
            }
            let bytes = memory.try_read_all().unwrap();
            for (id, cpu) in cpus.iter().enumerate() {
                let offset = 0x1000 + id * 8;
                assert_eq!(
                    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()),
                    1
                );
                let CpuState::Aarch64(state) = cpu.get_state().unwrap() else {
                    panic!("wrong architecture");
                };
                assert_eq!(state.regs.pc, 8);
            }
            drop(cpus);
            drop(vm);
        }
    }

    #[test]
    #[ignore = "requires physical Apple Silicon and signed Hypervisor executable"]
    fn invalid_intervals_reject_before_entry_without_poisoning_the_cpu() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (vm, memory) = fixture(&BUSY);
        let mut cpu = cpu(vm.as_ref(), &memory, 0);
        let before = rax::codec::serialize(&cpu.get_state().unwrap()).unwrap();
        for limit in [Duration::ZERO, Duration::from_nanos(1), Duration::MAX] {
            assert!(cpu.run_host_slice(limit).is_err());
            assert_eq!(
                rax::codec::serialize(&cpu.get_state().unwrap()).unwrap(),
                before
            );
        }
        for _ in 0..8 {
            assert!(
                cpu.run_host_slice(Duration::from_millis(10))
                    .unwrap()
                    .is_none()
            );
        }
        assert_eq!(memory.try_read_all().unwrap()[0x1000], 1);
    }

    #[test]
    #[ignore = "requires physical Apple Silicon and signed Hypervisor executable"]
    fn legacy_run_waits_for_the_actual_guest_shutdown_after_idle_cancellation() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (vm, memory) = fixture(&SYSTEM_OFF);
        let mut cpu = cpu(vm.as_ref(), &memory, 0);
        std::thread::sleep(Duration::from_millis(15));
        assert!(matches!(cpu.run().unwrap(), VcpuExit::Shutdown));
    }

    #[test]
    #[ignore = "requires physical Apple Silicon and signed Hypervisor executable"]
    fn actual_mmio_input_retains_fault_pc_until_full_reply_then_retires_once() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (vm, memory) = fixture(&INPUT);
        let mut cpu = cpu(vm.as_ref(), &memory, 0);
        let mut public = cpu.get_state().unwrap();
        let CpuState::Aarch64(state) = &mut public else {
            panic!("wrong architecture");
        };
        state.regs.x[0] = 0xdead_beef;
        state.regs.x[1] = 0x5000;
        state.regs.x[2] = 0x1000;
        cpu.set_state(&public).unwrap();
        let mut observed = false;
        for _ in 0..8 {
            if let Some(exit) = cpu.run_host_slice(Duration::from_millis(10)).unwrap() {
                assert!(matches!(
                    exit,
                    VcpuExit::MmioRead {
                        addr: 0x5000,
                        size: 8
                    }
                ));
                observed = true;
                break;
            }
        }
        assert!(observed, "native CPU did not reach the real input trap");
        let CpuState::Aarch64(state) = cpu.get_state().unwrap() else {
            panic!("wrong architecture");
        };
        assert_eq!((state.regs.pc, state.regs.x[0]), (0, 0xdead_beef));
        let before = rax::codec::serialize(&CpuState::Aarch64(state.clone())).unwrap();
        assert!(cpu.set_current_pc(0x100).is_err());
        assert_eq!(
            rax::codec::serialize(&cpu.get_state().unwrap()).unwrap(),
            before
        );
        let mut redirected = state;
        redirected.regs.pc = 0x100;
        assert!(cpu.update_state(&CpuState::Aarch64(redirected)).is_err());
        assert_eq!(
            rax::codec::serialize(&cpu.get_state().unwrap()).unwrap(),
            before
        );
        assert!(cpu.capture_backend_context().unwrap().is_some());
        cpu.set_current_pc(0).unwrap();
        cpu.complete_io_in(&[0xaa; 7]);
        assert!(cpu.io_completion_result().is_err());
        let CpuState::Aarch64(state) = cpu.get_state().unwrap() else {
            panic!("wrong architecture");
        };
        assert_eq!((state.regs.pc, state.regs.x[0]), (0, 0xdead_beef));
        assert!(matches!(
            cpu.run_host_slice(Duration::from_millis(5)).unwrap(),
            Some(VcpuExit::MmioRead {
                addr: 0x5000,
                size: 8
            })
        ));
        let value = 0x1122_3344_5566_7788u64;
        cpu.complete_io_in(&value.to_le_bytes());
        assert!(cpu.io_completion_result().is_ok());
        let CpuState::Aarch64(state) = cpu.get_state().unwrap() else {
            panic!("wrong architecture");
        };
        assert_eq!((state.regs.pc, state.regs.x[0]), (4, value));
        cpu.complete_io_in(&value.to_le_bytes());
        assert!(cpu.io_completion_result().is_ok());
        for _ in 0..8 {
            assert!(
                cpu.run_host_slice(Duration::from_millis(10))
                    .unwrap()
                    .is_none()
            );
        }
        let bytes = memory.try_read_all().unwrap();
        assert_eq!(
            u64::from_le_bytes(bytes[0x1000..0x1008].try_into().unwrap()),
            value
        );
        let CpuState::Aarch64(state) = cpu.get_state().unwrap() else {
            panic!("wrong architecture");
        };
        assert_eq!((state.regs.pc, state.regs.x[0]), (8, value));
    }
    #[test]
    #[ignore = "requires physical Apple Silicon and signed Hypervisor executable"]
    fn scalar_store_widths_and_zero_registers_wait_for_acknowledgement() {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (width, word) in [
            (1, 0x39000020),
            (2, 0x79000020),
            (4, 0xb9000020),
            (8, 0xf9000020),
        ] {
            for zero in [false, true] {
                check_store_width(width, word, zero);
            }
        }
    }
    fn check_store_width(width: usize, word: u32, zero: bool) {
        let vm = HvfArm64Backend::new().unwrap().create_vm().unwrap();
        let memory = GuestMemoryWrapper::new(0x4000).unwrap();
        let mut image = vec![0u8; 0x4000];
        for (chunk, word) in image
            .chunks_exact_mut(4)
            .zip([word | if zero { 31 } else { 0 }, 0x14000000])
        {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        memory.write_all(&image).unwrap();
        vm.as_any()
            .downcast_ref::<HvfArm64Vm>()
            .unwrap()
            .register_memory(&memory, 0, 0x4000)
            .unwrap();
        let mut cpu = vm
            .create_vcpu(0, Arc::new(memory.memory().clone()))
            .unwrap();
        let mut state = cpu.get_state().unwrap();
        let CpuState::Aarch64(s) = &mut state else {
            panic!()
        };
        s.regs.pc = 0;
        s.regs.pstate = 0x3c5;
        s.regs.sp = 0x4000;
        s.regs.x[0] = 0x8877665544332211;
        s.regs.x[1] = 0x5000;
        s.sregs.sctlr_el1 &= !((1 << 25) | (1 << 12) | (1 << 2) | 1);
        s.sregs.cntp_ctl_el0 = 0;
        s.sregs.cntv_ctl_el0 = 0;
        cpu.set_state(&state).unwrap();
        let expected = if zero {
            vec![0; width]
        } else {
            0x8877665544332211u64.to_le_bytes()[..width].to_vec()
        };
        let mut trapped = false;
        for _ in 0..16 {
            if let Some(exit) = cpu.run_host_slice(Duration::from_millis(10)).unwrap() {
                match exit {
                    VcpuExit::MmioWrite { addr: 0x5000, data } => {
                        assert_eq!(data, expected);
                        trapped = true;
                        break;
                    }
                    other => panic!("unexpected {other:?}"),
                }
            }
        }
        assert!(trapped);
        let CpuState::Aarch64(before) = cpu.get_state().unwrap() else {
            panic!()
        };
        assert_eq!(
            before.regs.pc, 0,
            "store width={width} zero={zero} retired before acknowledgement"
        );
        let snapshot = rax::codec::serialize(&cpu.get_state().unwrap()).unwrap();
        assert!(cpu.set_current_pc(0x100).is_err());
        assert_eq!(
            rax::codec::serialize(&cpu.get_state().unwrap()).unwrap(),
            snapshot
        );
        let mut overlay = cpu.get_state().unwrap();
        let CpuState::Aarch64(s) = &mut overlay else {
            panic!()
        };
        s.regs.x[0] = 0xdeadbeef;
        cpu.update_state(&overlay).unwrap();
        for _ in 0..2 {
            assert!(
                matches!(cpu.run_host_slice(Duration::from_millis(10)).unwrap(),Some(VcpuExit::MmioWrite{addr:0x5000,data}) if data==expected)
            );
            let CpuState::Aarch64(s) = cpu.get_state().unwrap() else {
                panic!()
            };
            assert_eq!(s.regs.pc, 0);
        }
        cpu.complete_io_out().unwrap();
        assert!(cpu.io_completion_result().is_ok());
        assert!(cpu.complete_io_out().is_err());
        let CpuState::Aarch64(done) = cpu.get_state().unwrap() else {
            panic!()
        };
        assert_eq!((done.regs.pc, done.regs.x[0]), (4, 0xdeadbeef));
        assert!(
            cpu.run_host_slice(Duration::from_millis(10))
                .unwrap()
                .is_none()
        );
        drop(cpu);
        drop(vm);
    }
}
