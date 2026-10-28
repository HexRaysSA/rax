//! Reservation conservation across real adapters sharing physical RAM.
use super::{CODE, Fixture};
use rax::vm::vcpu::CpuState;
use vm_memory::{Bytes, GuestAddress};

const DATA: u64 = 0x2000;
const LDXR: u32 = 0x885f_7c20;
const STXR: u32 = 0x8802_7c20;
const LDREX: u32 = 0xe191_0f9f;
const STREX: u32 = 0xe181_2f90;

fn x(f: &Fixture, id: usize, register: usize) -> u64 {
    let CpuState::Aarch64(state) = f.cpus[id].get_state().unwrap() else {
        panic!()
    };
    state.regs.x[register]
}

fn enter_arm(f: &mut Fixture) {
    let CpuState::Aarch64(mut state) = f.cpus[0].get_state().unwrap() else {
        panic!()
    };
    state.regs.pstate = 0x1d3;
    state.sregs.execution.as_mut().unwrap().sysregs.hcr_el2 &= !(1 << 31);
    f.cpus[0].update_state(&CpuState::Aarch64(state)).unwrap();
}

#[test]
fn cross_pe_identical_and_aba_stores_invalidate_a64_and_a32_reservations() {
    for arm in [false, true] {
        for values in [&[42][..], &[99, 42][..]] {
            let mut f = Fixture::new(2);
            f.start(1, 0);
            f.write(1, DATA, 42);
            if arm {
                enter_arm(&mut f);
            }
            assert_eq!(
                f.instruction(0, if arm { LDREX } else { LDXR }, 0, DATA),
                42
            );
            for &value in values {
                f.write(1, DATA, value);
            }
            f.instruction(0, if arm { STREX } else { STXR }, 123, DATA);
            assert_eq!(x(&f, 0, 2), 1, "arm={arm}, values={values:?}");
            assert_eq!(f.read(1, DATA), 42);
        }
    }
}

#[test]
fn reservation_granule_edges_and_tracked_host_writes_obey_the_same_domain() {
    for (offset, failed) in [(63, 1), (64, 0)] {
        let mut f = Fixture::new(2);
        f.start(1, 0);
        f.instruction(0, LDXR, 0, DATA);
        // A clone of the mmap handle must retain its physical domain.
        rax::vm::memory::write_guest_memory(&f.mem.as_ref().clone(), DATA + offset, &[0]).unwrap();
        f.instruction(0, STXR, 123, DATA);
        assert_eq!(x(&f, 0, 2), failed, "offset={offset}");
    }
}

#[test]
fn a_successful_exclusive_store_invalidates_the_other_pe() {
    let mut f = Fixture::new(2);
    f.start(1, 0);
    f.instruction(0, LDXR, 0, DATA);
    f.instruction(1, LDXR, 0, DATA);
    f.instruction(0, STXR, 111, DATA);
    assert_eq!(x(&f, 0, 2), 0);
    f.instruction(1, STXR, 222, DATA);
    assert_eq!(x(&f, 1, 2), 1);
    assert_eq!(f.read(0, DATA), 111);
}

#[test]
fn pair_exclusives_cover_both_elements_and_their_required_alignment() {
    for (load, store, size) in [
        (0x887f_0820, 0x8823_0820, 8),
        (0xc87f_0820, 0xc823_0820, 16),
    ] {
        let mut f = Fixture::new(2);
        f.start(1, 0);
        f.instruction(0, load, 0, DATA);
        f.write(1, DATA + size / 2, 55);
        f.instruction(0, store, 99, DATA);
        assert_eq!(x(&f, 0, 3), 1);
        assert_eq!(f.read(1, DATA + size / 2), 55);
        let CpuState::Aarch64(mut state) = f.cpus[0].get_state().unwrap() else {
            panic!()
        };
        state.regs.pc = CODE;
        state.regs.x[1] = DATA + 4;
        f.cpus[0].update_state(&CpuState::Aarch64(state)).unwrap();
        f.mem
            .write_slice(&load.to_le_bytes(), GuestAddress(CODE))
            .unwrap();
        let result = f.cpus[0].run_retirement_budget(1).unwrap();
        assert_eq!(result.retired, 0, "size={size}: {result:?}");
        let CpuState::Aarch64(after) = f.cpus[0].get_state().unwrap() else {
            panic!()
        };
        assert_eq!(after.sregs.esr_el1 & 0x3f, 0x21, "alignment syndrome");
    }
}

#[test]
fn device_exclusives_fault_before_touching_backing_ram() {
    use rax::backend::emulator::aarch64::Aarch64Vcpu;
    use rax::vm::vcpu::VCpu;
    use std::sync::Arc;
    use vm_memory::GuestMemoryMmap;
    for address in [0x0800_0000, 0x080a_0000, 0x0900_0000] {
        for word in [LDXR, STXR] {
            let memory = Arc::new(
                GuestMemoryMmap::from_ranges(&[
                    (GuestAddress(0), 0x4000),
                    (GuestAddress(address), 0x1000),
                ])
                .unwrap(),
            );
            memory
                .write_slice(&word.to_le_bytes(), GuestAddress(CODE))
                .unwrap();
            memory
                .write_slice(&42u32.to_le_bytes(), GuestAddress(address))
                .unwrap();
            let mut cpu = Aarch64Vcpu::new(0, memory.clone());
            let CpuState::Aarch64(mut state) = cpu.get_state().unwrap() else {
                panic!()
            };
            state.regs.pc = CODE;
            state.regs.x[0] = 123;
            state.regs.x[1] = address;
            cpu.update_state(&CpuState::Aarch64(state)).unwrap();
            let result = cpu.run_retirement_budget(1).unwrap();
            assert_eq!(
                result.retired, 0,
                "address={address:#x}, word={word:#x}: {result:?}"
            );
            let mut bytes = [0; 4];
            memory
                .read_slice(&mut bytes, GuestAddress(address))
                .unwrap();
            assert_eq!(u32::from_le_bytes(bytes), 42);
            let CpuState::Aarch64(after) = cpu.get_state().unwrap() else {
                panic!()
            };
            assert_eq!(after.regs.pc, 0x200);
        }
    }
}

#[test]
fn pair_exclusives_preserve_element_order_in_both_endiannesses() {
    use rax::isa::arm::aarch64::{AArch64Config, AArch64Cpu};
    use rax::isa::arm::cpu_trait::ArmCpu;
    use rax::isa::arm::memory::{ArmMemory, StandardMemory};
    for big_endian in [false, true] {
        for wide in [false, true] {
            let mut memory = StandardMemory::with_ram(0, 0x4000);
            memory.set_big_endian(big_endian);
            let (load, store) = if wide {
                (0xc87f_0820u32, 0xc823_0820u32)
            } else {
                (0x887f_0820u32, 0x8823_0820u32)
            };
            memory.write(0, &load.to_le_bytes()).unwrap();
            memory.write(4, &store.to_le_bytes()).unwrap();
            let size = if wide { 8 } else { 4 };
            let bytes: Vec<u8> = (1..=size as u8 * 2).collect();
            memory.write(DATA, &bytes).unwrap();
            let mut cpu = AArch64Cpu::new(
                AArch64Config {
                    gic_config: None,
                    ..Default::default()
                },
                Box::new(memory),
            );
            cpu.set_x(1, DATA);
            cpu.step().unwrap();
            for (register, chunk) in [0, 2].into_iter().zip(bytes.chunks_exact(size)) {
                let mut element = [0; 8];
                let expected = if big_endian {
                    element[8 - size..].copy_from_slice(chunk);
                    u64::from_be_bytes(element)
                } else {
                    element[..size].copy_from_slice(chunk);
                    u64::from_le_bytes(element)
                };
                assert_eq!(
                    cpu.get_x(register),
                    expected,
                    "big_endian={big_endian}, wide={wide}"
                );
            }
            cpu.set_x(0, 0x1122_3344_5566_7788);
            cpu.set_x(2, 0x99aa_bbcc_ddee_ff00);
            cpu.step().unwrap();
            assert_eq!(cpu.get_x(3), 0);
            let actual = cpu.read_memory(DATA, size * 2).unwrap();
            let expected: Vec<u8> = [0x1122_3344_5566_7788u64, 0x99aa_bbcc_ddee_ff00u64]
                .into_iter()
                .flat_map(|v| {
                    if big_endian {
                        v.to_be_bytes()[8 - size..].to_vec()
                    } else {
                        v.to_le_bytes()[..size].to_vec()
                    }
                })
                .collect();
            assert_eq!(actual, expected);
        }
    }
}

#[test]
fn process_frame_writes_and_zeroed_reuse_invalidate_reservations() {
    use rax::backend::emulator::aarch64::Aarch64Vcpu;
    use rax::user::mm::FrameArena;
    use rax::vm::vcpu::VCpu;
    for reuse in [false, true] {
        let arena = FrameArena::new(0x4000, &[]).unwrap();
        let code = arena.alloc_zeroed().unwrap();
        let data = arena.alloc_zeroed().unwrap();
        arena.write(code, &LDXR.to_le_bytes());
        arena.write(code + 4, &STXR.to_le_bytes());
        let mut cpu = Aarch64Vcpu::new_micro(0, arena.memory().clone());
        let CpuState::Aarch64(mut state) = cpu.get_state().unwrap() else {
            panic!()
        };
        state.regs.pc = code;
        state.regs.x[1] = data;
        cpu.update_state(&CpuState::Aarch64(state)).unwrap();
        assert_eq!(cpu.run_retirement_budget(1).unwrap().retired, 1);
        if reuse {
            arena.free(data);
            assert_eq!(arena.alloc_zeroed().unwrap(), data);
        } else {
            arena.write(data, &[0]);
        }
        assert_eq!(cpu.run_retirement_budget(1).unwrap().retired, 1);
        let CpuState::Aarch64(state) = cpu.get_state().unwrap() else {
            panic!()
        };
        assert_eq!(state.regs.x[2], 1, "reuse={reuse}");
    }
}

#[test]
fn rejected_crossing_host_write_preserves_its_prefix_and_live_reservation() {
    let mut f = Fixture::new(1);
    let last = 0x3fff;
    f.instruction(0, 0x085f_7c20, 0, last); // LDXRB W0,[X1]
    assert!(rax::vm::memory::write_guest_memory(&f.mem, last, &[9, 8]).is_err());
    let mut byte = [0];
    f.mem.read_slice(&mut byte, GuestAddress(last)).unwrap();
    assert_eq!(byte, [0], "failed crossing store must not publish a prefix");
    f.instruction(0, 0x0802_7c20, 7, last); // STXRB W2,W0,[X1]
    assert_eq!(x(&f, 0, 2), 0, "preflight failure must retain the lease");
    f.mem.read_slice(&mut byte, GuestAddress(last)).unwrap();
    assert_eq!(byte, [7]);
}
