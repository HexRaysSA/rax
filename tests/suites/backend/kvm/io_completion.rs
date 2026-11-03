//! Actual managed-CPU continuation; no replacement owner/adapter type seam.
use super::{fixture, in_child, next_exit};
use rax::vm::memory::vm::{Bytes, GuestAddress};
use rax::vm::vcpu::{CpuState, VCpu, VcpuExit};
use std::time::Duration;

#[path = "io_vmm.rs"]
mod vmm;

const COUNT: usize = 256;
const DATA: u64 = 0x4000;

fn value(element: usize, lane: usize) -> u8 {
    element.wrapping_mul(17).wrapping_add(lane * 53 + 0x21) as u8
}

fn program(width: u8, input: bool) -> Vec<u8> {
    let mut code = Vec::new();
    if width == 4 {
        code.push(0x66);
    }
    code.push(0xf3);
    code.push(match (input, width) {
        (true, 1) => 0x6c,
        (true, _) => 0x6d,
        (false, 1) => 0x6e,
        (false, _) => 0x6f,
    });
    code.push(0xf4);
    code
}

fn registers(cpu: &dyn VCpu) -> rax::vm::vcpu::X86_64CpuState {
    let CpuState::X86_64(state) = cpu.get_state().unwrap() else {
        panic!()
    };
    state
}

fn prepare(cpu: &mut dyn VCpu, width: u8, reverse: bool, input: bool) {
    let mut state = registers(cpu);
    state.regs.rdx = if input { 0x70 } else { 0x71 };
    state.regs.rcx = COUNT as u64;
    state.regs.rflags = 2 | if reverse { 1 << 10 } else { 0 };
    let start = DATA
        + if reverse {
            (COUNT - 1) as u64 * u64::from(width)
        } else {
            0
        };
    if input {
        state.regs.rdi = start;
    } else {
        state.regs.rsi = start;
    }
    cpu.set_state(&CpuState::X86_64(state)).unwrap();
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn rep_inputs_preserve_width_count_and_direction_in_the_managed_cpu() {
    in_child(
        "io_completion::rep_inputs_preserve_width_count_and_direction_in_the_managed_cpu",
        || {
            for width in [1u8, 2, 4] {
                for reverse in [false, true] {
                    let (memory, mut cpu) = fixture(&program(width, true));
                    prepare(&mut *cpu, width, reverse, true);
                    let mut received = 0;
                    for _ in 0..COUNT + 2 {
                        let exit = next_exit(&mut *cpu);
                        let (size, count) = match exit {
                            VcpuExit::IoIn { port: 0x70, size } => (size, 1),
                            VcpuExit::IoInString {
                                port: 0x70,
                                size,
                                count,
                            } => (size, count as usize),
                            VcpuExit::Hlt => break,
                            other => panic!("unexpected REP input exit: {other:?}"),
                        };
                        assert_eq!(size, width);
                        assert!(count > 0 && received + count <= COUNT);
                        assert!(cpu.run_host_slice(Duration::from_millis(2)).is_err());
                        assert!(cpu.io_completion_result().is_err());
                        let reply = (received..received + count)
                            .flat_map(|element| {
                                (0..usize::from(width)).map(move |lane| value(element, lane))
                            })
                            .collect::<Vec<_>>();
                        cpu.complete_io_in(&reply);
                        cpu.io_completion_result().unwrap();
                        // A reply does not complete the kernel's hidden emulation.
                        let captured = cpu.get_state().unwrap();
                        assert!(cpu.set_state(&captured).is_err());
                        received += count;
                    }
                    assert_eq!(received, COUNT);
                    let state = registers(&*cpu);
                    assert_eq!(state.regs.rcx & 0xffff, 0);
                    let mut actual = vec![0; COUNT * usize::from(width)];
                    memory
                        .memory()
                        .read_slice(&mut actual, GuestAddress(DATA))
                        .unwrap();
                    for transfer in 0..COUNT {
                        let slot = if reverse {
                            COUNT - 1 - transfer
                        } else {
                            transfer
                        };
                        for lane in 0..usize::from(width) {
                            assert_eq!(
                                actual[slot * usize::from(width) + lane],
                                value(transfer, lane),
                                "width={width}, reverse={reverse}, transfer={transfer}, lane={lane}"
                            );
                        }
                    }
                }
            }
        },
    );
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn rep_outputs_reemit_one_fixed_port_element_until_acknowledged() {
    in_child(
        "io_completion::rep_outputs_reemit_one_fixed_port_element_until_acknowledged",
        || {
            for width in [1u8, 2, 4] {
                for reverse in [false, true] {
                    let (memory, mut cpu) = fixture(&program(width, false));
                    let mut data = vec![0; COUNT * usize::from(width)];
                    for transfer in 0..COUNT {
                        let slot = if reverse {
                            COUNT - 1 - transfer
                        } else {
                            transfer
                        };
                        for lane in 0..usize::from(width) {
                            data[slot * usize::from(width) + lane] = value(transfer, lane);
                        }
                    }
                    memory
                        .memory()
                        .write_slice(&data, GuestAddress(DATA))
                        .unwrap();
                    prepare(&mut *cpu, width, reverse, false);
                    for transfer in 0..COUNT {
                        let expected = (0..usize::from(width))
                            .map(|lane| value(transfer, lane))
                            .collect::<Vec<_>>();
                        for repeat in 0..2 {
                            let exit = next_exit(&mut *cpu);
                            assert!(
                                matches!(exit, VcpuExit::IoOut { port: 0x71, data } if data == expected),
                                "width={width}, reverse={reverse}, transfer={transfer}, repeat={repeat}"
                            );
                            let state = cpu.get_state().unwrap();
                            assert!(cpu.set_state(&state).is_err());
                            assert!(cpu.io_completion_result().is_err());
                        }
                        cpu.complete_io_out().unwrap();
                    }
                    cpu.io_completion_result().unwrap();
                    // Even the final output ACK still requires native completion.
                    let state = cpu.get_state().unwrap();
                    assert!(cpu.set_state(&state).is_err());
                    assert!(matches!(next_exit(&mut *cpu), VcpuExit::Hlt));
                    assert_eq!(registers(&*cpu).regs.rcx & 0xffff, 0);
                }
            }
        },
    );
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn malformed_input_replies_poison_without_a_native_reentry() {
    in_child(
        "io_completion::malformed_input_replies_poison_without_a_native_reentry",
        || {
            for reply in [&[][..], &[0x5a, 0xa5][..]] {
                let (_memory, mut cpu) = fixture(&[0xe4, 0x70, 0xf4]);
                assert!(matches!(
                    next_exit(&mut *cpu),
                    VcpuExit::IoIn {
                        port: 0x70,
                        size: 1
                    }
                ));
                let pc = cpu.current_pc();
                cpu.complete_io_in(reply);
                assert!(cpu.io_completion_result().is_err());
                assert!(cpu.run_host_slice(Duration::from_millis(2)).is_err());
                assert_eq!(cpu.current_pc(), pc);
                cpu.complete_io_in(&[0x5a]);
                assert!(cpu.io_completion_result().is_err());
            }
        },
    );
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn mmio_read_modify_write_retains_the_followon_output_until_acknowledgment() {
    in_child(
        "io_completion::mmio_read_modify_write_retains_the_followon_output_until_acknowledgment",
        || {
            let (_memory, mut cpu) = fixture(&[0x67, 0xfe, 0x05, 0x00, 0x00, 0xe0, 0xfe, 0xf4]);
            let mut state = registers(&*cpu);
            state.sregs.ds.limit = u32::MAX;
            state.sregs.ds.g = true;
            cpu.set_state(&CpuState::X86_64(state)).unwrap();
            assert!(matches!(
                next_exit(&mut *cpu),
                VcpuExit::MmioRead {
                    addr: 0xfee00000,
                    size: 1
                }
            ));
            cpu.complete_io_in(&[0x5a]);
            cpu.io_completion_result().unwrap();
            for _ in 0..2 {
                assert!(
                    matches!(next_exit(&mut *cpu), VcpuExit::MmioWrite { addr: 0xfee00000, data } if data == [0x5b])
                );
            }
            cpu.complete_io_out().unwrap();
            cpu.io_completion_result().unwrap();
            assert!(matches!(next_exit(&mut *cpu), VcpuExit::Hlt));
        },
    );
}

#[test]
#[ignore = "requires native Linux KVM; selected by KVM CI"]
fn duplicate_output_acknowledgment_is_terminal_before_the_following_instruction() {
    in_child(
        "io_completion::duplicate_output_acknowledgment_is_terminal_before_the_following_instruction",
        || {
            let (_memory, mut cpu) = fixture(&[0xe6, 0x71, 0xf4]);
            assert!(matches!(
                next_exit(&mut *cpu),
                VcpuExit::IoOut { port: 0x71, .. }
            ));
            let pc = cpu.current_pc();
            cpu.complete_io_out().unwrap();
            assert!(cpu.complete_io_out().is_err());
            assert!(cpu.run_host_slice(Duration::from_millis(2)).is_err());
            assert_eq!(cpu.current_pc(), pc);
        },
    );
}
