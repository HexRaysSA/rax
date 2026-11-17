use super::*;
use crate::isa::arm::common::cpu::ArmCpu;
use crate::user::cpu::Isa;
use crate::user::cpu::aarch64::{A64Exit, CpuWithSpace as A64UserCpu};
use crate::user::cpu::arm::{A32Exit, A32UserCpu};
use crate::user::cpu::riscv64::{CpuWithSpace as RvUserCpu, RvExit};
use crate::user::cpu::x86_64::{CpuWithSpace as X86UserCpu, X86Exit};
use crate::user::mm::anonymous_file;
use crate::user::mm::process_lease::ProcessLease;
use crate::user::mm::process_owner::broker::send;
use crate::user::mm::process_owner::wire::{Request, Response, ViewOperation, ViewValue};
use crate::user::mm::process_owner::{Channel, Client};
use std::os::fd::AsFd;

#[test]
fn fatal_latch_preserves_first_typed_error_after_drain() {
    for isa in [Isa::X86_64, Isa::Aarch64, Isa::Arm, Isa::Riscv64] {
        for during_callback in [false, true] {
            let (mut server, channel) = Channel::pair().unwrap();
            let file = anonymous_file().unwrap();
            file.set_len(2 * crate::user::mm::EXTENT).unwrap();
            let worker = std::thread::spawn(move || {
                let request = |server: &mut Channel| {
                    serde_json::from_slice::<Request>(&server.receive().unwrap().bytes).unwrap()
                };
                assert!(matches!(request(&mut server), Request::Begin { .. }));
                send(
                    &mut server,
                    &Response::Grant {
                        serial: 1,
                        space: 1,
                    },
                    &[],
                )
                .unwrap();
                assert!(matches!(
                    request(&mut server),
                    Request::View {
                        operation: ViewOperation::Arena,
                        ..
                    }
                ));
                send(
                    &mut server,
                    &Response::View {
                        result: Ok(ViewValue::Arena {
                            bytes: 2 * crate::user::mm::EXTENT,
                        }),
                    },
                    &[file.as_fd()],
                )
                .unwrap();
                loop {
                    match request(&mut server) {
                        Request::Memory {
                            operation: Operation::CodeChanges { .. },
                            ..
                        } => {
                            if !during_callback {
                                break;
                            }
                            send(
                                &mut server,
                                &Response::Result {
                                    result: Ok(Value::Code {
                                        epoch: 0,
                                        all: false,
                                        ranges: Vec::new(),
                                    }),
                                },
                                &[],
                            )
                            .unwrap();
                        }
                        Request::View {
                            operation: ViewOperation::Translate { .. },
                            ..
                        } if during_callback => break,
                        other => panic!("unexpected failure-control request: {other:?}"),
                    }
                }
                // Close before entry acknowledgement, or during the first
                // instruction fetch. Neither may become a guest fault exit.
            });
            let mut client = Client::new(channel);
            let lease = ProcessLease::new().unwrap();
            let result: Result<(), RemoteError> = client.with(&lease, |session| {
                let memory = session.cpu_memory()?;
                match isa {
                    Isa::X86_64 => {
                        let mut cpu = X86UserCpu::with_space(&memory);
                        cpu.vcpu_mut().user_regs_mut().rip = 0x1000;
                        assert!(matches!(cpu.step(), X86Exit::Internal(_)));
                        assert_eq!(cpu.pc(), 0x1000);
                    }
                    Isa::Aarch64 => {
                        let mut cpu = A64UserCpu::with_space(&memory);
                        cpu.core_mut().set_pc(0x1000);
                        assert!(matches!(cpu.run(1), A64Exit::Internal(_)));
                        assert_eq!(cpu.pc(), 0x1000);
                    }
                    Isa::Arm => {
                        let mut cpu = A32UserCpu::new(&memory);
                        cpu.set_pc(0x1000);
                        assert!(matches!(cpu.run(1), A32Exit::Internal(_)));
                        assert_eq!(cpu.pc(), 0x1000);
                    }
                    Isa::Riscv64 => {
                        let mut cpu = RvUserCpu::with_space(
                            &memory,
                            crate::isa::riscv::RiscVConfig::default(),
                        );
                        cpu.core_mut().set_pc(0x1000);
                        assert!(matches!(cpu.run(1), RvExit::Internal(_)));
                        assert_eq!(cpu.pc(), 0x1000);
                    }
                }
                let first = memory.fatal_error().unwrap();
                memory.fail(io::Error::other("secondary error").into());
                let original = memory.take_error().unwrap();
                assert!(matches!(original, RemoteError::Transport(_)));
                assert_eq!(memory.fatal_error().as_deref(), Some(first.as_str()));
                assert!(memory.take_error().is_none());
                assert!(memory.execution_epoch(1).is_err());
                Err(original)
            });
            assert!(matches!(result, Err(RemoteError::Transport(_))));
            worker.join().unwrap();
        }
    }
}

#[test]
fn owner_page_state_transport_failure_remains_fatal_after_typed_error_drain() {
    for malformed in [false, true] {
        let (mut server, channel) = Channel::pair().unwrap();
        let file = anonymous_file().unwrap();
        file.set_len(2 * crate::user::mm::EXTENT).unwrap();
        let worker = std::thread::spawn(move || {
            let request = |server: &mut Channel| {
                serde_json::from_slice::<Request>(&server.receive().unwrap().bytes).unwrap()
            };
            assert!(matches!(request(&mut server), Request::Begin { .. }));
            send(
                &mut server,
                &Response::Grant {
                    serial: 1,
                    space: 1,
                },
                &[],
            )
            .unwrap();
            assert!(matches!(
                request(&mut server),
                Request::View {
                    operation: ViewOperation::Arena,
                    ..
                }
            ));
            send(
                &mut server,
                &Response::View {
                    result: Ok(ViewValue::Arena {
                        bytes: 2 * crate::user::mm::EXTENT,
                    }),
                },
                &[file.as_fd()],
            )
            .unwrap();
            assert!(matches!(
                request(&mut server),
                Request::Memory {
                    operation: Operation::ResidentAccessible { address: 0x1000 },
                    ..
                }
            ));
            if malformed {
                send(
                    &mut server,
                    &Response::Result {
                        result: Ok(Value::Unit),
                    },
                    &[],
                )
                .unwrap();
                assert!(
                    server.receive().is_err(),
                    "invalid page-state reply must close the endpoint"
                );
            }
        });
        let mut client = Client::new(channel);
        let lease = ProcessLease::new().unwrap();
        let result: Result<(), RemoteError> = client.with(&lease, |session| {
            let memory = session.cpu_memory()?;
            let first = memory.query_resident_accessible(0x1000).unwrap_err();
            assert_eq!(memory.fatal_error().as_deref(), Some(first.as_str()));
            let original = memory.take_error().unwrap();
            assert!(matches!(original, RemoteError::Transport(_)));
            assert_eq!(memory.query_resident_accessible(0x1000), Err(first));
            assert!(memory.take_error().is_none());
            Err(original)
        });
        assert!(matches!(result, Err(RemoteError::Transport(_))));
        worker.join().unwrap();
    }
}
