//! Linux ABI dispatch over real owner-managed storage and native worker IPC.

use super::*;
use crate::user::cpu::arm::A32AddressSpace;
use crate::user::linux::abi::LinuxAbi;
use crate::user::linux::arch::{CpuEvent, CpuOptions, CpuWithSpace, GuestCpu, LinuxAddressSpace};
use crate::user::linux::signal::frame::FaultUpdate;
use crate::user::linux::signal::{SIGSEGV, code};
use crate::user::mm::process_owner::OwnerMemory;

fn syscall(cpu: &mut CpuWithSpace<OwnerMemory>) -> CpuEvent {
    for _ in 0..16 {
        let event = cpu.step();
        if event != CpuEvent::Yield {
            return event;
        }
    }
    panic!("short syscall sequence did not reach its trap");
}

#[test]
fn native_linux_abi_dispatch_uses_owner_turn_for_all_guest_abis() {
    const NAME: &str = "user::mm::process_owner::broker::tests::linux::native_linux_abi_dispatch_uses_owner_turn_for_all_guest_abis";
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        let (memory, mut cpus) = client
            .with(lease, |session| {
                let mut mapping = match map(BASE, 5 * PAGE_SIZE, None, false) {
                    Operation::Map { mapping } => mapping,
                    _ => unreachable!(),
                };
                mapping.perms = RW.union(Perms::EXEC).bits();
                session.call(Operation::Map { mapping })?;
                let memory = session.cpu_memory()?;
                let cases: [(LinuxAbi, &[u8], u64); 5] = [
                    (
                        LinuxAbi::X86_64,
                        &[0xb8, 60, 0, 0, 0, 0xbf, 42, 0, 0, 0, 0x0f, 0x05],
                        60,
                    ),
                    (
                        LinuxAbi::I386,
                        &[0xb8, 1, 0, 0, 0, 0xbb, 42, 0, 0, 0, 0xcd, 0x80],
                        1,
                    ),
                    // MOV X0,#42; MOV X8,#93; SVC #0.
                    (
                        LinuxAbi::Aarch64,
                        &[
                            0x40, 0x05, 0x80, 0xd2, 0xa8, 0x0b, 0x80, 0xd2, 1, 0, 0, 0xd4,
                        ],
                        93,
                    ),
                    // MOV R0,#42; MOV R7,#1; SVC #0.
                    (
                        LinuxAbi::Arm,
                        &[42, 0, 0xa0, 0xe3, 1, 0x70, 0xa0, 0xe3, 0, 0, 0, 0xef],
                        1,
                    ),
                    // ADDI a0,zero,42; ADDI a7,zero,93; ECALL.
                    (
                        LinuxAbi::Riscv64,
                        &[0x13, 5, 0xa0, 2, 0x93, 8, 0xd0, 5, 0x73, 0, 0, 0],
                        93,
                    ),
                ];
                let mut cpus = Vec::new();
                for (index, (abi, bytes, nr)) in cases.into_iter().enumerate() {
                    let entry = BASE + index as u64 * PAGE_SIZE;
                    memory.write(entry, bytes).unwrap();
                    let mut cpu = CpuWithSpace::with_space(abi, &memory, &CpuOptions::default());
                    cpu.start(entry, BASE + 5 * PAGE_SIZE);
                    cpu.set_thread_pointer(BASE + 0x123);
                    assert_eq!(cpu.abi(), abi);
                    assert_eq!(cpu.thread_pointer(), BASE + 0x123);
                    assert_eq!(cpu.sp(), BASE + 5 * PAGE_SIZE);
                    assert_eq!(
                        syscall(&mut cpu),
                        CpuEvent::Syscall {
                            nr,
                            args: [42, 0, 0, 0, 0, 0]
                        }
                    );
                    assert_eq!(cpu.pc(), entry + bytes.len() as u64);
                    cpu.set_syscall_result(37);
                    let clone = cpu.clone_thread();
                    assert_eq!(clone.abi(), abi);
                    assert_eq!(clone.syscall_return_value(), 37);
                    assert_eq!(clone.thread_pointer(), cpu.thread_pointer());
                    assert_eq!(clone.caps(), cpu.caps());
                    let local = space();
                    let detached: GuestCpu = cpu.clone_to_space(&local);
                    assert!(detached.space().same_space(&local));
                    assert_eq!(detached.pc(), cpu.pc());
                    assert_eq!(detached.syscall_return_value(), 37);
                    cpus.push(cpu);
                }
                assert!(memory.take_error().is_none());
                Ok((memory, cpus))
            })
            .unwrap();
        for cpu in &mut cpus {
            assert!(
                matches!(cpu.run(0), CpuEvent::Internal(_)),
                "all Linux ABI entry paths require an active turn"
            );
        }
        assert!(memory.take_error().is_none());
        client
            .with(lease, |_| {
                for (index, cpu) in cpus.iter_mut().enumerate() {
                    cpu.set_pc(BASE + index as u64 * PAGE_SIZE);
                    assert!(matches!(
                        syscall(cpu),
                        CpuEvent::Syscall {
                            args: [42, 0, 0, 0, 0, 0],
                            ..
                        }
                    ));
                }
                Ok(())
            })
            .unwrap();
    });
    let lease = Arc::new(ProcessLease::new().unwrap());
    let (mut broker, client, _) = Broker::new(
        lease.clone(),
        &space(),
        Metadata {
            fail_private: false,
        },
    )
    .unwrap();
    let mut worker = spawn(client, &lease, NAME, "root");
    assert_eq!(drive(&mut broker, &mut worker), 0);
}

#[test]
fn native_linux_x86_fault_frames_query_owner_residency_without_populating() {
    const NAME: &str = "user::mm::process_owner::broker::tests::linux::native_linux_x86_fault_frames_query_owner_residency_without_populating";
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        client
            .with(lease, |session| {
                let mut mapping = match map(BASE, PAGE_SIZE, None, false) {
                    Operation::Map { mapping } => mapping,
                    _ => unreachable!(),
                };
                mapping.perms = RW.union(Perms::EXEC).bits();
                session.call(Operation::Map { mapping })?;
                let mut mapping = match map(SOURCE, 3 * PAGE_SIZE, None, false) {
                    Operation::Map { mapping } => mapping,
                    _ => unreachable!(),
                };
                mapping.perms = Perms::READ.bits();
                session.call(Operation::Map { mapping })?;
                let memory = session.cpu_memory()?;
                for _ in 0..2 {
                    assert!(
                        !memory.resident_accessible(SOURCE).unwrap(),
                        "query must not fault in an untouched page"
                    );
                }
                let mut byte = [0];
                memory.read(SOURCE + PAGE_SIZE, &mut byte).unwrap();
                memory.read(SOURCE + 2 * PAGE_SIZE, &mut byte).unwrap();
                assert!(memory.resident_accessible(SOURCE + PAGE_SIZE).unwrap());
                session.call(Operation::Protect {
                    start: SOURCE + 2 * PAGE_SIZE,
                    len: PAGE_SIZE,
                    perms: 0,
                })?;
                assert!(!memory.resident_accessible(SOURCE + 2 * PAGE_SIZE).unwrap());
                let mut cpu =
                    CpuWithSpace::with_space(LinuxAbi::X86_64, &memory, &CpuOptions::default());
                for (address, expected, signal_code) in [
                    (SOURCE, 6, code::SEGV_ACCERR),
                    (SOURCE + PAGE_SIZE, 7, code::SEGV_ACCERR),
                    (SOURCE + 2 * PAGE_SIZE, 6, code::SEGV_ACCERR),
                    (SOURCE + 3 * PAGE_SIZE, 6, code::SEGV_MAPERR),
                ] {
                    let mut code = vec![0x48, 0xb8]; // MOV RAX,address.
                    code.extend(address.to_le_bytes());
                    code.extend([0xc6, 0, 42]); // MOV BYTE PTR [RAX],42.
                    memory.write(BASE, &code).unwrap();
                    cpu.start(BASE, BASE + PAGE_SIZE);
                    assert_eq!(cpu.step(), CpuEvent::Yield);
                    match cpu.step() {
                        CpuEvent::Signal(
                            info,
                            FaultUpdate::X86 {
                                trap_nr,
                                error_code,
                                cr2,
                            },
                        ) => {
                            assert_eq!(info.signo, SIGSEGV);
                            assert_eq!(info.code, signal_code);
                            assert_eq!((trap_nr, error_code, cr2), (14, expected, Some(address)));
                        }
                        other => panic!("unexpected fault exit: {other:?}"),
                    }
                }
                assert!(memory.take_error().is_none());
                Ok(())
            })
            .unwrap();
    });
    let lease = Arc::new(ProcessLease::new().unwrap());
    let (mut broker, client, _) = Broker::new(
        lease.clone(),
        &space(),
        Metadata {
            fail_private: false,
        },
    )
    .unwrap();
    let mut worker = spawn(client, &lease, NAME, "root");
    assert_eq!(drive(&mut broker, &mut worker), 0);
}
