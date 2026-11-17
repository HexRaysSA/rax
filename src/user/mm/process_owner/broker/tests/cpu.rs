use super::*;
use crate::isa::arm::common::cpu::ArmCpu;
use crate::user::cpu::CpuAddressSpace;
use crate::user::cpu::aarch64::{A64Exit, CpuWithSpace as A64UserCpu};
use crate::user::cpu::arm::{A32AddressSpace, A32Exit, A32UserCpu};
use crate::user::cpu::riscv64::{CpuWithSpace as RvUserCpu, RvExit};
use crate::user::cpu::x86_64::{CpuWithSpace as X86UserCpu, X86Exit};

fn words(code: &[u32]) -> Vec<u8> {
    code.iter().flat_map(|word| word.to_le_bytes()).collect()
}

#[test]
fn native_traced_cpu_drop_after_end_retains_final_authoritative_mappings() {
    const NAME: &str = "user::mm::process_owner::broker::tests::cpu::native_traced_cpu_drop_after_end_retains_final_authoritative_mappings";
    rpc_if_requested(NAME, |lease, stream| {
        use crate::observability::memtrace;
        struct TraceFile(std::path::PathBuf);
        impl Drop for TraceFile {
            fn drop(&mut self) {
                memtrace::stop();
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let trace = TraceFile(
            std::env::temp_dir().join(format!("rax-owner-trace-{}.raxtrace", std::process::id())),
        );
        drop(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&trace.0)
                .unwrap(),
        );
        memtrace::start(&trace.0).unwrap();
        let mut client = Client::new(Channel::new(stream).unwrap());
        let (memory, cpu) = client
            .with(lease, |session| {
                let mut mapping = match map(BASE, PAGE_SIZE, None, false) {
                    Operation::Map { mapping } => mapping,
                    _ => unreachable!(),
                };
                mapping.perms = RW.union(Perms::EXEC).bits();
                session.call(Operation::Map { mapping })?;
                let memory = session.cpu_memory()?;
                memory.write(BASE, &[0xb8, 42, 0, 0, 0]).unwrap();
                let mut cpu = X86UserCpu::with_space(&memory);
                cpu.vcpu_mut().user_regs_mut().rip = BASE;
                assert!(matches!(cpu.step(), X86Exit::Yield));
                Ok((memory, cpu))
            })
            .unwrap();
        client
            .with(lease, |session| {
                let mut mapping = match map(SHARED, PAGE_SIZE, None, false) {
                    Operation::Map { mapping } => mapping,
                    _ => unreachable!(),
                };
                mapping.name = Some("final-owner-map".into());
                session.call(Operation::Map { mapping })?;
                Ok(())
            })
            .unwrap();
        drop(cpu);
        assert!(
            memory.take_error().is_none(),
            "drop after End must not issue an inactive RPC"
        );
        memtrace::stop();
        let bytes = std::fs::read(&trace.0).unwrap();
        assert_eq!(&bytes[..8], memtrace::MAGIC);
        let mut cursor = memtrace::HEADER_LEN;
        let mut final_maps = Vec::new();
        while cursor < bytes.len() {
            let record = &bytes[cursor..cursor + memtrace::RECORD_LEN];
            let name_len = u16::from_le_bytes(record[2..4].try_into().unwrap()) as usize;
            cursor += memtrace::RECORD_LEN;
            if record[0] == memtrace::TAG_SNAPSHOT {
                final_maps.clear();
            }
            if record[0] == memtrace::TAG_MAP {
                let start = u64::from_le_bytes(record[4..12].try_into().unwrap());
                let end = u64::from_le_bytes(record[12..20].try_into().unwrap());
                final_maps.push((
                    start,
                    end,
                    record[1],
                    bytes[cursor..cursor + name_len].to_vec(),
                ));
            }
            cursor += name_len;
        }
        assert_eq!(cursor, bytes.len());
        assert!(
            final_maps.contains(&(
                SHARED,
                SHARED + PAGE_SIZE,
                RW.bits(),
                b"final-owner-map".to_vec(),
            )),
            "the final snapshot includes the mapping added after the CPU's last instruction"
        );
        client
            .with(lease, |_| {
                let mut code = [0; 5];
                memory.read(BASE, &mut code).unwrap();
                assert_eq!(code, [0xb8, 42, 0, 0, 0]);
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
fn native_owner_exclusives_preserve_same_worker_and_reject_host_writes_and_cpu_switches() {
    const NAME: &str = "user::mm::process_owner::broker::tests::cpu::native_owner_exclusives_preserve_same_worker_and_reject_host_writes_and_cpu_switches";
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        let (memory, mut cpu) = client
            .with(lease, |session| {
                let mut mapping = match map(BASE, 2 * PAGE_SIZE, None, false) {
                    Operation::Map { mapping } => mapping,
                    _ => unreachable!(),
                };
                mapping.perms = RW.union(Perms::EXEC).bits();
                session.call(Operation::Map { mapping })?;
                let memory = session.cpu_memory()?;
                memory
                    .write(BASE, &words(&[0xc85f_7c20, 0xc802_7c20]))
                    .unwrap();
                memory
                    .write(BASE + 0x100, &words(&[0xe191_0f9f, 0xe181_2f90]))
                    .unwrap();
                memory
                    .write(BASE + PAGE_SIZE, &42u64.to_le_bytes())
                    .unwrap();
                let mut cpu = A64UserCpu::with_space(&memory);
                cpu.core_mut().set_pc(BASE);
                cpu.core_mut().set_x(1, BASE + PAGE_SIZE);
                assert_eq!(cpu.run(1), A64Exit::Yield);
                Ok((memory, cpu))
            })
            .unwrap();
        client
            .with(lease, |_| {
                assert_eq!(cpu.run(1), A64Exit::Yield);
                assert_eq!(cpu.core().get_x(2), 0, "same-worker next turn retains LDXR");
                cpu.core_mut().set_pc(BASE);
                assert_eq!(cpu.run(1), A64Exit::Yield);
                memory
                    .write(BASE + PAGE_SIZE, &42u64.to_le_bytes())
                    .unwrap();
                assert_eq!(cpu.run(1), A64Exit::Yield);
                assert_eq!(
                    cpu.core().get_x(2),
                    1,
                    "same-value host write invalidates LDXR"
                );
                cpu.core_mut().set_pc(BASE);
                assert_eq!(cpu.run(1), A64Exit::Yield);
                let mut other = A64UserCpu::with_space(&memory);
                assert_eq!(other.run(0), A64Exit::Yield);
                assert_eq!(cpu.run(1), A64Exit::Yield);
                assert_eq!(
                    cpu.core().get_x(2),
                    1,
                    "another CPU consumer invalidates LDXR"
                );
                let mut arm = A32UserCpu::new(&memory);
                arm.set_pc(BASE + 0x100);
                arm.core_mut().regs[1] = (BASE + PAGE_SIZE) as u32;
                assert_eq!(arm.step_instruction(), None);
                memory
                    .write(BASE + PAGE_SIZE, &42u32.to_le_bytes())
                    .unwrap();
                assert_eq!(arm.step_instruction(), None);
                assert_eq!(
                    arm.core().regs[2],
                    1,
                    "same-value host write invalidates LDREX"
                );
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

#[test]
fn native_foreign_mm_shared_file_changes_invalidate_cached_code_and_exclusives() {
    const NAME: &str = "user::mm::process_owner::broker::tests::cpu::native_foreign_mm_shared_file_changes_invalidate_cached_code_and_exclusives";
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        let phase = std::env::var("RAX_MM_OWNER_RPC_PHASE").unwrap();
        if !phase.starts_with("root-") {
            client
                .with(lease, |session| {
                    let memory = session.cpu_memory()?;
                    memory.write(SHARED, &[0xb8, 43, 0, 0, 0]).unwrap();
                    memory.write(SHARED + 0x80, &42u64.to_le_bytes()).unwrap();
                    Ok(())
                })
                .unwrap();
            return;
        }
        let a64 = phase == "root-a64";
        let (memory, mut arm, mut x86, child, epoch) = client
            .with(lease, |session| {
                let mut mapping = match map(SHARED, PAGE_SIZE, Some(BackingId(1)), true) {
                    Operation::Map { mapping } => mapping,
                    _ => unreachable!(),
                };
                mapping.perms = RW.union(Perms::EXEC).bits();
                session.call(Operation::Map { mapping })?;
                let mut mapping = match map(BASE, PAGE_SIZE, None, false) {
                    Operation::Map { mapping } => mapping,
                    _ => unreachable!(),
                };
                mapping.perms = RW.union(Perms::EXEC).bits();
                session.call(Operation::Map { mapping })?;
                let memory = session.cpu_memory()?;
                memory.write(SHARED, &[0xb8, 42, 0, 0, 0]).unwrap();
                memory.write(SHARED + 0x80, &42u64.to_le_bytes()).unwrap();
                memory
                    .write(BASE, &words(&[0xc85f_7c20, 0xc802_7c20]))
                    .unwrap();
                let mut arm = A64UserCpu::with_space(&memory);
                let mut x86 = X86UserCpu::with_space(&memory);
                if a64 {
                    arm.core_mut().set_pc(BASE);
                    arm.core_mut().set_x(1, SHARED + 0x80);
                    assert_eq!(arm.run(1), A64Exit::Yield);
                } else {
                    x86.vcpu_mut().user_regs_mut().rip = SHARED;
                    assert!(matches!(x86.step(), X86Exit::Yield));
                    assert_eq!(x86.vcpu().user_regs().rax, 42);
                }
                let child = session.fork(true)?;
                let Value::Code { epoch, .. } =
                    session.call(Operation::CodeChanges { epoch: 0 })?
                else {
                    unreachable!()
                };
                Ok((memory, arm, x86, child, epoch))
            })
            .unwrap();
        spawn(child, lease, NAME, if a64 { "a64" } else { "x86" }).wait();
        client.with(lease, |session| {
            assert!(matches!(session.call(Operation::CodeChanges { epoch })?,
                Value::Code { epoch: now, all: false, ranges } if now == epoch && ranges.is_empty()),
                "a write in the foreign MM does not update the parent's code log");
            if a64 {
                assert_eq!(arm.run(1), A64Exit::Yield);
                assert_eq!(arm.core().get_x(2), 1,
                    "a same-value store by a foreign worker invalidates the reservation");
            } else {
                x86.vcpu_mut().user_regs_mut().rip = SHARED;
                assert!(matches!(x86.step(), X86Exit::Yield));
                assert_eq!(x86.vcpu().user_regs().rax, 43,
                    "cached decode cannot survive a foreign MM's shared-file write");
            }
            assert!(memory.take_error().is_none());
            Ok(())
        }).unwrap();
    });
    for phase in ["root-a64", "root-x86"] {
        let lease = Arc::new(ProcessLease::new().unwrap());
        let (mut broker, client, worker_id) = Broker::new(
            lease.clone(),
            &space(),
            Metadata {
                fail_private: false,
            },
        )
        .unwrap();
        broker
            .register_backing(
                worker_id,
                Backing::Shared {
                    object: Arc::new(SharedObject::anonymous(EXTENT).unwrap()),
                    offset: 0,
                },
            )
            .unwrap();
        let mut worker = spawn(client, &lease, NAME, phase);
        assert_eq!(drive(&mut broker, &mut worker), 0);
    }
}

#[test]
fn native_owner_storage_executes_all_user_isas_and_rejects_inactive_entry() {
    const NAME: &str = "user::mm::process_owner::broker::tests::cpu::native_owner_storage_executes_all_user_isas_and_rejects_inactive_entry";
    rpc_if_requested(NAME, |lease, stream| {
        let mut client = Client::new(Channel::new(stream).unwrap());
        let (memory, mut x86, mut a64, mut a32, mut rv) = client
            .with(lease, |session| {
                let mut mapping = match map(BASE, 4 * PAGE_SIZE, None, false) {
                    Operation::Map { mapping } => mapping,
                    _ => unreachable!(),
                };
                mapping.perms = RW.union(Perms::EXEC).bits();
                session.call(Operation::Map { mapping })?;
                let memory = session.cpu_memory()?;
                let again = session.cpu_memory()?;
                assert!(Arc::ptr_eq(
                    memory.physical_memory(),
                    again.physical_memory()
                ));
                memory
                    .write(BASE, &[0xb8, 42, 0, 0, 0, 0x0f, 0x05])
                    .unwrap();
                memory
                    .write(
                        BASE + PAGE_SIZE,
                        &[
                            0x40, 0x05, 0x80, 0xd2, // MOV X0, #42
                            0x01, 0x00, 0x00, 0xd4, // SVC #0
                        ],
                    )
                    .unwrap();
                memory
                    .write(
                        BASE + 2 * PAGE_SIZE,
                        &[
                            0x2a, 0x00, 0xa0, 0xe3, // MOV R0, #42
                            0x00, 0x00, 0x00, 0xef, // SVC #0
                        ],
                    )
                    .unwrap();
                memory
                    .write(
                        BASE + 3 * PAGE_SIZE,
                        &[
                            0x13, 0x05, 0xa0, 0x02, // ADDI a0, zero, 42
                            0x73, 0x00, 0x00, 0x00, // ECALL
                        ],
                    )
                    .unwrap();
                let mut x86 = X86UserCpu::with_space(&memory);
                x86.vcpu_mut().user_regs_mut().rip = BASE;
                assert!(matches!(x86.step(), X86Exit::Yield));
                assert_eq!(x86.vcpu().user_regs().rax, 42);
                assert!(matches!(x86.step(), X86Exit::Syscall { .. }));
                let mut a64 = A64UserCpu::with_space(&memory);
                a64.core_mut().set_pc(BASE + PAGE_SIZE);
                assert!(matches!(a64.run(2), A64Exit::Svc { .. }));
                assert_eq!(a64.core().get_x(0), 42);
                let mut a32 = A32UserCpu::new(&memory);
                a32.set_pc(BASE + 2 * PAGE_SIZE);
                assert!(matches!(a32.run(2), A32Exit::Svc { .. }));
                assert_eq!(a32.core().regs[0], 42);
                let mut rv =
                    RvUserCpu::with_space(&memory, crate::isa::riscv::RiscVConfig::default());
                rv.core_mut().set_pc(BASE + 3 * PAGE_SIZE);
                assert!(matches!(rv.run(2), RvExit::Ecall { .. }));
                assert_eq!(rv.core().x(10), 42);
                let mut mapping = match map(BASE + 8 * PAGE_SIZE, PAGE_SIZE, None, false) {
                    Operation::Map { mapping } => mapping,
                    _ => unreachable!(),
                };
                let long_name = "trace\n\"é".repeat(12_000);
                mapping.name = Some(long_name.clone());
                session.call(Operation::Map { mapping })?;
                let maps = memory.trace_mappings();
                assert!(
                    maps.iter()
                        .any(|(start, _, _, name)| *start == BASE + 8 * PAGE_SIZE
                            && name.as_deref() == Some(long_name.as_str()))
                );
                assert!(memory.take_error().is_none());
                Ok((memory, x86, a64, a32, rv))
            })
            .unwrap();
        assert!(matches!(x86.step(), X86Exit::Internal(_)));
        assert!(matches!(a64.run(0), A64Exit::Internal(_)));
        assert!(matches!(a32.run(0), A32Exit::Internal(_)));
        assert!(matches!(rv.run(0), RvExit::Internal(_)));
        assert!(
            memory.take_error().is_none(),
            "rejected admission is not a transport exchange"
        );
        client
            .with(lease, |session| {
                let again = session.cpu_memory()?;
                assert!(Arc::ptr_eq(
                    memory.physical_memory(),
                    again.physical_memory()
                ));
                x86.vcpu_mut().user_regs_mut().rip = BASE;
                assert!(matches!(x86.step(), X86Exit::Yield));
                let foreign = memory.clone();
                std::thread::spawn(move || {
                    let mut cpu = A64UserCpu::with_space(&foreign);
                    assert!(matches!(cpu.run(0), A64Exit::Internal(_)));
                })
                .join()
                .unwrap();
                session.call(Operation::Protect {
                    start: BASE + PAGE_SIZE,
                    len: PAGE_SIZE,
                    perms: Perms::READ.bits(),
                })?;
                a64.core_mut().set_pc(BASE + PAGE_SIZE);
                assert!(matches!(a64.run(1), A64Exit::Fault(fault)
                if fault.kind == crate::user::cpu::AccessFaultKind::Permission));
                assert!(
                    memory.take_error().is_none(),
                    "guest faults do not poison the callback"
                );
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
