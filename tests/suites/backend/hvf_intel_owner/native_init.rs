//! INIT must reach the same permanent SDK owner used for execution.
use super::*;
use rax::vm::vcpu::{CpuState, VCpu, VcpuExit};

fn seed(id: u32, cache: u64) {
    let mut sdk = SDK.lock().unwrap();
    let cpu = sdk.cpus.get_mut(&id).unwrap();
    for register in (0..18).chain([38, 41, 42, 43, 44, 47]) {
        cpu.registers
            .insert(register, 0x1234_0000 + u64::from(register));
    }
    cpu.registers.insert(1, 0x246); // RFLAGS.
    cpu.registers.insert(50, 7); // XCR0 is retained across INIT.
    cpu.vmcs.insert(0x6800, cache | 0x8005_003f);
    cpu.vmcs.insert(0x6004, cache | 0x8005_003f);
    cpu.vmcs.insert(0x6802, 0x1000);
    cpu.vmcs.insert(0x6804, 0x40220);
    cpu.vmcs.insert(0x6006, 0x40220);
    cpu.vmcs.insert(0x2806, 0x500); // EFER.
    cpu.vmcs.insert(0x4824, 3); // STI and MOV SS shadows.
    cpu.vmcs.insert(0x4016, 0x8000_0051); // An accepted interrupt.
    cpu.vmcs.insert(0x6822, 1 << 14); // Pending single-step exception.
    cpu.vmcs.insert(0x482a, 0x10); // SYSENTER remains intact.
    cpu.vmcs.insert(0x6824, 0x8000);
    cpu.vmcs.insert(0x6826, 0x9000);
    for selector in [0xc000_0081, 0xc000_0082, 0xc000_0083, 0xc000_0084] {
        cpu.msrs.insert(selector, u64::from(selector));
    }
    cpu.fpstate[24..28].copy_from_slice(&0x3f80u32.to_le_bytes());
    cpu.fpstate[160..416].fill(0xa5);
    cpu.fpstate[576..832].fill(0x5a);
    cpu.fpstate[512..520].copy_from_slice(&7u64.to_le_bytes());
}

fn record(vm: &dyn rax::backend::Vm, cpu: &dyn VCpu) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let boundary = vm.checkpoint_boundary().unwrap();
    let (public, private) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
    (
        rax::codec::serialize(&public.state).unwrap(),
        rax::codec::serialize(&public.emulator).unwrap(),
        private.unwrap().data,
    )
}

#[test]
fn init_reaches_the_permanent_owner() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    cpu.deliver_init().unwrap();
    assert_eq!(SDK.lock().unwrap().wrong_owner, 0);
}

#[test]
fn init_resets_each_cpu_without_resetting_fp_msr_clock_or_debug_ownership() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for count in [1, 2, 4] {
        for cache in [0, 0x4000_0000, 0x6000_0000] {
            let (vm, memory) = fixture();
            let mut cpus = (0..count)
                .map(|id| {
                    vm.create_vcpu(id, Arc::new(memory.memory().clone()))
                        .unwrap()
                })
                .collect::<Vec<_>>();
            for id in 0..count {
                seed(id, cache);
            }
            for (id, cpu) in cpus.iter_mut().enumerate() {
                #[cfg(feature = "debug")]
                cpu.set_single_step(true);
                let (fp, msrs, offset) = {
                    let sdk = SDK.lock().unwrap();
                    let native = &sdk.cpus[&(id as u32)];
                    (
                        native.fpstate.clone(),
                        native.msrs.clone(),
                        native.tsc_offset,
                    )
                };
                let before = cpu.get_state().unwrap();
                cpu.deliver_init().unwrap();
                let CpuState::X86_64(state) = cpu.get_state().unwrap() else {
                    panic!("wrong architecture");
                };
                let CpuState::X86_64(before) = before else {
                    panic!("wrong architecture");
                };
                assert_eq!(state.regs.rip, 0xfff0);
                assert_eq!(state.regs.rflags, 2);
                assert_eq!(state.regs.rax, 0);
                assert_eq!(state.regs.r15, 0);
                assert_eq!(
                    state.regs.rdx,
                    u64::from(
                        rax::backend::hvf::rosetta::CpuidConfig::default()
                            .cpuid(1, 0)
                            .0
                    )
                );
                assert_eq!(state.sregs.cr0, cache | 0x10);
                assert_eq!(
                    (
                        state.sregs.cr2,
                        state.sregs.cr3,
                        state.sregs.cr4,
                        state.sregs.cr8,
                        state.sregs.efer
                    ),
                    (0, 0, 0, 0, 0)
                );
                assert_eq!(
                    (
                        state.sregs.cs.selector,
                        state.sregs.cs.base,
                        state.sregs.cs.limit
                    ),
                    (0xf000, 0xffff_0000, 0xffff)
                );
                assert_eq!((state.sregs.tr.type_, state.sregs.ldt.type_), (11, 2));
                assert_eq!(
                    (
                        state.sregs.dr0,
                        state.sregs.dr3,
                        state.sregs.dr6,
                        state.sregs.dr7
                    ),
                    (0, 0, 0xffff_0ff0, 0x400)
                );
                assert_eq!(
                    (
                        state.sregs.star,
                        state.sregs.lstar,
                        state.sregs.cstar,
                        state.sregs.fmask
                    ),
                    (
                        before.sregs.star,
                        before.sregs.lstar,
                        before.sregs.cstar,
                        before.sregs.fmask
                    )
                );
                assert_eq!(
                    (
                        state.sregs.sysenter_cs,
                        state.sregs.sysenter_esp,
                        state.sregs.sysenter_eip
                    ),
                    (0x10, 0x8000, 0x9000)
                );
                #[cfg(feature = "debug")]
                assert!(
                    cpu.is_single_step(),
                    "INIT discarded the host debugger control"
                );
                let sdk = SDK.lock().unwrap();
                let native = &sdk.cpus[&(id as u32)];
                assert_eq!(native.fpstate, fp);
                assert_eq!(native.msrs, msrs);
                assert_eq!(native.tsc_offset, offset);
                assert_eq!(native.registers[&50], 7);
                assert_eq!(native.vmcs[&0x4016], 0);
                assert_eq!(native.vmcs[&0x4824], 0);
                assert_eq!(native.vmcs[&0x6822], 0);
                assert_eq!(native.vmcs[&0x4826], 0);
                assert!(native.deadlines.is_empty() && native.raw_entries == 0);
                assert_eq!(sdk.wrong_owner, 0);
            }
        }
    }
}

#[test]
fn init_discards_the_old_unretired_input_before_the_next_guest_entry() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    {
        let mut sdk = SDK.lock().unwrap();
        let native = sdk.cpus.get_mut(&0).unwrap();
        native.vmcs.insert(0x6400, (0x3f8 << 16) | 8);
        native.vmcs.insert(0x440c, 3);
        native.exits.push_back(30);
    }
    assert!(matches!(cpu.run().unwrap(), VcpuExit::IoIn { .. }));
    cpu.deliver_init().unwrap();
    assert_eq!(SDK.lock().unwrap().cpus[&0].deadlines.len(), 1);
    {
        let mut sdk = SDK.lock().unwrap();
        let native = sdk.cpus.get_mut(&0).unwrap();
        native.vmcs.insert(0x440c, 1);
        native.exits.push_back(12); // Fresh HLT, rather than the old input.
    }
    assert!(matches!(cpu.run().unwrap(), VcpuExit::Hlt));
    let CpuState::X86_64(state) = cpu.get_state().unwrap() else {
        panic!("wrong architecture");
    };
    assert_eq!(state.regs.rip, 0xfff1);
    assert_eq!(SDK.lock().unwrap().cpus[&0].deadlines.len(), 2);
}

#[test]
fn failed_init_restores_the_complete_preceding_record_or_fences_the_vm() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for (operation, remaining) in [
        ("write-register", 1),
        ("write-register", 12),
        ("write-vmcs", 1),
        ("write-vmcs", 20),
        ("invalidate", 1),
    ] {
        for persistent in [false, true] {
            let (vm, memory) = fixture();
            let mut cpu = vm
                .create_vcpu(0, Arc::new(memory.memory().clone()))
                .unwrap();
            seed(0, 0x4000_0000);
            let before = record(vm.as_ref(), cpu.as_ref());
            SDK.lock().unwrap().fault = Some(Fault {
                operation,
                remaining,
                persistent,
            });
            assert!(
                cpu.deliver_init().is_err(),
                "fault was not reached: {operation}/{remaining}"
            );
            if persistent {
                assert!(cpu.run().is_err());
                assert!(cpu.get_state().is_err());
            } else {
                assert_eq!(
                    record(vm.as_ref(), cpu.as_ref()),
                    before,
                    "rollback differs: {operation}/{remaining}"
                );
            }
            let sdk = SDK.lock().unwrap();
            assert_eq!(sdk.wrong_owner, 0);
            assert_eq!(sdk.cpus[&0].raw_entries, 0);
            assert!(sdk.cpus[&0].deadlines.is_empty());
        }
    }
}
