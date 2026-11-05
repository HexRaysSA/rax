//! Architectural PAT stays in the backend because the Intel SDK hides its slot.
use super::*;
use rax::vm::vcpu::{CpuState, VCpu, VcpuExit};
use std::time::Duration;

const RESET: u64 = 0x0007_0406_0007_0406;

fn msr(cpu: &mut dyn VCpu, write: Option<u64>, cr0: u64, selector: u64, flags: u64) {
    {
        let mut sdk = SDK.lock().unwrap();
        let native = sdk.cpus.get_mut(&0).unwrap();
        native.registers.insert(0, 0x1000);
        native.registers.insert(1, flags);
        native.registers.insert(3, 0x277);
        native.registers.insert(36, cr0);
        native
            .registers
            .insert(2, write.map_or(0x1234_5678, |value| value & 0xffff_ffff));
        native
            .registers
            .insert(4, write.map_or(0x8765_4321, |value| value >> 32));
        native.vmcs.insert(0x802, selector);
        native.vmcs.insert(0x440c, 2);
        native.vmcs.insert(0x4016, 0);
        // Stop at the next entry, retaining the exception-injection slot.
        // The model executes neither the instruction nor an exception handler.
        native.exits = [if write.is_some() { 32 } else { 31 }, 0x8000_0021]
            .into_iter()
            .collect();
    }
    assert!(matches!(
        cpu.run_host_slice(Duration::from_secs(1)).unwrap(),
        Some(VcpuExit::FailEntry {
            reason: 0x8000_0021
        })
    ));
}

#[test]
fn pat_guest_writes_reads_and_private_checkpoint_restoration_agree() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    assert_eq!(cpu.get_emulator_state().unwrap().pat, RESET);
    for pat in [0, 0x0101_0101_0101_0101, 0x0405_0607_0001_0406, RESET] {
        msr(cpu.as_mut(), Some(pat), 1, 0, 2);
        assert_eq!(cpu.get_emulator_state().unwrap().pat, pat);
        let boundary = vm.checkpoint_boundary().unwrap();
        let (public, context) = cpu.capture_checkpoint_record(&boundary, None).unwrap();
        assert_eq!(public.emulator.pat, pat);
        assert_eq!(&context.as_ref().unwrap().data[..8], b"RAXHVI03");
        drop(boundary);
        msr(cpu.as_mut(), Some(pat ^ 1), 1, 0, 2);
        cpu.restore_checkpoint_context(&public.state, &public.emulator, context.as_ref())
            .unwrap();
        msr(cpu.as_mut(), None, 1, 0, 2);
        let CpuState::X86_64(state) = cpu.get_state().unwrap() else {
            panic!("wrong architecture")
        };
        assert_eq!(state.regs.rax | (state.regs.rdx << 32), pat);
        assert_eq!(state.regs.rip, 0x1002);
        assert_eq!(SDK.lock().unwrap().cpus[&0].vmcs[&0x4016], 0);
    }
}

#[test]
fn invalid_pat_writes_fault_without_changing_pat_or_retiring_the_instruction() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    for entry in 0..8 {
        for invalid in [2u64, 3, 8, 0x80, 0xff] {
            msr(cpu.as_mut(), Some(invalid << (entry * 8)), 1, 0, 2);
            assert_eq!(cpu.get_emulator_state().unwrap().pat, RESET);
            let native = SDK.lock().unwrap();
            assert_eq!(native.cpus[&0].registers[&0], 0x1000);
            assert_eq!(native.cpus[&0].vmcs[&0x4016], 0x8000_0b0d);
            assert_eq!(native.cpus[&0].vmcs[&0x4018], 0);
        }
    }
}

#[test]
fn pat_privilege_faults_preserve_registers_and_real_mode_remains_admitted() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (vm, memory) = fixture();
    let mut cpu = vm
        .create_vcpu(0, Arc::new(memory.memory().clone()))
        .unwrap();
    for (cr0, selector, flags, permitted) in [
        (0, 3, 2, true),
        (1, 0, 2, true),
        (1, 1, 2, false),
        (1, 2, 2, false),
        (1, 3, 2, false),
        (1, 0, 0x2_0002, false),
    ] {
        for write in [None, Some(0x0101_0101_0101_0101)] {
            msr(cpu.as_mut(), write, cr0, selector, flags);
            let native = SDK.lock().unwrap();
            let native = &native.cpus[&0];
            assert_eq!(
                native.registers[&0],
                if permitted { 0x1002 } else { 0x1000 }
            );
            assert_eq!(
                native.vmcs[&0x4016],
                if permitted { 0 } else { 0x8000_0b0d }
            );
            if !permitted {
                assert_eq!(
                    native.registers[&2],
                    write.map_or(0x1234_5678, |value| value & 0xffff_ffff)
                );
                assert_eq!(
                    native.registers[&4],
                    write.map_or(0x8765_4321, |value| value >> 32)
                );
            }
        }
    }
}
