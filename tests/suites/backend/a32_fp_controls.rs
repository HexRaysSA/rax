//! Arm ASL CheckAdvSIMDOrFPEnabled / CheckFPAdvSIMDTrap control boundaries.
use rax::isa::arm::aarch32::cp15::Cpacr;
use rax::isa::arm::aarch32::cpu::ProcessorMode;
use rax::isa::arm::aarch64::{AArch64Config, AArch64Cpu};
use rax::isa::arm::common::cpu::{ArmCpu, ArmError, CpuExit};
use rax::isa::arm::common::memory::FlatMemory as Memory64;
use rax::isa::arm::common::sysreg::Aarch64SysRegEncoding;
use rax::isa::arm::decoder::Aarch32Decoder;
use rax::isa::arm::execution::FlatMemory as Memory32;
use rax::isa::arm::{Armv7Cpu, ExecResult, Executor};

const VADD: u32 = 0xee31_0a02; // VADD.F32 S0,S2,S4.
const NEON_ADD: u32 = 0xf202_0844; // VADD.I8 Q0,Q1,Q2.

fn hyp() -> Armv7Cpu {
    let mut cpu = Armv7Cpu::new();
    cpu.cpsr.mode = ProcessorMode::Hyp as u8;
    cpu.cp15.scr = 1;
    cpu.cp15.nsacr = 1 << 10;
    cpu.vfp.dregs.fill(0x3f80_0000_3f80_0000);
    cpu
}

fn execute(cpu: &mut Armv7Cpu, raw: u32) -> ExecResult {
    let mut memory = Memory32::new(4096, 0);
    Executor::new(cpu, &mut memory).execute(&Aarch32Decoder::decode(raw).unwrap())
}

#[test]
fn hyp_bypasses_cpacr_permissions_and_asedis() {
    for raw in [VADD, NEON_ADD] {
        let mut cpu = hyp();
        cpu.cp15.cpacr = Cpacr::from_bits(1 << 31);
        let before = cpu.vfp.dregs;
        let result = execute(&mut cpu, raw);
        assert!(
            matches!(result, ExecResult::Continue),
            "{raw:#x}: {result:?}"
        );
        assert_ne!(cpu.vfp.dregs, before);
    }
}

#[test]
fn hyp_nsacr_clamps_fp_and_advsimd_access() {
    for (raw, nsacr) in [(VADD, 0), (NEON_ADD, (1 << 10) | (1 << 15))] {
        let mut cpu = hyp();
        cpu.cp15.nsacr = nsacr;
        let before = cpu.vfp.dregs;
        let result = execute(&mut cpu, raw);
        assert!(
            matches!(
                result,
                ExecResult::FpAccessTrap {
                    target_el: 2,
                    undefined: true,
                    ..
                }
            ),
            "{raw:#x}: {result:?}"
        );
        assert_eq!(cpu.vfp.dregs, before);
    }
}

#[test]
fn hyp_hcptr_written_by_the_guest_controls_fp_admission() {
    let mut cpu = hyp();
    cpu.regs[0] = 1 << 10;
    // MCR p15,4,R0,c1,c1,2: HCPTR.TCP10.
    assert!(matches!(
        execute(&mut cpu, 0xee81_0f51),
        ExecResult::Continue
    ));
    let before = cpu.vfp.dregs;
    let result = execute(&mut cpu, VADD);
    assert!(
        matches!(
            result,
            ExecResult::FpAccessTrap {
                target_el: 2,
                undefined: true,
                ..
            }
        ),
        "{result:?}"
    );
    assert_eq!(cpu.vfp.dregs, before);
}

fn mixed(raw: u32, thumb: bool, target: u8, secure: bool, fpexc: bool) -> AArch64Cpu {
    let mut cpu = AArch64Cpu::new(
        AArch64Config {
            initial_el: 3,
            gic_config: None,
            ..AArch64Config::default()
        },
        Box::new(Memory64::new(0, 0x4000)),
    );
    let mut state = cpu.export_sregs();
    let system = &mut state.execution.as_mut().unwrap().sysregs;
    system.scr_el3 = if secure { 0 } else { 1 | (1 << 10) }; // Secure EL1 A32 follows SCR.RW=0; NS EL2 uses A64.
    system.hcr_el2 = 0; // EL1 uses A32.
    system.el1.cpacr = 3 << 20;
    system.impl_defined.insert(
        Aarch64SysRegEncoding::new(3, 4, 5, 3, 0).encode(),
        if fpexc { 1 << 30 } else { 0 },
    );
    system.impl_defined.insert(
        Aarch64SysRegEncoding::new(3, if target == 2 { 4 } else { 6 }, 1, 1, 2).encode(),
        1 << 10,
    );
    cpu.import_sregs(&state).unwrap();
    cpu.set_pstate_bits(0x1d3 | u64::from(thumb) << 5).unwrap();
    cpu.set_pc(0x100);
    let bytes = if thumb {
        [
            ((raw >> 16) as u16).to_le_bytes(),
            (raw as u16).to_le_bytes(),
        ]
        .concat()
    } else {
        raw.to_le_bytes().to_vec()
    };
    cpu.write_memory(0x100, &bytes).unwrap();
    cpu.set_simd(0, (u128::from(0x3f80_0000u32) << 64) | 0x1234_5678);
    cpu.set_simd(1, 0x4000_0000);
    cpu
}

#[test]
fn mixed_a32_cptr_el2_traps_before_register_effects() {
    for thumb in [false, true] {
        let mut cpu = mixed(VADD, thumb, 2, false, true);
        let before = cpu.get_simd(0);
        let result = cpu.step();
        assert!(
            matches!(
                result,
                Err(ArmError::ArchitecturalException {
                    ec: 7,
                    target_el: Some(2),
                    ..
                })
            ),
            "Thumb={thumb}: {result:?}"
        );
        assert_eq!(cpu.get_pc(), 0x100);
        assert_eq!(cpu.get_simd(0), before);
        assert_eq!(cpu.instruction_count(), 0);
    }
}

#[test]
fn mixed_a32_cptr_el3_traps_from_both_security_states() {
    for secure in [false, true] {
        for thumb in [false, true] {
            let mut cpu = mixed(VADD, thumb, 3, secure, true);
            let before = cpu.get_simd(0);
            let result = cpu.step();
            assert!(
                matches!(
                    result,
                    Err(ArmError::ArchitecturalException {
                        ec: 7,
                        target_el: Some(3),
                        ..
                    })
                ),
                "secure={secure} Thumb={thumb}: {result:?}"
            );
            assert_eq!(cpu.get_pc(), 0x100);
            assert_eq!(cpu.get_simd(0), before);
            assert_eq!(cpu.instruction_count(), 0);
        }
    }
}

#[test]
fn mixed_a32_failed_predicates_suppress_higher_fp_traps() {
    for thumb in [false, true] {
        let mut cpu = mixed(
            if thumb { VADD } else { VADD & 0x0fff_ffff },
            thumb,
            2,
            false,
            true,
        );
        if thumb {
            cpu.set_pstate_bits(0x1f3 | (2 << 10)).unwrap();
        } // IT EQ, Z=0.
        let before = cpu.get_simd(0);
        assert!(matches!(cpu.step(), Ok(CpuExit::Continue)));
        assert_eq!(cpu.get_pc(), 0x104);
        assert_eq!(cpu.get_simd(0), before);
        assert_eq!(cpu.instruction_count(), 1);
    }
}

#[test]
fn mixed_a32_fpexc_disable_precedes_higher_fp_trap() {
    let mut cpu = mixed(VADD, false, 2, false, false);
    assert!(matches!(
        cpu.step(),
        Err(ArmError::UndefinedInstruction(VADD))
    ));
    assert_eq!(cpu.get_pc(), 0x100);
    assert_eq!(cpu.instruction_count(), 0);
}

fn ns_el1() -> Armv7Cpu {
    let mut cpu = hyp();
    cpu.change_mode(ProcessorMode::Supervisor);
    cpu.set_nonsecure(true);
    cpu.cp15.nsacr = 0xc00;
    cpu
}

fn cp15(read: bool, rt: u32, opc1: u32, crn: u32, crm: u32, opc2: u32) -> u32 {
    0xee00_0f10 | u32::from(read) << 20 | opc1 << 21 | crn << 16 | rt << 12 | opc2 << 5 | crm
}

fn undefined(result: ExecResult) -> bool {
    matches!(
        result,
        ExecResult::Undefined
            | ExecResult::Exception(rax::isa::arm::ExceptionType::UndefinedInstruction)
    )
}

#[test]
fn ns_el1_cannot_reprogram_secure_or_hyp_controls() {
    for (opc1, crn, crm, opc2) in [
        (0, 1, 1, 0),
        (0, 1, 1, 1),
        (0, 1, 1, 2),
        (4, 1, 1, 2),
        (4, 1, 1, 0),
        (4, 12, 0, 0),
    ] {
        let mut cpu = ns_el1();
        cpu.regs[0] = u32::MAX;
        let before = (
            cpu.cp15.scr,
            cpu.cp15.sder,
            cpu.cp15.nsacr,
            cpu.cp15.hcptr,
            cpu.cp15.hcr,
            cpu.cp15.hvbar,
        );
        let result = execute(&mut cpu, cp15(false, 0, opc1, crn, crm, opc2));
        assert!(
            undefined(result.clone()),
            "{opc1},{crn},{crm},{opc2}: {result:?}"
        );
        assert_eq!(
            (
                cpu.cp15.scr,
                cpu.cp15.sder,
                cpu.cp15.nsacr,
                cpu.cp15.hcptr,
                cpu.cp15.hcr,
                cpu.cp15.hvbar
            ),
            before
        );
    }
}

#[test]
fn ns_cpacr_clamps_readback_and_preserves_inaccessible_bits_on_write() {
    let mut cpu = ns_el1();
    cpu.cp15.nsacr = (1 << 11) | (1 << 15);
    cpu.cp15.cpacr = Cpacr::from_bits(0xf0_0000);
    assert!(matches!(
        execute(&mut cpu, cp15(true, 0, 0, 1, 0, 2)),
        ExecResult::Continue
    ));
    assert_eq!(cpu.regs[0], 0x80c0_0000);
    cpu.regs[0] = 0;
    assert!(matches!(
        execute(&mut cpu, cp15(false, 0, 0, 1, 0, 2)),
        ExecResult::Continue
    ));
    assert_eq!(cpu.cp15.cpacr.bits(), 0x0030_0000);
}

#[test]
fn ns_hcptr_clamps_readback_and_preserves_inaccessible_bits_on_write() {
    let mut cpu = hyp();
    cpu.cp15.nsacr = 1 << 15;
    cpu.cp15.hcptr = 0x33ff;
    assert!(matches!(
        execute(&mut cpu, cp15(true, 0, 4, 1, 1, 2)),
        ExecResult::Continue
    ));
    assert_eq!(cpu.regs[0], 0xbfff);
    cpu.regs[0] = 0x8c00;
    assert!(matches!(
        execute(&mut cpu, cp15(false, 0, 4, 1, 1, 2)),
        ExecResult::Continue
    ));
    assert_eq!(cpu.cp15.hcptr, 0x33ff);
}

#[test]
fn hcptr_tcpac_traps_both_cpacr_directions_without_effects() {
    for read in [false, true] {
        let mut cpu = ns_el1();
        cpu.regs[3] = 0x12345678;
        cpu.cp15.hcptr = 0x8000_33ff;
        let before = cpu.cp15.cpacr.bits();
        let raw = cp15(read, 3, 0, 1, 0, 2);
        let expected = (3 << 26)
            | (1 << 25)
            | (1 << 24)
            | (14 << 20)
            | (2 << 17)
            | (1 << 10)
            | (3 << 5)
            | u32::from(read);
        let result = execute(&mut cpu, raw);
        assert!(
            matches!(result,ExecResult::FpAccessTrap{target_el:2,syndrome,undefined:false} if syndrome==expected),
            "{result:?}"
        );
        assert_eq!(cpu.regs[3], 0x12345678);
        assert_eq!(cpu.cp15.cpacr.bits(), before);
    }
}

#[test]
fn vmrs_id_traps_preserve_registers_and_encode_the_complete_iss() {
    for register in [0, 5, 6, 7] {
        let mut cpu = ns_el1();
        cpu.cp15.hcr = if register == 0 { 1 << 15 } else { 1 << 18 };
        cpu.regs[4] = 0x12345678;
        let raw = 0xeef0_0a10 | (register << 16) | (4 << 12);
        let expected = (8 << 26)
            | (1 << 25)
            | (1 << 24)
            | (14 << 20)
            | (7 << 14)
            | (register << 10)
            | (4 << 5)
            | 1;
        let result = execute(&mut cpu, raw);
        assert!(
            matches!(result,ExecResult::FpAccessTrap{target_el:2,syndrome,undefined:false} if syndrome==expected),
            "reg {register}: {result:?}"
        );
        assert_eq!(cpu.regs[4], 0x12345678);
    }
}

#[test]
fn fp_hyp_entry_preserves_the_fault_pc_syndrome_and_banked_frame() {
    for from_hyp in [false, true] {
        let mut cpu = if from_hyp { hyp() } else { ns_el1() };
        cpu.cp15.hcptr = 0x37ff;
        cpu.cp15.hvbar = 0x8000;
        cpu.cp15.scr = 1;
        cpu.regs[15] = 0x120;
        cpu.regs[14] = 0xabcdef00;
        cpu.regs_usr[1] = 0x01234567;
        cpu.cpsr.it_state = 0x18;
        let saved = cpu.cpsr.to_u32();
        let mut mem = Memory32::new(4096, 0);
        let mut exec = Executor::new(&mut cpu, &mut mem);
        let result = exec.execute(&Aarch32Decoder::decode(VADD).unwrap());
        let ExecResult::FpAccessTrap {
            target_el: 2,
            syndrome,
            undefined,
        } = result
        else {
            panic!("{result:?}")
        };
        assert_eq!(syndrome, 0x1fe0000a);
        exec.take_exception(rax::isa::arm::ExceptionType::HypervisorTrap {
            syndrome,
            undefined,
        });
        assert_eq!(exec.cpu.spsr_hyp.to_u32(), saved);
        assert_eq!(exec.cpu.cp15.elr_hyp, 0x120);
        assert_eq!(exec.cpu.cp15.hsr, 0x1fe0000a);
        assert_eq!(exec.cpu.regs[15], if from_hyp { 0x8004 } else { 0x8014 });
        assert_eq!(
            exec.cpu.regs[14],
            if from_hyp { 0xabcdef00 } else { 0x01234567 }
        );
        if !from_hyp {
            assert_eq!(exec.cpu.regs_svc[1], 0xabcdef00);
        }
        assert_eq!(exec.cpu.cpsr.it_state, 0);
        assert_eq!(exec.cpu.cpsr.mode, ProcessorMode::Hyp as u8);
    }
}

#[test]
fn mixed_cpacr_tcpac_routes_both_directions_before_register_effects() {
    for target in [2, 3] {
        for read in [false, true] {
            for thumb in [false, true] {
                let raw = cp15(read, 3, 0, 1, 0, 2);
                let mut cpu = mixed(raw, thumb, target, false, true);
                let mut s = cpu.export_sregs();
                s.execution.as_mut().unwrap().sysregs.impl_defined.insert(
                    Aarch64SysRegEncoding::new(3, if target == 2 { 4 } else { 6 }, 1, 1, 2)
                        .encode(),
                    1 << 31,
                );
                cpu.import_sregs(&s).unwrap();
                let before = cpu.get_x(3);
                let result = cpu.step();
                let iss =
                    (1 << 24) | (14 << 20) | (2 << 17) | (1 << 10) | (3 << 5) | u32::from(read);
                assert!(
                    matches!(result,Err(ArmError::ArchitecturalException{ec:3,iss:actual,target_el:Some(el)}) if el==target&&actual==iss),
                    "EL{target},read={read},Thumb={thumb}: {result:?}"
                );
                assert_eq!(cpu.get_x(3), before);
                assert_eq!(cpu.get_pc(), 0x100);
                assert_eq!(cpu.instruction_count(), 0);
            }
        }
    }
}

#[test]
fn mixed_cpacr_guest_writes_reach_the_enclosing_pe() {
    let raw = cp15(false, 0, 0, 1, 0, 2);
    let mut cpu = mixed(raw, false, 2, false, true);
    let mut s = cpu.export_sregs();
    s.execution
        .as_mut()
        .unwrap()
        .sysregs
        .impl_defined
        .insert(Aarch64SysRegEncoding::new(3, 4, 1, 1, 2).encode(), 0);
    cpu.import_sregs(&s).unwrap();
    cpu.set_x(0, 0);
    let result = cpu.step();
    assert!(matches!(result, Ok(CpuExit::Continue)), "{result:?}");
    assert_eq!(
        cpu.export_sregs().execution.unwrap().sysregs.el1.cpacr & 0xf00000,
        0
    );
    cpu.write_memory(0x104, &VADD.to_le_bytes()).unwrap();
    assert!(matches!(cpu.step(), Err(ArmError::UndefinedInstruction(_))));
    assert_eq!(cpu.get_pc(), 0x104);
    assert_eq!(cpu.instruction_count(), 1);
}

#[test]
fn mixed_el0_effective_fpexc_enable_does_not_modify_stored_fpexc() {
    for raw in [VADD, NEON_ADD, 0xeef1_0a10] {
        let mut cpu = mixed(raw, false, 2, false, false);
        let mut s = cpu.export_sregs();
        let system = &mut s.execution.as_mut().unwrap().sysregs;
        system
            .impl_defined
            .insert(Aarch64SysRegEncoding::new(3, 4, 1, 1, 2).encode(), 0);
        system.hcr_el2 |= 1 << 27;
        cpu.import_sregs(&s).unwrap();
        cpu.set_pstate_bits(0x1d0).unwrap();
        let result = cpu.step();
        assert!(
            matches!(result, Ok(CpuExit::Continue)),
            "{raw:#x}: {result:?}"
        );
        let s = cpu.export_sregs();
        assert_eq!(
            s.execution.unwrap().sysregs.impl_defined
                [&Aarch64SysRegEncoding::new(3, 4, 5, 3, 0).encode()]
                & (1 << 30),
            0
        );
        assert_eq!(cpu.instruction_count(), 1);
    }
}

#[test]
fn unallocated_fp_coprocessor_transfers_do_not_become_nops() {
    for raw in [0xee10_0a30, 0xee00_0a30] {
        let mut cpu = Armv7Cpu::new();
        cpu.regs[0] = 0x12345678;
        let result = execute(&mut cpu, raw);
        assert!(undefined(result.clone()), "{raw:#x}: {result:?}");
        assert_eq!(cpu.regs[0], 0x12345678);
    }
}

#[test]
fn thumb32_fp_undefined_frame_uses_the_architectural_lr_offset() {
    let mut cpu = Armv7Cpu::new();
    cpu.cpsr.t = true;
    cpu.vfp.fpexc = 0;
    cpu.regs[15] = 0x100;
    let mut decoder = rax::isa::arm::Decoder::new(rax::isa::arm::ExecutionState::Thumb);
    let insn = decoder.decode(&[0x31, 0xee, 0x02, 0x0a]).unwrap();
    assert_eq!(insn.size, 4);
    let mut mem = Memory32::new(4096, 0);
    let mut exec = Executor::new(&mut cpu, &mut mem);
    assert!(undefined(exec.execute(&insn)));
    exec.take_exception(rax::isa::arm::ExceptionType::UndefinedInstruction);
    assert_eq!(exec.cpu.regs[14], 0x102);
}

#[test]
fn el0_fp_undefined_is_routed_to_hyp_by_hcr_tge() {
    let mut cpu = ns_el1();
    cpu.change_mode(ProcessorMode::User);
    cpu.cp15.hcr = 1 << 27;
    cpu.cp15.cpacr = Cpacr::from_bits(0);
    cpu.cp15.hvbar = 0x8000;
    cpu.regs[15] = 0x100;
    let mut mem = Memory32::new(4096, 0);
    let mut exec = Executor::new(&mut cpu, &mut mem);
    assert!(undefined(
        exec.execute(&Aarch32Decoder::decode(VADD).unwrap())
    ));
    exec.take_exception(rax::isa::arm::ExceptionType::UndefinedInstruction);
    assert_eq!(exec.cpu.cpsr.mode, ProcessorMode::Hyp as u8);
    assert_eq!(exec.cpu.regs[15], 0x8014);
    assert_eq!(exec.cpu.cp15.elr_hyp, 0x100);
}

#[test]
fn thumb_fp_and_cp15_trap_syndromes_retain_the_passed_it_condition() {
    for raw in [VADD, cp15(true, 0, 0, 1, 0, 2)] {
        let mut cpu = ns_el1();
        cpu.cpsr.t = true;
        cpu.cpsr.z = false;
        cpu.cpsr.it_state = 0x18; // IT NE, passes with Z=0.
        cpu.cp15.hcptr = if raw == VADD { 0x37ff } else { 0x800033ff };
        let bytes = [
            ((raw >> 16) as u16).to_le_bytes(),
            (raw as u16).to_le_bytes(),
        ]
        .concat();
        let mut d = rax::isa::arm::Decoder::new(rax::isa::arm::ExecutionState::Thumb);
        let insn = d.decode(&bytes).unwrap();
        let mut mem = Memory32::new(4096, 0);
        let result = Executor::new(&mut cpu, &mut mem).execute(&insn);
        let ExecResult::FpAccessTrap { syndrome, .. } = result else {
            panic!("{result:?}")
        };
        assert_eq!(
            (syndrome >> 20) & 31,
            0x11,
            "raw {raw:#x},syndrome {syndrome:#x}"
        );
        assert_eq!(cpu.cpsr.it_state, 0x18);
    }
}

#[test]
fn unallocated_vmrs_opcode_and_register_forms_fault_before_effects() {
    for raw in [0xeed0_0a10, 0xeef2_0a10, 0xeee5_0a10, 0xeef0_fa10] {
        let mut cpu = Armv7Cpu::new();
        cpu.regs[0] = 0x12345678;
        let result = execute(&mut cpu, raw);
        assert!(undefined(result.clone()), "{raw:#x}: {result:?}");
        assert_eq!(cpu.regs[0], 0x12345678);
    }
}

#[test]
fn standalone_backend_guest_programs_hyp_controls_and_traps_without_retirement() {
    use rax::backend::emulator::aarch32::Aarch32Vcpu;
    use rax::vm::vcpu::{CpuState, VCpu};
    use std::sync::Arc;
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
    for from_hyp in [false, true] {
        let memory =
            Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap());
        let mut cpu = Aarch32Vcpu::new(0, memory.clone());
        let CpuState::Aarch32(mut s) = cpu.get_state().unwrap() else {
            panic!()
        };
        s.regs.pc = 0x100;
        s.regs.cpsr = 0x1d3;
        s.regs.r[0] = 0xc00;
        s.regs.r[1] = 0xf00000;
        s.regs.r[2] = 1;
        cpu.set_state(&CpuState::Aarch32(s)).unwrap();
        for (i, raw) in [
            cp15(false, 0, 0, 1, 1, 2),
            cp15(false, 1, 0, 1, 0, 2),
            cp15(false, 2, 0, 1, 1, 0),
        ]
        .into_iter()
        .enumerate()
        {
            memory
                .write_slice(&raw.to_le_bytes(), GuestAddress(0x100 + i as u64 * 4))
                .unwrap();
            assert!(cpu.step_insn().unwrap().is_none());
        }
        let CpuState::Aarch32(mut s) = cpu.get_state().unwrap() else {
            panic!()
        };
        s.regs.pc = 0x200;
        s.regs.cpsr = 0x1da;
        s.regs.r[0] = 0x8000;
        s.regs.r[1] = 0x400;
        cpu.set_state(&CpuState::Aarch32(s)).unwrap();
        for (i, raw) in [cp15(false, 0, 4, 12, 0, 0), cp15(false, 1, 4, 1, 1, 2)]
            .into_iter()
            .enumerate()
        {
            memory
                .write_slice(&raw.to_le_bytes(), GuestAddress(0x200 + i as u64 * 4))
                .unwrap();
            assert!(cpu.step_insn().unwrap().is_none());
        }
        let CpuState::Aarch32(mut s) = cpu.get_state().unwrap() else {
            panic!()
        };
        s.regs.pc = 0x300;
        s.regs.cpsr = if from_hyp { 0x1da } else { 0x1d3 };
        let saved = s.regs.cpsr;
        cpu.set_state(&CpuState::Aarch32(s)).unwrap();
        memory
            .write_slice(&VADD.to_le_bytes(), GuestAddress(0x300))
            .unwrap();
        let before = cpu.instruction_count();
        assert!(cpu.step_insn().unwrap().is_none());
        assert_eq!(cpu.instruction_count(), before);
        let CpuState::Aarch32(s) = cpu.get_state().unwrap() else {
            panic!()
        };
        assert_eq!(s.regs.cpsr & 31, 0x1a);
        assert_eq!(s.regs.spsr, saved);
        assert_eq!(s.regs.pc, if from_hyp { 0x8004 } else { 0x8014 });
        memory
            .write_slice(
                &cp15(true, 4, 4, 5, 2, 0).to_le_bytes(),
                GuestAddress(u64::from(s.regs.pc)),
            )
            .unwrap();
        assert!(cpu.step_insn().unwrap().is_none());
        let CpuState::Aarch32(s) = cpu.get_state().unwrap() else {
            panic!()
        };
        assert_eq!(s.regs.r[4], 0x1fe0000a);
        assert_eq!(cpu.instruction_count(), before + 1);
    }
}

#[test]
fn invalid_fp_system_registers_preserve_the_existing_diagnostic_exit() {
    for raw in [0xeee5_0a10, 0xeef2_2a10] {
        let mut cpu = Armv7Cpu::new();
        assert!(matches!(execute(&mut cpu, raw), ExecResult::Undefined));
    }
    let mut cpu = Armv7Cpu::new();
    cpu.change_mode(ProcessorMode::User);
    assert!(matches!(
        execute(&mut cpu, 0xeef7_0a10),
        ExecResult::Undefined
    ));
    let mut cpu = Armv7Cpu::new();
    cpu.vfp.fpexc = 0;
    assert!(matches!(
        execute(&mut cpu, VADD),
        ExecResult::Exception(rax::isa::arm::ExceptionType::UndefinedInstruction)
    ));
}

#[path = "a32_fp_controls/register_banks.rs"]
mod register_banks;

#[path = "a32_fp_controls/base_precision.rs"]
mod base_precision;

#[path = "a32_fp_controls/simd_base.rs"]
mod simd_base;

#[path = "a32_fp_controls/simd_single.rs"]
mod simd_single;

#[path = "a32_fp_controls/id_views.rs"]
mod id_views;

#[path = "a32_fp_controls/restricted_modes.rs"]
mod restricted_modes;

#[path = "a32_fp_controls/structure_memory.rs"]
mod structure_memory;
