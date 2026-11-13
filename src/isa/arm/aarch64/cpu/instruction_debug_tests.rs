//! Architectural instruction comparator controls and precise exception entry.
use super::*;
use crate::isa::arm::common::memory::FlatMemory;

const PC: u64 = 0x100;
const EL0_EXEC: u64 = 0x1e5;
const MDE: u64 = 1 << 15;

fn cpu(el: u8) -> AArch64Cpu {
    let mut config = AArch64Config::v8_0();
    config.initial_el = el;
    config.gic_config = None;
    let mut cpu = AArch64Cpu::new(config, Box::new(FlatMemory::new(0, 0x5000)));
    cpu.sysregs.scr_el3 = 0x501;
    cpu.sysregs.hcr_el2 = 1 << 31;
    cpu.sysregs.mdscr_el1 = MDE;
    cpu.sysregs.el1.vbar = 0x1000;
    cpu.sysregs.el2.vbar = 0x2000;
    cpu.pc = PC;
    cpu.x[0] = 41;
    cpu.write_memory(PC, &0x91000400u32.to_le_bytes()).unwrap(); // ADD X0,X0,#1
    cpu
}

fn arm(cpu: &mut AArch64Cpu, slot: usize, control: u64) {
    cpu.sysregs.dbgbvr[slot] = PC;
    cpu.sysregs.dbgbcr[slot] = control;
}

fn expect_break(cpu: &mut AArch64Cpu, target: u8) {
    let old_el = cpu.current_el;
    let pstate = cpu.pstate_bits();
    let before = (cpu.x, cpu.v, cpu.insn_count, cpu.cycle_count, cpu.btype);
    let ec = if old_el == target { 0x31 } else { 0x30 };
    let error = cpu.step().expect_err("enabled instruction comparator");
    assert_eq!(
        error,
        ArmError::ArchitecturalException {
            ec,
            iss: 0x22,
            target_el: Some(target)
        }
    );
    assert_eq!(cpu.pc, PC);
    assert_eq!(
        (cpu.x, cpu.v, cpu.insn_count, cpu.cycle_count, cpu.btype),
        before
    );
    assert_eq!(cpu.pstate_bits(), pstate);
    cpu.deliver_fault(error).unwrap();
    let bank = cpu.sysregs.bank(target);
    assert_eq!(
        (bank.elr, bank.esr, bank.spsr),
        (PC, (u64::from(ec) << 26) | (1 << 25) | 0x22, pstate)
    );
}

#[test]
fn arm64_instruction_debug_call_target_retains_direct_or_indirect_btype() {
    for (word, expected_btype, link) in [
        (0x14000001u32, 0, false), // B +4
        (0x94000001, 0, true),     // BL +4
        (0xd63f0020, 2, true),     // BLR X1
    ] {
        let mut cpu = cpu(0);
        arm(&mut cpu, 0, EL0_EXEC);
        cpu.write_memory(PC - 4, &word.to_le_bytes()).unwrap();
        cpu.pc = PC - 4;
        cpu.x[1] = PC;
        assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
        assert_eq!((cpu.pc, cpu.insn_count, cpu.btype), (PC, 1, expected_btype));
        if link {
            assert_eq!(cpu.x[30], PC);
        }
        // The comparator faults before executing the target and saves the
        // preceding branch's state, including the distinction between BL/BLR.
        expect_break(&mut cpu, 1);
        assert_eq!((cpu.sysregs.el1.spsr >> 10) & 3, expected_btype as u64);
    }
}

#[test]
fn arm64_instruction_debug_all_implemented_slots_fault_before_retirement() {
    for slot in 0..16 {
        let mut cpu = cpu(0);
        arm(&mut cpu, slot, EL0_EXEC);
        if slot < usize::from(cpu.config.num_breakpoints) {
            expect_break(&mut cpu, 1);
        } else {
            assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
            assert_eq!((cpu.pc, cpu.x[0], cpu.insn_count), (PC + 4, 42, 1));
        }
    }
}

#[test]
fn arm64_instruction_debug_monitor_enable_privilege_security_and_address() {
    for variant in 0..7 {
        let mut cpu = cpu(0);
        arm(&mut cpu, 0, EL0_EXEC);
        match variant {
            0 => cpu.sysregs.mdscr_el1 = 0,
            1 => cpu.sysregs.dbgbcr[0] &= !1,
            2 => cpu.sysregs.dbgbvr[0] += 4,
            3 => cpu.sysregs.dbgbcr[0] = 0x1e3,    // EL1 only
            4 => cpu.sysregs.dbgbcr[0] |= 2 << 14, // Secure only
            5 => cpu.sysregs.osdlr_el1 = 1,
            6 => cpu.sysregs.dbgbcr[0] |= 6 << 20, // reserved on base Debugv8
            _ => unreachable!(),
        }
        assert_eq!(cpu.step().unwrap(), CpuExit::Continue, "variant {variant}");
        assert_eq!((cpu.pc, cpu.x[0], cpu.insn_count), (PC + 4, 42, 1));
    }
    // DebugAddrTop is bit 48 in this profile; upper address bits do not compare.
    let mut cpu = cpu(0);
    arm(&mut cpu, 0, EL0_EXEC);
    cpu.sysregs.dbgbvr[0] |= 0xff00_0000_0000_0000;
    expect_break(&mut cpu, 1);
}

#[test]
fn arm64_instruction_debug_pstate_d_only_masks_same_el_and_kde_is_required() {
    let mut lower = cpu(0);
    arm(&mut lower, 0, EL0_EXEC);
    lower.daif = 0xf;
    expect_break(&mut lower, 1);
    for kde in [false, true] {
        for masked in [false, true] {
            let mut cpu = cpu(1);
            arm(&mut cpu, 0, 0x1e3);
            cpu.daif = if masked { 8 } else { 0 };
            if kde {
                cpu.sysregs.mdscr_el1 |= 1 << 13;
            }
            if kde && !masked {
                expect_break(&mut cpu, 1);
            } else {
                assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
            }
        }
    }
}

#[test]
fn arm64_instruction_debug_el2_route_and_secure_disable() {
    for route in [1 << 27, 0] {
        let mut cpu = cpu(0);
        arm(&mut cpu, 0, EL0_EXEC);
        cpu.sysregs.hcr_el2 |= route;
        if route == 0 {
            cpu.sysregs.mdcr_el2 |= 1 << 8;
        }
        expect_break(&mut cpu, 2);
    }
    let mut secure = cpu(0);
    arm(&mut secure, 0, EL0_EXEC);
    secure.sysregs.scr_el3 &= !1;
    secure.sysregs.mdcr_el3 |= 1 << 16;
    assert_eq!(secure.step().unwrap(), CpuExit::Continue);
}

#[test]
fn arm64_instruction_debug_fetch_fault_wins_but_decode_and_il_follow_debug() {
    let mut missing = cpu(0);
    missing.pc = 0x6000;
    missing.sysregs.dbgbvr[0] = missing.pc;
    missing.sysregs.dbgbcr[0] = EL0_EXEC;
    assert!(matches!(missing.step(), Err(ArmError::MemoryError(_))));
    assert_eq!((missing.pc, missing.insn_count), (0x6000, 0));
    for word in [0u32, 0xd4200000, 0x91000400] {
        let mut cpu = cpu(0);
        cpu.write_memory(PC, &word.to_le_bytes()).unwrap();
        cpu.il = true;
        arm(&mut cpu, 0, EL0_EXEC);
        expect_break(&mut cpu, 1);
    }
}

#[test]
fn arm64_instruction_debug_context_and_linked_context_match() {
    for linked in [false, true] {
        for matches in [false, true] {
            let mut cpu = cpu(0);
            let context_slot = usize::from(cpu.config.num_breakpoints) - 1;
            cpu.sysregs.el1.contextidr = 0x1234;
            cpu.sysregs.dbgbvr[context_slot] = if matches { 0x1234 } else { 0x1235 };
            cpu.sysregs.dbgbcr[context_slot] = EL0_EXEC | (if linked { 3 } else { 2 } << 20);
            if linked {
                arm(
                    &mut cpu,
                    0,
                    EL0_EXEC | (1 << 20) | ((context_slot as u64) << 16),
                );
            }
            if matches {
                expect_break(&mut cpu, 1);
            } else {
                assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
            }
        }
    }
    // A context-aware unit with linking enabled cannot independently trigger.
    let mut cpu = cpu(0);
    let last = usize::from(cpu.config.num_breakpoints) - 1;
    cpu.sysregs.el1.contextidr = PC;
    arm(&mut cpu, last, EL0_EXEC | (3 << 20));
    assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
}

#[test]
fn arm64_instruction_debug_id_counts_match_config_and_survive_reset() {
    for (requested, expected) in [(0, 2), (1, 2), (6, 6), (16, 16), (255, 16)] {
        let mut config = AArch64Config::default();
        config.num_breakpoints = requested;
        config.num_watchpoints = requested;
        config.gic_config = None;
        let mut cpu = AArch64Cpu::new(config, Box::new(FlatMemory::new(0, 0x1000)));
        for reset in [false, true] {
            if reset {
                cpu.reset();
            }
            assert_eq!(cpu.config.num_breakpoints, expected);
            assert_eq!(cpu.config.num_watchpoints, expected);
            assert_eq!(
                (cpu.sysregs.id_aa64dfr0_el1 >> 12) & 15,
                u64::from(expected - 1)
            );
            assert_eq!(
                (cpu.sysregs.id_aa64dfr0_el1 >> 20) & 15,
                u64::from(expected - 1)
            );
        }
    }
}

#[test]
fn arm64_instruction_debug_private_checkpoint_retains_monitor_and_banks() {
    let mut original = cpu(0);
    arm(&mut original, 2, EL0_EXEC);
    let checkpoint = CoreCheckpoint::capture(&original).unwrap();
    let bytes = serde_json::to_vec(&checkpoint).unwrap();
    let checkpoint: CoreCheckpoint = serde_json::from_slice(&bytes).unwrap();
    let mut restored = cpu(0);
    checkpoint.install_in_prepared(&mut restored).unwrap();
    assert_eq!(CoreCheckpoint::capture(&restored).unwrap(), checkpoint);
    expect_break(&mut restored, 1);
}

#[test]
fn arm64_instruction_debug_invalid_checkpoint_counts_are_rejected_before_install() {
    for field in ["num_breakpoints", "num_watchpoints"] {
        for count in [0, 1, 17, 255] {
            let original = cpu(0);
            let checkpoint = CoreCheckpoint::capture(&original).unwrap();
            let mut value = serde_json::to_value(&checkpoint).unwrap();
            value["config"][field] = count.into();
            let invalid: CoreCheckpoint = serde_json::from_value(value).unwrap();
            let mut target = cpu(0);
            let before = CoreCheckpoint::capture(&target).unwrap();
            assert!(invalid.install_in_prepared(&mut target).is_err());
            assert_eq!(CoreCheckpoint::capture(&target).unwrap(), before);
        }
    }
}

#[test]
fn arm64_instruction_debug_mismatch_intersection_and_vmid_context() {
    for inside in [false, true] {
        let mut cpu = cpu(0);
        arm(&mut cpu, 0, EL0_EXEC);
        arm(&mut cpu, 1, EL0_EXEC | (4 << 20));
        cpu.sysregs.dbgbvr[1] = if inside { PC } else { PC + 4 };
        if inside {
            assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
        } else {
            expect_break(&mut cpu, 1);
        }
    }
    for matches in [false, true] {
        let mut cpu = cpu(0);
        let last = usize::from(cpu.config.num_breakpoints) - 1;
        cpu.sysregs.el1.contextidr = 0x1234;
        cpu.sysregs.vttbr_el2 = if matches { 5 } else { 6 } << 48;
        cpu.sysregs.dbgbvr[last] = (5 << 32) | 0x1234;
        cpu.sysregs.dbgbcr[last] = EL0_EXEC | (10 << 20);
        if matches {
            expect_break(&mut cpu, 1);
        } else {
            assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
        }
    }
}

#[test]
fn arm64_instruction_debug_host_context_uses_el2_context_id() {
    let mut cpu = cpu(0);
    cpu.config.features |= ArmFeatures::VHE;
    cpu.sysregs.hcr_el2 |= (1 << 34) | (1 << 27);
    cpu.sysregs.el1.contextidr = 0xbad;
    cpu.sysregs.el2.contextidr = 0x1234;
    let last = usize::from(cpu.config.num_breakpoints) - 1;
    cpu.sysregs.dbgbvr[last] = 0x1234;
    cpu.sysregs.dbgbcr[last] = EL0_EXEC | (2 << 20);
    expect_break(&mut cpu, 2);
}

#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
#[test]
fn arm64_instruction_debug_cached_pauth_and_legacy_regions_defer() {
    let mut cpu = cpu(0);
    let program = [0x91000400u32, 0xf100a803, 0x54ffffc3, 0xd4200000];
    cpu.write_memory(
        PC,
        &program
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let legacy = cpu.jit_compile_region().expect("bounded arithmetic loop");
    assert!(cpu.jit_run_region(&legacy));
    assert_eq!(cpu.pc, PC + 12);
    cpu.pc = PC;
    arm(&mut cpu, 0, EL0_EXEC);
    assert!(!cpu.jit_run_region(&legacy));
    cpu.sysregs.dbgbcr[0] = 0;
    cpu.write_memory(PC, &0xd503233fu32.to_le_bytes()).unwrap(); // PACIASP
    let pauth = cpu.jit_compile_pauth_instruction(0xd503233f).unwrap();
    assert!(cpu.jit_run_pauth_instruction(&pauth, 0xd503233f));
    cpu.pc = PC;
    arm(&mut cpu, 0, EL0_EXEC);
    assert!(!cpu.jit_run_pauth_instruction(&pauth, 0xd503233f));
    expect_break(&mut cpu, 1);
}

#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
#[test]
fn arm64_instruction_debug_warm_native_region_cannot_bypass_new_comparator() {
    let mut cpu = cpu(0);
    for _ in 0..100 {
        cpu.pc = PC;
        cpu.jit_step_bounded();
    }
    assert!(cpu.bounded_native_runs() > 0);
    cpu.pc = PC;
    let native = cpu.bounded_native_runs();
    arm(&mut cpu, 0, EL0_EXEC);
    assert!(!cpu.jit_step_bounded());
    assert_eq!(cpu.bounded_native_runs(), native);
    expect_break(&mut cpu, 1);
}
