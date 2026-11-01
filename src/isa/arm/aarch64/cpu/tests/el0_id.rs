//! Architectural EL0 ID faults and Linux-only software continuation.
use super::*;
use crate::isa::arm::common::cpu::{ArmCpu, ArmError, CpuExit};
use crate::user::cpu::aarch64::A64UserCpu;
use crate::user::linux::arch::{CpuEvent, aarch64 as linux};
use crate::user::mm::{AddressSpace, Mapping, PAGE_SIZE, Perms, SpaceConfig};

const CODE: u64 = 0x10000;
fn mrs(crm: u8, op2: u8, rt: u8) -> u32 {
    0xd538_0000 | (u32::from(crm) << 8) | (u32::from(op2) << 5) | u32::from(rt)
}
fn direct(word: u32, el: u8) -> AArch64Cpu {
    let mut config = AArch64Config::v8_2();
    config.initial_el = el;
    config.gic_config = None;
    let mut cpu = AArch64Cpu::new(config, Box::new(FlatMemory::new(0, 4096)));
    cpu.write_memory(0, &word.to_le_bytes()).unwrap();
    cpu.set_x(0, 0x1122_3344_5566_7788);
    cpu
}
fn user(words: &[u32], readable: bool) -> A64UserCpu {
    let space = AddressSpace::new(SpaceConfig {
        va_limit: 1 << 47,
        arena_bytes: 64 * PAGE_SIZE,
        reserved_phys: vec![],
    })
    .unwrap();
    let permissions = if readable {
        Perms::READ | Perms::EXEC
    } else {
        Perms::EXEC
    };
    space
        .map(CODE, PAGE_SIZE, Mapping::anonymous(permissions))
        .unwrap();
    let bytes: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    space.write_raw(CODE, &bytes).unwrap();
    let mut cpu = A64UserCpu::new(&space);
    cpu.core_mut().set_pc(CODE);
    cpu
}

#[test]
fn architectural_el0_id_reads_preserve_the_complete_fault_frontier() {
    for word in [mrs(0, 0, 0), mrs(0, 5, 0), mrs(3, 0, 0), mrs(4, 0, 0)] {
        let mut cpu = direct(word, 0);
        let before = crate::codec::serialize(&CoreCheckpoint::capture(&cpu).unwrap()).unwrap();
        assert!(
            matches!(cpu.step(), Err(ArmError::InvalidExceptionLevel(0))),
            "{word:#010x}"
        );
        let after = crate::codec::serialize(&CoreCheckpoint::capture(&cpu).unwrap()).unwrap();
        assert_eq!(before, after, "{word:#010x} changed its fault frontier");
        let mut privileged = direct(word, 1);
        assert_eq!(privileged.step().unwrap(), CpuExit::Continue);
        assert_eq!(
            (privileged.get_pc(), privileged.instruction_count()),
            (4, 1)
        );
        assert_ne!(privileged.get_x(0), 0x1122_3344_5566_7788);
    }
}

#[test]
fn linux_cpuid_accounts_prior_retirement_and_wrap_without_overrunning_a_slice() {
    let mut cpu = user(&[0x9100_0400, mrs(0, 0, 1), 0x9100_0400, 0xd400_0001], true);
    cpu.core_mut().insn_count = u64::MAX - 1;
    assert_eq!(linux::run(&mut cpu, 0), CpuEvent::Yield);
    assert_eq!(cpu.pc(), CODE);
    assert_eq!(linux::run(&mut cpu, 3), CpuEvent::Yield);
    assert_eq!(
        (
            cpu.pc(),
            cpu.core().get_x(0),
            cpu.core().instruction_count()
        ),
        (CODE + 12, 2, 0)
    );
    assert_ne!(cpu.core().get_x(1), 0);
    assert!(matches!(linux::run(&mut cpu, 1), CpuEvent::Syscall { .. }));
    assert_eq!((cpu.pc(), cpu.core().instruction_count()), (CODE + 16, 1));
}

#[test]
fn linux_identity_filters_preserve_underlying_pe_identity_and_skip_only_one_word() {
    let mut cpu = user(&[mrs(0, 5, 0), mrs(0, 6, 1), 0xd400_0001], true);
    cpu.core_mut().sysregs.mpidr_el1 = 0x8001_1234;
    cpu.core_mut().sysregs.revidr_el1 = 0x1122;
    assert_eq!(linux::run(&mut cpu, 1), CpuEvent::Yield);
    assert_eq!(cpu.core().get_x(0), 1 << 31);
    assert_eq!(cpu.pc(), CODE + 4);
    assert_eq!(linux::run(&mut cpu, 1), CpuEvent::Yield);
    assert_eq!(cpu.core().get_x(1), 0);
    assert_eq!((cpu.pc(), cpu.core().instruction_count()), (CODE + 8, 0));
    assert_eq!(cpu.core().sysregs.mpidr_el1, 0x8001_1234);
    assert_eq!(cpu.core().sysregs.revidr_el1, 0x1122);
}

#[test]
fn linux_feature_view_uses_hidden_safe_defaults_and_reserved_slot_zero() {
    let mut cpu = user(&[mrs(7, 0, 0), mrs(5, 0, 1), mrs(4, 3, 2)], true);
    cpu.core_mut().set_el0_spsr(0xa000_0400);
    assert_eq!(linux::run(&mut cpu, 3), CpuEvent::Yield);
    // Linux hides the granule fields: stage-2 selectors=1, TGran4/64=0xf.
    assert_eq!(
        cpu.core().get_x(0),
        (1 << 32) | (1 << 36) | (1 << 40) | (15 << 28) | (15 << 24)
    );
    assert_eq!(cpu.core().get_x(1), 6); // Hidden DebugVer safe default.
    assert_eq!(cpu.core().get_x(2), 0); // Untracked ID_AA64PFR3_EL1 slot.
    assert_eq!(cpu.core().el0_spsr(), 0xa000_0000); // Skip clears BTYPE only.
}

#[test]
fn linux_does_not_emulate_writes_other_privileged_words_or_unreadable_code() {
    for word in [0xd518_0000, 0xd538_1000, 0xd400_0002, 0xd440_0000] {
        let mut cpu = user(&[word], true);
        cpu.core_mut().set_x(0, 123);
        assert!(
            matches!(linux::run(&mut cpu, 1), CpuEvent::Signal(..)),
            "{word:#x}"
        );
        assert_eq!((cpu.pc(), cpu.core().get_x(0)), (CODE, 123));
    }
    let mut cpu = user(&[mrs(0, 0, 0)], false);
    assert!(matches!(linux::run(&mut cpu, 1), CpuEvent::Signal(..)));
    assert_eq!(cpu.pc(), CODE);
}

#[test]
fn linux_id_emulation_cannot_bypass_illegal_execution_state() {
    let mut cpu = user(&[mrs(0, 0, 0)], true);
    cpu.core_mut().set_x(0, 123);
    cpu.core_mut().set_el0_spsr(1 << 20);
    let CpuEvent::Signal(_, crate::user::linux::signal::frame::FaultUpdate::Arm64 { esr, .. }) =
        linux::run(&mut cpu, 1)
    else {
        panic!("illegal state must signal")
    };
    assert_eq!(esr >> 26, 0x0e);
    assert_eq!(
        (
            cpu.pc(),
            cpu.core().get_x(0),
            cpu.core().instruction_count()
        ),
        (CODE, 123, 0)
    );
}

#[test]
fn linux_xzr_destination_discards_the_id_value_and_fetch_faults_precede_emulation() {
    let mut cpu = user(&[mrs(0, 0, 31)], true);
    for index in 0u8..31 {
        cpu.core_mut().set_x(index, 0x1234 + u64::from(index));
    }
    let before: Vec<_> = (0u8..31).map(|index| cpu.core().get_x(index)).collect();
    assert_eq!(linux::run(&mut cpu, 1), CpuEvent::Yield);
    let after: Vec<_> = (0u8..31).map(|index| cpu.core().get_x(index)).collect();
    assert_eq!(before, after);
    assert_eq!((cpu.pc(), cpu.core().instruction_count()), (CODE + 4, 0));
    cpu.core_mut().set_pc(CODE + PAGE_SIZE);
    assert!(matches!(linux::run(&mut cpu, 1), CpuEvent::Signal(..)));
    assert_eq!(
        (cpu.pc(), cpu.core().instruction_count()),
        (CODE + PAGE_SIZE, 0)
    );
}

#[test]
fn architectural_id_writes_reject_before_modifying_private_register_storage() {
    for (crm, op2) in [
        (0, 0),
        (0, 5),
        (0, 6),
        (1, 0),
        (2, 0),
        (3, 0),
        (4, 0),
        (5, 0),
        (6, 0),
        (7, 0),
    ] {
        let word = mrs(crm, op2, 0) & !(1 << 21);
        let mut cpu = direct(word, 1);
        let before = crate::codec::serialize(&CoreCheckpoint::capture(&cpu).unwrap()).unwrap();
        assert!(matches!(cpu.step(), Err(ArmError::UndefinedInstruction(raw)) if raw == word));
        let after = crate::codec::serialize(&CoreCheckpoint::capture(&cpu).unwrap()).unwrap();
        assert_eq!(before, after, "{word:#010x} changed read-only ID state");
    }
}

#[cfg(all(feature = "smir-jit", target_arch = "aarch64"))]
#[test]
fn native_id_admission_cannot_bypass_the_architectural_fault() {
    for word in [
        mrs(0, 0, 0),
        mrs(0, 5, 0),
        mrs(3, 0, 0),
        mrs(4, 0, 0),
        0xd518_0000,
    ] {
        let mut cpu = direct(word, 0);
        assert!(
            cpu.jit_compile_region().is_none(),
            "ID access must stay outside legacy native regions"
        );
        cpu.jit.hot.insert(0, A64_JIT_HOT_THRESHOLD - 1);
        assert!(matches!(
            cpu.step_system_with_fault_exit(),
            Err(ArmError::InvalidExceptionLevel(0) | ArmError::UndefinedInstruction(_))
        ));
        assert_eq!(
            (cpu.pc, cpu.insn_count, cpu.jit.bounded_runs, cpu.get_x(0)),
            (0, 0, 0, 0x1122_3344_5566_7788)
        );
    }
}

#[test]
fn linux_emulated_id_fault_clears_the_exclusive_reservation() {
    // LDXR X0,[X1]; MRS X3,MIDR_EL1; STXR W2,X0,[X1].
    let mut cpu = user(&[0xc85f_7c20, mrs(0, 0, 3), 0xc802_7c20], true);
    let data = CODE + PAGE_SIZE;
    cpu.space()
        .map(
            data,
            PAGE_SIZE,
            Mapping::anonymous(Perms::READ | Perms::WRITE),
        )
        .unwrap();
    cpu.space().write(data, &41u64.to_le_bytes()).unwrap();
    cpu.core_mut().set_x(1, data);
    assert_eq!(linux::run(&mut cpu, 3), CpuEvent::Yield);
    assert_eq!(
        (
            cpu.pc(),
            cpu.core().instruction_count(),
            cpu.core().get_x(0),
            cpu.core().get_x(2)
        ),
        (CODE + 12, 2, 41, 1)
    );
    assert_ne!(cpu.core().get_x(3), 0);
}
