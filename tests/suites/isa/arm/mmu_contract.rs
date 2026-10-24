//! Stage-1 contracts from Arm's AArch64.TranslationTableWalk pseudocode
//! (docs/architecture/arm/asl/arm_defs.asl), including hierarchical AP polarity,
//! descriptor legality, and output-address-size faults.

#[path = "mmu_contract/data_access.rs"]
mod data_access;
#[path = "mmu_contract/stack_alignment.rs"]
mod stack_alignment;

use rax::isa::arm::aarch64::mmu::{Mmu, MmuConfig, TranslationFaultType, TranslationGranule};
use rax::isa::arm::common::cpu::{AccessType, MemoryFaultType};
use rax::isa::arm::common::memory::ArmMemory;
use rax::isa::arm::{AArch64Config, AArch64Cpu, ArmCpu, ArmError, FlatMemory};

const GRANULES: [TranslationGranule; 3] = [
    TranslationGranule::Granule4KB,
    TranslationGranule::Granule16KB,
    TranslationGranule::Granule64KB,
];
const DATA: u64 = 0x80000;

fn tables(granule: TranslationGranule, table_ap: u64, leaf: u64) -> FlatMemory {
    let mut memory = FlatMemory::new(0, 0x100000);
    let bases: &[u64] = match granule {
        TranslationGranule::Granule4KB | TranslationGranule::Granule16KB => {
            &[0x10000, 0x20000, 0x30000, 0x40000]
        }
        TranslationGranule::Granule64KB => &[0x10000, 0x20000, 0x30000],
    };
    for (index, pair) in bases.windows(2).enumerate() {
        let attrs = if index == 0 { table_ap << 61 } else { 0 };
        memory.write_u64(pair[0], pair[1] | 3 | attrs).unwrap();
    }
    memory.write_u64(*bases.last().unwrap(), leaf).unwrap();
    memory
}

fn mmu(granule: TranslationGranule, pa_size: u8) -> Mmu {
    Mmu::with_config(MmuConfig {
        enabled: true,
        ttbr0: 0x10000,
        tg0: granule,
        tg1: granule,
        pa_size,
        mair: 0xff,
        ..MmuConfig::default()
    })
}

#[test]
fn hierarchical_ap_never_grants_el0_access() {
    for granule in GRANULES {
        for table_ap in 0..4 {
            for leaf_ap in 0..4 {
                let memory = tables(granule, table_ap, DATA | 0x403 | (leaf_ap << 6));
                let unit = mmu(granule, 48);
                for write in [false, true] {
                    let allowed = table_ap & 1 == 0
                        && leaf_ap & 1 != 0
                        && (!write || (table_ap & 2 == 0 && leaf_ap & 2 == 0));
                    let result = unit.translate(0, &memory, write, false, false, 0);
                    assert_eq!(
                        result.is_ok(),
                        allowed,
                        "{granule:?} table={table_ap} leaf={leaf_ap} write={write}"
                    );
                    if let Err(fault) = result {
                        assert_eq!(fault.fault_type, TranslationFaultType::Permission);
                        assert_eq!(fault.level, 3);
                    }
                }
            }
        }
    }
}

#[test]
fn hierarchical_read_only_applies_to_supervisor_writes() {
    for granule in GRANULES {
        for table_ap in 0..4 {
            for leaf_ap in 0..4 {
                let memory = tables(granule, table_ap, DATA | 0x403 | (leaf_ap << 6));
                let unit = mmu(granule, 48);
                assert!(unit.translate(0, &memory, false, false, true, 1).is_ok());
                let result = unit.translate(0, &memory, true, false, true, 1);
                assert_eq!(result.is_ok(), table_ap & 2 == 0 && leaf_ap & 2 == 0);
            }
        }
    }
}

#[test]
fn level_three_block_encoding_is_a_translation_fault() {
    for granule in GRANULES {
        for access_flag in [0, 1 << 10] {
            let memory = tables(granule, 0, DATA | access_flag | 1);
            let fault = mmu(granule, 48)
                .translate(0, &memory, false, false, true, 1)
                .unwrap_err();
            assert_eq!(fault.fault_type, TranslationFaultType::Translation);
            assert_eq!(fault.level, 3);
        }
    }
}

#[test]
fn el1_execute_never_applies_to_effectively_el0_writable_pages() {
    for granule in GRANULES {
        for table_ap in 0..4 {
            for leaf_ap in 0..4 {
                let memory = tables(granule, table_ap, DATA | 0x403 | (leaf_ap << 6));
                let result = mmu(granule, 48).translate(0, &memory, false, true, true, 1);
                let el0_writable = table_ap == 0 && leaf_ap == 1;
                // APTable[0] can remove EL0 access; APTable[1] can remove writes.
                assert_eq!(
                    result.is_ok(),
                    !el0_writable,
                    "{granule:?} table={table_ap} leaf={leaf_ap}"
                );
            }
        }
    }
}

#[test]
fn el0_fetch_is_independent_of_data_read_permission() {
    for granule in GRANULES {
        let memory = tables(granule, 0, DATA | 0x403);
        assert!(
            mmu(granule, 48)
                .translate(0, &memory, false, true, false, 0)
                .is_ok()
        );
    }
}

#[test]
fn output_address_width_is_checked_at_the_leaf() {
    for granule in GRANULES {
        for bits in [32, 36, 40, 42, 44] {
            let memory = tables(granule, 0, (1u64 << bits) | 0x403);
            let fault = mmu(granule, bits)
                .translate(0, &memory, false, false, true, 1)
                .unwrap_err();
            assert_eq!(fault.fault_type, TranslationFaultType::AddressSize);
            assert_eq!(fault.level, 3);
            assert!(
                mmu(granule, 48)
                    .translate(0, &memory, false, false, true, 1)
                    .is_ok()
            );
        }
    }
}

#[test]
fn output_address_width_is_checked_before_following_a_table() {
    for granule in GRANULES {
        let mut memory = tables(granule, 0, DATA | 0x403);
        memory.write_u64(0x10000, (1u64 << 40) | 0x20003).unwrap();
        let fault = mmu(granule, 32)
            .translate(0, &memory, false, false, true, 1)
            .unwrap_err();
        assert_eq!(fault.fault_type, TranslationFaultType::AddressSize);
        assert_eq!(
            fault.level,
            if matches!(granule, TranslationGranule::Granule64KB) {
                1
            } else {
                0
            }
        );
    }
}

#[test]
fn cpu_honors_tcr_ips_for_output_address_faults() {
    for ips in 0..6 {
        let memory = tables(TranslationGranule::Granule4KB, 0, (1u64 << 40) | 0x403);
        let mut cpu = AArch64Cpu::new(AArch64Config::default(), Box::new(memory));
        let mut regs = cpu.export_sregs();
        regs.sctlr_el1 = 1;
        regs.tcr_el1 = 16 | (16 << 16) | (2 << 30) | (ips << 32);
        regs.ttbr0_el1 = 0x10000;
        cpu.import_sregs(&regs).unwrap();
        let error = cpu.mem_read_u64(0).unwrap_err();
        let ArmError::MemoryError(info) = error else {
            panic!("unexpected error: {error:?}");
        };
        assert_eq!(
            info.fault_type == MemoryFaultType::AddressSize,
            ips <= 2,
            "IPS={ips}: {info:?}"
        );
    }
}

#[test]
fn el0_uses_the_el1_ttbr1_configuration() {
    let mut memory = tables(TranslationGranule::Granule4KB, 0, DATA | 0x443);
    memory.write_u64(DATA, 0x12345678).unwrap();
    let config = AArch64Config {
        initial_el: 0,
        ..AArch64Config::default()
    };
    let mut cpu = AArch64Cpu::new(config, Box::new(memory));
    let mut regs = cpu.export_sregs();
    regs.sctlr_el1 = 1;
    regs.tcr_el1 = 16 | (16 << 16) | (2 << 30) | (5 << 32);
    regs.ttbr1_el1 = 0x10000;
    cpu.import_sregs(&regs).unwrap();
    assert_eq!(cpu.mem_read_u64(0xffff000000000000).unwrap(), 0x12345678);
}

#[test]
fn ttbr_address_size_fault_precedes_any_table_fetch() {
    for granule in GRANULES {
        let memory = tables(granule, 0, DATA | 0x403);
        let mut unit = mmu(granule, 32);
        let mut config = unit.config().clone();
        config.ttbr0 |= 1u64 << 40;
        unit.set_config(config);
        let fault = unit
            .translate(0, &memory, false, false, true, 1)
            .unwrap_err();
        assert_eq!(fault.fault_type, TranslationFaultType::AddressSize);
        assert_eq!(fault.level, 0);
        assert_eq!(fault.va, 0);
    }
}

#[test]
fn non_lpa_64k_descriptor_address_bits_are_not_silently_discarded() {
    let granule = TranslationGranule::Granule64KB;
    for bit in 12..16 {
        let memory = tables(granule, 0, DATA | 0x403 | (1 << bit));
        let fault = mmu(granule, 48)
            .translate(0, &memory, false, false, true, 1)
            .unwrap_err();
        assert_eq!(fault.fault_type, TranslationFaultType::AddressSize);
        assert_eq!(fault.level, 3);
    }
}

#[test]
fn leaf_and_hierarchical_execute_never_restrictions_are_preserved() {
    for granule in GRANULES {
        for bit in [53, 54, 59, 60] {
            let table_bit = if bit >= 59 { 1u64 << bit } else { 0 };
            let leaf_bit = if bit < 59 { 1u64 << bit } else { 0 };
            let mut memory = tables(granule, 0, DATA | 0x4c3 | leaf_bit);
            memory.write_u64(0x10000, 0x20003 | table_bit).unwrap();
            for privileged in [false, true] {
                let denied = if privileged {
                    matches!(bit, 53 | 59)
                } else {
                    matches!(bit, 54 | 60)
                };
                let result = mmu(granule, 48).translate(
                    0,
                    &memory,
                    false,
                    true,
                    privileged,
                    if privileged { 1 } else { 0 },
                );
                assert_eq!(
                    result.is_err(),
                    denied,
                    "{granule:?} bit={bit} privileged={privileged}"
                );
            }
        }
    }
}

#[test]
fn cpu_preserves_instruction_fetch_fault_classification() {
    let mut memory = tables(TranslationGranule::Granule4KB, 0, DATA | 0x443);
    memory.write_u32(DATA, 0xd503201f).unwrap();
    let mut cpu = AArch64Cpu::new(AArch64Config::default(), Box::new(memory));
    let mut regs = cpu.export_sregs();
    regs.sctlr_el1 = 1;
    regs.tcr_el1 = 16 | (16 << 16) | (2 << 30) | (5 << 32);
    regs.ttbr0_el1 = 0x10000;
    cpu.import_sregs(&regs).unwrap();
    cpu.set_pc(0);
    let Err(ArmError::MemoryError(info)) = cpu.step() else {
        panic!("expected an instruction permission fault");
    };
    assert_eq!(info.fault_type, MemoryFaultType::Permission);
    assert_eq!(info.access, AccessType::InstructionFetch);
    assert_eq!(info.address, 0);
    cpu.step_system().unwrap();
    let regs = cpu.export_sregs();
    assert_eq!((regs.esr_el1 >> 26) & 0x3f, 0x21);
    assert_eq!(regs.esr_el1 & 0x3f, 0x0f);
    assert_eq!(regs.far_el1, 0);
    assert_eq!(regs.elr_el1, 0);
}

#[test]
fn cpu_selects_el2_el3_ps_and_el2_host_ips_fields() {
    use rax::isa::arm::ArmFeatures;

    for (el, op1, host) in [(2, 4, false), (2, 4, true), (3, 6, false)] {
        for ps in [0u64, 5] {
            let memory = tables(TranslationGranule::Granule4KB, 0, (1u64 << 40) | 0x403);
            let mut config = AArch64Config {
                initial_el: el,
                ..AArch64Config::default()
            };
            config.features |= ArmFeatures::VHE;
            let mut cpu = AArch64Cpu::new(config, Box::new(memory));
            // A non-secure EL2 host regime requires EL2 to be enabled.
            let mut controls = cpu.pauth_controls();
            controls.scr_el3 |= 1;
            cpu.set_pauth_controls(controls).unwrap();
            // MSR S3_op1_Cn_Cm_op2, X0; encoding fields from Arm's MSR definition.
            let msr = |op1: u32, crn: u32, crm: u32, op2: u32| {
                0xd5000000u32 | (3 << 19) | (op1 << 16) | (crn << 12) | (crm << 8) | (op2 << 5)
            };
            let tcr = if host {
                16 | (16 << 16) | (2 << 30) | (ps << 32)
            } else {
                16 | (ps << 16)
            };
            let mut writes = Vec::new();
            if el == 2 {
                writes.push((msr(4, 1, 1, 0), if host { 1u64 << 34 } else { 0 }));
            }
            writes.extend([
                (msr(op1, 2, 0, 2), tcr),
                (msr(op1, 2, 0, 0), 0x10000),
                (msr(op1, 1, 0, 0), 1),
            ]);
            for (index, (word, value)) in writes.into_iter().enumerate() {
                let pc = 0x800 + index as u64 * 4;
                cpu.write_memory(pc, &word.to_le_bytes()).unwrap();
                cpu.set_pc(pc);
                cpu.set_x(0, value);
                cpu.step().unwrap();
            }
            let Err(ArmError::MemoryError(info)) = cpu.mem_read_u64(0) else {
                panic!("expected a translation or PA-size failure");
            };
            assert_eq!(
                info.fault_type == MemoryFaultType::AddressSize,
                ps == 0,
                "EL{el} host={host} PS={ps}: {info:?}"
            );
        }
    }
}
