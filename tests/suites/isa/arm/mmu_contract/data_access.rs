//! Cross-page accesses use each virtual page's translation, not adjacent PAs.

use super::*;
use rax::isa::arm::common::memory::StandardMemory;

const SECOND: u64 = 0xa0000;

fn cpu_with_pages(second: u64, alignment: bool) -> AArch64Cpu {
    translated_cpu(TranslationGranule::Granule4KB, second, alignment, false)
}

fn translated_cpu(
    granule: TranslationGranule,
    second: u64,
    alignment: bool,
    big_endian: bool,
) -> AArch64Cpu {
    let seed = tables(granule, 0, DATA | 0x403);
    let mut memory = StandardMemory::new();
    memory.add_ram_with_data(0, seed.data().to_vec());
    memory.set_require_alignment(false);
    let last = if granule == TranslationGranule::Granule64KB {
        0x30000
    } else {
        0x40000
    };
    memory.write_u64(last + 8, second).unwrap();
    if big_endian {
        let addresses: &[u64] = if granule == TranslationGranule::Granule64KB {
            &[0x10000, 0x20000, 0x30000, 0x30008]
        } else {
            &[0x10000, 0x20000, 0x30000, 0x40000, 0x40008]
        };
        let entries: Vec<_> = addresses
            .iter()
            .map(|&address| (address, memory.read_u64(address).unwrap()))
            .collect();
        memory.set_big_endian(true);
        for (address, value) in entries {
            memory.write_u64(address, value).unwrap();
        }
    }
    let tg0 = match granule {
        TranslationGranule::Granule4KB => 0,
        TranslationGranule::Granule16KB => 2,
        TranslationGranule::Granule64KB => 1,
    };
    let mut cpu = AArch64Cpu::new(AArch64Config::default(), Box::new(memory));
    let mut regs = cpu.export_sregs();
    regs.sctlr_el1 = 1 | if alignment { 2 } else { 0 };
    regs.tcr_el1 = 16 | (tg0 << 14) | (16 << 16) | (2 << 30) | (5 << 32);
    regs.ttbr0_el1 = 0x10000;
    regs.mair_el1 = 0xff;
    cpu.import_sregs(&regs).unwrap();
    cpu
}

// ArmCpu's public memory API is virtual. Disable translation only while
// preparing or inspecting the physical backing of this test machine.
fn physical_write(cpu: &mut AArch64Cpu, pa: u64, bytes: &[u8]) {
    let saved = cpu.export_sregs();
    let mut disabled = saved.clone();
    disabled.sctlr_el1 &= !1;
    cpu.import_sregs(&disabled).unwrap();
    cpu.write_memory(pa, bytes).unwrap();
    cpu.import_sregs(&saved).unwrap();
}

fn physical_read(cpu: &mut AArch64Cpu, pa: u64, size: usize) -> Vec<u8> {
    let saved = cpu.export_sregs();
    let mut disabled = saved.clone();
    disabled.sctlr_el1 &= !1;
    cpu.import_sregs(&disabled).unwrap();
    let bytes = cpu.read_memory(pa, size).unwrap();
    cpu.import_sregs(&saved).unwrap();
    bytes
}

fn read(cpu: &AArch64Cpu, va: u64, width: usize) -> Result<u64, ArmError> {
    match width {
        2 => cpu.mem_read_u16(va).map(u64::from),
        4 => cpu.mem_read_u32(va).map(u64::from),
        8 => cpu.mem_read_u64(va),
        _ => panic!("invalid test width"),
    }
}

fn write(cpu: &mut AArch64Cpu, va: u64, width: usize, value: u64) -> Result<(), ArmError> {
    match width {
        2 => cpu.mem_write_u16(va, value as u16),
        4 => cpu.mem_write_u32(va, value as u32),
        8 => cpu.mem_write_u64(va, value),
        _ => panic!("invalid test width"),
    }
}

#[test]
fn reads_follow_noncontiguous_virtual_pages_at_every_scalar_split() {
    for width in [2, 4, 8] {
        for first in 1..width {
            let va = 0x1000 - first as u64;
            let mut cpu = cpu_with_pages(SECOND | 0x403, false);
            let bytes = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
            physical_write(&mut cpu, DATA + va, &bytes[..first]);
            physical_write(&mut cpu, DATA + 0x1000, &[0xaa; 8]);
            physical_write(&mut cpu, SECOND, &bytes[first..width]);
            let mut expected = [0; 8];
            expected[..width].copy_from_slice(&bytes[..width]);
            assert_eq!(
                read(&cpu, va, width).unwrap(),
                u64::from_le_bytes(expected),
                "width={width} split={first}"
            );
        }
    }
}

#[test]
fn writes_follow_noncontiguous_virtual_pages_at_every_scalar_split() {
    for width in [2, 4, 8] {
        for first in 1..width {
            let va = 0x1000 - first as u64;
            let mut cpu = cpu_with_pages(SECOND | 0x403, false);
            let value = 0x8877665544332211;
            write(&mut cpu, va, width, value).unwrap();
            let bytes = u64::to_le_bytes(value);
            assert_eq!(physical_read(&mut cpu, DATA + va, first), &bytes[..first]);
            assert_eq!(
                physical_read(&mut cpu, SECOND, width - first),
                &bytes[first..width]
            );
            assert_eq!(
                physical_read(&mut cpu, DATA + 0x1000, width - first),
                vec![0; width - first]
            );
        }
    }
}

#[test]
fn missing_second_page_faults_at_its_virtual_address() {
    for width in [2, 4, 8] {
        for first in 1..width {
            let mut cpu = cpu_with_pages(0, false);
            let va = 0x1000 - first as u64;
            let Err(ArmError::MemoryError(info)) = read(&cpu, va, width) else {
                panic!("read must fault");
            };
            assert_eq!(info.address, 0x1000);
            assert_eq!(info.access, AccessType::Read);
            assert_eq!(info.fault_type, MemoryFaultType::Translation);
            let Err(ArmError::MemoryError(info)) = write(&mut cpu, va, width, 1) else {
                panic!("write must fault");
            };
            assert_eq!(info.address, 0x1000);
            assert_eq!(info.access, AccessType::Write);
            assert_eq!(info.fault_type, MemoryFaultType::Translation);
        }
    }
}

#[test]
fn second_page_write_permission_is_checked_before_touching_it() {
    let mut cpu = cpu_with_pages(SECOND | 0x483, false);
    physical_write(&mut cpu, SECOND, &[0x77; 8]);
    let Err(ArmError::MemoryError(info)) = cpu.mem_write_u64(0xffc, 0x1122334455667788) else {
        panic!("store must fault");
    };
    assert_eq!(info.address, 0x1000);
    assert_eq!(info.access, AccessType::Write);
    assert_eq!(info.fault_type, MemoryFaultType::Permission);
    assert_eq!(physical_read(&mut cpu, SECOND, 8), [0x77; 8]);
}

#[test]
fn failed_cross_page_ldr_preserves_the_destination_and_fault_pc() {
    let mut cpu = cpu_with_pages(0, false);
    physical_write(&mut cpu, DATA, &0xf9400020u32.to_le_bytes());
    cpu.set_pc(0);
    cpu.set_x(0, 0xfeedface);
    cpu.set_x(1, 0xffc);
    let Err(ArmError::MemoryError(info)) = cpu.step() else {
        panic!("LDR must fault");
    };
    assert_eq!(info.address, 0x1000);
    assert_eq!(cpu.get_x(0), 0xfeedface);
    assert_eq!(cpu.get_pc(), 0);
}

#[test]
fn sctlr_a_controls_ordinary_data_alignment() {
    for width in [2, 4, 8] {
        for alignment in [false, true] {
            let mut cpu = cpu_with_pages(SECOND | 0x403, alignment);
            let result = read(&cpu, 0x201, width);
            assert_eq!(result.is_err(), alignment, "width={width} A={alignment}");
            if let Err(ArmError::MemoryError(info)) = result {
                assert_eq!(info.address, 0x201);
                assert_eq!(info.fault_type, MemoryFaultType::Alignment);
                assert_eq!(info.access, AccessType::Read);
            }
            let result = write(&mut cpu, 0x201, width, 1);
            assert_eq!(result.is_err(), alignment, "width={width} A={alignment}");
            if let Err(ArmError::MemoryError(info)) = result {
                assert_eq!(info.address, 0x201);
                assert_eq!(info.fault_type, MemoryFaultType::Alignment);
                assert_eq!(info.access, AccessType::Write);
            }
        }
    }
}

#[test]
fn alignment_check_precedes_a_translation_fault() {
    let mut cpu = cpu_with_pages(0, true);
    for write_access in [false, true] {
        let result = if write_access {
            cpu.mem_write_u64(0x1001, 1)
        } else {
            cpu.mem_read_u64(0x1001).map(|_| ())
        };
        let Err(ArmError::MemoryError(info)) = result else {
            panic!("unaligned access must fault");
        };
        assert_eq!(info.address, 0x1001);
        assert_eq!(info.fault_type, MemoryFaultType::Alignment);
    }
}

#[test]
fn alignment_control_applies_with_translation_disabled() {
    let mut cpu = cpu_with_pages(0, true);
    let mut regs = cpu.export_sregs();
    regs.sctlr_el1 &= !1;
    cpu.import_sregs(&regs).unwrap();
    assert!(
        matches!(cpu.mem_read_u64(0x101), Err(ArmError::MemoryError(info))
        if info.fault_type == MemoryFaultType::Alignment)
    );
    assert!(
        matches!(cpu.mem_write_u64(0x101, 1), Err(ArmError::MemoryError(info))
        if info.fault_type == MemoryFaultType::Alignment && info.access == AccessType::Write)
    );
}

#[test]
fn device_mapping_requires_natural_alignment_with_a_clear() {
    let mut cpu = cpu_with_pages(SECOND | 0x403, false);
    let mut regs = cpu.export_sregs();
    regs.mair_el1 = 0;
    cpu.import_sregs(&regs).unwrap();
    for width in [2, 4, 8] {
        assert!(read(&cpu, 0x200, width).is_ok());
        assert!(
            matches!(read(&cpu, 0x201, width), Err(ArmError::MemoryError(info))
            if info.fault_type == MemoryFaultType::Alignment)
        );
    }
}

#[test]
fn all_granules_and_backend_byte_orders_follow_both_mappings() {
    for granule in GRANULES {
        for big_endian in [false, true] {
            for width in [2, 4, 8] {
                for first in 1..width {
                    let mut cpu = translated_cpu(granule, SECOND | 0x403, false, big_endian);
                    let va = granule.page_size() - first as u64;
                    let value = 0x8877665544332211;
                    let encoded = if big_endian {
                        u64::to_be_bytes(value)
                    } else {
                        u64::to_le_bytes(value)
                    };
                    let bytes = if big_endian {
                        &encoded[8 - width..]
                    } else {
                        &encoded[..width]
                    };
                    physical_write(&mut cpu, DATA + va, &bytes[..first]);
                    physical_write(&mut cpu, SECOND, &bytes[first..]);
                    let mask = u64::MAX >> ((8 - width) * 8);
                    assert_eq!(
                        read(&cpu, va, width).unwrap(),
                        value & mask,
                        "{granule:?} big_endian={big_endian} width={width} split={first}"
                    );
                    write(&mut cpu, va, width, !value).unwrap();
                    let expected: Vec<_> = bytes.iter().map(|byte| !byte).collect();
                    assert_eq!(physical_read(&mut cpu, DATA + va, first), expected[..first]);
                    assert_eq!(
                        physical_read(&mut cpu, SECOND, width - first),
                        expected[first..]
                    );
                }
            }
        }
    }
}

#[test]
fn physical_backing_faults_preserve_virtual_address_and_access_intent() {
    let mut cpu = cpu_with_pages(0x100000 | 0x403, false);
    for write_access in [false, true] {
        let result = if write_access {
            cpu.mem_write_u64(0x1200, 1)
        } else {
            cpu.mem_read_u64(0x1200).map(|_| ())
        };
        let Err(ArmError::MemoryError(info)) = result else {
            panic!("physical backing must fault");
        };
        assert_eq!(info.address, 0x1200);
        assert_eq!(info.fault_type, MemoryFaultType::External);
        assert_eq!(
            info.access,
            if write_access {
                AccessType::Write
            } else {
                AccessType::Read
            }
        );
    }
}
