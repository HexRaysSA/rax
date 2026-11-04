use rax::isa::arm::aarch64::{AArch64Config, AArch64Cpu};
use rax::isa::arm::common::cpu::{ArmCpu, ArmError, CpuExit};
use rax::isa::arm::common::memory::FlatMemory;
use rax::isa::arm::common::sysreg::Aarch64SysRegEncoding;
fn cpu(raw: u32, thumb: bool, enabled: bool, trapped: bool) -> AArch64Cpu {
    let mut cpu = AArch64Cpu::new(
        AArch64Config {
            initial_el: 3,
            gic_config: None,
            ..Default::default()
        },
        Box::new(FlatMemory::new(0, 0x4000)),
    );
    let mut state = cpu.export_sregs();
    let sys = &mut state.execution.as_mut().unwrap().sysregs;
    sys.scr_el3 = 0;
    sys.hcr_el2 = 0;
    sys.el1.cpacr = if enabled { 3 << 20 } else { 0 };
    sys.impl_defined.insert(
        Aarch64SysRegEncoding::new(3, 6, 1, 1, 2).encode(),
        if trapped { 1 << 10 } else { 0 },
    );
    sys.impl_defined.insert(
        Aarch64SysRegEncoding::new(3, 4, 5, 3, 0).encode(),
        if enabled { 1 << 30 } else { 0 },
    );
    cpu.import_sregs(&state).unwrap();
    cpu.set_pstate_bits(0x1d3 | u64::from(thumb) << 5).unwrap();
    cpu.set_pc(0x100);
    for i in 0..31 {
        cpu.set_x(
            i,
            0x1133557700000000 | u64::from(0x10203040u32.wrapping_mul(u32::from(i) + 1)),
        );
    }
    cpu.set_x(0, 0x1133557710203040);
    cpu.set_x(12, 0x1133557750607080);
    cpu.set_x(18, 0x1133557790a0b0c0);
    for i in 0..32 {
        cpu.set_simd(
            i,
            0x12345678abcdef01fedcba9887654321u128.rotate_left(u32::from(i)),
        );
    }
    for i in 0..16 {
        let lo = 0x8877665590f0b180u64 ^ (u64::from(2 * i) * 0x0101010101010101);
        let hi = 0x8877665590f0b180u64 ^ (u64::from(2 * i + 1) * 0x0101010101010101);
        cpu.set_simd(i, u128::from(lo) | (u128::from(hi) << 64));
    }
    cpu.set_fpsr_value(0xa800009f);
    cpu.set_fpcr_value(0);
    let bytes = if thumb {
        [(raw >> 16) as u16, raw as u16]
            .into_iter()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>()
    } else {
        raw.to_le_bytes().to_vec()
    };
    cpu.write_memory(0x100, &bytes).unwrap();
    cpu
}
fn main() {
    let directory = std::path::PathBuf::from(std::env::args().nth(1).unwrap());
    let cases: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.join("cases.json")).unwrap()).unwrap();
    let data = std::fs::read(directory.join("results.bin")).unwrap();
    let mut valid = 0;
    for (index, case) in cases.as_array().unwrap().iter().enumerate() {
        let raw = case["raw"].as_u64().unwrap() as u32;
        let thumb = case["thumb"].as_bool().unwrap();
        let rt = case["rt"].as_u64().unwrap() as u8;
        let mut cpu = cpu(raw, thumb, true, false);
        let physical = if rt == 14 { 18 } else { rt };
        cpu.set_x(physical, 0x11335577dead89a5);
        let mut x = std::array::from_fn::<_, 31, _>(|i| cpu.get_x(i as u8));
        let mut v = std::array::from_fn::<_, 32, _>(|i| cpu.get_simd(i as u8));
        let record = &data[index * 280..(index + 1) * 280];
        for (offset, physical) in [(8, 0u8), (12, 12), (16, 18)] {
            let value = u32::from_le_bytes(record[offset..offset + 4].try_into().unwrap());
            x[physical as usize] = (x[physical as usize] & 0xffffffff00000000) | u64::from(value);
        }
        for i in 0..16 {
            v[i] = u128::from_le_bytes(record[24 + i * 16..40 + i * 16].try_into().unwrap());
        }
        let psr = cpu.pstate_bits();
        assert_eq!(
            cpu.step().unwrap(),
            CpuExit::Continue,
            "{index}/{raw:08x}/{thumb}"
        );
        assert_eq!(
            std::array::from_fn::<_, 31, _>(|i| cpu.get_x(i as u8)),
            x,
            "X {index}/{raw:08x}/{thumb}"
        );
        assert_eq!(
            std::array::from_fn::<_, 32, _>(|i| cpu.get_simd(i as u8)),
            v,
            "V {index}/{raw:08x}/{thumb}"
        );
        assert_eq!(cpu.fpsr_value(), 0xa800009f);
        assert_eq!(cpu.fpcr_value(), 0);
        assert_eq!(cpu.pstate_bits(), psr);
        assert_eq!(cpu.get_pc(), 0x104);
        assert_eq!(cpu.instruction_count(), 1);
        valid += 1;
    }
    let forms = [
        0xee000a10u32,
        0xee100a10,
        0xee000b10,
        0xee100b10,
        0xee000b30,
        0xee100b30,
        0xee900b30,
        0xee400b10,
        0xee500b10,
        0xeed00b10,
    ];
    let mut invalid = 0;
    let mut skipped = 0;
    for thumb in [false, true] {
        for enabled in [false, true] {
            for trapped in [false, true] {
                for word in forms {
                    let raw = word | 0xf000;
                    let mut cpu = cpu(raw, thumb, enabled, trapped);
                    let x = std::array::from_fn::<_, 31, _>(|i| cpu.get_x(i as u8));
                    let v = std::array::from_fn::<_, 32, _>(|i| cpu.get_simd(i as u8));
                    let sys = cpu.export_sregs();
                    let psr = cpu.pstate_bits();
                    assert!(
                        matches!(cpu.step(), Err(ArmError::UndefinedInstruction(_))),
                        "{raw:08x}/{thumb}/{enabled}/{trapped}"
                    );
                    assert_eq!(cpu.get_pc(), 0x100);
                    assert_eq!(cpu.instruction_count(), 0);
                    assert_eq!(cpu.export_sregs(), sys);
                    assert_eq!(std::array::from_fn::<_, 31, _>(|i| cpu.get_x(i as u8)), x);
                    assert_eq!(
                        std::array::from_fn::<_, 32, _>(|i| cpu.get_simd(i as u8)),
                        v
                    );
                    assert_eq!(cpu.pstate_bits(), psr);
                    invalid += 1;
                }
            }
        }
    }
    for thumb in [false, true] {
        for word in forms {
            let raw = if thumb {
                word | 0xf000
            } else {
                (word & 0xfffffff) | 0xf000
            };
            let mut cpu = cpu(raw, thumb, false, true);
            if thumb {
                cpu.set_pstate_bits(cpu.pstate_bits() | 0x800).unwrap();
            }
            let x = std::array::from_fn::<_, 31, _>(|i| cpu.get_x(i as u8));
            let v = std::array::from_fn::<_, 32, _>(|i| cpu.get_simd(i as u8));
            assert_eq!(cpu.step().unwrap(), CpuExit::Continue);
            assert_eq!(cpu.get_pc(), 0x104);
            assert_eq!(cpu.instruction_count(), 1);
            assert_eq!(std::array::from_fn::<_, 31, _>(|i| cpu.get_x(i as u8)), x);
            assert_eq!(
                std::array::from_fn::<_, 32, _>(|i| cpu.get_simd(i as u8)),
                v
            );
            skipped += 1;
        }
    }
    println!("MIXED valid={valid} invalid={invalid} skipped={skipped}");
}
