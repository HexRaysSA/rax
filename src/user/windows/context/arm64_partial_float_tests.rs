use super::tests::cpu;
use super::*;

#[test]
fn arm64_partial_floating_groups_preserve_the_other_bank_and_its_controls() {
    let observed: Vec<serde_json::Value> = serde_json::from_str(include_str!("../../../../docs/specifications/windows/native-compat-exception-entry/native-partial-floating-v1.json")).unwrap();
    let rows: Vec<_> = observed
        .iter()
        .filter(|row| row["kind"] == "vectors")
        .collect();
    assert_eq!(rows.len(), 8);
    for paired in [false, true] {
        for row in &rows {
            let selected = row["flags"].as_u64().unwrap() as u32;
            let mut cpu = cpu(if paired { WinArch::X64 } else { WinArch::Arm64 });
            if paired {
                cpu.enable_arm64ec().unwrap();
            }
            let mut initial = cpu.arm64_kernel_context().unwrap();
            initial.set_flags(CONTEXT_ARM64 | FLOATING_POINT_ARM64);
            for n in 0..32 {
                initial.set_v(n, (0x1020 + n as u128) | ((0x11220000 + n as u128) << 64));
            }
            initial.put32(arm64::FPCR, 1 << 22);
            initial.put32(arm64::FPSR, 1);
            cpu.apply_kernel_context(&initial).unwrap();
            let before = cpu.arm64_kernel_context().unwrap();
            let mut input = before.clone();
            input.set_flags(CONTEXT_ARM64 | selected);
            for n in 0..32 {
                input.set_v(n, (0x5060 + n as u128) | ((0x33440000 + n as u128) << 64));
            }
            input.put32(arm64::FPCR, 1 << 23);
            input.put32(arm64::FPSR, 2);
            cpu.apply_kernel_context(&input).unwrap();
            let after = cpu.arm64_kernel_context().unwrap();
            for n in 0..32 {
                let changed = selected & if n < 16 { 0x44 } else { 0x84 } != 0;
                let native = u128::from(row["low"][n].as_u64().unwrap())
                    | (u128::from(row["high"][n].as_u64().unwrap()) << 64);
                assert_eq!(
                    after.v(n),
                    native,
                    "paired={paired} flags={selected:#x} V{n}"
                );
                assert_eq!(after.v(n), if changed { input.v(n) } else { before.v(n) });
            }
            let low = selected & 0x44 != 0;
            for at in [arm64::FPCR, arm64::FPSR] {
                assert_eq!(
                    after.get32(at),
                    if low {
                        input.get32(at)
                    } else {
                        before.get32(at)
                    },
                    "paired={paired} flags={selected:#x} at={at}"
                );
            }
            assert_eq!(after.pc(), before.pc());
            assert_eq!(after.sp(), before.sp());
        }
    }
}

#[test]
fn arm64_partial_float_admission_does_not_admit_sve_or_amd64_xstate() {
    for arch in [WinArch::Arm64, WinArch::X64] {
        let mut cpu = cpu(arch);
        let before = RegContext::capture(&cpu);
        let mut input = before.clone();
        input.set_flags(
            RegContext::arch_flag(arch) | if arch == WinArch::Arm64 { 0x20 } else { 0x40 },
        );
        assert_eq!(input.apply(&mut cpu), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(RegContext::capture(&cpu), before);
    }
}
