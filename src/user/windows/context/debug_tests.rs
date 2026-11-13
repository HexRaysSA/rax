use super::tests::cpu;
use super::*;

#[test]
fn arm64_control_context_matches_native_cpsr_sanitization_and_fiq_mask() {
    let profile: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../docs/specifications/windows/native-arm64-context/profile-29704-v1.json"
    ))
    .unwrap();
    for paired in [false, true] {
        let mut cpu = cpu(if paired { WinArch::X64 } else { WinArch::Arm64 });
        if paired {
            cpu.enable_arm64ec().unwrap();
        }
        for row in profile["pstate"].as_array().unwrap() {
            let input = row["input"].as_u64().unwrap() as u32;
            let expected = row["observed"].as_u64().unwrap() as u32;
            assert_eq!(row["set_ok"], 1);
            let mut context = cpu.arm64_kernel_context().unwrap();
            context.set_flags(CONTEXT_ARM64 | CONTROL);
            context.put32(arm64::CPSR, input);
            cpu.apply_kernel_context(&context).unwrap();
            let result = cpu.arm64_kernel_context().unwrap();
            assert_eq!(
                result.flags_register(),
                expected,
                "paired={paired}, input={input:#010x}"
            );
            // An unselected CONTROL group must retain all current PSTATE.
            let mut unselected = result.clone();
            unselected.set_flags(CONTEXT_ARM64 | INTEGER);
            unselected.put32(arm64::CPSR, !input);
            cpu.apply_kernel_context(&unselected).unwrap();
            assert_eq!(
                cpu.arm64_kernel_context().unwrap().flags_register(),
                expected
            );
        }
    }
}

#[test]
fn kernel_context_groups_preserve_x18_payload_and_independent_api_selection() {
    for arch in WinArch::ALL {
        let mut cpu = cpu(arch);
        let ordinary = RegContext::capture(&cpu);
        let kernel = RegContext::capture_kernel(&cpu);
        if arch == WinArch::Arm64 {
            assert_eq!(ordinary.flags(), 0x0040_001f);
            assert_eq!(kernel.flags(), 0x0040_000f);
            assert_eq!(kernel.gpr(18), ordinary.gpr(18));
            let teb = cpu.teb();
            let mut changed = kernel.clone();
            changed.set_gpr(18, teb + 16);
            changed.apply(&mut cpu).unwrap();
            assert_eq!(cpu.teb(), teb);
            changed.set_flags(CONTEXT_ARM64 | ARM64_X18);
            changed.apply(&mut cpu).unwrap();
            assert_eq!(cpu.teb(), teb + 16);
        } else {
            assert_eq!(kernel, ordinary, "{arch}");
        }
    }
}

#[test]
fn windows_arm64_initial_status_and_thread_copy_keep_their_own_os_invariant() {
    let cpu = cpu(WinArch::Arm64);
    assert_eq!(cpu.a64().unwrap().core().el0_spsr(), 0x40);
    assert_eq!(cpu.new_thread().a64().unwrap().core().el0_spsr(), 0x40);
    let neutral = crate::user::cpu::aarch64::A64UserCpu::new(cpu.a64().unwrap().space());
    assert_eq!(neutral.core().el0_spsr(), 0);
}

fn group(arch: WinArch) -> (u32, std::ops::Range<usize>) {
    match arch {
        WinArch::X86 => (16, 4..28),
        WinArch::X64 => (16, 72..120),
        WinArch::Arm64 => (8, 792..912),
    }
}

fn armed(cpu: &mut WinCpu, arch: WinArch) -> Vec<u8> {
    let mut bytes = vec![0; group(arch).1.len()];
    if arch == WinArch::Arm64 {
        bytes[..4].copy_from_slice(&0x1e5u32.to_le_bytes());
        bytes[32..40].copy_from_slice(&0x10000u64.to_le_bytes());
    } else {
        let width = arch.ptr_size() as usize;
        bytes[..width].copy_from_slice(&0x10000u64.to_le_bytes()[..width]);
        bytes[5 * width..6 * width].copy_from_slice(&0x401u64.to_le_bytes()[..width]);
    }
    cpu.apply_kernel_debug_context(arch, &bytes, 1 << 47)
        .unwrap();
    cpu.kernel_debug_context(arch).unwrap()
}

#[test]
fn exception_context_captures_the_debug_bank_for_every_architecture() {
    for arch in WinArch::ALL {
        let mut cpu = cpu(arch);
        let expected = armed(&mut cpu, arch);
        let context = RegContext::capture(&cpu);
        let (bit, range) = group(arch);
        assert_ne!(context.flags() & bit, 0, "{arch}");
        assert_eq!(&context.bytes()[range], expected, "{arch}");
    }
}

#[test]
fn exception_context_debug_restore_is_selected_and_transactional() {
    for arch in WinArch::ALL {
        let mut cpu = cpu(arch);
        let expected = armed(&mut cpu, arch);
        let original = RegContext::capture(&cpu);
        let (bit, range) = group(arch);
        let mut bytes = original.bytes().to_vec();
        bytes[range].fill(0);
        let mut context = RegContext::from_bytes(arch, bytes);
        context.set_flags(RegContext::arch_flag(arch) | bit);
        context.set_gpr(0, 0xdead);
        context.apply(&mut cpu).unwrap();
        assert_eq!(cpu.gpr(0), original.gpr(0), "unselected integer {arch}");
        let cleared = cpu.kernel_debug_context(arch).unwrap();
        assert_ne!(cleared, expected, "{arch}");
        let mut context = original.clone();
        context.set_flags(RegContext::arch_flag(arch) | INTEGER);
        context.set_gpr(0, 0xbeef);
        context.apply(&mut cpu).unwrap();
        assert_eq!(cpu.kernel_debug_context(arch).unwrap(), cleared, "{arch}");
        original.apply(&mut cpu).unwrap();
        assert_eq!(cpu.kernel_debug_context(arch).unwrap(), expected, "{arch}");
        if arch != WinArch::Arm64 {
            let before = RegContext::capture(&cpu);
            let mut bad = before.clone();
            bad.bytes[group(arch).1].fill(0);
            let offset = if arch == WinArch::X86 {
                x86::EXTENDED + 24
            } else {
                x64::MXCSR
            };
            bad.put32(offset, 0x1_0000);
            assert_eq!(bad.apply(&mut cpu), Err(STATUS_INVALID_PARAMETER));
            assert_eq!(RegContext::capture(&cpu), before);
        }
    }
}
