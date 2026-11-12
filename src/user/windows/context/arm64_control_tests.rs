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
fn windows_arm64_initial_status_and_thread_copy_keep_their_own_os_invariant() {
    let cpu = cpu(WinArch::Arm64);
    assert_eq!(cpu.a64().unwrap().core().el0_spsr(), 0x40);
    assert_eq!(cpu.new_thread().a64().unwrap().core().el0_spsr(), 0x40);
    let neutral = crate::user::cpu::aarch64::A64UserCpu::new(cpu.a64().unwrap().space());
    assert_eq!(neutral.core().el0_spsr(), 0);
}
