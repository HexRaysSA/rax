//! `rax.h` is the hand-written source of truth for the ABI; the Rust
//! constants must mirror it exactly.
use crate::arch::RAX_MODE_USER;
use crate::hook::RAX_HOOK_SYSCALL;
use crate::run::RAX_STOP_SYSCALL;
use crate::user::*;

const HEADER: &str = include_str!("../../include/rax.h");

/// The value of a simple `#define NAME value` in `rax.h`: a decimal or hex
/// literal with an optional `u` suffix, or `(1u << n)`.
fn define(name: &str) -> u64 {
    let line = HEADER
        .lines()
        .find(|line| {
            let mut words = line.split_whitespace();
            words.next() == Some("#define") && words.next() == Some(name)
        })
        .unwrap_or_else(|| panic!("{name} is not defined in rax.h"));
    let value = line
        .split_whitespace()
        .skip(2)
        .take_while(|word| !word.starts_with("/*"))
        .collect::<String>();
    let literal = |text: &str| -> u64 {
        let text = text.trim_end_matches(['u', 'U']);
        match text.strip_prefix("0x") {
            Some(hex) => u64::from_str_radix(hex, 16).unwrap(),
            None => text.parse().unwrap(),
        }
    };
    match value
        .strip_prefix("(1u<<")
        .and_then(|v| v.strip_suffix(')'))
    {
        Some(shift) => 1 << literal(shift),
        None => literal(&value),
    }
}

#[test]
fn abi_1_5_constants_match_the_header() {
    assert_eq!(define("RAX_API_MINOR"), u64::from(crate::RAX_API_MINOR));
    assert_eq!(define("RAX_MODE_USER"), u64::from(RAX_MODE_USER));
    assert_eq!(define("RAX_STOP_SYSCALL"), RAX_STOP_SYSCALL as u64);
    assert_eq!(define("RAX_HOOK_SYSCALL"), u64::from(RAX_HOOK_SYSCALL));
    for (name, value) in [
        ("RAX_SYSCALL_INSN_SYSCALL", RAX_SYSCALL_INSN_SYSCALL),
        ("RAX_SYSCALL_INSN_SYSENTER", RAX_SYSCALL_INSN_SYSENTER),
        ("RAX_SYSCALL_INSN_SVC", RAX_SYSCALL_INSN_SVC),
        ("RAX_SYSCALL_INSN_ECALL", RAX_SYSCALL_INSN_ECALL),
        ("RAX_EXCEPTION_INFO_VERSION", RAX_EXCEPTION_INFO_VERSION),
        ("RAX_EXCEPTION_VALID", RAX_EXCEPTION_VALID),
        ("RAX_EXCEPTION_SYNDROME", RAX_EXCEPTION_SYNDROME),
        ("RAX_EXCEPTION_SOFTWARE", RAX_EXCEPTION_SOFTWARE),
    ] {
        assert_eq!(define(name), u64::from(value), "{name}");
    }
}

#[test]
fn new_register_ids_match_the_header() {
    use crate::reg::rax_reg_size;
    let x86 = crate::arch::RaxArch::X86 as i32;
    let arm64 = crate::arch::RaxArch::Arm64 as i32;
    let riscv = crate::arch::RaxArch::Riscv64 as i32;
    let cortexm = crate::arch::RaxArch::CortexM as i32;
    for (name, arch, width) in [
        ("RAX_X86_REG_KERNEL_GS_BASE", x86, 8),
        ("RAX_X86_REG_TSC_AUX", x86, 4),
        ("RAX_X86_REG_PKRU", x86, 4),
        ("RAX_X86_REG_TR_ATTR", x86, 4),
        ("RAX_X86_REG_LDTR_ATTR", x86, 4),
        ("RAX_X86_REG_FPCW", x86, 2),
        ("RAX_X86_REG_FPSW", x86, 2),
        ("RAX_X86_REG_FPTAG", x86, 2),
        ("RAX_X86_REG_FOP", x86, 2),
        ("RAX_X86_REG_FIP", x86, 8),
        ("RAX_X86_REG_FDP", x86, 8),
        ("RAX_X86_REG_MXCSR", x86, 4),
        ("RAX_ARM64_REG_TPIDR_EL0", arm64, 8),
        ("RAX_ARM64_REG_TPIDRRO_EL0", arm64, 8),
        ("RAX_ARM64_REG_TPIDR_EL1", arm64, 8),
        ("RAX_ARM64_REG_SP_EL0", arm64, 8),
        ("RAX_ARM64_REG_SP_EL1", arm64, 8),
        ("RAX_ARM64_REG_ELR_EL1", arm64, 8),
        ("RAX_ARM64_REG_SPSR_EL1", arm64, 8),
        ("RAX_ARM64_REG_ESR_EL1", arm64, 8),
        ("RAX_ARM64_REG_FAR_EL1", arm64, 8),
        ("RAX_ARM64_REG_VBAR_EL1", arm64, 8),
        ("RAX_ARM64_REG_SCTLR_EL1", arm64, 8),
        ("RAX_ARM64_REG_TCR_EL1", arm64, 8),
        ("RAX_ARM64_REG_TTBR0_EL1", arm64, 8),
        ("RAX_ARM64_REG_TTBR1_EL1", arm64, 8),
        ("RAX_ARM64_REG_MAIR_EL1", arm64, 8),
        ("RAX_ARM64_REG_CNTP_CTL_EL0", arm64, 8),
        ("RAX_ARM64_REG_CNTP_CVAL_EL0", arm64, 8),
        ("RAX_ARM64_REG_CNTV_CTL_EL0", arm64, 8),
        ("RAX_ARM64_REG_CNTV_CVAL_EL0", arm64, 8),
        ("RAX_RISCV_REG_PRIV", riscv, 1),
        ("RAX_CM_REG_VTOR", cortexm, 4),
        ("RAX_CM_REG_CCR", cortexm, 4),
        ("RAX_CM_REG_SHCSR", cortexm, 4),
        ("RAX_CM_REG_CFSR", cortexm, 4),
        ("RAX_CM_REG_HFSR", cortexm, 4),
        ("RAX_CM_REG_BFAR", cortexm, 4),
        ("RAX_CM_REG_AIRCR", cortexm, 4),
        ("RAX_CM_REG_SHPR1", cortexm, 4),
        ("RAX_CM_REG_SHPR2", cortexm, 4),
        ("RAX_CM_REG_SHPR3", cortexm, 4),
    ] {
        assert_eq!(rax_reg_size(arch, define(name) as i32), width, "{name}");
    }
    for family in [
        "#define RAX_X86_ST(i)            (0x1200 + (i))",
        "#define RAX_X86_SEG_ATTR(i)      (0x1300 + (i))",
        "#define RAX_ARM_D(i)    (0x0300 + (i))",
        "#define RAX_ARM_Q(i)    (0x0400 + (i))",
        "#define RAX_RISCV_V(i)       (0x0300 + (i))",
        "#define RAX_RISCV_CSR(n)     (0x1000 + (n))",
    ] {
        assert!(HEADER.contains(family), "{family}");
    }
}

#[test]
fn exception_record_layout_matches_the_header() {
    use std::mem::{offset_of, size_of};
    assert_eq!(size_of::<RaxExceptionInfo>(), 40);
    assert_eq!(offset_of!(RaxExceptionInfo, vector), 8);
    assert_eq!(offset_of!(RaxExceptionInfo, flags), 12);
    assert_eq!(offset_of!(RaxExceptionInfo, pc), 16);
    assert_eq!(offset_of!(RaxExceptionInfo, return_pc), 24);
    assert_eq!(offset_of!(RaxExceptionInfo, syndrome), 32);
}

#[test]
fn process_abi_constants_match_the_header() {
    use crate::process::*;
    for (name, value) in [
        ("RAX_PROCESS_RESULT_VERSION", RAX_PROCESS_RESULT_VERSION),
        ("RAX_PROCESS_READY", RAX_PROCESS_READY),
        ("RAX_PROCESS_BUDGET", RAX_PROCESS_BUDGET),
        ("RAX_PROCESS_BLOCKED", RAX_PROCESS_BLOCKED),
        ("RAX_PROCESS_CANCELLED", RAX_PROCESS_CANCELLED),
        ("RAX_PROCESS_EXITED", RAX_PROCESS_EXITED),
        ("RAX_PROCESS_FAILED", RAX_PROCESS_FAILED),
        ("RAX_PROCESS_TIMEOUT", RAX_PROCESS_TIMEOUT),
        ("RAX_PROCESS_STDOUT", RAX_PROCESS_STDOUT),
        ("RAX_PROCESS_STDERR", RAX_PROCESS_STDERR),
    ] {
        assert_eq!(define(name), u64::from(value), "{name}");
    }
    assert_eq!(std::mem::size_of::<RaxProcessResult>(), 32);
    assert_eq!(std::mem::offset_of!(RaxProcessResult, turns_started), 16);
    assert_eq!(std::mem::offset_of!(RaxProcessResult, elapsed_us), 24);
}
