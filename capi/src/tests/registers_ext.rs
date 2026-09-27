//! Register ids added in ABI 1.5: x87/SSE control state and MSRs kept in the
//! engine's extended x86 state, x86 segment access rights, AArch64 system
//! registers, and AArch32 doubleword/quadword views.
use super::*;

const RBX: i32 = 0x0103;
const RFLAGS: i32 = 0x0012;
const AL: i32 = 0x0400;
const DS: i32 = 0x0603;
const X86_ST0: i32 = 0x1200;
const FPCW: i32 = 0x1210;
const FPSW: i32 = 0x1211;
const FPTAG: i32 = 0x1212;
const FOP: i32 = 0x1213;
const FIP: i32 = 0x1214;
const FDP: i32 = 0x1215;
const MXCSR: i32 = 0x1216;
const KERNEL_GS_BASE: i32 = 0x100B;
const TSC_AUX: i32 = 0x100C;
const PKRU: i32 = 0x100D;
const SEG_ATTR_CS: i32 = 0x1301;
const SEG_ATTR_DS: i32 = 0x1303;
const TR_ATTR: i32 = 0x110A;
const LDTR_ATTR: i32 = 0x110B;

fn bits80(significand: u64, sign_exponent: u16) -> [u8; 10] {
    let mut raw = [0u8; 10];
    raw[..8].copy_from_slice(&significand.to_le_bytes());
    raw[8..].copy_from_slice(&sign_exponent.to_le_bytes());
    raw
}

unsafe fn read_bytes(e: *mut Engine, id: i32) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let mut n = 0usize;
    assert_eq!(rax_reg_read(e, id, buf.as_mut_ptr(), &mut n), RaxStatus::Ok);
    buf[..n].to_vec()
}

/// Runs `[pc, until)` and checks it stopped at `until`. (A guest halt would
/// leave the vCPU halted for later runs.)
unsafe fn run(e: *mut Engine, pc: u64, until: u64) {
    assert_eq!(rax_emu_start(e, pc, until, 0, 0), RaxStatus::Ok);
    let mut x = ExitInfo::none();
    assert_eq!(rax_emu_last_exit(e, &mut x), RaxStatus::Ok);
    assert_eq!((x.reason, x.address), (RAX_STOP_UNTIL, until));
}

#[test]
fn x87_stack_and_control_state_are_exact() {
    let e = open_x86();
    unsafe {
        // fld1 ; fldpi
        write(e, 0x1000, &[0xD9, 0xE8, 0xD9, 0xEB]);
        run(e, 0x1000, 0x1004);
        assert_eq!(rd_u64(e, FPCW), 0x037F);
        // Two pushes from TOP 0 leave TOP = 6 (Intel SDM Vol. 1 §8.1.3.1).
        assert_eq!(rd_u64(e, FPSW) & 0x3800, 6 << 11);
        // FLDPI rounds pi to nearest: 0xC90FDAA22168C235 * 2^(0x4000 - 16383 - 63).
        assert_eq!(
            read_bytes(e, X86_ST0),
            bits80(0xC90F_DAA2_2168_C235, 0x4000)
        );
        assert_eq!(read_bytes(e, X86_ST0 + 1), bits80(1 << 63, 0x3FFF));
        // R6 and R7 valid (00), R0-R5 empty (11).
        assert_eq!(rd_u64(e, FPTAG), 0x0FFF);
        // FOP is the low three bits of the first opcode byte and the second
        // byte; FIP addresses the last x87 instruction.
        assert_eq!(rd_u64(e, FOP), 0x1EB);
        assert_eq!(rd_u64(e, FIP), 0x1002);
        let _ = rd_u64(e, FDP);

        // ST(0) := 2.5 and ST(2) (empty R0) := +0.0, then fstp qword [rbx].
        let two_and_half = bits80(0xA000_0000_0000_0000, 0x4000);
        assert_eq!(
            rax_reg_write(e, X86_ST0, two_and_half.as_ptr()),
            RaxStatus::Ok
        );
        let zero = [0u8; 10];
        assert_eq!(rax_reg_write(e, X86_ST0 + 2, zero.as_ptr()), RaxStatus::Ok);
        // R0 is now tagged zero (01); R6/R7 stay valid.
        assert_eq!(rd_u64(e, FPTAG), 0x0FFD);
        write(e, 0x2000, &[0xDD, 0x1B]); // fstp qword [rbx]
        assert_eq!(rax_reg_write_u64(e, RBX, 0x3000), RaxStatus::Ok);
        run(e, 0x2000, 0x2002);
        let mut stored = [0u8; 8];
        assert_eq!(
            rax_mem_read(e, 0x3000, stored.as_mut_ptr(), 8),
            RaxStatus::Ok
        );
        assert_eq!(f64::from_le_bytes(stored), 2.5);
        assert_eq!(rd_u64(e, FPSW) & 0x3800, 7 << 11);

        // Writing FPSW moves TOP, and ST(i) follows it.
        assert_eq!(rax_reg_write_u64(e, FPSW, 0), RaxStatus::Ok);
        assert_eq!(rd_u64(e, FPSW), 0);
        assert_eq!(read_bytes(e, X86_ST0), zero, "ST(0) is now R0");
    }
    rax_engine_close(e);
}

#[test]
fn mxcsr_is_validated_and_guest_visible() {
    let e = open_x86();
    unsafe {
        assert_eq!(rax_reg_size(RaxArch::X86 as i32, MXCSR), 4);
        assert_eq!(rd_u64(e, MXCSR), 0x1F80);
        // Round toward zero (RC = 11).
        assert_eq!(rax_reg_write_u64(e, MXCSR, 0x7F80), RaxStatus::Ok);
        write(e, 0x1000, &[0x0F, 0xAE, 0x1B]); // stmxcsr [rbx]
        assert_eq!(rax_reg_write_u64(e, RBX, 0x3000), RaxStatus::Ok);
        run(e, 0x1000, 0x1003);
        let mut stored = [0u8; 4];
        assert_eq!(
            rax_mem_read(e, 0x3000, stored.as_mut_ptr(), 4),
            RaxStatus::Ok
        );
        assert_eq!(u32::from_le_bytes(stored), 0x7F80);
        // LDMXCSR would #GP on a reserved bit; the register write refuses it.
        assert_eq!(rax_reg_write_u64(e, MXCSR, 0x1_1F80), RaxStatus::Arg);
        assert_eq!(rd_u64(e, MXCSR), 0x7F80);
    }
    rax_engine_close(e);
}

#[test]
fn extended_msrs_round_trip_and_reach_the_guest() {
    let e = open_x86();
    unsafe {
        for (id, value, width) in [
            (KERNEL_GS_BASE, 0xFFFF_8000_1234_5000u64, 8),
            (TSC_AUX, 0x0000_0007, 4),
            (PKRU, 0x5555_5554, 4),
        ] {
            assert_eq!(rax_reg_size(RaxArch::X86 as i32, id), width);
            assert_eq!(rax_reg_write_u64(e, id, value), RaxStatus::Ok);
            assert_eq!(rd_u64(e, id), value);
        }
        // RDTSCP returns IA32_TSC_AUX in ECX.
        write(e, 0x1000, &[0x0F, 0x01, 0xF9]);
        run(e, 0x1000, 0x1003);
        assert_eq!(rd_u64(e, RCX), 7);
    }
    rax_engine_close(e);
}

#[test]
fn segment_access_rights_use_the_vmx_layout_and_take_effect() {
    let e = open_x86();
    unsafe {
        for id in [SEG_ATTR_CS, SEG_ATTR_DS, TR_ATTR, LDTR_ATTR] {
            assert_eq!(rax_reg_size(RaxArch::X86 as i32, id), 4);
        }
        assert_eq!(rax_reg_size(RaxArch::X86 as i32, 0x1306), 0);
        // Flat 64-bit code: type 0xB, S, P, L, G. Flat data: type 3, S, P, D/B, G.
        assert_eq!(rd_u64(e, SEG_ATTR_CS), 0xA09B);
        assert_eq!(rd_u64(e, SEG_ATTR_DS), 0xC093);
        // Reserved bits are ignored and read as zero.
        assert_eq!(
            rax_reg_write_u64(e, SEG_ATTR_DS, 0xFFFF_FFFF),
            RaxStatus::Ok
        );
        assert_eq!(rd_u64(e, SEG_ATTR_DS), 0x1_F0FF);
        assert_eq!(rax_reg_write_u64(e, SEG_ATTR_DS, 0xC093), RaxStatus::Ok);
        assert_eq!(rd_u64(e, DS) & 0xFFFF, 0x10, "the selector is unchanged");

        // L = 0, D = 1 in long mode selects compatibility mode, where 0x40 is
        // INC EAX rather than a REX prefix: 40 90.
        write(e, 0x1000, &[0x40, 0x90]);
        assert_eq!(rax_reg_write_u64(e, RAX, 41), RaxStatus::Ok);
        run(e, 0x1000, 0x1002);
        assert_eq!(rd_u64(e, RAX), 41, "64-bit mode: REX + NOP");
        assert_eq!(rax_reg_write_u64(e, SEG_ATTR_CS, 0xC09B), RaxStatus::Ok);
        run(e, 0x1000, 0x1002);
        assert_eq!(rd_u64(e, RAX), 42, "compatibility mode: INC EAX ; NOP");
    }
    rax_engine_close(e);
}

#[test]
fn rflags_writes_replace_lazily_computed_flags() {
    let e = open_x86();
    unsafe {
        // xor eax,eax (ZF=1, PF=1, CF=0)
        write(e, 0x1000, &[0x31, 0xC0]);
        run(e, 0x1000, 0x1002);
        // ZF and PF set, CF and SF clear.
        assert_eq!(rd_u64(e, RFLAGS) & 0xC5, 0x44);
        // CF=1, ZF=0 must stick even though the last ALU result is pending.
        assert_eq!(rax_reg_write_u64(e, RFLAGS, 0x203), RaxStatus::Ok);
        assert_eq!(rd_u64(e, RFLAGS), 0x203);
        write(e, 0x2000, &[0x0F, 0x92, 0xC0]); // setc al
        run(e, 0x2000, 0x2003);
        assert_eq!(rd_u64(e, AL), 1);
    }
    rax_engine_close(e);
}

// AArch64 system register ids.
const A64_SP: i32 = 0x0010;
const A64_PSTATE: i32 = 0x0012;
const A64_TPIDR_EL0: i32 = 0x0400;
const A64_TPIDRRO_EL0: i32 = 0x0401;
const A64_SP_EL0: i32 = 0x0403;
const A64_SP_EL1: i32 = 0x0404;
const A64_CNTV_CVAL_EL0: i32 = 0x0412;

fn open_arm64() -> *mut Engine {
    let mut e = ptr::null_mut();
    assert_eq!(
        rax_engine_open(RaxArch::Arm64 as i32, 0, &mut e),
        RaxStatus::Ok
    );
    e
}

#[test]
fn arm64_system_registers_round_trip() {
    let e = open_arm64();
    unsafe {
        for id in A64_TPIDR_EL0..=A64_CNTV_CVAL_EL0 {
            assert_eq!(rax_reg_size(RaxArch::Arm64 as i32, id), 8, "{id:#x}");
            // The timer control registers keep ENABLE and IMASK only.
            let value = if id == 0x040F || id == 0x0411 {
                3
            } else {
                0x0123_4567_0000_0000 | id as u64
            };
            if id == A64_SP_EL0 || id == A64_SP_EL1 {
                continue;
            }
            assert_eq!(rax_reg_write_u64(e, id, value), RaxStatus::Ok, "{id:#x}");
            assert_eq!(rd_u64(e, id), value, "{id:#x}");
        }
        assert_eq!(rax_reg_size(RaxArch::Arm64 as i32, 0x0413), 0);
    }
    rax_engine_close(e);
}

#[test]
fn arm64_banked_stack_pointers_follow_pstate() {
    let e = open_arm64();
    unsafe {
        // EL1h: SP is SP_EL1.
        assert_eq!(rax_reg_write_u64(e, A64_PSTATE, 0x3C5), RaxStatus::Ok);
        assert_eq!(rax_reg_write_u64(e, A64_SP_EL0, 0x7000), RaxStatus::Ok);
        assert_eq!(rax_reg_write_u64(e, A64_SP_EL1, 0x8000), RaxStatus::Ok);
        assert_eq!(rd_u64(e, A64_SP), 0x8000);
        assert_eq!(rd_u64(e, A64_SP_EL0), 0x7000);
        // Writing SP writes the selected bank only.
        assert_eq!(rax_reg_write_u64(e, A64_SP, 0x8800), RaxStatus::Ok);
        assert_eq!(rd_u64(e, A64_SP_EL1), 0x8800);
        assert_eq!(rd_u64(e, A64_SP_EL0), 0x7000);
        // EL1t: SP is SP_EL0.
        assert_eq!(rax_reg_write_u64(e, A64_PSTATE, 0x3C4), RaxStatus::Ok);
        assert_eq!(rd_u64(e, A64_SP), 0x7000);
        assert_eq!(rax_reg_write_u64(e, A64_SP_EL0, 0x7100), RaxStatus::Ok);
        assert_eq!(rd_u64(e, A64_SP), 0x7100);
        assert_eq!(rd_u64(e, A64_SP_EL1), 0x8800);
    }
    rax_engine_close(e);
}

#[test]
fn arm64_thread_pointers_are_guest_visible() {
    let e = open_arm64();
    unsafe {
        // mrs x0, tpidr_el0 ; mrs x1, tpidrro_el0
        let code: Vec<u8> = [0xD53B_D040u32, 0xD53B_D061]
            .iter()
            .flat_map(|i| i.to_le_bytes())
            .collect();
        write(e, 0x1000, &code);
        assert_eq!(rax_reg_write_u64(e, A64_TPIDR_EL0, 0x1111), RaxStatus::Ok);
        assert_eq!(rax_reg_write_u64(e, A64_TPIDRRO_EL0, 0x2222), RaxStatus::Ok);
        run(e, 0x1000, 0x1008);
        assert_eq!(rd_u64(e, ARM64_X0), 0x1111);
        assert_eq!(rd_u64(e, ARM64_X0 + 1), 0x2222);
    }
    rax_engine_close(e);
}

// AArch32 ids.
const ARM_S0: i32 = 0x0200;
const ARM_D0: i32 = 0x0300;
const ARM_Q0: i32 = 0x0400;

#[test]
fn arm32_doubleword_and_quadword_views_alias_the_register_file() {
    let mut e = ptr::null_mut();
    assert_eq!(
        rax_engine_open(RaxArch::Arm as i32, crate::arch::RAX_MODE_ARM, &mut e),
        RaxStatus::Ok
    );
    unsafe {
        assert_eq!(rax_reg_size(RaxArch::Arm as i32, ARM_D0 + 31), 8);
        assert_eq!(rax_reg_size(RaxArch::Arm as i32, ARM_D0 + 32), 0);
        assert_eq!(rax_reg_size(RaxArch::Arm as i32, ARM_Q0 + 15), 16);
        assert_eq!(rax_reg_size(RaxArch::Arm as i32, ARM_Q0 + 16), 0);
        // D0 is S1:S0.
        assert_eq!(rax_reg_write_u64(e, ARM_S0, 0x1111_1111), RaxStatus::Ok);
        assert_eq!(rax_reg_write_u64(e, ARM_S0 + 1, 0x2222_2222), RaxStatus::Ok);
        assert_eq!(rd_u64(e, ARM_D0), 0x2222_2222_1111_1111);
        // Q8 is D17:D16, above the single-precision file.
        assert_eq!(
            rax_reg_write_u64(e, ARM_D0 + 16, 0xAAAA_0000_BBBB_0000),
            RaxStatus::Ok
        );
        assert_eq!(
            rax_reg_write_u64(e, ARM_D0 + 17, 0xCCCC_0000_DDDD_0000),
            RaxStatus::Ok
        );
        let mut q8 = 0xAAAA_0000_BBBB_0000u64.to_le_bytes().to_vec();
        q8.extend_from_slice(&0xCCCC_0000_DDDD_0000u64.to_le_bytes());
        assert_eq!(read_bytes(e, ARM_Q0 + 8), q8);
        // Writing Q1 writes S4-S7.
        let q1: Vec<u8> = (1u8..=16).collect();
        assert_eq!(rax_reg_write(e, ARM_Q0 + 1, q1.as_ptr()), RaxStatus::Ok);
        assert_eq!(rd_u64(e, ARM_S0 + 4), 0x0403_0201);
        assert_eq!(rd_u64(e, ARM_S0 + 7), 0x100F_0E0D);
        assert_eq!(rd_u64(e, ARM_D0 + 3), 0x100F_0E0D_0C0B_0A09);
    }
    rax_engine_close(e);
}
