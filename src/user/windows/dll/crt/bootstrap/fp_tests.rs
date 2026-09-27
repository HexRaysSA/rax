//! Pinned publisher FP-reset effects and retained fault phases, not native parity.
//!
//! Primary body receipts are under docs/specifications/windows/crt-bootstrap/
//! publisher/ucrtbase-{x86,x64,arm64}-disassembly.json. The x86 converter emits
//! raw FLDCW operand 0x023F; no hardware readback guarantee is inferred for
//! reserved FCW bit 6. Intel SDM 086 Vol. 2A FNINIT/FLDCW defines the preserved
//! binary80 payloads and the distinction between waiting and nonwaiting control.

use super::super::RuntimeKind;
use super::super::tests::{area, int, invoke, run, void};
use crate::isa::arm::common::cpu::ArmCpu;
use crate::user::mm::{Mapping, PAGE_SIZE, Perms};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Cont, Ctx, Flow};
use crate::user::windows::memory::{Mem, MemFault, mem, prot};

const U: RuntimeKind = RuntimeKind::Ucrt;
const OLD_STATUS: u32 = 0x91A2_B3C4;
const OLD_TAG: u32 = 0xB1B2_C3D4;

fn span(c: &mut Ctx, bytes: u64) -> u64 {
    c.p.vm
        .allocate(None, bytes, mem::RESERVE | mem::COMMIT, prot::READWRITE)
        .unwrap()
        .0
}

fn slot(c: &mut Ctx) -> u64 {
    let first = int(invoke(c, U, "__pxcptinfoptrs", &[]));
    assert_eq!(int(invoke(c, U, "__pxcptinfoptrs", &[])), first);
    first
}

fn retry(result: ApiResult, address: u64, write: bool) -> Cont {
    match result.unwrap() {
        Flow::RetryFault { fault, retry } => {
            assert_eq!(
                fault,
                MemFault {
                    addr: address,
                    write
                }
            );
            retry
        }
        _ => panic!("expected the exact retained FP-reset fault phase"),
    }
}

fn binary80(significand: u64, sign_exponent: u16) -> [u8; 10] {
    let mut raw = [0; 10];
    raw[..8].copy_from_slice(&significand.to_le_bytes());
    raw[8..].copy_from_slice(&sign_exponent.to_le_bytes());
    raw
}

fn physical_payloads() -> [[u8; 10]; 8] {
    [
        binary80(0, 0),
        binary80(0, 0x8000),
        binary80(1, 0),
        binary80(u64::MAX, 0x7FFE),
        binary80(0x8000_0000_0000_0000, 0x7FFF),
        binary80(0xC000_0000_0000_0123, 0xFFFF),
        binary80(0x8000_0000_0000_0123, 0x7FFF),
        binary80(0x1234_5678_9ABC_DEF0, 0x3FFF),
    ]
}

fn pattern(index: usize) -> u64 {
    0xA55A_39C6_817E_02FDu64
        .rotate_left(index as u32)
        .wrapping_add((index as u64).wrapping_mul(0x1020_3040_5060_7081))
}

/// Seed through public CPU state/FXRSTOR interfaces, never private FpuState.
fn poison_x86(c: &mut Ctx, top: usize) -> Vec<u8> {
    let core = c.t.cpu.x86_mut().unwrap().vcpu_mut();
    let r = core.user_regs_mut();
    for (index, register) in [
        &mut r.rax, &mut r.rbx, &mut r.rcx, &mut r.rdx, &mut r.rsi, &mut r.rdi, &mut r.rsp,
        &mut r.rbp, &mut r.r8, &mut r.r9, &mut r.r10, &mut r.r11, &mut r.r12, &mut r.r13,
        &mut r.r14, &mut r.r15, &mut r.r16, &mut r.r17, &mut r.r18, &mut r.r19, &mut r.r20,
        &mut r.r21, &mut r.r22, &mut r.r23, &mut r.r24, &mut r.r25, &mut r.r26, &mut r.r27,
        &mut r.r28, &mut r.r29, &mut r.r30, &mut r.r31,
    ]
    .into_iter()
    .enumerate()
    {
        *register = pattern(index);
    }
    r.rip = pattern(32);
    r.rflags = 0x0024_0247;
    r.xmm = std::array::from_fn(|i| std::array::from_fn(|j| pattern(40 + i * 2 + j)));
    r.ymm_high = std::array::from_fn(|i| std::array::from_fn(|j| pattern(80 + i * 2 + j)));
    r.zmm_high = std::array::from_fn(|i| std::array::from_fn(|j| pattern(120 + i * 4 + j)));
    r.zmm_ext = std::array::from_fn(|i| std::array::from_fn(|j| pattern(200 + i * 8 + j)));
    r.k = std::array::from_fn(|i| pattern(340 + i));
    r.mm = std::array::from_fn(|i| {
        u64::from_le_bytes(physical_payloads()[i][..8].try_into().unwrap())
    });
    let mut image = core.xsave_image(3).bytes;
    image[0..2].copy_from_slice(&0x0040u16.to_le_bytes());
    image[2..4].copy_from_slice(&(0xC7FFu16 | ((top as u16) << 11)).to_le_bytes());
    image[4] = 0xA5;
    image[6..8].copy_from_slice(&0x07FFu16.to_le_bytes());
    image[8..16].copy_from_slice(&0x1234_5678_9ABC_DEF0u64.to_le_bytes());
    image[16..24].copy_from_slice(&0xFEDC_BA98_7654_3210u64.to_le_bytes());
    image[24..28].copy_from_slice(&0xDFC5u32.to_le_bytes());
    let raw = physical_payloads();
    // FXSAVE/FXRSTOR slots are logical ST(i), whereas FTW bits are physical.
    for logical in 0..8 {
        let at = 32 + logical * 16;
        image[at..at + 10].copy_from_slice(&raw[(top + logical) & 7]);
    }
    core.fxrstor_image(&image).unwrap();
    core.xsave_image(3).bytes
}

fn fp_image(c: &Ctx) -> Vec<u8> {
    c.t.cpu.x86().unwrap().vcpu().xsave_image(3).bytes
}

fn registers(c: &Ctx) -> serde_json::Value {
    serde_json::to_value(c.t.cpu.x86().unwrap().vcpu().user_regs()).unwrap()
}

fn expected_x86_reset(mut before: Vec<u8>) -> Vec<u8> {
    // This raw u16 golden is the selected converter operand, not a silicon
    // assertion about reserved-bit readback (Intel SDM Vol. 1 section 1.3.2).
    before[0..2].copy_from_slice(&0x023Fu16.to_le_bytes());
    before[2..5].fill(0);
    before[6..24].fill(0);
    before[24..28].copy_from_slice(&0x1F80u32.to_le_bytes());
    for (physical, raw) in physical_payloads().iter().enumerate() {
        let at = 32 + physical * 16;
        before[at..at + 10].copy_from_slice(raw);
    }
    before
}

fn context(c: &Ctx, at: u64, flags: u32) -> Vec<u8> {
    let mut bytes: Vec<_> = (0..0x80).map(|i| 0xA5u8.wrapping_add(i)).collect();
    bytes[0..4].copy_from_slice(&flags.to_le_bytes());
    bytes[0x20..0x24].copy_from_slice(&OLD_STATUS.to_le_bytes());
    bytes[0x24..0x28].copy_from_slice(&OLD_TAG.to_le_bytes());
    c.mem().wr(at, &bytes).unwrap();
    bytes
}

fn attach(c: &mut Ctx, at: u64) -> (u64, u64) {
    let slot = slot(c);
    let info = area(c);
    c.mem().w32(info, 0xDEAD_BEEF).unwrap(); // ExceptionRecord is not loaded.
    c.mem().w32(info + 4, at as u32).unwrap();
    c.mem().w32(slot, info as u32).unwrap();
    (slot, info)
}

#[test]
fn fpreset_architectural_effects_and_payload_preservation_all_abis() {
    run(|c| {
        let slot = slot(c);
        c.mem().wptr(slot, c.psize(), 0).unwrap();
        if c.arch() == WinArch::Arm64 {
            for flags in 0..16 {
                let core = c.t.cpu.a64_mut().unwrap().core_mut();
                for index in 0..31 {
                    core.set_x(index, pattern(index as usize));
                }
                for index in 0..32 {
                    core.set_simd(
                        index,
                        u128::from(pattern(index as usize))
                            | (u128::from(pattern(40 + index as usize)) << 64),
                    );
                }
                core.set_fpcr_value(0x07C8_0007);
                core.set_fpsr_value(0xF800_009F);
                core.set_nzcv(
                    flags & 8 != 0,
                    flags & 4 != 0,
                    flags & 2 != 0,
                    flags & 1 != 0,
                );
                let vectors: Vec<_> = (0..32).map(|i| core.get_simd(i)).collect();
                let gprs: Vec<_> = (0..31).map(|i| core.get_x(i)).collect();
                let sp = core.current_sp();
                let pc = core.get_pc();
                void(invoke(c, U, "_fpreset", &[]));
                let core = c.t.cpu.a64().unwrap().core();
                assert_eq!(core.fpcr_value(), 0);
                assert_eq!(core.fpsr_value(), 0);
                assert_eq!(
                    (0..32).map(|i| core.get_simd(i)).collect::<Vec<_>>(),
                    vectors
                );
                assert_eq!((0..31).map(|i| core.get_x(i)).collect::<Vec<_>>(), gprs);
                assert_eq!(core.current_sp(), sp);
                assert_eq!(core.get_pc(), pc);
                assert_eq!(
                    (core.get_n(), core.get_z(), core.get_c(), core.get_v()),
                    (
                        flags & 8 != 0,
                        flags & 4 != 0,
                        flags & 2 != 0,
                        flags & 1 != 0
                    )
                );
            }
        } else {
            for top in 0..8 {
                let before = poison_x86(c, top);
                let before_regs = registers(c);
                void(invoke(c, U, "_fpreset", &[]));
                let mut expected = before;
                if c.arch() == WinArch::X86 {
                    expected = expected_x86_reset(expected);
                } else {
                    expected[24..28].copy_from_slice(&0x1F80u32.to_le_bytes());
                }
                assert_eq!(fp_image(c), expected, "{:?}, TOP={top}", c.arch());
                assert_eq!(registers(c), before_regs);
            }
        }
    });
}

#[test]
fn fpreset_win64_ignores_nonnull_and_unreadable_exception_slot() {
    run(|c| {
        if c.arch() == WinArch::X86 {
            return;
        }
        let slot = slot(c);
        c.mem().w64(slot, u64::MAX).unwrap();
        let page = slot & !(PAGE_SIZE - 1);
        c.p.vm.protect(page, PAGE_SIZE, prot::NOACCESS).unwrap();
        if c.arch() == WinArch::X64 {
            let mut expected = poison_x86(c, 7);
            expected[24..28].copy_from_slice(&0x1F80u32.to_le_bytes());
            void(invoke(c, U, "_fpreset", &[]));
            assert_eq!(fp_image(c), expected);
        } else {
            let core = c.t.cpu.a64_mut().unwrap().core_mut();
            core.set_fpcr_value(0x07C8_0007);
            core.set_fpsr_value(0xF800_009F);
            void(invoke(c, U, "_fpreset", &[]));
            let core = c.t.cpu.a64().unwrap().core();
            assert_eq!((core.fpcr_value(), core.fpsr_value()), (0, 0));
        }
        c.p.vm.protect(page, PAGE_SIZE, prot::READWRITE).unwrap();
        assert_eq!(c.mem().u64(slot).unwrap(), u64::MAX);
    });
}

#[test]
fn fpreset_x86_any_flag_bit_predicate_and_exact_saved_dword_writes() {
    run(|c| {
        if c.arch() != WinArch::X86 {
            return;
        }
        let at = area(c);
        attach(c, at);
        for (flags, clears) in [
            (0, false),
            (1, false),
            (0x8000_0000, false),
            (8, true),
            (0x0001_0000, true),
            (0x0001_0008, true),
        ] {
            let mut expected = context(c, at, flags);
            if clears {
                expected[0x20..0x24].fill(0);
                expected[0x24..0x28].copy_from_slice(&0xFFFFu32.to_le_bytes());
            }
            let before = poison_x86(c, 3);
            void(invoke(c, U, "_fpreset", &[]));
            assert_eq!(fp_image(c), expected_x86_reset(before));
            assert_eq!(c.mem().bytes(at, 0x80).unwrap(), expected);
        }
    });
}

#[test]
fn fpreset_x86_ptd_slot_read_fault_precedes_reset() {
    run(|c| {
        if c.arch() != WinArch::X86 {
            return;
        }
        let slot = slot(c);
        let page = slot & !(PAGE_SIZE - 1);
        let original = poison_x86(c, 6);
        c.p.vm.protect(page, PAGE_SIZE, prot::NOACCESS).unwrap();
        let then = retry(invoke(c, U, "_fpreset", &[]), slot, false);
        assert_eq!(fp_image(c), original, "PTD snapshot must precede FNINIT");
        c.p.vm.protect(page, PAGE_SIZE, prot::READWRITE).unwrap();
        c.mem().w32(slot, 0).unwrap();
        let repaired = poison_x86(c, 2);
        void(then(c, 0));
        assert_eq!(fp_image(c), expected_x86_reset(repaired));
    });
}

#[test]
fn fpreset_x86_info_read_retry_keeps_snapshot_and_does_not_repeat_reset() {
    run(|c| {
        if c.arch() != WinArch::X86 {
            return;
        }
        let at = area(c);
        let expected = context(c, at, 0x0001_0000);
        let (slot, info) = attach(c, at);
        c.p.vm.protect(info, PAGE_SIZE, prot::NOACCESS).unwrap();
        let original = poison_x86(c, 1);
        let then = retry(invoke(c, U, "_fpreset", &[]), info + 4, false);
        assert_eq!(fp_image(c), expected_x86_reset(original));
        c.p.vm.protect(info, PAGE_SIZE, prot::READWRITE).unwrap();
        c.mem().w32(slot, 0xFFFF_FFFF).unwrap();
        let repaired = poison_x86(c, 7);
        void(then(c, 0));
        assert_eq!(fp_image(c), repaired);
        let mut expected = expected;
        expected[0x20..0x24].fill(0);
        expected[0x24..0x28].copy_from_slice(&0xFFFFu32.to_le_bytes());
        assert_eq!(c.mem().bytes(at, 0x80).unwrap(), expected);
    });
}

#[test]
fn fpreset_x86_flags_retry_keeps_loaded_context_and_does_not_repeat_reset() {
    run(|c| {
        if c.arch() != WinArch::X86 {
            return;
        }
        let at = area(c);
        context(c, at, 8);
        let (slot, info) = attach(c, at);
        c.p.vm.protect(at, PAGE_SIZE, prot::NOACCESS).unwrap();
        let original = poison_x86(c, 4);
        let then = retry(invoke(c, U, "_fpreset", &[]), at, false);
        assert_eq!(fp_image(c), expected_x86_reset(original));
        c.p.vm.protect(at, PAGE_SIZE, prot::READWRITE).unwrap();
        c.mem().w32(slot, u32::MAX).unwrap();
        c.mem().w32(info + 4, u32::MAX).unwrap();
        let repaired = poison_x86(c, 2);
        void(then(c, 0));
        assert_eq!(fp_image(c), repaired);
        assert_eq!(c.mem().u32(at + 0x20).unwrap(), 0);
        assert_eq!(c.mem().u32(at + 0x24).unwrap(), 0xFFFF);
    });
}

#[test]
fn fpreset_x86_status_read_fault_retains_decoded_flags() {
    run(|c| {
        if c.arch() != WinArch::X86 {
            return;
        }
        let base = span(c, 2 * PAGE_SIZE);
        let at = base + PAGE_SIZE - 0x20;
        context(c, at, 0x0001_0000);
        let (slot, info) = attach(c, at);
        c.p.vm
            .protect(base + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
            .unwrap();
        let original = poison_x86(c, 3);
        let then = retry(invoke(c, U, "_fpreset", &[]), at + 0x20, false);
        assert_eq!(fp_image(c), expected_x86_reset(original));
        c.p.vm
            .protect(base + PAGE_SIZE, PAGE_SIZE, prot::READWRITE)
            .unwrap();
        assert_eq!(c.mem().u32(at + 0x20).unwrap(), OLD_STATUS);
        assert_eq!(c.mem().u32(at + 0x24).unwrap(), OLD_TAG);
        c.mem().w32(at, 0).unwrap();
        c.mem().w32(slot, u32::MAX).unwrap();
        c.mem().w32(info + 4, u32::MAX).unwrap();
        let repaired = poison_x86(c, 6);
        void(then(c, 0));
        assert_eq!(fp_image(c), repaired);
        assert_eq!(c.mem().u32(at).unwrap(), 0);
        assert_eq!(c.mem().u32(at + 0x20).unwrap(), 0);
        assert_eq!(c.mem().u32(at + 0x24).unwrap(), 0xFFFF);
    });
}

#[test]
fn fpreset_x86_status_write_fault_restarts_rmw_read_only() {
    run(|c| {
        if c.arch() != WinArch::X86 {
            return;
        }
        let base = span(c, 2 * PAGE_SIZE);
        let at = base + PAGE_SIZE - 0x20;
        context(c, at, 8);
        let (slot, info) = attach(c, at);
        c.p.vm
            .protect(base + PAGE_SIZE, PAGE_SIZE, prot::READONLY)
            .unwrap();
        poison_x86(c, 4);
        let then = retry(invoke(c, U, "_fpreset", &[]), at + 0x20, true);
        assert_eq!(c.mem().u32(at + 0x20).unwrap(), OLD_STATUS);
        assert_eq!(c.mem().u32(at + 0x24).unwrap(), OLD_TAG);
        c.mem().w32(at, 0).unwrap();
        c.mem().w32(slot, u32::MAX).unwrap();
        c.mem().w32(info + 4, u32::MAX).unwrap();
        c.p.vm
            .protect(base + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
            .unwrap();
        let repaired = poison_x86(c, 1);
        // Intel SDM Vol. 3A 7.5/7.6: a #PF restarts its instruction. The
        // publisher AND DWORD [context+0x20],0 must repeat its read, unlike
        // the earlier completed FP reset and pointer/flags instructions.
        let then = retry(then(c, 0), at + 0x20, false);
        assert_eq!(fp_image(c), repaired);
        // Deliberately embedder-only permissions: PAGE_* has no write-only
        // protection. Even though a store is permitted, the RMW read must
        // still fault rather than being optimized to a blind zero store.
        c.p.space
            .protect(base + PAGE_SIZE, PAGE_SIZE, Perms::WRITE)
            .unwrap();
        let then = retry(then(c, 0), at + 0x20, false);
        assert_eq!(fp_image(c), repaired);
        c.p.space
            .protect(base + PAGE_SIZE, PAGE_SIZE, Perms::READ | Perms::WRITE)
            .unwrap();
        assert_eq!(c.mem().u32(at + 0x20).unwrap(), OLD_STATUS);
        assert_eq!(c.mem().u32(at + 0x24).unwrap(), OLD_TAG);
        void(then(c, 0));
        assert_eq!(fp_image(c), repaired);
        assert_eq!(c.mem().u32(at).unwrap(), 0);
        assert_eq!(c.mem().u32(at + 0x20).unwrap(), 0);
        assert_eq!(c.mem().u32(at + 0x24).unwrap(), 0xFFFF);
    });
}

#[test]
fn fpreset_x86_tag_retry_does_not_repeat_status_store_or_pointer_loads() {
    run(|c| {
        if c.arch() != WinArch::X86 {
            return;
        }
        let base = span(c, 2 * PAGE_SIZE);
        let at = base + PAGE_SIZE - 0x24;
        context(c, at, 8);
        let (slot, info) = attach(c, at);
        c.p.vm
            .protect(base + PAGE_SIZE, PAGE_SIZE, prot::READONLY)
            .unwrap();
        poison_x86(c, 5);
        let then = retry(invoke(c, U, "_fpreset", &[]), at + 0x24, true);
        assert_eq!(c.mem().u32(at + 0x20).unwrap(), 0);
        assert_eq!(c.mem().u32(at + 0x24).unwrap(), OLD_TAG);
        c.mem().w32(at + 0x20, 0xA1B2_C3D4).unwrap();
        c.mem().w32(slot, u32::MAX).unwrap();
        c.mem().w32(info + 4, u32::MAX).unwrap();
        c.p.vm.protect(base, PAGE_SIZE, prot::NOACCESS).unwrap();
        c.p.vm
            .protect(base + PAGE_SIZE, PAGE_SIZE, prot::READWRITE)
            .unwrap();
        let repaired = poison_x86(c, 7);
        void(then(c, 0));
        assert_eq!(fp_image(c), repaired);
        c.p.vm.protect(base, PAGE_SIZE, prot::READWRITE).unwrap();
        assert_eq!(c.mem().u32(at + 0x20).unwrap(), 0xA1B2_C3D4);
        assert_eq!(c.mem().u32(at + 0x24).unwrap(), 0xFFFF);
    });
}

#[test]
fn fpreset_x86_info_effective_address_wraps_modulo_32_bits() {
    run(|c| {
        if c.arch() != WinArch::X86 {
            return;
        }
        let at = area(c);
        context(c, at, 8);
        let slot = slot(c);
        assert!(c.mem().u32(0).is_err());
        // A deliberate embedder mapping, not a native Windows low-page
        // allocation claim. Only [info+4] is dereferenced: FFFF_FFFC+4 = 0.
        c.p.space
            .map(0, PAGE_SIZE, Mapping::anonymous(Perms::READ | Perms::WRITE))
            .unwrap();
        c.mem().w32(0, at as u32).unwrap();
        c.mem().w32(slot, 0xFFFF_FFFC).unwrap();
        let before = poison_x86(c, 6);
        void(invoke(c, U, "_fpreset", &[]));
        assert_eq!(fp_image(c), expected_x86_reset(before));
        assert_eq!(c.mem().u32(at + 0x20).unwrap(), 0);
        assert_eq!(c.mem().u32(at + 0x24).unwrap(), 0xFFFF);
        c.p.space.unmap(0, PAGE_SIZE).unwrap();
    });
}
