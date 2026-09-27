//! Context format compatibility: version 2 (ABI 1.5) keeps the x87
//! registers in their exact 80-bit encoding; version-1 contexts written by ABI
//! 1.4 and earlier, which held them as binary64, still restore.
use super::*;
use crate::context::{rax_context_restore, rax_context_save};

const RBX: i32 = 0x0103;
const X86_ST0: i32 = 0x1200;
const FPTAG: i32 = 0x1212;
const KERNEL_GS_BASE: i32 = 0x100B;
const TSC_AUX: i32 = 0x100C;
const PKRU: i32 = 0x100D;

/// A small x86-64 engine so a context is a few kilobytes.
fn small_x86() -> *mut Engine {
    let cfg = RaxEngineConfig {
        size: std::mem::size_of::<RaxEngineConfig>() as u32,
        arch: RaxArch::X86 as i32,
        mode: RAX_MODE_64,
        backend: crate::arch::RAX_BACKEND_DEFAULT,
        mem_base: 0,
        mem_size: 0x4000,
        mem_perms: RAX_PROT_ALL,
        flags: 0,
        riscv_ext: 0,
    };
    let mut e = ptr::null_mut();
    assert_eq!(rax_engine_open_config(&cfg, &mut e), RaxStatus::Ok);
    e
}

fn save(e: *mut Engine) -> Vec<u8> {
    let mut len = 0;
    assert_eq!(
        rax_context_save(e, ptr::null_mut(), 0, &mut len),
        RaxStatus::Ok
    );
    let mut blob = vec![0u8; len];
    assert_eq!(
        rax_context_save(e, blob.as_mut_ptr(), len, &mut len),
        RaxStatus::Ok
    );
    blob
}

/// A context's sections: 20-byte header, CPU state, extended state, and the
/// region records.
struct Sections {
    header: Vec<u8>,
    cpu: Vec<u8>,
    emu: Vec<u8>,
    regions: Vec<u8>,
}

fn u64_at(b: &[u8], at: usize) -> usize {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap()) as usize
}

fn split(blob: &[u8]) -> Sections {
    let header = blob[..20].to_vec();
    let cpu_len = u64_at(blob, 20);
    let cpu = blob[28..28 + cpu_len].to_vec();
    let at = 28 + cpu_len;
    let emu_len = u64_at(blob, at);
    let emu = blob[at + 8..at + 8 + emu_len].to_vec();
    let regions = blob[at + 8 + emu_len..].to_vec();
    Sections {
        header,
        cpu,
        emu,
        regions,
    }
}

fn join(version: u32, s: &Sections, emu: &[u8]) -> Vec<u8> {
    let mut blob = s.header.clone();
    blob[4..8].copy_from_slice(&version.to_le_bytes());
    blob.extend_from_slice(&(s.cpu.len() as u64).to_le_bytes());
    blob.extend_from_slice(&s.cpu);
    blob.extend_from_slice(&(emu.len() as u64).to_le_bytes());
    blob.extend_from_slice(emu);
    blob.extend_from_slice(&s.regions);
    blob
}

/// The extended x86 state as ABI 1.4 serialized it (bincode 1, fixed-width
/// little-endian, fields in declaration order): FPU {control, status, tag
/// u16; data_ptr, instr_ptr u64; last_opcode u16; st [f64; 8]; top u8}, lazy
/// flags {op u8; result, src, dst u64; size u8}, kernel_gs_base u64,
/// tsc_adjust u64, tsc_aux u32, misc_enable u64, pat u64, umwait_control
/// u64, pkru u32, mxcsr u32, halted bool, interrupt_inhibit bool.
fn legacy_emulator_state(st: [f64; 8], top: u8, tag: u16, mxcsr: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&0x037Fu16.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&tag.to_le_bytes());
    b.extend_from_slice(&0u64.to_le_bytes());
    b.extend_from_slice(&0x1000u64.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    for value in st {
        b.extend_from_slice(&value.to_bits().to_le_bytes());
    }
    b.push(top);
    b.push(0); // lazy flags: none
    b.extend_from_slice(&[0u8; 24]);
    b.push(4);
    b.extend_from_slice(&0xFFFF_8000_0000_1000u64.to_le_bytes()); // kernel_gs_base
    b.extend_from_slice(&0u64.to_le_bytes()); // tsc_adjust
    b.extend_from_slice(&9u32.to_le_bytes()); // tsc_aux
    b.extend_from_slice(&1u64.to_le_bytes()); // misc_enable
    b.extend_from_slice(&0x0007_0406_0007_0406u64.to_le_bytes()); // pat
    b.extend_from_slice(&0u64.to_le_bytes()); // umwait_control
    b.extend_from_slice(&4u32.to_le_bytes()); // pkru
    b.extend_from_slice(&mxcsr.to_le_bytes());
    b.push(0); // halted
    b.push(0); // interrupt_inhibit
    assert_eq!(b.len(), 169);
    b
}

#[test]
fn saved_contexts_are_version_2() {
    let e = small_x86();
    let blob = save(e);
    assert_eq!(&blob[..4], &0x5241_5843u32.to_le_bytes());
    assert_eq!(&blob[4..8], &2u32.to_le_bytes());
    // The current layout stores ten bytes per x87 register.
    assert_eq!(split(&blob).emu.len(), 169 - 8 * 8 + 8 * 10);
    rax_engine_close(e);
}

#[test]
fn version_1_contexts_restore_exact_x87_values() {
    let e = small_x86();
    unsafe {
        // fstp qword [rbx] ; fstp qword [rbx+8] ; fstp qword [rbx+16]
        write(e, 0x1000, &[0xDD, 0x1B, 0xDD, 0x5B, 0x08, 0xDD, 0x5B, 0x10]);
    }
    let sections = split(&save(e));
    rax_engine_close(e);

    // TOP = 5: ST(0) = R5 (the smallest binary64 subnormal), ST(1) = R6,
    // ST(2) = R7. R0-R4 are empty.
    let tiny = f64::from_bits(1);
    let values = [0.0, 0.0, 0.0, 0.0, 0.0, tiny, 2.5, -1.0e300];
    let v1 = join(
        1,
        &sections,
        &legacy_emulator_state(values, 5, 0x03FF, 0x1F80),
    );

    let e = small_x86();
    assert_eq!(rax_context_restore(e, v1.as_ptr(), v1.len()), RaxStatus::Ok);
    unsafe {
        let mut st0 = [0u8; 10];
        let mut n = 0;
        assert_eq!(
            rax_reg_read(e, X86_ST0, st0.as_mut_ptr(), &mut n),
            RaxStatus::Ok
        );
        // 2^-1074 is the normal binary80 value 1.0 * 2^(0x3BCD - 16383).
        let mut expected = [0u8; 10];
        expected[7] = 0x80;
        expected[8..].copy_from_slice(&0x3BCDu16.to_le_bytes());
        assert_eq!(st0, expected);
        assert_eq!(rd_u64(e, FPTAG), 0x03FF);
        assert_eq!(rd_u64(e, KERNEL_GS_BASE), 0xFFFF_8000_0000_1000);
        assert_eq!(rd_u64(e, TSC_AUX), 9);
        assert_eq!(rd_u64(e, PKRU), 4);

        // Storing each register reproduces the saved binary64 exactly.
        assert_eq!(rax_reg_write_u64(e, RBX, 0x2000), RaxStatus::Ok);
        assert_eq!(rax_emu_start(e, 0x1000, 0x1008, 0, 0), RaxStatus::Ok);
        for (i, value) in [tiny, 2.5, -1.0e300].into_iter().enumerate() {
            let mut stored = [0u8; 8];
            assert_eq!(
                rax_mem_read(e, 0x2000 + 8 * i as u64, stored.as_mut_ptr(), 8),
                RaxStatus::Ok
            );
            assert_eq!(u64::from_le_bytes(stored), value.to_bits(), "ST({i})");
        }
    }
    rax_engine_close(e);
}

#[test]
fn malformed_contexts_are_format_errors_and_leave_the_engine_intact() {
    let e = small_x86();
    unsafe {
        assert_eq!(rax_reg_write_u64(e, RAX, 0x1234), RaxStatus::Ok);
    }
    let blob = save(e);
    let sections = split(&blob);
    let legacy = legacy_emulator_state([1.0; 8], 0, 0xFFFF, 0x1F80);

    let mut cases: Vec<(&str, Vec<u8>, RaxStatus)> = vec![
        (
            "unknown version",
            join(3, &sections, &sections.emu),
            RaxStatus::Format,
        ),
        (
            "truncated version-1 state",
            join(1, &sections, &legacy[..168]),
            RaxStatus::Format,
        ),
        (
            "trailing version-1 bytes",
            join(1, &sections, &[legacy.clone(), vec![0]].concat()),
            RaxStatus::Format,
        ),
        (
            "version-1 state in a version-2 context",
            join(2, &sections, &legacy),
            RaxStatus::Format,
        ),
        (
            "invalid boolean",
            join(1, &sections, &[&legacy[..167], &[2, 0][..]].concat()),
            RaxStatus::Format,
        ),
        (
            "reserved MXCSR bits",
            join(
                1,
                &sections,
                &legacy_emulator_state([1.0; 8], 0, 0xFFFF, 0x1_1F80),
            ),
            RaxStatus::Arg,
        ),
    ];
    // A CPU-state length no buffer can hold.
    let mut huge = blob.clone();
    huge[20..28].copy_from_slice(&u64::MAX.to_le_bytes());
    cases.push(("oversized length", huge, RaxStatus::Format));
    // x86 user mode has no real-mode form.
    let mut bad_mode = blob.clone();
    bad_mode[12..16]
        .copy_from_slice(&(crate::arch::RAX_MODE_16 | crate::arch::RAX_MODE_USER).to_le_bytes());
    cases.push(("invalid mode", bad_mode, RaxStatus::Format));

    for (what, data, status) in cases {
        assert_eq!(
            rax_context_restore(e, data.as_ptr(), data.len()),
            status,
            "{what}"
        );
        unsafe {
            assert_eq!(rd_u64(e, RAX), 0x1234, "{what}: the engine is unchanged");
        }
    }
    // The genuine context still restores.
    assert_eq!(
        rax_context_restore(e, blob.as_ptr(), blob.len()),
        RaxStatus::Ok
    );
    rax_engine_close(e);
}

/// A RISC-V `CpuState` as ABI 1.4 serialized it (bincode 1): the variant
/// index 5, then x[32], pc, f[32] (u64), fcsr (u32), and a `None`
/// tohost address.
fn legacy_riscv_state(x: [u64; 32], pc: u64, f: [u64; 32], fcsr: u32) -> Vec<u8> {
    let mut b = 5u32.to_le_bytes().to_vec();
    for v in x.iter().chain([pc].iter()).chain(f.iter()) {
        b.extend_from_slice(&v.to_le_bytes());
    }
    b.extend_from_slice(&fcsr.to_le_bytes());
    b.push(0);
    assert_eq!(b.len(), 4 + 65 * 8 + 4 + 1);
    b
}

#[test]
fn version_1_riscv_contexts_restore_their_registers() {
    const MSCRATCH: i32 = 0x1340;
    let e = open_riscv_with_ext(0);
    let mut sections = split(&save(e));
    let mut x = [0u64; 32];
    x[5] = 0x55;
    let mut f = [0u64; 32];
    f[3] = 0x4000_0000_0000_0000;
    sections.cpu = legacy_riscv_state(x, 0x2468, f, 0x61);
    let v1 = join(1, &sections, &[]);
    unsafe {
        assert_eq!(rax_reg_write_u64(e, MSCRATCH, 0x77), RaxStatus::Ok);
        assert_eq!(rax_context_restore(e, v1.as_ptr(), v1.len()), RaxStatus::Ok);
        assert_eq!(rd_u64(e, RISCV_X0 + 5), 0x55);
        assert_eq!(rd_u64(e, RISCV_PC), 0x2468);
        assert_eq!(rd_u64(e, 0x0203), 0x4000_0000_0000_0000);
        assert_eq!(rd_u64(e, 0x0023), 0x61);
        // Version 1 did not record the CSRs: they have their reset values.
        assert_eq!(rd_u64(e, MSCRATCH), 0);
    }
    // A current-layout state under a version-1 header is rejected.
    let current = save(e);
    let mut sections = split(&current);
    sections.emu.clear();
    let mislabeled = join(1, &sections, &[]);
    assert_eq!(
        unsafe { rax_context_restore(e, mislabeled.as_ptr(), mislabeled.len()) },
        RaxStatus::Format
    );
    rax_engine_close(e);
}
