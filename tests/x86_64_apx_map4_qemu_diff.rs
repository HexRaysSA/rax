//! Generated APX MAP4 differential tests: rax vs. qemu-x86_64.
//!
//! This corpus is scoped to APX/EVEX MAP4 GPR handlers implemented by rax.
//! SIMD EVEX coverage lives in `x86_64_evex_qemu_diff.rs`; this harness uses a
//! scalar oracle because MAP4 mutates GPRs, RFLAGS, scratch memory, and stack.

#![cfg(all(feature = "x86_64-suite", target_os = "linux", target_arch = "x86_64"))]

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[path = "x86_64/common/mod.rs"]
mod common;

use common::{Bytes, GuestAddress, Registers, run_until_hlt, setup_vm};

const WIRE_MAGIC: u32 = 0x3458_5041; // 'A','P','X','4'
const GPR_REGS: usize = 32;
const SCRATCH_BYTES: usize = 256;
const STACK_BYTES: usize = 256;
const SCRATCH_ADDR: u64 = 0x4000;
const STACK_ADDR: u64 = 0x7000;
const STACK_CURSOR: u64 = 0x80;

const MODE_SCRATCH_RAX: u32 = 1 << 0;
const MODE_STACK_RSP: u32 = 1 << 1;

const FLAG_CF: u64 = 0x001;
const FLAG_PF: u64 = 0x004;
const FLAG_AF: u64 = 0x010;
const FLAG_ZF: u64 = 0x040;
const FLAG_SF: u64 = 0x080;
const FLAG_OF: u64 = 0x800;
const FLAG_RESERVED: u64 = 0x002;
const FLAGS_STATUS: u64 = FLAG_CF | FLAG_PF | FLAG_AF | FLAG_ZF | FLAG_SF | FLAG_OF;
const FLAGS_LOGIC: u64 = FLAG_CF | FLAG_PF | FLAG_ZF | FLAG_SF | FLAG_OF;
const FLAGS_SHIFT: u64 = FLAG_CF | FLAG_PF | FLAG_ZF | FLAG_SF | FLAG_OF;
const FLAGS_CMP_TEST: u64 = FLAG_CF | FLAG_ZF | FLAG_SF | FLAG_OF;

const IN_GPR: usize = 8;
const IN_RFLAGS: usize = IN_GPR + GPR_REGS * 8;
const OUT_GPR: usize = 16;
const OUT_RFLAGS: usize = OUT_GPR + GPR_REGS * 8;
const OUT_SCRATCH: usize = OUT_RFLAGS + 8;
const OUT_STACK: usize = OUT_SCRATCH + SCRATCH_BYTES;

const LLVM_MATTR: &str = "+egpr,+ndd,+ccmp";

#[repr(C)]
#[derive(Clone, Copy)]
struct InCase {
    id: u32,
    mode: u32,
    gpr: [u64; GPR_REGS],
    rflags: u64,
    scratch: [u8; SCRATCH_BYTES],
    stack: [u8; STACK_BYTES],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct OutCase {
    id: u32,
    valid: u32,
    signal: u32,
    reserved: u32,
    gpr: [u64; GPR_REGS],
    rflags: u64,
    scratch: [u8; SCRATCH_BYTES],
    stack: [u8; STACK_BYTES],
}

enum CaseSource {
    Asm(String),
    Bytes(Vec<u8>),
}

struct CaseSpec {
    family: &'static str,
    label: String,
    source: CaseSource,
    mode: u32,
    initial_flags: u64,
    flag_mask: u64,
}

struct DiffCase {
    id: u32,
    family: &'static str,
    label: String,
    op: Vec<u8>,
    input: InCase,
    flag_mask: u64,
}

fn which(prog: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(prog))
        .find(|candidate| candidate.is_file())
}

fn qemu_path() -> Option<PathBuf> {
    std::env::var_os("QEMU_X86_64")
        .map(PathBuf::from)
        .or_else(|| which("qemu-x86_64"))
}

fn llvm_mc_path() -> Option<PathBuf> {
    std::env::var_os("LLVM_MC")
        .map(PathBuf::from)
        .or_else(|| which("llvm-mc"))
}

fn cc_path() -> Option<PathBuf> {
    std::env::var_os("CC")
        .map(PathBuf::from)
        .or_else(|| which("clang"))
        .or_else(|| which("cc"))
}

fn as_bytes<T: Copy>(value: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts(value as *const T as *const u8, std::mem::size_of::<T>()) }
}

fn read_struct<T: Copy>(buf: &[u8], offset: usize) -> T {
    unsafe { std::ptr::read_unaligned(buf[offset..].as_ptr() as *const T) }
}

fn gpr_from_regs(regs: &Registers) -> [u64; GPR_REGS] {
    [
        regs.rax, regs.rbx, regs.rcx, regs.rdx, regs.rsi, regs.rdi, regs.rsp, regs.rbp, regs.r8,
        regs.r9, regs.r10, regs.r11, regs.r12, regs.r13, regs.r14, regs.r15, regs.r16, regs.r17,
        regs.r18, regs.r19, regs.r20, regs.r21, regs.r22, regs.r23, regs.r24, regs.r25, regs.r26,
        regs.r27, regs.r28, regs.r29, regs.r30, regs.r31,
    ]
}

fn regs_from_gpr(gpr: [u64; GPR_REGS], rflags: u64) -> Registers {
    Registers {
        rax: gpr[0],
        rbx: gpr[1],
        rcx: gpr[2],
        rdx: gpr[3],
        rsi: gpr[4],
        rdi: gpr[5],
        rsp: gpr[6],
        rbp: gpr[7],
        r8: gpr[8],
        r9: gpr[9],
        r10: gpr[10],
        r11: gpr[11],
        r12: gpr[12],
        r13: gpr[13],
        r14: gpr[14],
        r15: gpr[15],
        r16: gpr[16],
        r17: gpr[17],
        r18: gpr[18],
        r19: gpr[19],
        r20: gpr[20],
        r21: gpr[21],
        r22: gpr[22],
        r23: gpr[23],
        r24: gpr[24],
        r25: gpr[25],
        r26: gpr[26],
        r27: gpr[27],
        r28: gpr[28],
        r29: gpr[29],
        r30: gpr[30],
        r31: gpr[31],
        rflags,
        ..Registers::default()
    }
}

fn input_for(id: u32, spec: &CaseSpec) -> InCase {
    let mut gpr = [0u64; GPR_REGS];
    for (index, value) in gpr.iter_mut().enumerate() {
        *value = 0x1000_0000_0000_0000u64
            .wrapping_add((index as u64) << 40)
            .wrapping_add(0x1010_2030_4050_6070u64 ^ ((index as u64) * 0x1111_1111));
    }

    gpr[0] = 0x0102_0304_0506_0708;
    gpr[1] = 0x1111_2222_3333_4444;
    gpr[2] = 1;
    gpr[3] = 0;
    gpr[6] = STACK_ADDR + STACK_CURSOR;
    gpr[8] = 0xDEAD_BEEF_CAFE_BABE;
    gpr[16] = 0x0123_4567_89AB_CDEF;
    gpr[17] = 0x0000_0000_0000_0021;
    gpr[18] = 0x0000_0000_0000_0003;
    gpr[24] = 0x7777_8888_9999_AAAA;
    gpr[25] = 0xBBBB_CCCC_DDDD_EEEE;
    gpr[29] = 0x00FF_00FF_00FF_00FF;
    gpr[30] = 0x0F0F_0F0F_0F0F_0F0F;
    gpr[31] = 0x3333_3333_3333_3333;

    if spec.mode & MODE_SCRATCH_RAX != 0 {
        gpr[0] = SCRATCH_ADDR;
    }

    let mut scratch = [0u8; SCRATCH_BYTES];
    for (i, byte) in scratch.iter_mut().enumerate() {
        *byte = (0xA0u8).wrapping_add((i as u8).wrapping_mul(3));
    }
    scratch[0..8].copy_from_slice(&0x0000_0000_0000_0015u64.to_le_bytes());
    scratch[8..16].copy_from_slice(&0xFFFF_FFFF_FFFF_FFF0u64.to_le_bytes());

    let mut stack = [0u8; STACK_BYTES];
    for (i, byte) in stack.iter_mut().enumerate() {
        *byte = (0x40u8).wrapping_add(i as u8);
    }
    let cursor = STACK_CURSOR as usize;
    stack[cursor..cursor + 8].copy_from_slice(&0xCAFE_BABE_DEAD_BEEFu64.to_le_bytes());
    stack[cursor + 8..cursor + 16].copy_from_slice(&0x0123_4567_89AB_CDEFu64.to_le_bytes());

    InCase {
        id,
        mode: spec.mode,
        gpr,
        rflags: spec.initial_flags | FLAG_RESERVED,
        scratch,
        stack,
    }
}

fn run_rax(case: &DiffCase) -> OutCase {
    let mut code = case.op.clone();
    code.push(0xf4);

    let (mut vcpu, mem) = setup_vm(
        &code,
        Some(regs_from_gpr(case.input.gpr, case.input.rflags)),
    );
    mem.write_slice(&case.input.scratch, GuestAddress(SCRATCH_ADDR))
        .unwrap();
    mem.write_slice(&case.input.stack, GuestAddress(STACK_ADDR))
        .unwrap();

    let regs = run_until_hlt(&mut vcpu).unwrap_or_else(|err| {
        panic!(
            "{}: rax failed while executing APX MAP4 case: {err}",
            case.label
        )
    });

    let mut scratch = [0u8; SCRATCH_BYTES];
    let mut stack = [0u8; STACK_BYTES];
    mem.read_slice(&mut scratch, GuestAddress(SCRATCH_ADDR))
        .unwrap();
    mem.read_slice(&mut stack, GuestAddress(STACK_ADDR))
        .unwrap();

    OutCase {
        id: case.id,
        valid: 1,
        signal: 0,
        reserved: 0,
        gpr: gpr_from_regs(&regs),
        rflags: regs.rflags,
        scratch,
        stack,
    }
}

fn asm_case(
    specs: &mut Vec<CaseSpec>,
    family: &'static str,
    label: impl Into<String>,
    asm: impl Into<String>,
    mode: u32,
    initial_flags: u64,
    flag_mask: u64,
) {
    specs.push(CaseSpec {
        family,
        label: label.into(),
        source: CaseSource::Asm(asm.into()),
        mode,
        initial_flags,
        flag_mask: flag_mask | FLAG_RESERVED,
    });
}

fn byte_case(
    specs: &mut Vec<CaseSpec>,
    family: &'static str,
    label: impl Into<String>,
    bytes: &[u8],
    mode: u32,
    initial_flags: u64,
    flag_mask: u64,
) {
    specs.push(CaseSpec {
        family,
        label: label.into(),
        source: CaseSource::Bytes(bytes.to_vec()),
        mode,
        initial_flags,
        flag_mask: flag_mask | FLAG_RESERVED,
    });
}

fn generated_specs() -> Vec<CaseSpec> {
    let mut specs = Vec::new();
    let flagful = FLAG_RESERVED | FLAG_CF;
    let preserved = FLAG_RESERVED | FLAGS_STATUS;

    for mnemonic in ["add", "or", "adc", "sbb", "and", "sub", "xor"] {
        let mask = match mnemonic {
            "or" | "and" | "xor" => FLAGS_LOGIC,
            _ => FLAGS_STATUS,
        };
        asm_case(
            &mut specs,
            "alu_ndd",
            format!("{mnemonic}_ndd_low"),
            format!("{mnemonic} r8, rbx, rax"),
            0,
            flagful,
            mask,
        );
        asm_case(
            &mut specs,
            "alu_ndd",
            format!("{mnemonic}_ndd_egpr"),
            format!("{mnemonic} r24, r17, r16"),
            0,
            flagful,
            mask,
        );
        if !matches!(mnemonic, "adc" | "sbb") {
            asm_case(
                &mut specs,
                "alu_nf",
                format!("{mnemonic}_nf_two_operand"),
                format!("{{nf}} {mnemonic} rax, rbx"),
                0,
                preserved,
                FLAGS_STATUS,
            );
        }
        asm_case(
            &mut specs,
            "alu_mem",
            format!("{mnemonic}_evex_mem_dst"),
            format!("{{evex}} {mnemonic} qword ptr [rax], rbx"),
            MODE_SCRATCH_RAX,
            flagful,
            mask,
        );
    }

    for (suffix, asm) in [
        ("8", "add r8b, bl, al"),
        ("16", "add r8w, bx, ax"),
        ("32", "add r8d, ebx, eax"),
        ("64", "add r8, rbx, rax"),
    ] {
        asm_case(
            &mut specs,
            "alu_size",
            format!("add_ndd_size_{suffix}"),
            asm,
            0,
            flagful,
            FLAGS_STATUS,
        );
    }

    for mnemonic in ["add", "or", "adc", "sbb", "and", "sub", "xor"] {
        let mask = match mnemonic {
            "or" | "and" | "xor" => FLAGS_LOGIC,
            _ => FLAGS_STATUS,
        };
        asm_case(
            &mut specs,
            "group1_imm",
            format!("{mnemonic}_imm_ndd"),
            format!("{mnemonic} r8, rax, 0x11"),
            0,
            flagful,
            mask,
        );
    }
    asm_case(
        &mut specs,
        "group1_imm",
        "cmp_imm_evex",
        "{evex} cmp rax, 0x11",
        0,
        flagful,
        FLAGS_STATUS,
    );

    for (label, asm, flags) in [
        ("shl_one", "shl r8, rax", FLAGS_SHIFT),
        ("shr_cl", "shr r8, rax, cl", FLAGS_SHIFT),
        ("sar_one", "sar r8, rax", FLAGS_SHIFT),
        ("rol_one", "rol r8, rax", FLAGS_STATUS),
        ("ror_cl", "ror r8, rax, cl", FLAGS_STATUS),
        ("rcl_one", "rcl r8, rax", FLAGS_STATUS),
        ("rcr_cl", "rcr r8, rax, cl", FLAGS_STATUS),
    ] {
        asm_case(&mut specs, "shift_rotate", label, asm, 0, flagful, flags);
    }
    asm_case(
        &mut specs,
        "shift_rotate",
        "shr_nf_cl",
        "{nf} shr r8, rax, cl",
        0,
        preserved,
        FLAGS_STATUS,
    );
    asm_case(
        &mut specs,
        "double_shift",
        "shld_imm",
        "shld r8, rbx, rax, 1",
        0,
        flagful,
        FLAGS_SHIFT,
    );
    asm_case(
        &mut specs,
        "double_shift",
        "shrd_cl",
        "shrd r8, rbx, rax, cl",
        0,
        flagful,
        FLAGS_SHIFT,
    );
    asm_case(
        &mut specs,
        "double_shift",
        "shld_nf_imm",
        "{nf} shld r8, rbx, rax, 1",
        0,
        preserved,
        FLAGS_STATUS,
    );

    asm_case(
        &mut specs,
        "movbe",
        "movbe_q_egpr",
        "movbe r24, r16",
        0,
        preserved,
        FLAGS_STATUS,
    );
    asm_case(
        &mut specs,
        "movbe",
        "movbe_l",
        "movbe r8d, eax",
        0,
        preserved,
        FLAGS_STATUS,
    );
    asm_case(
        &mut specs,
        "movbe",
        "movbe_w",
        "movbe r8w, ax",
        0,
        preserved,
        FLAGS_STATUS,
    );

    asm_case(
        &mut specs,
        "movrs",
        "movrs_q_egpr_from_scratch",
        "movrs r16, qword ptr [rax]",
        MODE_SCRATCH_RAX,
        preserved,
        FLAGS_STATUS,
    );
    asm_case(
        &mut specs,
        "movrs",
        "movrs_l_egpr_from_scratch",
        "movrs r16d, dword ptr [rax]",
        MODE_SCRATCH_RAX,
        preserved,
        FLAGS_STATUS,
    );

    byte_case(
        &mut specs,
        "lea",
        "lea_map4_raw_r8_rax_rbx2",
        &[0x62, 0xF4, 0xFC, 0x08, 0x8D, 0x04, 0x58],
        0,
        preserved,
        FLAGS_STATUS,
    );

    for asm in [
        "ccmpo {dfv=cf,zf} rax, rbx",
        "ccmpno {dfv=cf,zf} rax, rbx",
        "ccmpne {dfv=of,sf} rbx, qword ptr [rax]",
    ] {
        asm_case(
            &mut specs,
            "ccmp",
            asm.replace([' ', '{', '}', ',', '[', ']'], "_"),
            asm,
            if asm.contains("[rax]") {
                MODE_SCRATCH_RAX
            } else {
                0
            },
            flagful,
            FLAGS_CMP_TEST,
        );
    }
    for asm in [
        "ctesto {dfv=sf,of} rax, rbx",
        "ctestne {dfv=sf,of} rax, 15",
        "ctestb {dfv=of,sf} qword ptr [rax], rcx",
    ] {
        asm_case(
            &mut specs,
            "ctest",
            asm.replace([' ', '{', '}', ',', '[', ']'], "_"),
            asm,
            if asm.contains("[rax]") {
                MODE_SCRATCH_RAX
            } else {
                0
            },
            flagful,
            FLAGS_CMP_TEST,
        );
    }

    for asm in ["setzuo al", "setzune r8b", "setzuo r16b"] {
        asm_case(
            &mut specs,
            "setzu",
            asm.replace(' ', "_"),
            asm,
            0,
            FLAG_RESERVED | FLAG_OF,
            FLAGS_STATUS,
        );
    }
    for asm in [
        "cmovb r8, rax, rbx",
        "cfcmovb r8, rax, rbx",
        "cfcmovb r8, rbx, qword ptr [rax]",
        "cfcmovb qword ptr [rax], rbx",
    ] {
        asm_case(
            &mut specs,
            "conditional_mov",
            asm.replace([' ', ',', '[', ']'], "_"),
            asm,
            if asm.contains("[rax]") {
                MODE_SCRATCH_RAX
            } else {
                0
            },
            FLAG_RESERVED | FLAG_CF,
            FLAGS_STATUS,
        );
    }

    asm_case(
        &mut specs,
        "push2_pop2",
        "push2_low",
        "push2 rax, rbx",
        MODE_STACK_RSP,
        preserved,
        FLAGS_STATUS,
    );
    asm_case(
        &mut specs,
        "push2_pop2",
        "pop2_low",
        "pop2 r8, r9",
        MODE_STACK_RSP,
        preserved,
        FLAGS_STATUS,
    );
    asm_case(
        &mut specs,
        "push2_pop2",
        "push2_egpr",
        "push2 r16, r17",
        MODE_STACK_RSP,
        preserved,
        FLAGS_STATUS,
    );
    asm_case(
        &mut specs,
        "push2_pop2",
        "pop2_egpr",
        "pop2 r24, r25",
        MODE_STACK_RSP,
        preserved,
        FLAGS_STATUS,
    );

    asm_case(
        &mut specs,
        "imul",
        "imul_ndd",
        "imul r8, rbx, rax",
        0,
        flagful,
        FLAG_CF | FLAG_OF,
    );
    asm_case(
        &mut specs,
        "imul",
        "imul_nf_ndd",
        "{nf} imul r8, rbx, rax",
        0,
        preserved,
        FLAGS_STATUS,
    );
    asm_case(
        &mut specs,
        "imul",
        "imul_nf_imm8",
        "{nf} imul r8, rax, 7",
        0,
        preserved,
        FLAGS_STATUS,
    );

    for asm in ["not r8, rax", "neg r8, rax", "{nf} neg rax"] {
        asm_case(
            &mut specs,
            "group3_unary",
            asm.replace([' ', '{', '}'], "_"),
            asm,
            0,
            preserved,
            if asm.contains("{nf}") || asm.starts_with("not") {
                FLAGS_STATUS
            } else {
                FLAGS_STATUS
            },
        );
    }
    for asm in [
        "{nf} mul rbx",
        "{nf} imul rbx",
        "{nf} div rbx",
        "{nf} idiv rbx",
    ] {
        asm_case(
            &mut specs,
            "group3_implicit",
            asm.replace([' ', '{', '}'], "_"),
            asm,
            0,
            preserved,
            FLAGS_STATUS,
        );
    }

    for asm in [
        "{nf} popcnt r8, rax",
        "{nf} lzcnt r8, rax",
        "{nf} tzcnt r8, rax",
        "{nf} lzcnt r8, qword ptr [rax]",
    ] {
        asm_case(
            &mut specs,
            "count_nf",
            asm.replace([' ', '{', '}', ',', '[', ']'], "_"),
            asm,
            if asm.contains("[rax]") {
                MODE_SCRATCH_RAX
            } else {
                0
            },
            preserved,
            FLAGS_STATUS,
        );
    }

    for asm in ["inc r8, rax", "dec r8, rax", "{nf} inc rax", "{nf} dec rax"] {
        asm_case(
            &mut specs,
            "inc_dec",
            asm.replace([' ', '{', '}'], "_"),
            asm,
            0,
            preserved,
            if asm.contains("{nf}") {
                FLAGS_STATUS
            } else {
                FLAGS_STATUS
            },
        );
    }

    specs
}

fn expected_families() -> &'static [&'static str] {
    &[
        "alu_ndd",
        "alu_nf",
        "alu_mem",
        "alu_size",
        "group1_imm",
        "shift_rotate",
        "double_shift",
        "movbe",
        "movrs",
        "lea",
        "ccmp",
        "ctest",
        "setzu",
        "conditional_mov",
        "push2_pop2",
        "imul",
        "group3_unary",
        "group3_implicit",
        "count_nf",
        "inc_dec",
    ]
}

fn assert_family_coverage(specs: &[CaseSpec]) {
    let present = specs
        .iter()
        .map(|spec| spec.family)
        .collect::<BTreeSet<_>>();
    for family in expected_families() {
        assert!(
            present.contains(family),
            "APX MAP4 differential corpus is missing family {family}"
        );
    }
}

fn assert_assembled_family_coverage(cases: &[DiffCase]) {
    let present = cases
        .iter()
        .map(|case| case.family)
        .collect::<BTreeSet<_>>();
    for family in expected_families() {
        assert!(
            present.contains(family),
            "APX MAP4 differential corpus did not assemble any case for family {family}"
        );
    }
}

fn parse_encoding(text: &str) -> Option<Vec<u8>> {
    let start = text.find("encoding: [")? + "encoding: [".len();
    let rest = &text[start..];
    let end = rest.find(']')?;
    let mut bytes = Vec::new();
    for token in rest[..end].split(',') {
        let token = token.trim().trim_start_matches("0x");
        bytes.push(u8::from_str_radix(token, 16).ok()?);
    }
    Some(bytes)
}

fn assemble_intel(llvm_mc: &Path, asm: &str) -> Option<Vec<u8>> {
    let mut child = Command::new(llvm_mc)
        .args([
            "-triple=x86_64",
            "-mattr",
            LLVM_MATTR,
            "-x86-asm-syntax=intel",
            "-show-encoding",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{asm}\n").as_bytes())
        .ok()?;

    let output = child.wait_with_output().ok()?;
    if !output.status.success() {
        return None;
    }
    parse_encoding(&String::from_utf8_lossy(&output.stdout))
}

fn is_evex_map4(bytes: &[u8]) -> bool {
    bytes.len() >= 5 && bytes[0] == 0x62 && (bytes[1] & 0x07) == 4
}

fn assembled_cases(llvm_mc: &Path) -> Vec<DiffCase> {
    let specs = generated_specs();
    assert_family_coverage(&specs);

    let mut cases = Vec::new();
    let mut failures = Vec::new();
    for spec in specs {
        let op = match &spec.source {
            CaseSource::Asm(asm) => {
                let Some(bytes) = assemble_intel(llvm_mc, asm) else {
                    failures.push(format!("{}: {asm}", spec.label));
                    continue;
                };
                bytes
            }
            CaseSource::Bytes(bytes) => bytes.clone(),
        };

        assert!(
            is_evex_map4(&op),
            "{} assembled outside EVEX MAP4: {:02x?}",
            spec.label,
            op
        );

        let id = cases.len() as u32;
        cases.push(DiffCase {
            id,
            family: spec.family,
            label: spec.label.clone(),
            op,
            input: input_for(id, &spec),
            flag_mask: spec.flag_mask,
        });
    }

    assert!(
        failures.is_empty(),
        "APX MAP4 differential corpus failed to assemble:\n{}",
        failures.join("\n")
    );

    if !cases.is_empty() {
        assert_assembled_family_coverage(&cases);
    }

    cases
}

fn c_byte_directive(bytes: &[u8]) -> String {
    let mut text = String::from(".byte ");
    for (i, byte) in bytes.iter().enumerate() {
        if i > 0 {
            text.push_str(", ");
        }
        text.push_str(&format!("0x{byte:02x}"));
    }
    text
}

fn write_decls_inc(build_dir: &Path, cases: &[DiffCase]) -> Option<PathBuf> {
    let decls_inc = build_dir.join("decls.inc");
    let mut text = String::new();
    for case in cases {
        text.push_str(&format!(
            "extern void apx_case_{}(const struct in_case *in, struct out_case *out);\n",
            case.id
        ));
    }
    std::fs::write(&decls_inc, text).ok()?;
    Some(decls_inc)
}

fn write_cases_inc(build_dir: &Path, cases: &[DiffCase]) -> Option<PathBuf> {
    let cases_inc = build_dir.join("cases.inc");
    let mut text = String::new();
    for case in cases {
        text.push_str(&format!(
            "    case {}: return apx_case_{}; /* {}:{} */\n",
            case.id, case.id, case.family, case.label
        ));
    }
    std::fs::write(&cases_inc, text).ok()?;
    Some(cases_inc)
}

fn high_reg_snippet(llvm_mc: &Path, asm: &str) -> Option<String> {
    let bytes = assemble_intel(llvm_mc, asm)?;
    Some(format!("    {}\n", c_byte_directive(&bytes)))
}

fn emit_load_gprs(text: &mut String, llvm_mc: &Path, mode: u32) -> Option<()> {
    if mode & MODE_SCRATCH_RAX != 0 {
        text.push_str("    mov rax, qword ptr [rip + apx_out_ptr]\n");
        text.push_str(&format!("    lea rax, [rax + {OUT_SCRATCH}]\n"));
    } else {
        text.push_str(&format!("    mov rax, qword ptr [r15 + {IN_GPR}]\n"));
    }

    for (reg, index) in [
        ("rbx", 1usize),
        ("rcx", 2),
        ("rdx", 3),
        ("rsi", 4),
        ("rdi", 5),
        ("rbp", 7),
        ("r8", 8),
        ("r9", 9),
        ("r10", 10),
        ("r11", 11),
        ("r12", 12),
    ] {
        text.push_str(&format!(
            "    mov {reg}, qword ptr [r15 + {}]\n",
            IN_GPR + index * 8
        ));
    }

    for index in 16..GPR_REGS {
        text.push_str(&high_reg_snippet(
            llvm_mc,
            &format!("mov r{index}, qword ptr [r15 + {}]", IN_GPR + index * 8),
        )?);
    }

    if mode & MODE_STACK_RSP != 0 {
        text.push_str("    mov rsp, qword ptr [rip + apx_tmp_stack_rsp]\n");
    }

    for (reg, index) in [("r13", 13usize), ("r14", 14), ("r15", 15)] {
        text.push_str(&format!(
            "    mov {reg}, qword ptr [r15 + {}]\n",
            IN_GPR + index * 8
        ));
    }

    Some(())
}

fn emit_store_gprs(text: &mut String, llvm_mc: &Path, mode: u32) -> Option<()> {
    text.push_str("    mov qword ptr [rip + apx_tmp_rax], rax\n");
    text.push_str("    mov qword ptr [rip + apx_tmp_rsp], rsp\n");
    text.push_str("    mov rsp, qword ptr [rip + apx_host_rsp]\n");
    text.push_str("    pushfq\n");
    text.push_str("    pop qword ptr [rip + apx_tmp_rflags]\n");
    text.push_str("    mov rax, qword ptr [rip + apx_out_ptr]\n");

    for (reg, index) in [
        ("rbx", 1usize),
        ("rcx", 2),
        ("rdx", 3),
        ("rsi", 4),
        ("rdi", 5),
        ("rbp", 7),
        ("r8", 8),
        ("r9", 9),
        ("r10", 10),
        ("r11", 11),
        ("r12", 12),
        ("r13", 13),
        ("r14", 14),
        ("r15", 15),
    ] {
        text.push_str(&format!(
            "    mov qword ptr [rax + {}], {reg}\n",
            OUT_GPR + index * 8
        ));
    }

    for index in 16..GPR_REGS {
        text.push_str(&high_reg_snippet(
            llvm_mc,
            &format!("mov qword ptr [rax + {}], r{index}", OUT_GPR + index * 8),
        )?);
    }

    if mode & MODE_STACK_RSP != 0 {
        text.push_str("    mov rbx, qword ptr [rip + apx_tmp_rsp]\n");
        text.push_str(&format!("    lea r10, [rax + {OUT_STACK}]\n"));
        text.push_str("    sub rbx, r10\n");
        text.push_str(&format!("    add rbx, {STACK_ADDR}\n"));
        text.push_str(&format!(
            "    mov qword ptr [rax + {}], rbx\n",
            OUT_GPR + 6 * 8
        ));
    } else {
        text.push_str("    mov r10, qword ptr [rip + apx_in_ptr]\n");
        text.push_str(&format!(
            "    mov rbx, qword ptr [r10 + {}]\n",
            IN_GPR + 6 * 8
        ));
        text.push_str(&format!(
            "    mov qword ptr [rax + {}], rbx\n",
            OUT_GPR + 6 * 8
        ));
    }

    if mode & MODE_SCRATCH_RAX != 0 {
        text.push_str("    mov rbx, qword ptr [rip + apx_tmp_rax]\n");
        text.push_str(&format!("    lea r10, [rax + {OUT_SCRATCH}]\n"));
        text.push_str("    sub rbx, r10\n");
        text.push_str(&format!("    add rbx, {SCRATCH_ADDR}\n"));
        text.push_str(&format!("    mov qword ptr [rax + {OUT_GPR}], rbx\n"));
    } else {
        text.push_str("    mov rbx, qword ptr [rip + apx_tmp_rax]\n");
        text.push_str(&format!("    mov qword ptr [rax + {OUT_GPR}], rbx\n"));
    }

    text.push_str("    mov rbx, qword ptr [rip + apx_tmp_rflags]\n");
    text.push_str(&format!("    mov qword ptr [rax + {OUT_RFLAGS}], rbx\n"));
    Some(())
}

fn write_cases_asm(build_dir: &Path, llvm_mc: &Path, cases: &[DiffCase]) -> Option<PathBuf> {
    let cases_s = build_dir.join("cases.S");
    let mut text = String::new();
    text.push_str(".intel_syntax noprefix\n");
    text.push_str(".data\n");
    text.push_str(".align 8\n");
    for symbol in [
        "apx_host_rsp",
        "apx_tmp_rax",
        "apx_tmp_rsp",
        "apx_tmp_rflags",
        "apx_tmp_stack_rsp",
        "apx_in_ptr",
        "apx_out_ptr",
    ] {
        text.push_str(&format!(".globl {symbol}\n{symbol}: .quad 0\n"));
    }
    text.push_str(".text\n");

    for case in cases {
        text.push_str(&format!(
            ".globl apx_case_{}\n.type apx_case_{}, @function\napx_case_{}:\n",
            case.id, case.id, case.id
        ));
        text.push_str("    push rbx\n");
        text.push_str("    push rbp\n");
        text.push_str("    push r12\n");
        text.push_str("    push r13\n");
        text.push_str("    push r14\n");
        text.push_str("    push r15\n");
        text.push_str("    mov qword ptr [rip + apx_host_rsp], rsp\n");
        text.push_str("    mov qword ptr [rip + apx_in_ptr], rdi\n");
        text.push_str("    mov qword ptr [rip + apx_out_ptr], rsi\n");
        text.push_str("    mov r15, rdi\n");
        text.push_str("    mov r14, rsi\n");
        if case.input.mode & MODE_STACK_RSP != 0 {
            text.push_str(&format!(
                "    mov r13, qword ptr [r15 + {}]\n",
                IN_GPR + 6 * 8
            ));
            text.push_str(&format!("    sub r13, {STACK_ADDR}\n"));
            text.push_str(&format!("    lea r12, [r14 + {OUT_STACK}]\n"));
            text.push_str("    lea r13, [r12 + r13]\n");
            text.push_str("    mov qword ptr [rip + apx_tmp_stack_rsp], r13\n");
        }
        text.push_str(&format!("    push qword ptr [r15 + {IN_RFLAGS}]\n"));
        text.push_str("    popfq\n");
        emit_load_gprs(&mut text, llvm_mc, case.input.mode)?;
        text.push_str(&format!("    {}\n", c_byte_directive(&case.op)));
        emit_store_gprs(&mut text, llvm_mc, case.input.mode)?;
        text.push_str("    pop r15\n");
        text.push_str("    pop r14\n");
        text.push_str("    pop r13\n");
        text.push_str("    pop r12\n");
        text.push_str("    pop rbp\n");
        text.push_str("    pop rbx\n");
        text.push_str("    ret\n");
        text.push_str(&format!(
            ".size apx_case_{}, .-apx_case_{}\n",
            case.id, case.id
        ));
    }

    std::fs::write(&cases_s, text).ok()?;
    Some(cases_s)
}

fn oracle_path(llvm_mc: &Path, cases: &[DiffCase]) -> Option<PathBuf> {
    let cc = cc_path()?;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let src = root.join("tools/x86_64-apx-map4-diff/oracle.c");
    let build_dir = root.join("target/x86_64-apx-map4-diff");
    let oracle = build_dir.join("oracle");
    std::fs::create_dir_all(&build_dir).ok()?;

    let decls_inc = write_decls_inc(&build_dir, cases)?;
    let cases_inc = write_cases_inc(&build_dir, cases)?;
    let cases_s = write_cases_asm(&build_dir, llvm_mc, cases)?;

    let decls_arg = format!("-DAPX_MAP4_DIFF_DECLS_INC=\"{}\"", decls_inc.display());
    let cases_arg = format!("-DAPX_MAP4_DIFF_CASES_INC=\"{}\"", cases_inc.display());
    let status = Command::new(cc)
        .args(["-O2", "-std=c11", "-Wall", "-Wextra", "-o"])
        .arg(&oracle)
        .arg(&decls_arg)
        .arg(&cases_arg)
        .arg(&src)
        .arg(&cases_s)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()?;
    if !status.success() {
        return None;
    }

    oracle.exists().then_some(oracle)
}

fn run_oracle(qemu: &Path, oracle: &Path, cases: &[DiffCase]) -> Option<Vec<OutCase>> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&WIRE_MAGIC.to_le_bytes());
    payload.extend_from_slice(&(cases.len() as u32).to_le_bytes());
    for case in cases {
        payload.extend_from_slice(as_bytes(&case.input));
    }

    let cpu = std::env::var("QEMU_X86_64_CPU").unwrap_or_else(|_| "max".to_string());
    let mut child = Command::new(qemu)
        .args(["-cpu", &cpu])
        .arg(oracle)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&payload);
    });

    let mut out = Vec::new();
    child.stdout.take().unwrap().read_to_end(&mut out).ok()?;
    let _ = writer.join();
    if !child.wait().ok()?.success() || out.len() < 8 {
        return None;
    }

    let magic = u32::from_le_bytes(out[0..4].try_into().unwrap());
    let count = u32::from_le_bytes(out[4..8].try_into().unwrap()) as usize;
    if magic != WIRE_MAGIC || count != cases.len() {
        return None;
    }

    let expected_len = 8 + count * std::mem::size_of::<OutCase>();
    if out.len() != expected_len {
        return None;
    }

    let mut outputs = Vec::with_capacity(count);
    let mut offset = 8;
    for _ in 0..count {
        outputs.push(read_struct::<OutCase>(&out, offset));
        offset += std::mem::size_of::<OutCase>();
    }
    Some(outputs)
}

fn assert_same_snapshot(case: &DiffCase, rax: &OutCase, oracle: &OutCase) {
    assert_eq!(rax.id, oracle.id, "{}: case id", case.label);
    assert_eq!(rax.gpr, oracle.gpr, "{}: GPR snapshot", case.label);
    assert_eq!(
        rax.rflags & case.flag_mask,
        oracle.rflags & case.flag_mask,
        "{}: RFLAGS masked by {:#x}",
        case.label,
        case.flag_mask
    );
    assert_eq!(
        rax.scratch, oracle.scratch,
        "{}: scratch memory snapshot",
        case.label
    );
    assert_eq!(
        rax.stack, oracle.stack,
        "{}: stack memory snapshot",
        case.label
    );
}

#[test]
fn qemu_apx_map4_generated_corpus_matches_rax() {
    let Some(qemu) = qemu_path() else {
        eprintln!("[skip] qemu-x86_64 unavailable; skipping APX MAP4 differential corpus");
        return;
    };
    let Some(llvm_mc) = llvm_mc_path() else {
        eprintln!("[skip] llvm-mc unavailable; skipping APX MAP4 differential corpus");
        return;
    };

    let cases = assembled_cases(&llvm_mc);
    if cases.is_empty() {
        eprintln!("[skip] llvm-mc did not assemble any APX MAP4 differential cases");
        return;
    }

    let Some(oracle) = oracle_path(&llvm_mc, &cases) else {
        eprintln!("[skip] APX MAP4 oracle build failed or compiler unavailable");
        return;
    };
    let Some(outputs) = run_oracle(&qemu, &oracle, &cases) else {
        eprintln!("[skip] qemu-x86_64 could not run the APX MAP4 oracle");
        return;
    };

    let mut compared = 0usize;
    let mut qemu_unsupported = 0usize;
    for (case, oracle) in cases.iter().zip(outputs.iter()) {
        assert_eq!(oracle.id, case.id, "{}: oracle case id", case.label);
        if oracle.valid == 0 {
            qemu_unsupported += 1;
            continue;
        }
        let rax = run_rax(case);
        assert_same_snapshot(case, &rax, oracle);
        compared += 1;
    }

    if compared == 0 {
        eprintln!(
            "[skip] qemu rejected all {} generated APX MAP4 differential cases",
            qemu_unsupported
        );
    } else {
        eprintln!("[info] compared {compared} APX MAP4 cases; qemu rejected {qemu_unsupported}");
    }
}
