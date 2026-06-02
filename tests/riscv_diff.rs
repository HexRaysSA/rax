//! RISC-V (RV64GC) differential test harness: rax interpreter vs. QEMU oracle.
//!
//! The rax software interpreter (`src/riscv/`) is checked against a
//! hardware-semantics reference produced by running each instruction under
//! `qemu-riscv64` (user mode). The reference harness is `tools/riscv-diff/
//! oracle.c`, built on demand into a static RV64GC ELF.
//!
//! For each `(instruction, initial architectural state)` pair we:
//!   1. run it on the oracle (x1..x31 except gp/tp, f0..f31, fcsr, plus a shared
//!      scratch window captured), and
//!   2. run it on the rax `RiscVCpu` from the *identical* initial state,
//! then compare the full register file. Any divergence is an interpreter bug.
//!
//! Robustness (mirrors `tests/arm_diff.rs`):
//!   - if the cross compiler or `qemu-riscv64` is unavailable, every test
//!     self-skips (returns without failing) so the suite is green anywhere.
//!   - only non-PC-relative instructions are tested (no AUIPC/JAL/JALR/branch),
//!     because the oracle executes at a different PC than rax. Control-flow
//!     correctness is covered by the in-crate unit tests.
//!
//! `x3` (gp) and `x4` (tp) are reserved by the oracle (it must preserve them
//! for the signal handler's TLS), so they are never used as operands and never
//! compared.

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use rax::riscv::{FlatMemory, RiscVConfig, RiscVCpu, RiscVExit};

// ---------------------------------------------------------------------------
// Wire format -- must match tools/riscv-diff/oracle.c byte for byte.
// ---------------------------------------------------------------------------

const WIRE_MAGIC: u32 = 0x3436_5652; // 'R','V','6','4'
const SCRATCH_ADDR: u64 = 0x20_0000;
const SCRATCH_BASE: u64 = SCRATCH_ADDR + 64;

/// Full architectural register file exchanged with the oracle.
#[repr(C)]
#[derive(Clone, Copy)]
struct RvState {
    x: [u64; 32],
    f: [u64; 32],
    pc: u64,
    fcsr: u64,
    scratch: [u64; 32],
}

impl RvState {
    fn zeroed() -> Self {
        RvState {
            x: [0; 32],
            f: [0; 32],
            pc: 0,
            fcsr: 0,
            scratch: [0; 32],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct InCase {
    insn: u32,
    insn_len: u32,
    st: RvState,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct OutCase {
    st: RvState,
    trapped: u32,
    valid: u32,
}

fn as_bytes<T: Copy>(v: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts(v as *const T as *const u8, std::mem::size_of::<T>()) }
}

fn read_struct<T: Copy>(buf: &[u8], off: usize) -> T {
    assert!(off + std::mem::size_of::<T>() <= buf.len());
    unsafe { std::ptr::read_unaligned(buf[off..].as_ptr() as *const T) }
}

// ---------------------------------------------------------------------------
// Deterministic PRNG (splitmix64) -- reproducible without std rng.
// ---------------------------------------------------------------------------

struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed)
    }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// A register value biased towards interesting bit patterns.
    fn reg(&mut self) -> u64 {
        match self.next() % 16 {
            0 => 0,
            1 => 1,
            2 => u64::MAX,
            3 => 1u64 << 63,
            4 => 0x8000_0000,
            5 => 0xffff_ffff,
            6 => (self.next() & 0x3f), // small shift-amount sized
            7 => self.next() & 0xff,
            _ => self.next(),
        }
    }
}

// ---------------------------------------------------------------------------
// Instruction encoders.
// ---------------------------------------------------------------------------

fn r_type(funct7: u32, rs2: u32, rs1: u32, funct3: u32, rd: u32, opcode: u32) -> u32 {
    (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
}
fn i_type(imm: i32, rs1: u32, funct3: u32, rd: u32, opcode: u32) -> u32 {
    (((imm as u32) & 0xfff) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
}
fn shift_imm(funct6: u32, shamt: u32, rs1: u32, funct3: u32, rd: u32, opcode: u32) -> u32 {
    (funct6 << 26) | ((shamt & 0x3f) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
}
fn shift_imm_w(funct7: u32, shamt: u32, rs1: u32, funct3: u32, rd: u32, opcode: u32) -> u32 {
    (funct7 << 25) | ((shamt & 0x1f) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
}
fn s_type(imm: i32, rs2: u32, rs1: u32, funct3: u32, opcode: u32) -> u32 {
    let u = (imm as u32) & 0xfff;
    let hi = (u >> 5) & 0x7f;
    let lo = u & 0x1f;
    (hi << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (lo << 7) | opcode
}
fn amo(funct5: u32, rs2: u32, rs1: u32, funct3: u32, rd: u32) -> u32 {
    (funct5 << 27) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | 0x2f
}

// ---------------------------------------------------------------------------
// Oracle build + run.
// ---------------------------------------------------------------------------

fn oracle_path() -> Option<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools/riscv-diff");
    let oracle = dir.join("oracle");
    let needs_build = match (oracle.metadata(), dir.join("oracle.c").metadata()) {
        (Ok(o), Ok(s)) => match (o.modified(), s.modified()) {
            (Ok(om), Ok(sm)) => om < sm,
            _ => true,
        },
        _ => true,
    };
    if needs_build {
        let status = Command::new("bash")
            .arg(dir.join("build.sh"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .ok()?;
        if !status.success() {
            return None;
        }
    }
    if oracle.exists() {
        Some(oracle)
    } else {
        None
    }
}

fn run_oracle(oracle: &PathBuf, cases: &[(u32, u32, RvState)]) -> Option<Vec<OutCase>> {
    let mut payload = Vec::with_capacity(8 + cases.len() * std::mem::size_of::<InCase>());
    payload.extend_from_slice(&WIRE_MAGIC.to_le_bytes());
    payload.extend_from_slice(&(cases.len() as u32).to_le_bytes());
    for (insn, len, st) in cases {
        let ic = InCase {
            insn: *insn,
            insn_len: *len,
            st: *st,
        };
        payload.extend_from_slice(as_bytes(&ic));
    }

    let mut child = Command::new("qemu-riscv64")
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
    let status = child.wait().ok()?;
    if !status.success() || out.len() < 8 {
        return None;
    }
    let magic = u32::from_le_bytes([out[0], out[1], out[2], out[3]]);
    let count = u32::from_le_bytes([out[4], out[5], out[6], out[7]]) as usize;
    if magic != WIRE_MAGIC || count != cases.len() {
        return None;
    }
    let mut res = Vec::with_capacity(count);
    let mut off = 8;
    for _ in 0..count {
        res.push(read_struct::<OutCase>(&out, off));
        off += std::mem::size_of::<OutCase>();
    }
    Some(res)
}

// ---------------------------------------------------------------------------
// rax: run one instruction from an identical initial state.
// ---------------------------------------------------------------------------

const INSN_ADDR: u64 = 0x1000;

fn run_rax(insn: u32, len: u32, input: &RvState) -> Option<RvState> {
    let mem = FlatMemory::new(0, 0x21_0000); // covers code @0x1000 and scratch @0x200000
    let mut cpu = RiscVCpu::new(RiscVConfig::rv64gc(), Box::new(mem));

    for i in 1..32u8 {
        if i == 3 || i == 4 {
            continue;
        }
        cpu.set_x(i, input.x[i as usize]);
    }
    for i in 0..32u8 {
        cpu.set_f(i, input.f[i as usize]);
    }
    cpu.set_fcsr(input.fcsr as u32);

    // Install the scratch window.
    let mut scratch_bytes: Vec<u8> = Vec::with_capacity(256);
    for w in input.scratch.iter() {
        scratch_bytes.extend_from_slice(&w.to_le_bytes());
    }
    cpu.write_memory(SCRATCH_ADDR, &scratch_bytes).ok()?;

    cpu.write_memory(INSN_ADDR, &insn.to_le_bytes()[..len as usize])
        .ok()?;
    cpu.set_pc(INSN_ADDR);

    match cpu.step() {
        RiscVExit::Continue => {}
        _ => return None,
    }

    let mut out = RvState::zeroed();
    for i in 1..32u8 {
        out.x[i as usize] = cpu.x(i);
    }
    for i in 0..32u8 {
        out.f[i as usize] = cpu.f(i);
    }
    out.fcsr = cpu.fcsr() as u64;
    for (i, w) in out.scratch.iter_mut().enumerate() {
        *w = cpu.mem_read_u64(SCRATCH_ADDR + (i as u64) * 8).ok()?;
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Comparison.
// ---------------------------------------------------------------------------

struct Mismatch {
    label: String,
    insn: u32,
    detail: String,
}

fn compare_case(
    label: &str,
    insn: u32,
    input: &RvState,
    oracle: &OutCase,
    cmp_fp: bool,
    mismatches: &mut Vec<Mismatch>,
) {
    let rax = run_rax(insn, if insn & 3 == 3 { 4 } else { 2 }, input);

    if oracle.trapped != 0 {
        if rax.is_some() {
            mismatches.push(Mismatch {
                label: label.into(),
                insn,
                detail: format!(
                    "hw faulted (sig {}) but rax executed the encoding",
                    oracle.trapped
                ),
            });
        }
        return;
    }
    let rax = match rax {
        Some(s) => s,
        None => {
            mismatches.push(Mismatch {
                label: label.into(),
                insn,
                detail: "hw executed but rax rejected the encoding".into(),
            });
            return;
        }
    };

    let mut diffs = Vec::new();
    for i in 1..32usize {
        if i == 3 || i == 4 {
            continue;
        }
        if rax.x[i] != oracle.st.x[i] {
            diffs.push(format!(
                "x{i}: rax={:#018x} hw={:#018x}",
                rax.x[i], oracle.st.x[i]
            ));
        }
    }
    for i in 0..32usize {
        if rax.scratch[i] != oracle.st.scratch[i] {
            diffs.push(format!(
                "scratch[{i}]: rax={:#018x} hw={:#018x}",
                rax.scratch[i], oracle.st.scratch[i]
            ));
        }
    }
    if cmp_fp {
        for i in 0..32usize {
            if rax.f[i] != oracle.st.f[i] {
                diffs.push(format!(
                    "f{i}: rax={:#018x} hw={:#018x}",
                    rax.f[i], oracle.st.f[i]
                ));
            }
        }
        if rax.fcsr != oracle.st.fcsr {
            diffs.push(format!(
                "fcsr: rax={:#x} hw={:#x}",
                rax.fcsr, oracle.st.fcsr
            ));
        }
    }

    if !diffs.is_empty() {
        mismatches.push(Mismatch {
            label: label.into(),
            insn,
            detail: diffs.join(", "),
        });
    }
}

/// Run a batch of `(label, insn, input_state)` cases against the oracle and
/// fail with a report if any diverge. Self-skips if the toolchain is absent.
fn run_batch(batch: &[(String, u32, RvState)], cmp_fp: bool) {
    let oracle = match oracle_path() {
        Some(p) => p,
        None => {
            eprintln!("riscv_diff: oracle/toolchain unavailable; skipping");
            return;
        }
    };
    let cases: Vec<(u32, u32, RvState)> = batch
        .iter()
        .map(|(_, insn, st)| (*insn, if *insn & 3 == 3 { 4 } else { 2 }, *st))
        .collect();
    let outs = match run_oracle(&oracle, &cases) {
        Some(o) => o,
        None => {
            eprintln!("riscv_diff: oracle run failed; skipping");
            return;
        }
    };
    let mut mismatches = Vec::new();
    for ((label, insn, st), oc) in batch.iter().zip(outs.iter()) {
        compare_case(label, *insn, st, oc, cmp_fp, &mut mismatches);
    }
    if !mismatches.is_empty() {
        let mut msg = format!("\n{} divergence(s) from qemu-riscv64:\n", mismatches.len());
        for m in mismatches.iter().take(40) {
            msg += &format!("  [{}] insn={:#010x}: {}\n", m.label, m.insn, m.detail);
        }
        if mismatches.len() > 40 {
            msg += &format!("  ... and {} more\n", mismatches.len() - 40);
        }
        panic!("{msg}");
    }
}

/// Register operands used in tests (excludes x0, x3=gp, x4=tp).
const POOL: [u32; 6] = [1, 5, 6, 10, 28, 31];

/// Build a random integer input state.
fn rand_state(rng: &mut Rng) -> RvState {
    let mut st = RvState::zeroed();
    for i in 1..32usize {
        if i == 3 || i == 4 {
            continue;
        }
        st.x[i] = rng.reg();
    }
    st
}

// ===========================================================================
// Tests.
// ===========================================================================

#[test]
fn diff_alu_reg() {
    let ops: &[(&str, u32, u32)] = &[
        ("add", 0b0000000, 0),
        ("sub", 0b0100000, 0),
        ("sll", 0b0000000, 1),
        ("slt", 0b0000000, 2),
        ("sltu", 0b0000000, 3),
        ("xor", 0b0000000, 4),
        ("srl", 0b0000000, 5),
        ("sra", 0b0100000, 5),
        ("or", 0b0000000, 6),
        ("and", 0b0000000, 7),
    ];
    let mut rng = Rng::new(0x1111);
    let mut batch = Vec::new();
    for (name, f7, f3) in ops {
        for _ in 0..40 {
            let rd = POOL[(rng.next() % 6) as usize];
            let rs1 = POOL[(rng.next() % 6) as usize];
            let rs2 = POOL[(rng.next() % 6) as usize];
            let insn = r_type(*f7, rs2, rs1, *f3, rd, 0x33);
            batch.push((name.to_string(), insn, rand_state(&mut rng)));
        }
    }
    run_batch(&batch, false);
}

#[test]
fn diff_alu_imm() {
    // (name, funct3) for I-type; shifts handled separately.
    let imm_ops: &[(&str, u32)] = &[
        ("addi", 0),
        ("slti", 2),
        ("sltiu", 3),
        ("xori", 4),
        ("ori", 6),
        ("andi", 7),
    ];
    let mut rng = Rng::new(0x2222);
    let mut batch = Vec::new();
    for (name, f3) in imm_ops {
        for _ in 0..40 {
            let rd = POOL[(rng.next() % 6) as usize];
            let rs1 = POOL[(rng.next() % 6) as usize];
            let imm = (rng.next() as i32 % 4096) - 2048;
            let insn = i_type(imm, rs1, *f3, rd, 0x13);
            batch.push((name.to_string(), insn, rand_state(&mut rng)));
        }
    }
    // Shift immediates (RV64: 6-bit shamt).
    let shifts: &[(&str, u32, u32)] = &[("slli", 0b000000, 1), ("srli", 0b000000, 5), ("srai", 0b010000, 5)];
    for (name, f6, f3) in shifts {
        for sh in 0..64u32 {
            let rd = POOL[(rng.next() % 6) as usize];
            let rs1 = POOL[(rng.next() % 6) as usize];
            let insn = shift_imm(*f6, sh, rs1, *f3, rd, 0x13);
            batch.push((name.to_string(), insn, rand_state(&mut rng)));
        }
    }
    run_batch(&batch, false);
}

#[test]
fn diff_alu_word() {
    let ops: &[(&str, u32, u32)] = &[
        ("addw", 0b0000000, 0),
        ("subw", 0b0100000, 0),
        ("sllw", 0b0000000, 1),
        ("srlw", 0b0000000, 5),
        ("sraw", 0b0100000, 5),
    ];
    let mut rng = Rng::new(0x3333);
    let mut batch = Vec::new();
    for (name, f7, f3) in ops {
        for _ in 0..40 {
            let rd = POOL[(rng.next() % 6) as usize];
            let rs1 = POOL[(rng.next() % 6) as usize];
            let rs2 = POOL[(rng.next() % 6) as usize];
            let insn = r_type(*f7, rs2, rs1, *f3, rd, 0x3b);
            batch.push((name.to_string(), insn, rand_state(&mut rng)));
        }
    }
    // word immediates
    let mut push_imm = |batch: &mut Vec<(String, u32, RvState)>, rng: &mut Rng| {
        for _ in 0..40 {
            let rd = POOL[(rng.next() % 6) as usize];
            let rs1 = POOL[(rng.next() % 6) as usize];
            let imm = (rng.next() as i32 % 4096) - 2048;
            batch.push(("addiw".into(), i_type(imm, rs1, 0, rd, 0x1b), rand_state(rng)));
        }
        for sh in 0..32u32 {
            let rd = POOL[(rng.next() % 6) as usize];
            let rs1 = POOL[(rng.next() % 6) as usize];
            batch.push(("slliw".into(), shift_imm_w(0b0000000, sh, rs1, 1, rd, 0x1b), rand_state(rng)));
            batch.push(("srliw".into(), shift_imm_w(0b0000000, sh, rs1, 5, rd, 0x1b), rand_state(rng)));
            batch.push(("sraiw".into(), shift_imm_w(0b0100000, sh, rs1, 5, rd, 0x1b), rand_state(rng)));
        }
    };
    push_imm(&mut batch, &mut rng);
    run_batch(&batch, false);
}

#[test]
fn diff_muldiv() {
    let ops: &[(&str, u32, u32)] = &[
        ("mul", 1, 0),
        ("mulh", 1, 1),
        ("mulhsu", 1, 2),
        ("mulhu", 1, 3),
        ("div", 1, 4),
        ("divu", 1, 5),
        ("rem", 1, 6),
        ("remu", 1, 7),
    ];
    let word_ops: &[(&str, u32)] = &[("mulw", 0), ("divw", 4), ("divuw", 5), ("remw", 6), ("remuw", 7)];
    let mut rng = Rng::new(0x4444);
    let mut batch = Vec::new();
    for (name, f7, f3) in ops {
        for _ in 0..60 {
            let rd = POOL[(rng.next() % 6) as usize];
            let rs1 = POOL[(rng.next() % 6) as usize];
            let rs2 = POOL[(rng.next() % 6) as usize];
            batch.push((name.to_string(), r_type(*f7, rs2, rs1, *f3, rd, 0x33), rand_state(&mut rng)));
        }
    }
    for (name, f3) in word_ops {
        for _ in 0..60 {
            let rd = POOL[(rng.next() % 6) as usize];
            let rs1 = POOL[(rng.next() % 6) as usize];
            let rs2 = POOL[(rng.next() % 6) as usize];
            batch.push((name.to_string(), r_type(1, rs2, rs1, *f3, rd, 0x3b), rand_state(&mut rng)));
        }
    }
    run_batch(&batch, false);
}

#[test]
fn diff_bitmanip() {
    let mut rng = Rng::new(0x5555);
    let mut batch = Vec::new();
    // Zba (OP, funct7=0x10)
    for (name, f3) in [("sh1add", 2u32), ("sh2add", 4), ("sh3add", 6)] {
        for _ in 0..30 {
            let (rd, rs1, rs2) = (POOL[(rng.next() % 6) as usize], POOL[(rng.next() % 6) as usize], POOL[(rng.next() % 6) as usize]);
            batch.push((name.into(), r_type(0b0010000, rs2, rs1, f3, rd, 0x33), rand_state(&mut rng)));
        }
    }
    // Zba (OP-32)
    for _ in 0..30 {
        let (rd, rs1, rs2) = (POOL[(rng.next() % 6) as usize], POOL[(rng.next() % 6) as usize], POOL[(rng.next() % 6) as usize]);
        batch.push(("add.uw".into(), r_type(0b0000100, rs2, rs1, 0, rd, 0x3b), rand_state(&mut rng)));
        batch.push(("sh1add.uw".into(), r_type(0b0010000, rs2, rs1, 2, rd, 0x3b), rand_state(&mut rng)));
        batch.push(("sh2add.uw".into(), r_type(0b0010000, rs2, rs1, 4, rd, 0x3b), rand_state(&mut rng)));
        batch.push(("sh3add.uw".into(), r_type(0b0010000, rs2, rs1, 6, rd, 0x3b), rand_state(&mut rng)));
    }
    // slli.uw (OP-IMM-32, funct6=0b000010)
    for sh in 0..64u32 {
        let (rd, rs1) = (POOL[(rng.next() % 6) as usize], POOL[(rng.next() % 6) as usize]);
        batch.push(("slli.uw".into(), shift_imm(0b000010, sh, rs1, 1, rd, 0x1b), rand_state(&mut rng)));
    }
    // Zbb logic-with-negate (OP, funct7=0x20)
    for (name, f3) in [("andn", 7u32), ("orn", 6), ("xnor", 4)] {
        for _ in 0..30 {
            let (rd, rs1, rs2) = (POOL[(rng.next() % 6) as usize], POOL[(rng.next() % 6) as usize], POOL[(rng.next() % 6) as usize]);
            batch.push((name.into(), r_type(0b0100000, rs2, rs1, f3, rd, 0x33), rand_state(&mut rng)));
        }
    }
    // Zbb rotate (OP, funct7=0x30)
    for (name, f3) in [("rol", 1u32), ("ror", 5)] {
        for _ in 0..30 {
            let (rd, rs1, rs2) = (POOL[(rng.next() % 6) as usize], POOL[(rng.next() % 6) as usize], POOL[(rng.next() % 6) as usize]);
            batch.push((name.into(), r_type(0b0110000, rs2, rs1, f3, rd, 0x33), rand_state(&mut rng)));
        }
    }
    // rolw/rorw (OP-32)
    for (name, f3) in [("rolw", 1u32), ("rorw", 5)] {
        for _ in 0..30 {
            let (rd, rs1, rs2) = (POOL[(rng.next() % 6) as usize], POOL[(rng.next() % 6) as usize], POOL[(rng.next() % 6) as usize]);
            batch.push((name.into(), r_type(0b0110000, rs2, rs1, f3, rd, 0x3b), rand_state(&mut rng)));
        }
    }
    // Zbb min/max (OP, funct7=0x05)
    for (name, f3) in [("min", 4u32), ("minu", 5), ("max", 6), ("maxu", 7)] {
        for _ in 0..30 {
            let (rd, rs1, rs2) = (POOL[(rng.next() % 6) as usize], POOL[(rng.next() % 6) as usize], POOL[(rng.next() % 6) as usize]);
            batch.push((name.into(), r_type(0b0000101, rs2, rs1, f3, rd, 0x33), rand_state(&mut rng)));
        }
    }
    // Zbc clmul (OP, funct7=0x05)
    for (name, f3) in [("clmul", 1u32), ("clmulr", 2), ("clmulh", 3)] {
        for _ in 0..30 {
            let (rd, rs1, rs2) = (POOL[(rng.next() % 6) as usize], POOL[(rng.next() % 6) as usize], POOL[(rng.next() % 6) as usize]);
            batch.push((name.into(), r_type(0b0000101, rs2, rs1, f3, rd, 0x33), rand_state(&mut rng)));
        }
    }
    // Zbb unary (OP-IMM funct7=0x30): clz/ctz/cpop/sext.b/sext.h
    for (name, rs2v) in [("clz", 0u32), ("ctz", 1), ("cpop", 2), ("sext.b", 4), ("sext.h", 5)] {
        for _ in 0..30 {
            let (rd, rs1) = (POOL[(rng.next() % 6) as usize], POOL[(rng.next() % 6) as usize]);
            let insn = r_type(0b0110000, rs2v, rs1, 1, rd, 0x13);
            batch.push((name.into(), insn, rand_state(&mut rng)));
        }
    }
    // Zbb unary word (OP-IMM-32 funct7=0x30): clzw/ctzw/cpopw
    for (name, rs2v) in [("clzw", 0u32), ("ctzw", 1), ("cpopw", 2)] {
        for _ in 0..30 {
            let (rd, rs1) = (POOL[(rng.next() % 6) as usize], POOL[(rng.next() % 6) as usize]);
            let insn = r_type(0b0110000, rs2v, rs1, 1, rd, 0x1b);
            batch.push((name.into(), insn, rand_state(&mut rng)));
        }
    }
    // zext.h (OP-32 funct7=0x04, rs2=0, funct3=4)
    for _ in 0..30 {
        let (rd, rs1) = (POOL[(rng.next() % 6) as usize], POOL[(rng.next() % 6) as usize]);
        batch.push(("zext.h".into(), r_type(0b0000100, 0, rs1, 4, rd, 0x3b), rand_state(&mut rng)));
    }
    // orc.b / rev8 / rori / roriw
    for _ in 0..30 {
        let (rd, rs1) = (POOL[(rng.next() % 6) as usize], POOL[(rng.next() % 6) as usize]);
        batch.push(("orc.b".into(), r_type(0b0010100, 0b00111, rs1, 5, rd, 0x13), rand_state(&mut rng)));
        batch.push(("rev8".into(), i_type(0b011010111000, rs1, 5, rd, 0x13), rand_state(&mut rng)));
    }
    for sh in 0..64u32 {
        let (rd, rs1) = (POOL[(rng.next() % 6) as usize], POOL[(rng.next() % 6) as usize]);
        batch.push(("rori".into(), shift_imm(0b011000, sh, rs1, 5, rd, 0x13), rand_state(&mut rng)));
    }
    for sh in 0..32u32 {
        let (rd, rs1) = (POOL[(rng.next() % 6) as usize], POOL[(rng.next() % 6) as usize]);
        batch.push(("roriw".into(), shift_imm_w(0b0110000, sh, rs1, 5, rd, 0x1b), rand_state(&mut rng)));
    }
    // Zbs (OP funct7) and immediate forms
    for (name, f7, f3) in [("bclr", 0b0100100u32, 1u32), ("bext", 0b0100100, 5), ("binv", 0b0110100, 1), ("bset", 0b0010100, 1)] {
        for _ in 0..30 {
            let (rd, rs1, rs2) = (POOL[(rng.next() % 6) as usize], POOL[(rng.next() % 6) as usize], POOL[(rng.next() % 6) as usize]);
            batch.push((name.into(), r_type(f7, rs2, rs1, f3, rd, 0x33), rand_state(&mut rng)));
        }
    }
    for (name, f6, f3) in [("bclri", 0b010010u32, 1u32), ("bexti", 0b010010, 5), ("binvi", 0b011010, 1), ("bseti", 0b001010, 1)] {
        for sh in (0..64u32).step_by(7) {
            let (rd, rs1) = (POOL[(rng.next() % 6) as usize], POOL[(rng.next() % 6) as usize]);
            batch.push((name.into(), shift_imm(f6, sh, rs1, f3, rd, 0x13), rand_state(&mut rng)));
        }
    }
    run_batch(&batch, false);
}

#[test]
fn diff_loads_stores() {
    let mut rng = Rng::new(0x6666);
    let mut batch = Vec::new();
    // Base register x10 -> SCRATCH_BASE; offsets small so we stay in the window.
    let loads: &[(&str, u32)] = &[("lb", 0), ("lh", 1), ("lw", 2), ("ld", 3), ("lbu", 4), ("lhu", 5), ("lwu", 6)];
    let stores: &[(&str, u32)] = &[("sb", 0), ("sh", 1), ("sw", 2), ("sd", 3)];
    let offs: [i32; 5] = [0, 8, 16, -8, 24];
    for (name, f3) in loads {
        for &off in offs.iter() {
            for _ in 0..6 {
                let rd = POOL[(rng.next() % 6) as usize];
                if rd == 10 {
                    continue;
                }
                let mut st = rand_state(&mut rng);
                st.x[10] = SCRATCH_BASE;
                for s in st.scratch.iter_mut() {
                    *s = rng.next();
                }
                batch.push((name.to_string(), i_type(off, 10, *f3, rd, 0x03), st));
            }
        }
    }
    for (name, f3) in stores {
        for &off in offs.iter() {
            for _ in 0..6 {
                let rs2 = POOL[(rng.next() % 6) as usize];
                if rs2 == 10 {
                    continue;
                }
                let mut st = rand_state(&mut rng);
                st.x[10] = SCRATCH_BASE;
                for s in st.scratch.iter_mut() {
                    *s = rng.next();
                }
                batch.push((name.to_string(), s_type(off, rs2, 10, *f3, 0x23), st));
            }
        }
    }
    run_batch(&batch, false);
}

#[test]
fn diff_atomics() {
    let mut rng = Rng::new(0x7777);
    let mut batch = Vec::new();
    // base x10 -> SCRATCH_BASE (8-aligned). rd, rs2 from pool != 10.
    let amos: &[(&str, u32, u32)] = &[
        ("amoswap.w", 0b00001, 0b010),
        ("amoadd.w", 0b00000, 0b010),
        ("amoxor.w", 0b00100, 0b010),
        ("amoand.w", 0b01100, 0b010),
        ("amoor.w", 0b01000, 0b010),
        ("amomin.w", 0b10000, 0b010),
        ("amomax.w", 0b10100, 0b010),
        ("amominu.w", 0b11000, 0b010),
        ("amomaxu.w", 0b11100, 0b010),
        ("amoswap.d", 0b00001, 0b011),
        ("amoadd.d", 0b00000, 0b011),
        ("amoxor.d", 0b00100, 0b011),
        ("amoand.d", 0b01100, 0b011),
        ("amoor.d", 0b01000, 0b011),
        ("amomin.d", 0b10000, 0b011),
        ("amomax.d", 0b10100, 0b011),
        ("amominu.d", 0b11000, 0b011),
        ("amomaxu.d", 0b11100, 0b011),
        ("lr.w", 0b00010, 0b010),
        ("lr.d", 0b00010, 0b011),
        ("sc.w", 0b00011, 0b010),
        ("sc.d", 0b00011, 0b011),
    ];
    for (name, f5, f3) in amos {
        for _ in 0..30 {
            let rd = POOL[(rng.next() % 6) as usize];
            let rs2 = POOL[(rng.next() % 6) as usize];
            if rd == 10 || rs2 == 10 {
                continue;
            }
            let rs2enc = if name.starts_with("lr") { 0 } else { rs2 };
            let mut st = rand_state(&mut rng);
            st.x[10] = SCRATCH_BASE;
            for s in st.scratch.iter_mut() {
                *s = rng.next();
            }
            batch.push((name.to_string(), amo(*f5, rs2enc, 10, *f3, rd), st));
        }
    }
    run_batch(&batch, false);
}
