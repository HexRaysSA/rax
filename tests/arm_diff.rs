//! AArch64 differential test harness: rax interpreter vs. QEMU (hardware oracle).
//!
//! The rax software interpreter (`src/arm/aarch64/cpu.rs`) is checked against a
//! hardware-semantics reference produced by running each instruction under
//! `qemu-aarch64` (user mode). The reference harness is `tools/arm-diff/oracle.c`,
//! built on demand into a static AArch64 ELF.
//!
//! For each `(instruction, initial architectural state)` pair we:
//!   1. run it on the oracle (X0..X30, SP, NZCV, V0..V31 captured), and
//!   2. run it on the rax `AArch64Cpu` from the *identical* initial state,
//! then compare the full register file. Any divergence is an interpreter bug.
//!
//! Robustness (mirrors `tests/differential.rs` for x86-vs-KVM):
//!   - if the cross compiler or `qemu-aarch64` is unavailable, every test
//!     self-skips (returns without failing) so the suite is green anywhere.
//!   - only register-only instructions (no memory / branch / system) are tested;
//!     these are exactly where the SIMD/FP semantic bugs live.
//!
//! Scope is intentionally exhaustive *within* a family: encodings are enumerated
//! over their opcode/size/Q/U fields with fixed register fields, and many
//! pseudo-random input states are driven through each.

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use rax::arm::{AArch64Config, AArch64Cpu, ArmCpu, CpuExit, FlatMemory};

// ---------------------------------------------------------------------------
// Wire format -- must match tools/arm-diff/oracle.c byte for byte.
// ---------------------------------------------------------------------------

/// Full architectural register file exchanged with the oracle.
#[repr(C)]
#[derive(Clone, Copy)]
struct ArmState {
    x: [u64; 31],     // X0..X30
    sp: u64,          // SP
    pc: u64,          // input: unused; output: post-instruction PC
    pstate: u64,      // NZCV in bits [31:28]
    fpsr: u64,
    fpcr: u64,
    v: [u64; 64],     // V0..V31 as lo/hi u64 pairs
    scratch: [u64; 32], // shared scratch window (256 bytes) for load/store tests
}

/// AArch64 NOP (used to fill the oracle's unused second instruction slot).
const NOP: u32 = 0xd503201f;
/// Address of the shared scratch window (matches oracle.c SCRATCH_ADDR).
const SCRATCH_ADDR: u64 = 0x20_0000;
/// Base pointer tests aim a register at (matches oracle.c SCRATCH_BASE).
const SCRATCH_BASE: u64 = SCRATCH_ADDR + 64;

impl ArmState {
    fn zeroed() -> Self {
        ArmState {
            x: [0; 31],
            sp: 0,
            pc: 0,
            pstate: 0,
            fpsr: 0,
            fpcr: 0,
            v: [0; 64],
            scratch: [0; 32],
        }
    }
    fn vreg(&self, r: usize) -> (u64, u64) {
        (self.v[2 * r], self.v[2 * r + 1])
    }
    fn set_vreg(&mut self, r: usize, lo: u64, hi: u64) {
        self.v[2 * r] = lo;
        self.v[2 * r + 1] = hi;
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct InCase {
    insn: u32,
    flags: u32,
    st: ArmState,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct OutCase {
    st: ArmState,
    trapped: u32,
    valid: u32,
}

const WIRE_MAGIC: u32 = 0x314d_5241; // 'A','R','M','1'

// Compile-time guarantee the layout matches the C side.
const _: () = assert!(core::mem::size_of::<ArmState>() == 1056);
const _: () = assert!(core::mem::size_of::<InCase>() == 1064);
const _: () = assert!(core::mem::size_of::<OutCase>() == 1064);

// ---------------------------------------------------------------------------
// Byte (de)serialisation helpers -- plain little-endian copies of the structs.
// ---------------------------------------------------------------------------

fn as_bytes<T: Copy>(v: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts(v as *const T as *const u8, std::mem::size_of::<T>()) }
}

fn read_struct<T: Copy>(buf: &[u8], off: usize) -> T {
    assert!(off + std::mem::size_of::<T>() <= buf.len());
    unsafe { std::ptr::read_unaligned(buf[off..].as_ptr() as *const T) }
}

// ---------------------------------------------------------------------------
// Oracle: build on demand, then run a whole batch through one qemu invocation.
// ---------------------------------------------------------------------------

/// Build the oracle if needed; return its path, or `None` if the toolchain is
/// unavailable (test self-skips).
fn oracle_path() -> Option<PathBuf> {
    if which("qemu-aarch64").is_none() {
        return None;
    }
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools/arm-diff");
    let bin = dir.join("oracle");
    let need_build = match (bin.metadata(), dir.join("oracle.c").metadata()) {
        (Ok(b), Ok(c)) => match (b.modified(), c.modified()) {
            (Ok(bm), Ok(cm)) => bm < cm,
            _ => true,
        },
        _ => true,
    };
    if need_build {
        let status = Command::new("bash")
            .arg(dir.join("build.sh"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        match status {
            Ok(s) if s.success() => {}
            _ => return None, // cross compiler absent -> skip
        }
    }
    if bin.exists() { Some(bin) } else { None }
}

fn which(prog: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let cand = dir.join(prog);
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

/// Run `cases` through the oracle under qemu; returns one `OutCase` per input.
fn run_oracle(oracle: &PathBuf, cases: &[(u32, u32, ArmState)]) -> Option<Vec<OutCase>> {
    let mut payload = Vec::with_capacity(8 + cases.len() * std::mem::size_of::<InCase>());
    payload.extend_from_slice(&WIRE_MAGIC.to_le_bytes());
    payload.extend_from_slice(&(cases.len() as u32).to_le_bytes());
    for (insn, insn2, st) in cases {
        let ic = InCase { insn: *insn, flags: *insn2, st: *st };
        payload.extend_from_slice(as_bytes(&ic));
    }

    let mut child = Command::new("qemu-aarch64")
        .arg(oracle)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    // The oracle interleaves reads and writes, so feeding the whole batch before
    // draining stdout would deadlock once both pipe buffers fill. Write from a
    // dedicated thread while the main thread drains stdout.
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&payload);
        // drop(stdin) closes the pipe, signalling EOF to the oracle
    });
    let mut out = Vec::new();
    child.stdout.take().unwrap().read_to_end(&mut out).ok()?;
    let _ = writer.join();
    let status = child.wait().ok()?;
    if !status.success() {
        return None;
    }
    if out.len() < 8 {
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

/// Returns `Some(out_state)` if rax executed the instruction (CpuExit::Continue),
/// or `None` if rax treated it as undefined / errored.
fn run_rax(insn: u32, input: &ArmState) -> Option<ArmState> {
    // Memory must cover both the instruction (at 0) and the scratch window.
    let mem = FlatMemory::new(0, 0x30_0000);
    let mut cpu = AArch64Cpu::new(AArch64Config::default(), Box::new(mem));

    for i in 0..31u8 {
        cpu.set_gpr(i, input.x[i as usize]);
    }
    cpu.set_current_sp(input.sp);
    let ps = input.pstate;
    cpu.set_nzcv(ps & (1 << 31) != 0, ps & (1 << 30) != 0, ps & (1 << 29) != 0, ps & (1 << 28) != 0);
    for r in 0..32u8 {
        let (lo, hi) = input.vreg(r as usize);
        cpu.set_simd_reg(r, lo, hi).ok()?;
    }

    // Install the scratch window at SCRATCH_ADDR.
    let scratch_bytes: Vec<u8> = input.scratch.iter().flat_map(|w| w.to_le_bytes()).collect();
    cpu.write_memory(SCRATCH_ADDR, &scratch_bytes).ok()?;

    cpu.write_memory(0, &insn.to_le_bytes()).ok()?;
    cpu.set_pc(0);

    match cpu.step() {
        Ok(CpuExit::Continue) => {}
        _ => return None,
    }

    let mut out = ArmState::zeroed();
    for i in 0..31u8 {
        out.x[i as usize] = cpu.get_gpr(i);
    }
    out.sp = cpu.current_sp();
    out.pc = cpu.get_pc();
    let mut pstate = 0u64;
    if cpu.get_n() { pstate |= 1 << 31; }
    if cpu.get_z() { pstate |= 1 << 30; }
    if cpu.get_c() { pstate |= 1 << 29; }
    if cpu.get_v() { pstate |= 1 << 28; }
    out.pstate = pstate;
    for r in 0..32u8 {
        if let Some((lo, hi)) = cpu.get_simd_reg(r) {
            out.set_vreg(r as usize, lo, hi);
        }
    }
    // Read the scratch window back.
    for (i, w) in out.scratch.iter_mut().enumerate() {
        *w = cpu.mem_read_u64(SCRATCH_ADDR + (i as u64) * 8).ok()?;
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Comparison.
// ---------------------------------------------------------------------------

/// Description of a single divergence between rax and the oracle.
struct Mismatch {
    label: String,
    insn: u32,
    detail: String,
}

/// Compare one case. `cmp_flags` selects whether NZCV is compared (only for
/// flag-setting instructions; otherwise both should be unchanged anyway).
fn compare_case(
    label: &str,
    insn: u32,
    input: &ArmState,
    oracle: &OutCase,
    mismatches: &mut Vec<Mismatch>,
) {
    let rax = run_rax(insn, input);

    // Agreement on legality first.
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
        return; // both reject -> fine; nothing to value-compare
    }
    let rax = match rax {
        Some(s) => s,
        None => {
            mismatches.push(Mismatch {
                label: label.into(),
                insn,
                detail: "hw executed but rax rejected the encoding (undefined/err)".into(),
            });
            return;
        }
    };

    let mut diffs = Vec::new();
    for i in 0..31 {
        if rax.x[i] != oracle.st.x[i] {
            diffs.push(format!("x{i}: rax={:#018x} hw={:#018x}", rax.x[i], oracle.st.x[i]));
        }
    }
    if rax.sp != oracle.st.sp {
        diffs.push(format!("sp: rax={:#018x} hw={:#018x}", rax.sp, oracle.st.sp));
    }
    let rax_nzcv = (rax.pstate >> 28) & 0xF;
    let hw_nzcv = (oracle.st.pstate >> 28) & 0xF;
    if rax_nzcv != hw_nzcv {
        diffs.push(format!("nzcv: rax={:#x} hw={:#x}", rax_nzcv, hw_nzcv));
    }
    for r in 0..32 {
        let (rlo, rhi) = rax.vreg(r);
        let (hlo, hhi) = oracle.st.vreg(r);
        if (rlo, rhi) != (hlo, hhi) {
            diffs.push(format!(
                "v{r}: rax={:#018x}{:016x} hw={:#018x}{:016x}",
                rhi, rlo, hhi, hlo
            ));
        }
    }
    for i in 0..32 {
        if rax.scratch[i] != oracle.st.scratch[i] {
            diffs.push(format!(
                "scratch[{i}]: rax={:#018x} hw={:#018x}",
                rax.scratch[i], oracle.st.scratch[i]
            ));
        }
    }

    if !diffs.is_empty() {
        mismatches.push(Mismatch {
            label: label.into(),
            insn,
            detail: diffs.join("  |  "),
        });
    }
}

// ---------------------------------------------------------------------------
// Deterministic pseudo-random input generation.
// ---------------------------------------------------------------------------

struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed ^ 0x9e37_79b9_7f4a_7c15)
    }
    fn next(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    /// A value biased toward "interesting" bit patterns.
    fn interesting(&mut self) -> u64 {
        match self.next() % 8 {
            0 => 0,
            1 => u64::MAX,
            2 => 1,
            3 => 0x8000_0000_0000_0000,
            4 => 0x0000_0000_8000_0000,
            5 => self.next() & 0xFF,
            6 => self.next() & 0xFFFF_FFFF,
            _ => self.next(),
        }
    }
}

/// Build a randomised input state. GPRs x1.. and V1.. carry operands; the
/// destination registers are also randomised so unintended clobbers show up.
fn gen_input(rng: &mut Rng) -> ArmState {
    let mut st = ArmState::zeroed();
    for i in 0..31 {
        st.x[i] = rng.interesting();
    }
    st.sp = rng.interesting() & !0xF; // keep 16-aligned-ish; sp not dereferenced
    st.pstate = (rng.next() & 0xF) << 28; // random NZCV
    st.fpcr = 0; // round-to-nearest, no flush -- matches rax default
    st.fpsr = 0;
    for r in 0..32 {
        st.set_vreg(r, rng.interesting(), rng.interesting());
    }
    st
}

// ---------------------------------------------------------------------------
// Instruction family encoders.  Register fields are fixed: Rd=0, Rn=1, Rm=2,
// Ra=3.  Inputs vary the register *values*, exercising the data path.
// ---------------------------------------------------------------------------

const RD: u32 = 0;
const RN: u32 = 1;
const RM: u32 = 2;
const RA: u32 = 3;

/// Advanced SIMD three-same (integer + FP), main encoding:
/// `0 Q U 01110 size 1 Rm opcode 1 Rn Rd`
fn enc_three_same(q: u32, u: u32, size: u32, opcode: u32) -> u32 {
    (q << 30) | (u << 29) | (0b01110 << 24) | (size << 22) | (1 << 21)
        | (RM << 16) | (opcode << 11) | (1 << 10) | (RN << 5) | RD
}

/// Build the full list of three-same encodings to test (over-generates; illegal
/// combos are filtered by oracle agreement).
fn three_same_cases() -> Vec<(String, u32)> {
    let mut v = Vec::new();
    for q in 0..2 {
        for u in 0..2 {
            for size in 0..4 {
                // Integer opcodes 0x00..=0x17. FP opcodes (0x18..=0x1F) are
                // exercised separately with NaN-aware comparison.
                for opcode in 0..0b11000u32 {
                    let insn = enc_three_same(q, u, size, opcode);
                    v.push((
                        format!("3same q{q} u{u} sz{size} op{:05b}", opcode),
                        insn,
                    ));
                }
            }
        }
    }
    v
}

/// Data-processing (2 source): `sf 0 0 11010110 Rm opcode2 Rn Rd`
fn enc_dp2(sf: u32, opcode2: u32) -> u32 {
    (sf << 31) | (0b0011010110 << 21) | (RM << 16) | (opcode2 << 10) | (RN << 5) | RD
}

fn dp2_cases() -> Vec<(String, u32)> {
    let mut v = Vec::new();
    // opcode2: 0010=UDIV 0011=SDIV 1000=LSLV 1001=LSRV 1010=ASRV 1011=RORV
    for &op in &[0b0010u32, 0b0011, 0b1000, 0b1001, 0b1010, 0b1011] {
        for sf in 0..2 {
            v.push((format!("dp2 sf{sf} op{:04b}", op), enc_dp2(sf, op)));
        }
    }
    v
}

/// Data-processing (3 source): `sf 00 11011 op31 Rm o0 Ra Rn Rd`
fn enc_dp3(sf: u32, op31: u32, o0: u32) -> u32 {
    enc_dp3_ra(sf, op31, o0, RA)
}

/// Same, but with an explicit Ra field (SMULH/UMULH require Ra = 31/xzr).
fn enc_dp3_ra(sf: u32, op31: u32, o0: u32, ra: u32) -> u32 {
    (sf << 31) | (0b11011 << 24) | (op31 << 21) | (RM << 16) | (o0 << 15)
        | (ra << 10) | (RN << 5) | RD
}

fn dp3_cases() -> Vec<(String, u32)> {
    let mut v = Vec::new();
    // MADD: op31=000 o0=0 ; MSUB: op31=000 o0=1
    v.push(("madd".into(), enc_dp3(1, 0b000, 0)));
    v.push(("msub".into(), enc_dp3(1, 0b000, 1)));
    v.push(("madd_w".into(), enc_dp3(0, 0b000, 0)));
    v.push(("msub_w".into(), enc_dp3(0, 0b000, 1)));
    // SMADDL: op31=001 o0=0 ; SMSUBL: 001 o0=1 ; UMADDL: 101 o0=0 ; UMSUBL: 101 o0=1
    v.push(("smaddl".into(), enc_dp3(1, 0b001, 0)));
    v.push(("smsubl".into(), enc_dp3(1, 0b001, 1)));
    v.push(("umaddl".into(), enc_dp3(1, 0b101, 0)));
    v.push(("umsubl".into(), enc_dp3(1, 0b101, 1)));
    // SMULH: op31=010 o0=0 ; UMULH: 110 o0=0 (Ra must be 31/xzr)
    v.push(("smulh".into(), enc_dp3_ra(1, 0b010, 0, 31)));
    v.push(("umulh".into(), enc_dp3_ra(1, 0b110, 0, 31)));
    v
}

/// Add/subtract (shifted register): `sf op S 01011 shift 0 Rm imm6 Rn Rd`
fn enc_addsub_shift(sf: u32, op: u32, s: u32, shift: u32, imm6: u32) -> u32 {
    (sf << 31) | (op << 30) | (s << 29) | (0b01011 << 24) | (shift << 22)
        | (RM << 16) | (imm6 << 10) | (RN << 5) | RD
}

fn addsub_shift_cases() -> Vec<(String, u32)> {
    let mut v = Vec::new();
    for sf in 0..2 {
        for op in 0..2 {
            for s in 0..2 {
                for shift in 0..3 {
                    // LSL/LSR/ASR
                    for &imm6 in &[0u32, 1, 7, 31, if sf == 1 { 63 } else { 31 }] {
                        v.push((
                            format!("addsub sf{sf} op{op} s{s} sh{shift} #{imm6}"),
                            enc_addsub_shift(sf, op, s, shift, imm6),
                        ));
                    }
                }
            }
        }
    }
    v
}

/// Logical (shifted register): `sf opc 01010 shift N Rm imm6 Rn Rd`
fn enc_logical_shift(sf: u32, opc: u32, shift: u32, n: u32, imm6: u32) -> u32 {
    (sf << 31) | (opc << 29) | (0b01010 << 24) | (shift << 22) | (n << 21)
        | (RM << 16) | (imm6 << 10) | (RN << 5) | RD
}

fn logical_shift_cases() -> Vec<(String, u32)> {
    let mut v = Vec::new();
    for sf in 0..2 {
        for opc in 0..4 {
            // AND/ORR/EOR/ANDS
            for n in 0..2 {
                for shift in 0..4 {
                    for &imm6 in &[0u32, 1, 31, if sf == 1 { 63 } else { 31 }] {
                        v.push((
                            format!("logical sf{sf} opc{opc} n{n} sh{shift} #{imm6}"),
                            enc_logical_shift(sf, opc, shift, n, imm6),
                        ));
                    }
                }
            }
        }
    }
    v
}

// ---------------------------------------------------------------------------
// Test driver.
// ---------------------------------------------------------------------------

/// Run a family of encodings, each with `n_inputs` random states, against the
/// oracle and assert no divergences.
fn run_family(name: &str, cases: Vec<(String, u32)>, n_inputs: usize, seed: u64) {
    // Build the full batch of (label, insn, state) triples.
    let mut rng = Rng::new(seed);
    let mut batch: Vec<(String, u32, ArmState)> = Vec::new();
    for (label, insn) in &cases {
        for _ in 0..n_inputs {
            let st = gen_input(&mut rng);
            batch.push((label.clone(), *insn, st));
        }
    }
    run_batch(name, batch);
}

/// Run an explicit batch of (label, insn, input-state) triples against the
/// oracle and assert no divergences. Self-skips if the toolchain is absent.
fn run_batch(name: &str, batch: Vec<(String, u32, ArmState)>) {
    let oracle = match oracle_path() {
        Some(p) => p,
        None => {
            eprintln!("[arm_diff] {name}: qemu/cross-toolchain unavailable -> skipping");
            return;
        }
    };

    let labels: Vec<String> = batch.iter().map(|(l, _, _)| l.clone()).collect();
    let cases: Vec<(u32, u32, ArmState)> = batch.iter().map(|(_, i, s)| (*i, NOP, *s)).collect();

    let outs = match run_oracle(&oracle, &cases) {
        Some(o) => o,
        None => {
            eprintln!("[arm_diff] {name}: oracle run failed -> skipping");
            return;
        }
    };
    assert_eq!(outs.len(), cases.len());

    let mut mismatches = Vec::new();
    for (i, ((insn, _insn2, st), out)) in cases.iter().zip(outs.iter()).enumerate() {
        compare_case(&labels[i], *insn, st, out, &mut mismatches);
    }

    let batch = &cases; // for the count in the summary below
    if !mismatches.is_empty() {
        // Summarise: group by label, show a few representative cases.
        use std::collections::BTreeMap;
        let mut by_label: BTreeMap<String, usize> = BTreeMap::new();
        for m in &mismatches {
            *by_label.entry(m.label.clone()).or_default() += 1;
        }
        eprintln!("\n==== {name}: {} mismatches across {} cases ====", mismatches.len(), batch.len());
        eprintln!("-- by encoding --");
        for (label, count) in &by_label {
            eprintln!("  {count:5}x  {label}");
        }
        eprintln!("-- first 25 examples --");
        for m in mismatches.iter().take(25) {
            eprintln!("  [{}] {:#010x}: {}", m.label, m.insn, m.detail);
        }
        panic!("{name}: {} divergences vs hardware oracle", mismatches.len());
    }
}

/// Run rax over a two-instruction sequence and return the final state.
fn run_rax_pair(insn: u32, insn2: u32, input: &ArmState) -> Option<ArmState> {
    let mem = FlatMemory::new(0, 0x30_0000);
    let mut cpu = AArch64Cpu::new(AArch64Config::default(), Box::new(mem));
    for i in 0..31u8 {
        cpu.set_gpr(i, input.x[i as usize]);
    }
    cpu.set_current_sp(input.sp);
    let ps = input.pstate;
    cpu.set_nzcv(ps & (1 << 31) != 0, ps & (1 << 30) != 0, ps & (1 << 29) != 0, ps & (1 << 28) != 0);
    for r in 0..32u8 {
        let (lo, hi) = input.vreg(r as usize);
        cpu.set_simd_reg(r, lo, hi).ok()?;
    }
    let scratch_bytes: Vec<u8> = input.scratch.iter().flat_map(|w| w.to_le_bytes()).collect();
    cpu.write_memory(SCRATCH_ADDR, &scratch_bytes).ok()?;
    cpu.write_memory(0, &insn.to_le_bytes()).ok()?;
    cpu.write_memory(4, &insn2.to_le_bytes()).ok()?;
    cpu.set_pc(0);
    match cpu.step() {
        Ok(CpuExit::Continue) => {}
        _ => return None,
    }
    match cpu.step() {
        Ok(CpuExit::Continue) => {}
        _ => return None,
    }
    let mut out = ArmState::zeroed();
    for i in 0..31u8 {
        out.x[i as usize] = cpu.get_gpr(i);
    }
    out.sp = cpu.current_sp();
    out.pc = cpu.get_pc();
    let mut pstate = 0u64;
    if cpu.get_n() { pstate |= 1 << 31; }
    if cpu.get_z() { pstate |= 1 << 30; }
    if cpu.get_c() { pstate |= 1 << 29; }
    if cpu.get_v() { pstate |= 1 << 28; }
    out.pstate = pstate;
    for r in 0..32u8 {
        if let Some((lo, hi)) = cpu.get_simd_reg(r) {
            out.set_vreg(r as usize, lo, hi);
        }
    }
    for (i, w) in out.scratch.iter_mut().enumerate() {
        *w = cpu.mem_read_u64(SCRATCH_ADDR + (i as u64) * 8).ok()?;
    }
    Some(out)
}

/// Run a batch of two-instruction sequences differentially.
fn run_batch_pair(name: &str, batch: Vec<(String, u32, u32, ArmState)>) {
    let oracle = match oracle_path() {
        Some(p) => p,
        None => {
            eprintln!("[arm_diff] {name}: qemu/cross-toolchain unavailable -> skipping");
            return;
        }
    };
    let cases: Vec<(u32, u32, ArmState)> = batch.iter().map(|(_, a, b, s)| (*a, *b, *s)).collect();
    let outs = match run_oracle(&oracle, &cases) {
        Some(o) => o,
        None => {
            eprintln!("[arm_diff] {name}: oracle run failed -> skipping");
            return;
        }
    };
    let mut mismatches = Vec::new();
    for (i, ((insn, insn2, st), out)) in cases.iter().zip(outs.iter()).enumerate() {
        let rax = run_rax_pair(*insn, *insn2, st);
        if out.trapped != 0 {
            if rax.is_some() {
                mismatches.push(Mismatch { label: batch[i].0.clone(), insn: *insn, detail: format!("hw faulted (sig {}) but rax executed", out.trapped) });
            }
            continue;
        }
        let rax = match rax {
            Some(r) => r,
            None => { mismatches.push(Mismatch { label: batch[i].0.clone(), insn: *insn, detail: "hw executed but rax rejected".into() }); continue; }
        };
        let mut diffs = Vec::new();
        for r in 0..31 { if rax.x[r] != out.st.x[r] { diffs.push(format!("x{r}: rax={:#x} hw={:#x}", rax.x[r], out.st.x[r])); } }
        if (rax.pstate>>28)&0xF != (out.st.pstate>>28)&0xF { diffs.push(format!("nzcv: rax={:#x} hw={:#x}", (rax.pstate>>28)&0xF, (out.st.pstate>>28)&0xF)); }
        for r in 0..32 { if rax.vreg(r) != out.st.vreg(r) { diffs.push(format!("v{r} differs")); } }
        for k in 0..32 { if rax.scratch[k] != out.st.scratch[k] { diffs.push(format!("scratch[{k}]: rax={:#x} hw={:#x}", rax.scratch[k], out.st.scratch[k])); } }
        if !diffs.is_empty() {
            mismatches.push(Mismatch { label: batch[i].0.clone(), insn: *insn, detail: diffs.join("  |  ") });
        }
    }
    if !mismatches.is_empty() {
        use std::collections::BTreeMap;
        let mut by_label: BTreeMap<String, usize> = BTreeMap::new();
        for m in &mismatches { *by_label.entry(m.label.clone()).or_default() += 1; }
        eprintln!("\n==== {name}: {} mismatches across {} cases ====", mismatches.len(), cases.len());
        for (label, count) in &by_label { eprintln!("  {count:5}x  {label}"); }
        for m in mismatches.iter().take(25) { eprintln!("  [{}] {:#010x}: {}", m.label, m.insn, m.detail); }
        panic!("{name}: {} divergences vs hardware oracle", mismatches.len());
    }
}

#[test]
fn diff_dp_addsub_shifted() {
    run_family("dp_addsub_shifted", addsub_shift_cases(), 12, 0x1001);
}

#[test]
fn diff_dp_logical_shifted() {
    run_family("dp_logical_shifted", logical_shift_cases(), 12, 0x1002);
}

#[test]
fn diff_dp2_source() {
    run_family("dp2_source", dp2_cases(), 40, 0x1003);
}

#[test]
fn diff_dp3_source() {
    run_family("dp3_source", dp3_cases(), 40, 0x1004);
}

#[test]
fn diff_simd_three_same() {
    run_family("simd_three_same", three_same_cases(), 8, 0x2001);
}

// A few finite FP16 bit patterns; products stay exactly representable in FP32,
// so the result can be compared bit-exactly (no NaN/inf payload ambiguity).
const F16_VALUES: [u16; 10] = [
    0x0000, // 0.0
    0x3C00, // 1.0
    0x4000, // 2.0
    0x4200, // 3.0
    0x4400, // 4.0
    0x3800, // 0.5
    0xBC00, // -1.0
    0xC000, // -2.0
    0xB800, // -0.5
    0x4500, // 5.0
];

/// FMLAL/FMLSL/FMLAL2/FMLSL2 widening FP16 multiply-accumulate. Inputs use
/// clean finite FP16 lanes and small finite FP32 accumulators.
#[test]
fn diff_fmlal() {
    // size<1:0> = {a, 0}: a=0 -> FMLAL/FMLAL2, a=1 -> FMLSL/FMLSL2.
    let mut cases: Vec<(String, u32)> = Vec::new();
    for q in 0..2 {
        // FMLAL (u=0, opcode 11101, size=00) / FMLSL (size=10)
        cases.push((format!("fmlal q{q}"), enc_three_same(q, 0, 0b00, 0b11101)));
        cases.push((format!("fmlsl q{q}"), enc_three_same(q, 0, 0b10, 0b11101)));
        // FMLAL2 (u=1, opcode 11001, size=00) / FMLSL2 (size=10)
        cases.push((format!("fmlal2 q{q}"), enc_three_same(q, 1, 0b00, 0b11001)));
        cases.push((format!("fmlsl2 q{q}"), enc_three_same(q, 1, 0b10, 0b11001)));
    }

    let mut rng = Rng::new(0x2002);
    let mut batch: Vec<(String, u32, ArmState)> = Vec::new();
    for (label, insn) in &cases {
        for _ in 0..32 {
            let mut st = ArmState::zeroed();
            // v1 (Rn) and v2 (Rm): 8 finite FP16 lanes each (mix of the fixed
            // clean set with random finite normals/subnormals/zeros so the
            // subnormal fp16->fp32 widening path is exercised). No inf/NaN to
            // avoid 0*inf -> NaN payload ambiguity.
            for r in [1usize, 2] {
                let mut packed: u128 = 0;
                for lane in 0..8 {
                    let h = if rng.next() & 1 == 0 {
                        F16_VALUES[(rng.next() as usize) % F16_VALUES.len()] as u128
                    } else {
                        let sign = (rng.next() & 1) as u128;
                        match rng.next() % 4 {
                            0 => sign << 15,                              // signed zero
                            1 => (sign << 15) | (rng.next() as u128 & 0x3FF), // subnormal
                            _ => {
                                let exp = (rng.next() % 30 + 1) as u128; // normal 1..30
                                (sign << 15) | (exp << 10) | (rng.next() as u128 & 0x3FF)
                            }
                        }
                    };
                    packed |= h << (16 * lane);
                }
                st.set_vreg(r, packed as u64, (packed >> 64) as u64);
            }
            // v0 (Rd) accumulator: 4 small finite FP32 lanes.
            let mut acc: u128 = 0;
            for lane in 0..4 {
                let val = ((rng.next() % 21) as i64 - 10) as f32; // -10..10
                acc |= (val.to_bits() as u128) << (32 * lane);
            }
            st.set_vreg(0, acc as u64, (acc >> 64) as u64);
            batch.push((label.clone(), *insn, st));
        }
    }
    run_batch("fmlal", batch);
}

/// AdvSIMD load/store single structure:
/// `0 Q 001101 post L R Rm opcode S size Rn Rt`. Rn=x1, Rt=v0.
fn enc_single_fields(q: u32, post: u32, l: u32, r: u32, rm: u32, opcode: u32, s: u32, size: u32) -> u32 {
    (q << 30) | (0b001101 << 24) | (post << 23) | (l << 22) | (r << 21) | (rm << 16)
        | (opcode << 13) | (s << 12) | (size << 10) | (RN << 5) | RD
}

/// Single-element form for element-log2-size `esz` (0=B,1=H,2=S,3=D), structure
/// size `selem` (1-4), lane `index`, load `l`, and `post` index.
fn enc_single(esz: u32, selem: u32, index: u32, l: u32, post: u32) -> u32 {
    let scale = if esz == 3 { 0b10 } else { esz };
    let lsb = ((selem - 1) >> 1) & 1;
    let r = (selem - 1) & 1;
    let opcode = (scale << 1) | lsb;
    let (q, s, size) = match esz {
        0 => ((index >> 3) & 1, (index >> 2) & 1, index & 3),
        1 => ((index >> 2) & 1, (index >> 1) & 1, (index & 1) << 1),
        2 => ((index >> 1) & 1, index & 1, 0),
        _ => (index & 1, 0, 1),
    };
    let rm = if post == 1 { 31 } else { 0 };
    enc_single_fields(q, post, l, r, rm, opcode, s, size)
}

/// Replicating load LD1R-LD4R for element-log2-size `esz`, structure `selem`, Q.
fn enc_single_rep(esz: u32, selem: u32, q: u32, post: u32) -> u32 {
    let lsb = ((selem - 1) >> 1) & 1;
    let r = (selem - 1) & 1;
    let opcode = (0b11 << 1) | lsb;
    let rm = if post == 1 { 31 } else { 0 };
    enc_single_fields(q, post, 1, r, rm, opcode, 0, esz)
}

#[test]
fn diff_mem_ldst_single() {
    let mut cases: Vec<(String, u32)> = Vec::new();
    for esz in 0..4u32 {
        let max_index = 16u32 >> esz; // B:16 H:8 S:4 D:2
        for selem in 1..=4u32 {
            for &index in &[0u32, max_index - 1] {
                for l in 0..2 {
                    let op = if l == 1 { "ld" } else { "st" };
                    cases.push((format!("{op}{selem}_single e{esz} i{index}"), enc_single(esz, selem, index, l, 0)));
                    cases.push((format!("{op}{selem}_single e{esz} i{index} post"), enc_single(esz, selem, index, l, 1)));
                }
            }
            // Replicating loads (LD1R-LD4R)
            for q in 0..2 {
                cases.push((format!("ld{selem}r e{esz} q{q}"), enc_single_rep(esz, selem, q, 0)));
            }
        }
    }
    let mut rng = Rng::new(0x1_0005);
    let mut batch: Vec<(String, u32, ArmState)> = Vec::new();
    for (label, insn) in &cases {
        for _ in 0..6 {
            batch.push((label.clone(), *insn, mem_input(&mut rng)));
        }
    }
    run_batch("mem_ldst_single", batch);
}

/// LDXR/LDAXR <Rt>, [Rn]: `size 001000 0 1 0 11111 o0 11111 Rn Rt`. Rt=x0, Rn=x1.
fn enc_ldxr(size: u32, o0: u32) -> u32 {
    (size << 30) | (0b001000 << 24) | (1 << 22) | (0b11111 << 16) | (o0 << 15)
        | (0b11111 << 10) | (RN << 5) | RD
}
/// STXR/STLXR <Ws>, <Rt>, [Rn]: `size 001000 0 0 0 Rs o0 11111 Rn Rt`. Ws=x2, Rt=x3, Rn=x1.
fn enc_stxr(size: u32, o0: u32) -> u32 {
    (size << 30) | (0b001000 << 24) | (2 << 16) | (o0 << 15) | (0b11111 << 10) | (RN << 5) | 3
}

/// AES single-block op: `0100111000 10100 opcode 10 Rn Rd`. Rn=v1, Rd=v0.
fn enc_aes(opcode: u32) -> u32 {
    0x4e28_0800 | (opcode << 12) | (RN << 5) | RD
}

/// Advanced SIMD three-same (FP16): `0 Q U 01110 a 10 Rm 00 opcode 1 Rn Rd`.
/// Rd=v0, Rn=v1, Rm=v2.
fn enc_fp16_3s(q: u32, u: u32, a: u32, opcode: u32) -> u32 {
    (q << 30) | (u << 29) | (0b01110 << 24) | (a << 23) | (1 << 22)
        | (RM << 16) | (opcode << 11) | (1 << 10) | (RN << 5) | RD
}

/// Generate a finite/inf/zero/subnormal binary16 value (never a NaN, to keep
/// NaN-payload propagation out of the differential comparison).
fn rand_fp16(rng: &mut Rng) -> u16 {
    let sign = (rng.next() & 1) as u16;
    match rng.next() % 16 {
        0 => sign << 15,                                    // zero
        1 => (sign << 15) | 0x7C00,                         // infinity
        2 => (sign << 15) | (rng.next() as u16 & 0x3FF),    // subnormal
        _ => {
            let exp = (rng.next() % 28 + 1) as u16; // normal exponent 1..28
            let mant = rng.next() as u16 & 0x3FF;
            (sign << 15) | (exp << 10) | mant
        }
    }
}

fn fp16_vec(rng: &mut Rng) -> (u64, u64) {
    let mut lo = 0u64;
    let mut hi = 0u64;
    for e in 0..4 {
        lo |= (rand_fp16(rng) as u64) << (e * 16);
        hi |= (rand_fp16(rng) as u64) << (e * 16);
    }
    (lo, hi)
}

/// Advanced SIMD vector x indexed element (FP16):
/// `0 Q U 01111 00 L M Rm opcode H 0 Rn Rd`. Rd=v0, Rn=v1, Rm=v2. The broadcast
/// lane index is H:L:M.
fn enc_fp16_idx(q: u32, u: u32, opcode: u32, index: u32) -> u32 {
    let h = (index >> 2) & 1;
    let l = (index >> 1) & 1;
    let m = index & 1;
    (q << 30) | (u << 29) | (0b01111 << 24) | (l << 21) | (m << 20)
        | (RM << 16) | (opcode << 12) | (h << 11) | (RN << 5) | RD
}

/// Scalar three-same FP16: `01 U 11110 a 10 Rm 00 opcode 1 Rn Rd`.
fn enc_fp16_3s_scalar(u: u32, a: u32, opcode: u32) -> u32 {
    (1 << 30) | (u << 29) | (0b11110 << 24) | (a << 23) | (1 << 22)
        | (RM << 16) | (opcode << 11) | (1 << 10) | (RN << 5) | RD
}

/// Scalar two-reg-misc FP16: `01 U 11110 a 1 11100 opcode 10 Rn Rd`.
fn enc_fp16_2r_scalar(u: u32, a: u32, opcode: u32) -> u32 {
    (1 << 30) | (u << 29) | (0b11110 << 24) | (a << 23) | (1 << 22)
        | (0b11100 << 17) | (opcode << 12) | (0b10 << 10) | (RN << 5) | RD
}

#[test]
fn diff_simd_fp16_scalar() {
    let mut rng = Rng::new(0x1_0015);
    let mut batch: Vec<(String, u32, ArmState)> = Vec::new();
    // Scalar three-same FP16 (only lane 0 is used; upper bits must zero).
    // Genuine scalar three-same forms plus several with no scalar encoding
    // (fadd/fmul/fmax/fmaxnm/fmla/faddp) — both rax and the oracle must reject
    // those.
    let three: &[(u32, u32, u32, &str)] = &[
        (0, 0, 0b011, "fmulx"),
        (0, 0, 0b111, "frecps"),
        (0, 1, 0b111, "frsqrts"),
        (1, 1, 0b010, "fabd"),
        (0, 0, 0b100, "fcmeq"),
        (1, 0, 0b100, "fcmge"),
        (1, 1, 0b100, "fcmgt"),
        (1, 0, 0b101, "facge"),
        (1, 1, 0b101, "facgt"),
        (0, 0, 0b010, "fadd"),
        (1, 0, 0b011, "fmul"),
        (0, 0, 0b110, "fmax"),
        (0, 0, 0b000, "fmaxnm"),
        (0, 0, 0b001, "fmla"),
        (1, 0, 0b010, "faddp"),
    ];
    for &(u, a, opcode, name) in three {
        let insn = enc_fp16_3s_scalar(u, a, opcode);
        for _ in 0..24 {
            let mut st = ArmState::zeroed();
            let (a1, b1) = fp16_vec(&mut rng);
            let (a2, b2) = fp16_vec(&mut rng);
            st.set_vreg(1, a1, b1);
            st.set_vreg(2, a2, b2);
            batch.push((format!("3s {name}"), insn, st));
        }
    }
    // Scalar two-reg-misc FP16.
    // Includes ops with no SIMD-scalar form (fsqrt/fabs/fneg/frint*) — both rax
    // and the oracle must reject those — alongside the genuine scalar forms.
    let two: &[(u32, u32, u32, &str)] = &[
        (1, 1, 0b11111, "fsqrt"),
        (0, 1, 0b11111, "frecpx"),
        (0, 1, 0b11101, "frecpe"),
        (1, 1, 0b11101, "frsqrte"),
        (0, 1, 0b01100, "fcmgt0"),
        (1, 1, 0b01101, "fcmle0"),
        (0, 1, 0b11011, "fcvtzs"),
        (1, 1, 0b11011, "fcvtzu"),
        (0, 0, 0b11101, "scvtf"),
        (0, 1, 0b01111, "fabs"),
        (1, 1, 0b01111, "fneg"),
        (1, 1, 0b11001, "frinti"),
        (0, 0, 0b11000, "frintn"),
    ];
    for &(u, a, opcode, name) in two {
        let insn = enc_fp16_2r_scalar(u, a, opcode);
        for _ in 0..24 {
            let mut st = ArmState::zeroed();
            let (a1, b1) = fp16_vec(&mut rng);
            st.set_vreg(1, a1, b1);
            batch.push((format!("2r {name}"), insn, st));
        }
    }
    run_batch("simd_fp16_scalar", batch);
}

/// A binary16 NaN (signaling or quiet), random sign/payload (payload != 0).
fn rand_fp16_nan(rng: &mut Rng) -> u16 {
    let sign = (rng.next() & 1) as u16;
    let quiet = (rng.next() & 1) as u16; // bit9 (0x0200) set => quiet
    let payload = ((rng.next() as u16) & 0x1FF).max(1); // bits[8:0], nonzero
    (sign << 15) | 0x7C00 | (quiet << 9) | payload
}

#[test]
fn diff_simd_fp16_nan() {
    // Verify NaN propagation/quieting with exactly one NaN operand (so the
    // result is unambiguous — no two-NaN ordering dependence).
    let three: &[(u32, u32, u32, &str)] = &[
        (0, 0, 0b010, "fadd"),
        (0, 1, 0b010, "fsub"),
        (1, 0, 0b011, "fmul"),
        (0, 0, 0b000, "fmaxnm"),
        (0, 0, 0b110, "fmax"),
        (0, 0, 0b001, "fmla"),
        (0, 0, 0b100, "fcmeq"),
    ];
    let two: &[(u32, u32, u32, &str)] = &[
        (0, 1, 0b01111, "fabs"),
        (1, 1, 0b01111, "fneg"),
        (1, 1, 0b11111, "fsqrt"),
        (0, 1, 0b11101, "frecpe"),
        (1, 1, 0b11101, "frsqrte"),
        (1, 1, 0b11001, "frinti"),
        (0, 1, 0b11011, "fcvtzs"),
    ];
    let mut rng = Rng::new(0x1_0014);
    let mut batch: Vec<(String, u32, ArmState)> = Vec::new();
    // Three-same: NaN in exactly one of v1/v2 per lane, finite elsewhere. v0
    // (the FMLA accumulator) stays finite.
    for &(u, a, opcode, name) in three {
        let insn = enc_fp16_3s(1, u, a, opcode);
        for _ in 0..32 {
            let mut st = ArmState::zeroed();
            let (mut a1, mut b1) = fp16_vec(&mut rng);
            let (mut a2, mut b2) = fp16_vec(&mut rng);
            let (a0, b0) = fp16_vec(&mut rng);
            // Force one operand of each 16-bit lane to be a NaN, the other finite.
            for lane in 0..8 {
                let nan = rand_fp16_nan(&mut rng) as u64;
                let pick = rng.next() & 1;
                let sh = (lane % 4) * 16;
                let (v1, v2) = if lane < 4 {
                    (&mut a1, &mut a2)
                } else {
                    (&mut b1, &mut b2)
                };
                if pick == 0 {
                    *v1 = (*v1 & !(0xFFFFu64 << sh)) | (nan << sh);
                } else {
                    *v2 = (*v2 & !(0xFFFFu64 << sh)) | (nan << sh);
                }
            }
            st.set_vreg(0, a0, b0);
            st.set_vreg(1, a1, b1);
            st.set_vreg(2, a2, b2);
            batch.push((format!("3s {name}"), insn, st));
        }
    }
    // Two-reg-misc: NaN inputs in v1.
    for &(u, a, opcode, name) in two {
        let insn = enc_fp16_2r(1, u, a, opcode);
        for _ in 0..32 {
            let mut st = ArmState::zeroed();
            let lo = ((rand_fp16_nan(&mut rng) as u64) << 48)
                | ((rand_fp16_nan(&mut rng) as u64) << 32)
                | ((rand_fp16_nan(&mut rng) as u64) << 16)
                | rand_fp16_nan(&mut rng) as u64;
            let hi = ((rand_fp16_nan(&mut rng) as u64) << 48)
                | ((rand_fp16_nan(&mut rng) as u64) << 32)
                | ((rand_fp16_nan(&mut rng) as u64) << 16)
                | rand_fp16_nan(&mut rng) as u64;
            st.set_vreg(1, lo, hi);
            batch.push((format!("2r {name}"), insn, st));
        }
    }
    run_batch("simd_fp16_nan", batch);
}

#[test]
fn diff_simd_fp16_indexed() {
    let ops: &[(u32, u32, &str)] = &[
        (0, 0b0001, "fmla"),
        (0, 0b0101, "fmls"),
        (0, 0b1001, "fmul"),
        (1, 0b1001, "fmulx"),
    ];
    let mut rng = Rng::new(0x1_0013);
    let mut batch: Vec<(String, u32, ArmState)> = Vec::new();
    for &(u, opcode, name) in ops {
        for q in 0..2u32 {
            for index in 0..8u32 {
                let insn = enc_fp16_idx(q, u, opcode, index);
                for _ in 0..6 {
                    let mut st = ArmState::zeroed();
                    let (a0, b0) = fp16_vec(&mut rng);
                    let (a1, b1) = fp16_vec(&mut rng);
                    let (a2, b2) = fp16_vec(&mut rng);
                    st.set_vreg(0, a0, b0);
                    st.set_vreg(1, a1, b1);
                    st.set_vreg(2, a2, b2);
                    batch.push((format!("{name} q{q} i{index}"), insn, st));
                }
            }
        }
    }
    run_batch("simd_fp16_indexed", batch);
}

/// Advanced SIMD two-register miscellaneous (FP16):
/// `0 Q U 01110 a 1 11100 opcode 10 Rn Rd`. Rd=v0, Rn=v1.
fn enc_fp16_2r(q: u32, u: u32, a: u32, opcode: u32) -> u32 {
    (q << 30) | (u << 29) | (0b01110 << 24) | (a << 23) | (1 << 22)
        | (0b11100 << 17) | (opcode << 12) | (0b10 << 10) | (RN << 5) | RD
}

#[test]
fn diff_simd_fp16_2reg() {
    // (U, a=bit23, opcode) table for the FP16 two-register-misc group.
    let ops: &[(u32, u32, u32, &str)] = &[
        (0, 1, 0b01111, "fabs"),
        (1, 1, 0b01111, "fneg"),
        (1, 1, 0b11111, "fsqrt"),
        (0, 1, 0b11101, "frecpe"),
        (1, 1, 0b11101, "frsqrte"),
        (0, 1, 0b01100, "fcmgt0"),
        (0, 1, 0b01101, "fcmeq0"),
        (0, 1, 0b01110, "fcmlt0"),
        (1, 1, 0b01100, "fcmge0"),
        (1, 1, 0b01101, "fcmle0"),
        (0, 0, 0b11000, "frintn"),
        (0, 0, 0b11001, "frintm"),
        (0, 1, 0b11000, "frintp"),
        (0, 1, 0b11001, "frintz"),
        (1, 0, 0b11000, "frinta"),
        (1, 0, 0b11001, "frintx"),
        (1, 1, 0b11001, "frinti"),
        (0, 0, 0b11010, "fcvtns"),
        (0, 0, 0b11011, "fcvtms"),
        (0, 0, 0b11100, "fcvtas"),
        (0, 1, 0b11010, "fcvtps"),
        (0, 1, 0b11011, "fcvtzs"),
        (1, 0, 0b11010, "fcvtnu"),
        (1, 0, 0b11011, "fcvtmu"),
        (1, 0, 0b11100, "fcvtau"),
        (1, 1, 0b11010, "fcvtpu"),
        (1, 1, 0b11011, "fcvtzu"),
        (0, 0, 0b11101, "scvtf"),
        (1, 0, 0b11101, "ucvtf"),
    ];
    let mut rng = Rng::new(0x1_0012);
    let mut batch: Vec<(String, u32, ArmState)> = Vec::new();
    for &(u, a, opcode, name) in ops {
        for q in 0..2u32 {
            let insn = enc_fp16_2r(q, u, a, opcode);
            for _ in 0..24 {
                let mut st = ArmState::zeroed();
                let (lo, hi) = fp16_vec(&mut rng);
                st.set_vreg(1, lo, hi);
                batch.push((format!("{name} q{q}"), insn, st));
            }
        }
    }
    run_batch("simd_fp16_2reg", batch);
}

#[test]
fn diff_simd_fp16_3same() {
    // Full (U, a, opcode) table of the FP16 three-same group.
    let ops: &[(u32, u32, u32, &str)] = &[
        (0, 0, 0b000, "fmaxnm"),
        (0, 1, 0b000, "fminnm"),
        (0, 0, 0b001, "fmla"),
        (0, 1, 0b001, "fmls"),
        (0, 0, 0b010, "fadd"),
        (0, 1, 0b010, "fsub"),
        (0, 0, 0b011, "fmulx"),
        (0, 0, 0b100, "fcmeq"),
        (0, 0, 0b110, "fmax"),
        (0, 1, 0b110, "fmin"),
        (0, 0, 0b111, "frecps"),
        (0, 1, 0b111, "frsqrts"),
        (1, 0, 0b000, "fmaxnmp"),
        (1, 1, 0b000, "fminnmp"),
        (1, 0, 0b010, "faddp"),
        (1, 1, 0b010, "fabd"),
        (1, 0, 0b011, "fmul"),
        (1, 0, 0b100, "fcmge"),
        (1, 1, 0b100, "fcmgt"),
        (1, 0, 0b101, "facge"),
        (1, 1, 0b101, "facgt"),
        (1, 0, 0b110, "fmaxp"),
        (1, 1, 0b110, "fminp"),
        (1, 0, 0b111, "fdiv"),
    ];
    let mut rng = Rng::new(0x1_0011);
    let mut batch: Vec<(String, u32, ArmState)> = Vec::new();
    for &(u, a, opcode, name) in ops {
        for q in 0..2u32 {
            let insn = enc_fp16_3s(q, u, a, opcode);
            for _ in 0..24 {
                let mut st = ArmState::zeroed();
                // v0 (Rd) seeds the FMLA/FMLS accumulator; v1/v2 are the sources.
                let (a0, b0) = fp16_vec(&mut rng);
                let (a1, b1) = fp16_vec(&mut rng);
                let (a2, b2) = fp16_vec(&mut rng);
                st.set_vreg(0, a0, b0);
                st.set_vreg(1, a1, b1);
                st.set_vreg(2, a2, b2);
                batch.push((format!("{name} q{q}"), insn, st));
            }
        }
    }
    run_batch("simd_fp16_3same", batch);
}

#[test]
fn diff_simd_urecpe() {
    // URECPE (U=0) / URSQRTE (U=1): 32-bit unsigned integer estimates.
    let mut cases: Vec<(String, u32)> = Vec::new();
    for q in 0..2 {
        cases.push((format!("urecpe q{q}"), enc_two_reg(q, 0, 0b10, 0b11100)));
        cases.push((format!("ursqrte q{q}"), enc_two_reg(q, 1, 0b10, 0b11100)));
    }
    run_family("simd_urecpe", cases, 40, 0x1_000C);
}

#[test]
fn diff_simd_frecpe() {
    // FRECPE: U=0, opcode 11101, sz_hi=1 -> size = 0b10 (f32) / 0b11 (f64).
    let mut cases: Vec<(String, u32, bool)> = Vec::new();
    for q in 0..2 {
        cases.push((format!("frecpe f32 q{q}"), enc_two_reg(q, 0, 0b10, 0b11101), false));
    }
    cases.push(("frecpe f64".into(), enc_two_reg(1, 0, 0b11, 0b11101), true));
    // Normal positive finite inputs so no special-case / over-underflow paths.
    let mut rng = Rng::new(0x1_000A);
    let mut batch: Vec<(String, u32, ArmState)> = Vec::new();
    for (label, insn, f64op) in &cases {
        for _ in 0..16 {
            let mut st = ArmState::zeroed();
            let mut packed: u128 = 0;
            if *f64op {
                for lane in 0..2 {
                    let v = ((rng.next() % 200 + 1) as f64) * 0.125;
                    packed |= (v.to_bits() as u128) << (64 * lane);
                }
            } else {
                for lane in 0..4 {
                    let v = ((rng.next() % 200 + 1) as f32) * 0.125;
                    packed |= (v.to_bits() as u128) << (32 * lane);
                }
            }
            st.set_vreg(1, packed as u64, (packed >> 64) as u64);
            batch.push((label.clone(), *insn, st));
        }
    }
    run_batch("simd_frecpe", batch);
}

#[test]
fn diff_simd_frsqrte() {
    let mut cases: Vec<(String, u32, bool)> = Vec::new();
    for q in 0..2 {
        cases.push((format!("frsqrte f32 q{q}"), enc_two_reg(q, 1, 0b10, 0b11101), false));
    }
    cases.push(("frsqrte f64".into(), enc_two_reg(1, 1, 0b11, 0b11101), true));
    let mut rng = Rng::new(0x1_000B);
    let mut batch: Vec<(String, u32, ArmState)> = Vec::new();
    for (label, insn, f64op) in &cases {
        for _ in 0..16 {
            let mut st = ArmState::zeroed();
            let mut packed: u128 = 0;
            if *f64op {
                for lane in 0..2 {
                    let v = ((rng.next() % 500 + 1) as f64) * 0.0625;
                    packed |= (v.to_bits() as u128) << (64 * lane);
                }
            } else {
                for lane in 0..4 {
                    let v = ((rng.next() % 500 + 1) as f32) * 0.0625;
                    packed |= (v.to_bits() as u128) << (32 * lane);
                }
            }
            st.set_vreg(1, packed as u64, (packed >> 64) as u64);
            batch.push((label.clone(), *insn, st));
        }
    }
    run_batch("simd_frsqrte", batch);
}

#[test]
fn diff_crypto_aes() {
    let ops: &[(u32, &str)] = &[
        (0b00100, "aese"),
        (0b00101, "aesd"),
        (0b00110, "aesmc"),
        (0b00111, "aesimc"),
    ];
    let mut cases: Vec<(String, u32)> = Vec::new();
    for &(opcode, name) in ops {
        cases.push((name.to_string(), enc_aes(opcode)));
    }
    run_family("crypto_aes", cases, 40, 0x1_0009);
}

/// Three-register SHA: `0101 1110 000 Rm 0 opcode 00 Rn Rd`.
fn enc_sha3(opcode: u32) -> u32 {
    0x5E00_0000 | (RM << 16) | (opcode << 12) | (RN << 5) | RD
}

/// Two-register SHA: `0101 1110 0010 1000 opcode 10 Rn Rd`.
fn enc_sha2(opcode: u32) -> u32 {
    0x5E28_0800 | (opcode << 12) | (RN << 5) | RD
}

#[test]
fn diff_crypto_sha() {
    let mut cases: Vec<(String, u32)> = Vec::new();
    // Three-register (opcode at bits[14:12]).
    for &(opcode, name) in &[
        (0b000u32, "sha1c"),
        (0b001, "sha1p"),
        (0b010, "sha1m"),
        (0b011, "sha1su0"),
        (0b100, "sha256h"),
        (0b101, "sha256h2"),
        (0b110, "sha256su1"),
    ] {
        cases.push((name.to_string(), enc_sha3(opcode)));
    }
    // Two-register (opcode at bits[16:12]).
    for &(opcode, name) in &[
        (0b00000u32, "sha1h"),
        (0b00001, "sha1su1"),
        (0b00010, "sha256su0"),
    ] {
        cases.push((name.to_string(), enc_sha2(opcode)));
    }
    run_family("crypto_sha", cases, 40, 0x1_000D);
}

/// SM4E Vd.4S, Vn.4S: `11001110 11000000 100001 Rn Rd`. Rd=v0, Rn=v1.
fn enc_sm4e() -> u32 {
    0xCE00_0000 | (0xC0 << 16) | (0b100001 << 10) | (RN << 5) | RD
}

/// SM4EKEY Vd.4S, Vn.4S, Vm.4S: `11001110 011 Rm 110010 Rn Rd`. Rd=v0, Rn=v1, Rm=v2.
fn enc_sm4ekey() -> u32 {
    0xCE00_0000 | (0b011 << 21) | (RM << 16) | (0b110010 << 10) | (RN << 5) | RD
}

#[test]
fn diff_crypto_sm4() {
    let cases: Vec<(String, u32)> = vec![
        ("sm4e".to_string(), enc_sm4e()),
        ("sm4ekey".to_string(), enc_sm4ekey()),
    ];
    run_family("crypto_sm4", cases, 40, 0x1_0016);
}

#[test]
fn diff_excl_load() {
    let mut cases: Vec<(String, u32)> = Vec::new();
    for size in 0..4u32 {
        for o0 in 0..2 {
            cases.push((format!("ldxr sz{size} o0{o0}"), enc_ldxr(size, o0)));
        }
    }
    let mut rng = Rng::new(0x1_0007);
    let mut batch: Vec<(String, u32, ArmState)> = Vec::new();
    for (label, insn) in &cases {
        for _ in 0..8 {
            batch.push((label.clone(), *insn, mem_input(&mut rng)));
        }
    }
    run_batch("excl_load", batch);
}

#[test]
fn diff_excl_pair() {
    let mut cases: Vec<(String, u32, u32)> = Vec::new();
    for size in 0..4u32 {
        for o0 in 0..2 {
            cases.push((format!("ldxr_stxr sz{size} o0{o0}"), enc_ldxr(size, o0), enc_stxr(size, o0)));
        }
    }
    let mut rng = Rng::new(0x1_0008);
    let mut batch: Vec<(String, u32, u32, ArmState)> = Vec::new();
    for (label, ldxr, stxr) in &cases {
        for _ in 0..8 {
            batch.push((label.clone(), *ldxr, *stxr, mem_input(&mut rng)));
        }
    }
    run_batch_pair("excl_pair", batch);
}

/// CAS: `size 0010001 L 1 Rs o0 11111 Rn Rt`. Rs=x2 (compare/old), Rn=x1, Rt=x0 (new).
fn enc_cas(size: u32, l: u32, o0: u32) -> u32 {
    (size << 30) | (0b001000 << 24) | (1 << 23) | (l << 22) | (1 << 21) | (2 << 16)
        | (o0 << 15) | (0b11111 << 10) | (RN << 5) | RD
}

#[test]
fn diff_mem_cas() {
    let mut cases: Vec<(String, u32)> = Vec::new();
    for size in 0..4u32 {
        for l in 0..2 {
            for o0 in 0..2 {
                cases.push((format!("cas sz{size} l{l} o0{o0}"), enc_cas(size, l, o0)));
            }
        }
    }
    let mut rng = Rng::new(0x1_0006);
    let mut batch: Vec<(String, u32, ArmState)> = Vec::new();
    for (label, insn) in &cases {
        for k in 0..12 {
            let mut st = mem_input(&mut rng);
            // Half the cases: make x2 (the comparison value) equal the memory at
            // SCRATCH_BASE so the swap succeeds; otherwise it (usually) fails.
            if k % 2 == 0 {
                st.x[2] = st.scratch[8]; // SCRATCH_BASE = SCRATCH_ADDR + 64 -> scratch[8]
            }
            batch.push((label.clone(), *insn, st));
        }
    }
    run_batch("mem_cas", batch);
}

/// LDXP: `1 sz 001000 0 1 1 11111 o0 Rt2 Rn Rt`. Rt=x4, Rt2=x5, Rn=x1.
/// sz64 selects 64-bit (size=11) vs 32-bit (size=10) element pair.
fn enc_ldxp(sz64: bool, o0: u32) -> u32 {
    let size = if sz64 { 3 } else { 2 };
    (size << 30) | (0b001000 << 24) | (1 << 22) | (1 << 21) | (0b11111 << 16)
        | (o0 << 15) | (5 << 10) | (RN << 5) | 4
}

/// STXP: `1 sz 001000 0 0 1 Rs o0 Rt2 Rn Rt`. Rs=x6 (status), Rt=x4, Rt2=x5, Rn=x1.
fn enc_stxp(sz64: bool, o0: u32) -> u32 {
    let size = if sz64 { 3 } else { 2 };
    (size << 30) | (0b001000 << 24) | (1 << 21) | (6 << 16)
        | (o0 << 15) | (5 << 10) | (RN << 5) | 4
}

#[test]
fn diff_excl_ldxp() {
    let mut cases: Vec<(String, u32)> = Vec::new();
    for &sz64 in &[false, true] {
        for o0 in 0..2 {
            cases.push((format!("ldxp sz64{sz64} o0{o0}"), enc_ldxp(sz64, o0)));
        }
    }
    let mut rng = Rng::new(0x1_000F);
    let mut batch: Vec<(String, u32, ArmState)> = Vec::new();
    for (label, insn) in &cases {
        for _ in 0..10 {
            batch.push((label.clone(), *insn, mem_input(&mut rng)));
        }
    }
    run_batch("excl_ldxp", batch);
}

#[test]
fn diff_excl_stxp() {
    // LDXP then STXP (round-trip): the monitor set by LDXP lets STXP succeed.
    let mut cases: Vec<(String, u32, u32)> = Vec::new();
    for &sz64 in &[false, true] {
        for o0 in 0..2 {
            cases.push((
                format!("ldxp_stxp sz64{sz64} o0{o0}"),
                enc_ldxp(sz64, o0),
                enc_stxp(sz64, o0),
            ));
        }
    }
    let mut rng = Rng::new(0x1_0010);
    let mut batch: Vec<(String, u32, u32, ArmState)> = Vec::new();
    for (label, ldxp, stxp) in &cases {
        for _ in 0..10 {
            batch.push((label.clone(), *ldxp, *stxp, mem_input(&mut rng)));
        }
    }
    run_batch_pair("excl_stxp", batch);
}

/// CASP: `0 sz 001000 0 L 1 Rs o0 11111 Rn Rt`. Rs=x2:x3 (compare/old),
/// Rt=x4:x5 (new), Rn=x1. sz selects 32-bit (0) or 64-bit (1) element pair.
fn enc_casp(sz: u32, l: u32, o0: u32) -> u32 {
    (sz << 30) | (0b001000 << 24) | (l << 22) | (1 << 21) | (2 << 16)
        | (o0 << 15) | (0b11111 << 10) | (RN << 5) | 4
}

#[test]
fn diff_mem_casp() {
    let mut cases: Vec<(String, u32, u32)> = Vec::new();
    for sz in 0..2u32 {
        for l in 0..2 {
            for o0 in 0..2 {
                cases.push((format!("casp sz{sz} l{l} o0{o0}"), enc_casp(sz, l, o0), sz));
            }
        }
    }
    let mut rng = Rng::new(0x1_000E);
    let mut batch: Vec<(String, u32, ArmState)> = Vec::new();
    for (label, insn, sz) in &cases {
        for k in 0..12 {
            let mut st = mem_input(&mut rng);
            // Half the cases: make the compare pair (x2:x3) equal the memory pair
            // at SCRATCH_BASE (scratch[8]/scratch[9]) so the swap succeeds.
            if k % 2 == 0 {
                if *sz == 0 {
                    st.x[2] = st.scratch[8] & 0xFFFF_FFFF;
                    st.x[3] = st.scratch[8] >> 32;
                } else {
                    st.x[2] = st.scratch[8];
                    st.x[3] = st.scratch[9];
                }
            }
            batch.push((label.clone(), *insn, st));
        }
    }
    run_batch("mem_casp", batch);
}

/// Atomic memory op: `size 111 0 00 A R 1 Rs o3 opc 00 Rn Rt`. Rs=x2, Rn=x1, Rt=x0.
fn enc_atomic(size: u32, a: u32, r: u32, o3: u32, opc: u32) -> u32 {
    (size << 30) | (0b111 << 27) | (a << 23) | (r << 22) | (1 << 21) | (2 << 16)
        | (o3 << 15) | (opc << 12) | (RN << 5) | RD
}

#[test]
fn diff_mem_atomic() {
    let ops: &[(u32, u32, &str)] = &[
        (0, 0b000, "ldadd"),
        (0, 0b001, "ldclr"),
        (0, 0b010, "ldeor"),
        (0, 0b011, "ldset"),
        (0, 0b100, "ldsmax"),
        (0, 0b101, "ldsmin"),
        (0, 0b110, "ldumax"),
        (0, 0b111, "ldumin"),
        (1, 0b000, "swp"),
    ];
    let mut cases: Vec<(String, u32)> = Vec::new();
    for &(o3, opc, name) in ops {
        for size in 0..4u32 {
            for &(a, r) in &[(0u32, 0u32), (1, 1)] {
                cases.push((format!("{name} sz{size} a{a}r{r}"), enc_atomic(size, a, r, o3, opc)));
            }
        }
    }
    let mut rng = Rng::new(0x1_0004);
    let mut batch: Vec<(String, u32, ArmState)> = Vec::new();
    for (label, insn) in &cases {
        for _ in 0..8 {
            batch.push((label.clone(), *insn, mem_input(&mut rng)));
        }
    }
    run_batch("mem_atomic", batch);
}

/// AdvSIMD load/store multiple structures: `0 Q 0011 0 0 post L rm opcode size Rn Rt`.
fn enc_ldst_struct(q: u32, post: u32, l: u32, rm: u32, opcode: u32, size: u32) -> u32 {
    (q << 30) | (0b001100 << 24) | (post << 23) | (l << 22) | (rm << 16) | (opcode << 12)
        | (size << 10) | (RN << 5) | RD
}

#[test]
fn diff_mem_ldst_struct() {
    // (opcode, name) -- LD1 x1/x2/x3/x4, LD2, LD3, LD4.
    let ops: &[(u32, &str)] = &[
        (0b0111, "ld1x1"),
        (0b1010, "ld1x2"),
        (0b0110, "ld1x3"),
        (0b0010, "ld1x4"),
        (0b1000, "ld2"),
        (0b0100, "ld3"),
        (0b0000, "ld4"),
    ];
    let mut cases: Vec<(String, u32)> = Vec::new();
    for &(opcode, name) in ops {
        for size in 0..4u32 {
            for q in 0..2 {
                for l in 0..2 {
                    let op = if l == 1 { name.to_string() } else { name.replace("ld", "st") };
                    // no-offset
                    cases.push((format!("{op} sz{size} q{q} noff"), enc_ldst_struct(q, 0, l, 0, opcode, size)));
                    // post-index, immediate increment (Rm == 31)
                    cases.push((format!("{op} sz{size} q{q} post"), enc_ldst_struct(q, 1, l, 31, opcode, size)));
                }
            }
        }
    }
    let mut rng = Rng::new(0x1_0003);
    let mut batch: Vec<(String, u32, ArmState)> = Vec::new();
    for (label, insn) in &cases {
        for _ in 0..6 {
            batch.push((label.clone(), *insn, mem_input(&mut rng)));
        }
    }
    run_batch("mem_ldst_struct", batch);
}

/// Load/store pair: `opc 101 V 0 mode L imm7 Rt2 Rn Rt`. Rt=x0, Rt2=x2, Rn=x1.
fn enc_ldp(opc: u32, v: u32, mode: u32, l: u32, imm7: u32) -> u32 {
    (opc << 30) | (0b101 << 27) | (v << 26) | (mode << 23) | (l << 22) | ((imm7 & 0x7F) << 15)
        | (2 << 10) | (RN << 5) | RD
}

#[test]
fn diff_mem_ldp_stp() {
    // (opc, V, name) for GPR (32/LDPSW/64) and SIMD (S/D/Q).
    let kinds: &[(u32, u32, bool, &str)] = &[
        (0b00, 0, false, "stp_w"),
        (0b10, 0, false, "stp_x"),
        (0b00, 1, false, "stp_s"),
        (0b01, 1, false, "stp_d"),
        (0b10, 1, false, "stp_q"),
        (0b01, 0, true, "ldpsw"), // load-only
    ];
    let mut cases: Vec<(String, u32)> = Vec::new();
    for &(opc, v, load_only, name) in kinds {
        // modes: 10=signed offset, 01=post-index, 11=pre-index
        for &mode in &[0b10u32, 0b01, 0b11] {
            for &l in if load_only { &[1u32][..] } else { &[0u32, 1][..] } {
                for imm7 in 0..3u32 {
                    let nm = if l == 1 && !load_only {
                        name.replace("stp", "ldp")
                    } else {
                        name.to_string()
                    };
                    cases.push((format!("{nm} m{mode} #{imm7}"), enc_ldp(opc, v, mode, l, imm7)));
                }
            }
        }
    }
    let mut rng = Rng::new(0x1_0002);
    let mut batch: Vec<(String, u32, ArmState)> = Vec::new();
    for (label, insn) in &cases {
        for _ in 0..8 {
            batch.push((label.clone(), *insn, mem_input(&mut rng)));
        }
    }
    run_batch("mem_ldp_stp", batch);
}

/// Load/store register, unsigned immediate offset:
/// `size 111 V 01 opc imm12 Rn Rt`. Rn=base (x1), Rt=Rd (x0/v0).
fn enc_ldst_uimm(size: u32, v: u32, opc: u32, imm12: u32) -> u32 {
    (size << 30) | (0b111 << 27) | (v << 26) | (0b01 << 24) | (opc << 22) | (imm12 << 10)
        | (RN << 5) | RD
}

/// Build a memory-test input: base register x1 -> SCRATCH_BASE, random scratch
/// and operand registers.
fn mem_input(rng: &mut Rng) -> ArmState {
    let mut st = gen_input(rng);
    st.x[1] = SCRATCH_BASE; // Rn base pointer
    for w in st.scratch.iter_mut() {
        *w = rng.interesting();
    }
    st
}

#[test]
fn diff_mem_ldst_imm() {
    // (size, V, opc, name)
    let ops: &[(u32, u32, u32, &str)] = &[
        (3, 0, 0, "str_x"),
        (3, 0, 1, "ldr_x"),
        (2, 0, 0, "str_w"),
        (2, 0, 1, "ldr_w"),
        (0, 1, 0, "str_b"),
        (0, 1, 1, "ldr_b"),
        (1, 1, 0, "str_h"),
        (1, 1, 1, "ldr_h"),
        (2, 1, 0, "str_s"),
        (2, 1, 1, "ldr_s"),
        (3, 1, 0, "str_d"),
        (3, 1, 1, "ldr_d"),
        (0, 1, 2, "str_q"),
        (0, 1, 3, "ldr_q"),
        // sign-extending loads (GPR): opc=10 -> LDRSx to X, opc=11 -> to W
        (0, 0, 2, "ldrsb_x"),
        (1, 0, 2, "ldrsh_x"),
        (2, 0, 2, "ldrsw_x"),
        (0, 0, 1, "ldrb_w"),
        (1, 0, 1, "ldrh_w"),
    ];
    let mut cases: Vec<(String, u32)> = Vec::new();
    for &(size, v, opc, name) in ops {
        for imm12 in 0..4u32 {
            cases.push((format!("{name} #{imm12}"), enc_ldst_uimm(size, v, opc, imm12)));
        }
    }
    // Custom batch with memory inputs.
    let mut rng = Rng::new(0x1_0001);
    let mut batch: Vec<(String, u32, ArmState)> = Vec::new();
    for (label, insn) in &cases {
        for _ in 0..8 {
            batch.push((label.clone(), *insn, mem_input(&mut rng)));
        }
    }
    run_batch("mem_ldst_imm", batch);
}

/// Scalar FP 3-source: `0001_1111 type o1 Rm o0 Ra Rn Rd`.
fn enc_fp3(fp_type: u32, o1: u32, o0: u32) -> u32 {
    (0b00011111 << 24) | (fp_type << 22) | (o1 << 21) | (RM << 16) | (o0 << 15)
        | (RA << 10) | (RN << 5) | RD
}
/// Scalar FP 2-source: `0001_1110 type 1 Rm opcode 10 Rn Rd`.
fn enc_fp2(fp_type: u32, opcode: u32) -> u32 {
    (0b00011110 << 24) | (fp_type << 22) | (1 << 21) | (RM << 16) | (opcode << 12)
        | (0b10 << 10) | (RN << 5) | RD
}
/// Scalar FP 1-source: `0001_1110 type 1 opcode 10000 Rn Rd`.
fn enc_fp1(fp_type: u32, opcode: u32) -> u32 {
    (0b00011110 << 24) | (fp_type << 22) | (1 << 21) | (opcode << 15) | (0b10000 << 10)
        | (RN << 5) | RD
}

/// Fill v0..v3 low elements with finite (non-zero) floats. `nonneg` keeps them
/// >= 0 (for FSQRT).
fn fill_scalar_fp(st: &mut ArmState, rng: &mut Rng, f64op: bool, nonneg: bool) {
    for r in 0..4usize {
        let n = (rng.next() % 40) as i64 - 20;
        let iv = if nonneg { (n.abs()) + 1 } else if n == 0 { 1 } else { n };
        if f64op {
            let v = iv as f64 * 0.25;
            st.set_vreg(r, v.to_bits(), 0);
        } else {
            let v = iv as f32 * 0.25;
            st.set_vreg(r, v.to_bits() as u64, 0);
        }
    }
}

#[test]
fn diff_fp_scalar() {
    let mut cases: Vec<(String, u32, bool)> = Vec::new();
    for &ft in &[0u32, 1] {
        let f64op = ft == 1;
        // 3-source: FMADD/FMSUB/FNMADD/FNMSUB
        for o1 in 0..2 {
            for o0 in 0..2 {
                cases.push((format!("fp3 t{ft} o1{o1} o0{o0}"), enc_fp3(ft, o1, o0), f64op));
            }
        }
        // 2-source: FMUL/FDIV/FADD/FSUB/FMAX/FMIN/FMAXNM/FMINNM/FNMUL
        for opcode in 0..9u32 {
            cases.push((format!("fp2 t{ft} op{opcode}"), enc_fp2(ft, opcode), f64op));
        }
        // 1-source: FMOV/FABS/FNEG + FRINT family (skip FSQRT here; tested below)
        for &opcode in &[0b000000u32, 0b000001, 0b000010, 0b001000, 0b001001, 0b001010, 0b001011, 0b001100, 0b001110, 0b001111] {
            cases.push((format!("fp1 t{ft} op{opcode:06b}"), enc_fp1(ft, opcode), f64op));
        }
    }
    let mut rng = Rng::new(0xF101);
    let mut batch: Vec<(String, u32, ArmState)> = Vec::new();
    for (label, insn, f64op) in &cases {
        for _ in 0..16 {
            let mut st = ArmState::zeroed();
            fill_scalar_fp(&mut st, &mut rng, *f64op, false);
            batch.push((label.clone(), *insn, st));
        }
    }
    run_batch("fp_scalar", batch);
}

#[test]
fn diff_fp_scalar_sqrt() {
    let mut cases: Vec<(String, u32, bool)> = Vec::new();
    for &ft in &[0u32, 1] {
        cases.push((format!("fsqrt t{ft}"), enc_fp1(ft, 0b000011), ft == 1));
    }
    let mut rng = Rng::new(0xF102);
    let mut batch: Vec<(String, u32, ArmState)> = Vec::new();
    for (label, insn, f64op) in &cases {
        for _ in 0..24 {
            let mut st = ArmState::zeroed();
            fill_scalar_fp(&mut st, &mut rng, *f64op, true);
            batch.push((label.clone(), *insn, st));
        }
    }
    run_batch("fp_scalar_sqrt", batch);
}

/// FCCMP/FCCMPE: scalar FP conditional compare. Output is only NZCV (the flag
/// rules are deterministic even for NaN operands), so comparison is exact.
#[test]
fn diff_fp_ccmp() {
    let mut cases: Vec<(String, u32)> = Vec::new();
    for &fp_type in &[0b00u32, 0b01, 0b11] {
        for cond in 0..16u32 {
            for op in 0..2u32 {
                for &nzcv in &[0u32, 0xF, 0x5] {
                    let insn = (0b00011110u32 << 24)
                        | (fp_type << 22)
                        | (1 << 21)
                        | (RM << 16)
                        | (cond << 12)
                        | (0b01 << 10)
                        | (RN << 5)
                        | (op << 4)
                        | nzcv;
                    cases.push((format!("fccmp ty{fp_type} cond{cond} op{op} nzcv{nzcv}"), insn));
                }
            }
        }
    }
    run_family("fp_ccmp", cases, 6, 0x3001);
}

/// Advanced SIMD shift-by-immediate: `0 Q U 011110 immh immb opcode 1 Rn Rd`.
fn enc_shift_imm(q: u32, u: u32, opcode: u32, immhimmb: u32) -> u32 {
    let immh = (immhimmb >> 3) & 0xF;
    let immb = immhimmb & 0x7;
    (q << 30) | (u << 29) | (0b011110 << 23) | (immh << 19) | (immb << 16)
        | (opcode << 11) | (1 << 10) | (RN << 5) | RD
}

/// Integer shift-by-immediate cases: same-size, widening and narrowing forms
/// across all element sizes and the full range of valid shift amounts.
fn shift_imm_int_cases() -> Vec<(String, u32)> {
    let mut v = Vec::new();
    // Same-size ops: (opcode, U-options, is_left)
    let same: &[(u32, &[u32], bool)] = &[
        (0b00000, &[0, 1], false), // SSHR/USHR
        (0b00010, &[0, 1], false), // SSRA/USRA
        (0b00100, &[0, 1], false), // SRSHR/URSHR
        (0b00110, &[0, 1], false), // SRSRA/URSRA
        (0b01000, &[1], false),    // SRI
        (0b01010, &[0, 1], true),  // SHL / SLI
        (0b01100, &[1], true),     // SQSHLU
        (0b01110, &[0, 1], true),  // SQSHL / UQSHL
    ];
    for &(opcode, us, is_left) in same {
        for &bits in &[8u32, 16, 32, 64] {
            for &u in us {
                for q in 0..2 {
                    if bits == 64 && q == 0 {
                        continue; // 1D not valid
                    }
                    let shifts: Vec<u32> = if is_left {
                        (0..bits).collect()
                    } else {
                        (1..=bits).collect()
                    };
                    for sh in shifts {
                        let immhimmb = if is_left { bits + sh } else { 2 * bits - sh };
                        v.push((
                            format!("sh same op{opcode:05b} u{u} b{bits} q{q} #{sh}"),
                            enc_shift_imm(q, u, opcode, immhimmb),
                        ));
                    }
                }
            }
        }
    }
    // Widening SSHLL/USHLL (opcode 10100), source size 8/16/32.
    for &bits in &[8u32, 16, 32] {
        for u in 0..2 {
            for q in 0..2 {
                for sh in 0..bits {
                    let immhimmb = bits + sh;
                    v.push((
                        format!("sshll u{u} b{bits} q{q} #{sh}"),
                        enc_shift_imm(q, u, 0b10100, immhimmb),
                    ));
                }
            }
        }
    }
    // Narrowing (opcode 10000/10001/10010/10011), dest size 8/16/32.
    for &opcode in &[0b10000u32, 0b10001, 0b10010, 0b10011] {
        for &bits in &[8u32, 16, 32] {
            for u in 0..2 {
                for q in 0..2 {
                    for sh in 1..=bits {
                        let immhimmb = 2 * bits - sh;
                        v.push((
                            format!("narrow op{opcode:05b} u{u} b{bits} q{q} #{sh}"),
                            enc_shift_imm(q, u, opcode, immhimmb),
                        ));
                    }
                }
            }
        }
    }
    v
}

#[test]
fn diff_simd_shift_imm() {
    run_family("simd_shift_imm", shift_imm_int_cases(), 6, 0x4001);
}

/// Fixed-point convert (SCVTF/UCVTF/FCVTZS/FCVTZU), clean finite inputs.
#[test]
fn diff_simd_shift_fixedpoint() {
    let mut cases: Vec<(String, u32)> = Vec::new();
    for &opcode in &[0b11100u32, 0b11111] {
        for &bits in &[32u32, 64] {
            for u in 0..2 {
                for q in 0..2 {
                    if bits == 64 && q == 0 {
                        continue;
                    }
                    for &fbits in &[1u32, bits / 2, bits - 1] {
                        let immhimmb = 2 * bits - fbits;
                        cases.push((
                            format!("fxp op{opcode:05b} u{u} b{bits} q{q} f{fbits}"),
                            enc_shift_imm(q, u, opcode, immhimmb),
                        ));
                    }
                }
            }
        }
    }
    // Inputs: for FCVTZS/U the source lanes are floats; for SCVTF/UCVTF they are
    // integers. Use small finite magnitudes so results are exact / unambiguous.
    let mut rng = Rng::new(0x4002);
    let mut batch: Vec<(String, u32, ArmState)> = Vec::new();
    for (label, insn) in &cases {
        let is_fcvt = label.contains("11111");
        let bits64 = label.contains("b64");
        for _ in 0..16 {
            let mut st = ArmState::zeroed();
            let mut packed: u128 = 0;
            for lane in 0..4 {
                let word: u64 = if is_fcvt {
                    // small finite float values
                    let val = ((rng.next() % 41) as i64 - 20) as f64 * 0.25;
                    if bits64 { val.to_bits() } else { (val as f32).to_bits() as u64 }
                } else {
                    // small signed integers
                    ((rng.next() % 4001) as i64 - 2000) as u64
                };
                if bits64 {
                    packed |= (word as u128) << (64 * lane.min(1));
                    if lane == 1 { break; }
                } else {
                    packed |= ((word as u32) as u128) << (32 * lane);
                }
            }
            st.set_vreg(1, packed as u64, (packed >> 64) as u64);
            batch.push((label.clone(), *insn, st));
        }
    }
    run_batch("simd_shift_fixedpoint", batch);
}

/// Advanced SIMD three-different (widening/narrowing): `0 Q U 01110 size 1 Rm opcode 00 Rn Rd`.
fn enc_3diff(q: u32, u: u32, size: u32, opcode: u32) -> u32 {
    (q << 30) | (u << 29) | (0b01110 << 24) | (size << 22) | (1 << 21) | (RM << 16)
        | (opcode << 12) | (RN << 5) | RD
}

#[test]
fn diff_simd_three_diff() {
    // (opcode, U-options, name)
    let ops: &[(u32, &[u32], &str)] = &[
        (0b0000, &[0, 1], "saddl_uaddl"),
        (0b0001, &[0, 1], "saddw_uaddw"),
        (0b0010, &[0, 1], "ssubl_usubl"),
        (0b0011, &[0, 1], "ssubw_usubw"),
        (0b0100, &[0, 1], "addhn_raddhn"),
        (0b0101, &[0, 1], "sabal_uabal"),
        (0b0110, &[0, 1], "subhn_rsubhn"),
        (0b0111, &[0, 1], "sabdl_uabdl"),
        (0b1000, &[0, 1], "smlal_umlal"),
        (0b1001, &[0], "sqdmlal"),
        (0b1010, &[0, 1], "smlsl_umlsl"),
        (0b1011, &[0], "sqdmlsl"),
        (0b1100, &[0, 1], "smull_umull"),
        (0b1101, &[0], "sqdmull"),
        (0b1110, &[0], "pmull"),
    ];
    let mut cases: Vec<(String, u32)> = Vec::new();
    for &(opcode, us, name) in ops {
        for &u in us {
            for size in 0..3 {
                for q in 0..2 {
                    cases.push((format!("{name} sz{size} q{q}"), enc_3diff(q, u, size, opcode)));
                }
            }
            // PMULL.1Q (size==3) for the polynomial op only.
            if opcode == 0b1110 {
                for q in 0..2 {
                    cases.push((format!("{name} sz3 q{q}"), enc_3diff(q, u, 3, opcode)));
                }
            }
        }
    }
    run_family("simd_three_diff", cases, 8, 0x8001);
}

/// Advanced SIMD across-lanes reduction: `0 Q U 01110 size 11000 opcode 10 Rn Rd`.
fn enc_across(q: u32, u: u32, size: u32, opcode: u32) -> u32 {
    (q << 30) | (u << 29) | (0b01110 << 24) | (size << 22) | (0b11000 << 17)
        | (opcode << 12) | (0b10 << 10) | (RN << 5) | RD
}

#[test]
fn diff_simd_across_int() {
    let ops: &[(u32, u32, &str)] = &[
        (0, 0b11011, "addv"),
        (0, 0b00011, "saddlv"),
        (1, 0b00011, "uaddlv"),
        (0, 0b01010, "smaxv"),
        (1, 0b01010, "umaxv"),
        (0, 0b11010, "sminv"),
        (1, 0b11010, "uminv"),
    ];
    let mut cases: Vec<(String, u32)> = Vec::new();
    for &(u, opcode, name) in ops {
        for size in 0..4 {
            for q in 0..2 {
                cases.push((format!("{name} sz{size} q{q}"), enc_across(q, u, size, opcode)));
            }
        }
    }
    run_family("simd_across_int", cases, 10, 0x7001);
}

#[test]
fn diff_simd_across_fp() {
    // FMAXV/FMINV/FMAXNMV/FMINNMV over 4S (q==1), size bit23 picks min.
    let mut cases: Vec<(String, u32)> = Vec::new();
    for &(opcode, name) in &[(0b01111u32, "fmaxv_fminv"), (0b01100, "fmaxnmv_fminnmv")] {
        for &size in &[0b00u32, 0b10] {
            cases.push((format!("{name} sz{size}"), enc_across(1, 1, size, opcode)));
        }
    }
    let mut rng = Rng::new(0x7002);
    let mut batch: Vec<(String, u32, ArmState)> = Vec::new();
    for (label, insn) in &cases {
        for _ in 0..24 {
            let mut st = ArmState::zeroed();
            let mut packed: u128 = 0;
            for lane in 0..4 {
                let val = ((rng.next() % 81) as i64 - 40) as f32 * 0.25;
                packed |= (val.to_bits() as u128) << (32 * lane);
            }
            st.set_vreg(1, packed as u64, (packed >> 64) as u64);
            batch.push((label.clone(), *insn, st));
        }
    }
    run_batch("simd_across_fp", batch);
}

#[test]
fn diff_simd_three_same_fp() {
    // (U, a, opcode, name) for the FP three-same ops. size = (a<<1)|sz.
    let ops: &[(u32, u32, u32, &str)] = &[
        (0, 0, 0b11000, "fmaxnm"),
        (0, 0, 0b11001, "fmla"),
        (0, 0, 0b11010, "fadd"),
        (0, 0, 0b11011, "fmulx"),
        (0, 0, 0b11100, "fcmeq"),
        (0, 0, 0b11110, "fmax"),
        (0, 0, 0b11111, "frecps"),
        (0, 1, 0b11000, "fminnm"),
        (0, 1, 0b11001, "fmls"),
        (0, 1, 0b11010, "fsub"),
        (0, 1, 0b11110, "fmin"),
        (0, 1, 0b11111, "frsqrts"),
        (1, 0, 0b11000, "fmaxnmp"),
        (1, 0, 0b11010, "faddp"),
        (1, 0, 0b11011, "fmul"),
        (1, 0, 0b11100, "fcmge"),
        (1, 0, 0b11101, "facge"),
        (1, 0, 0b11110, "fmaxp"),
        (1, 0, 0b11111, "fdiv"),
        (1, 1, 0b11000, "fminnmp"),
        (1, 1, 0b11010, "fabd"),
        (1, 1, 0b11100, "fcmgt"),
        (1, 1, 0b11101, "facgt"),
        (1, 1, 0b11110, "fminp"),
    ];
    let mut cases: Vec<(String, u32, bool)> = Vec::new();
    for &(u, a, opcode, name) in ops {
        for q in 0..2 {
            cases.push((format!("{name} f32 q{q}"), enc_three_same(q, u, a << 1, opcode), false));
        }
        cases.push((format!("{name} f64"), enc_three_same(1, u, (a << 1) | 1, opcode), true));
    }
    // Non-zero finite lanes (multiples of 0.25) so FDIV is well-defined and
    // products/sums stay exactly representable.
    let mut rng = Rng::new(0xE001);
    let mut batch: Vec<(String, u32, ArmState)> = Vec::new();
    for (label, insn, f64op) in &cases {
        for _ in 0..12 {
            let mut st = ArmState::zeroed();
            for r in 0..3usize {
                let mut packed: u128 = 0;
                if *f64op {
                    for lane in 0..2 {
                        let n = (rng.next() % 40) as i64 - 20;
                        let v = if n == 0 { 1 } else { n } as f64 * 0.25;
                        packed |= (v.to_bits() as u128) << (64 * lane);
                    }
                } else {
                    for lane in 0..4 {
                        let n = (rng.next() % 40) as i64 - 20;
                        let v = if n == 0 { 1 } else { n } as f32 * 0.25;
                        packed |= (v.to_bits() as u128) << (32 * lane);
                    }
                }
                st.set_vreg(r, packed as u64, (packed >> 64) as u64);
            }
            batch.push((label.clone(), *insn, st));
        }
    }
    run_batch("simd_three_same_fp", batch);
}

/// Scalar Advanced SIMD three-same: `01 U 11110 size 1 Rm opcode 1 Rn Rd`.
fn enc_scalar_3same(u: u32, size: u32, opcode: u32) -> u32 {
    (0b01 << 30) | (u << 29) | (0b11110 << 24) | (size << 22) | (1 << 21) | (RM << 16)
        | (opcode << 11) | (1 << 10) | (RN << 5) | RD
}

#[test]
fn diff_simd_scalar_three_same() {
    // Integer scalar three-same opcodes (size validity is enforced by rax /
    // checked against the oracle).
    let opcodes: &[(u32, &str)] = &[
        (0b00001, "sqadd"),
        (0b00101, "sqsub"),
        (0b00110, "cmgt_cmhi"),
        (0b00111, "cmge_cmhs"),
        (0b01000, "sshl_ushl"),
        (0b01001, "sqshl_uqshl"),
        (0b01010, "srshl_urshl"),
        (0b01011, "sqrshl_uqrshl"),
        (0b10000, "add_sub"),
        (0b10001, "cmtst_cmeq"),
        (0b10110, "sqdmulh_sqrdmulh"),
    ];
    let mut cases: Vec<(String, u32)> = Vec::new();
    for &(opcode, name) in opcodes {
        for u in 0..2 {
            for size in 0..4 {
                cases.push((format!("{name} u{u} sz{size}"), enc_scalar_3same(u, size, opcode)));
            }
        }
    }
    run_family("simd_scalar_three_same", cases, 8, 0xD001);
}

/// SIMD modified immediate: `0 Q op 0111100000 abc cmode o2 1 defgh Rd`.
fn enc_modimm(q: u32, op: u32, cmode: u32, imm8: u32) -> u32 {
    let abc = (imm8 >> 5) & 0x7;
    let defgh = imm8 & 0x1F;
    (q << 30) | (op << 29) | (0x0F << 24) | (abc << 16) | (cmode << 12) | (1 << 10)
        | (defgh << 5) | RD
}

#[test]
fn diff_simd_modimm() {
    let mut cases: Vec<(String, u32)> = Vec::new();
    for op in 0..2u32 {
        for cmode in 0..16u32 {
            for q in 0..2 {
                for &imm8 in &[0x00u32, 0xFF, 0x55, 0xA3, 0x80, 0x01] {
                    cases.push((
                        format!("modimm op{op} cm{cmode:04b} q{q} #{imm8:#04x}"),
                        enc_modimm(q, op, cmode, imm8),
                    ));
                }
            }
        }
    }
    run_family("simd_modimm", cases, 4, 0xC001);
}

/// Advanced SIMD permute (ZIP/UZP/TRN): `0 Q 0 01110 size 0 Rm 0 opcode 10 Rn Rd`.
fn enc_permute(q: u32, size: u32, opcode: u32) -> u32 {
    (q << 30) | (0b01110 << 24) | (size << 22) | (RM << 16) | (opcode << 12) | (0b10 << 10)
        | (RN << 5) | RD
}

#[test]
fn diff_simd_permute() {
    let ops: &[(u32, &str)] = &[
        (0b001, "uzp1"),
        (0b101, "uzp2"),
        (0b010, "trn1"),
        (0b110, "trn2"),
        (0b011, "zip1"),
        (0b111, "zip2"),
    ];
    let mut cases: Vec<(String, u32)> = Vec::new();
    for &(opcode, name) in ops {
        for size in 0..4 {
            for q in 0..2 {
                cases.push((format!("{name} sz{size} q{q}"), enc_permute(q, size, opcode)));
            }
        }
    }
    run_family("simd_permute", cases, 6, 0xB001);
}

/// Advanced SIMD EXT: `0 Q 10 1110 00 0 Rm 0 imm4 0 Rn Rd`.
fn enc_ext(q: u32, imm4: u32) -> u32 {
    (q << 30) | (1 << 29) | (0b01110 << 24) | (RM << 16) | (imm4 << 11) | (RN << 5) | RD
}

#[test]
fn diff_simd_ext() {
    let mut cases: Vec<(String, u32)> = Vec::new();
    for q in 0..2 {
        let maxidx = if q == 1 { 16 } else { 8 };
        for imm4 in 0..maxidx {
            cases.push((format!("ext q{q} #{imm4}"), enc_ext(q, imm4)));
        }
    }
    run_family("simd_ext", cases, 6, 0xB002);
}

/// Advanced SIMD TBL/TBX: `0 Q 00 1110 00 0 Rm 0 len op 00 Rn Rd`.
fn enc_tbl(q: u32, len: u32, op: u32) -> u32 {
    (q << 30) | (0b001110 << 23) | (RM << 16) | (len << 13) | (op << 12) | (RN << 5) | RD
}

#[test]
fn diff_simd_tbl() {
    let mut cases: Vec<(String, u32)> = Vec::new();
    for op in 0..2 {
        for len in 0..4 {
            for q in 0..2 {
                let name = if op == 0 { "tbl" } else { "tbx" };
                cases.push((format!("{name} len{len} q{q}"), enc_tbl(q, len, op)));
            }
        }
    }
    run_family("simd_tbl", cases, 8, 0xB003);
}

/// Advanced SIMD copy: `0 Q op 01110000 imm5 0 imm4 1 Rn Rd`.
fn enc_copy(q: u32, op: u32, imm5: u32, imm4: u32) -> u32 {
    (q << 30) | (op << 29) | (0b01110 << 24) | (imm5 << 16) | (imm4 << 11) | (1 << 10)
        | (RN << 5) | RD
}

/// imm5 for a given element size index (0=B,1=H,2=S,3=D) and lane index.
fn copy_imm5(size: u32, index: u32) -> u32 {
    (index << (size + 1)) | (1 << size)
}

#[test]
fn diff_simd_copy() {
    let mut cases: Vec<(String, u32)> = Vec::new();
    // DUP element (op0 imm4 0000), DUP general (imm4 0001), INS general (0011),
    // SMOV (0101), UMOV (0111); INS element (op1).
    for size in 0..4u32 {
        let lanes: u32 = 16u32 >> size; // lanes in 128 bits (16/8/4/2)
        for &index in &[0u32, lanes - 1] {
            for q in 0..2 {
                cases.push((format!("dupelem sz{size} i{index} q{q}"), enc_copy(q, 0, copy_imm5(size, index), 0b0000)));
                cases.push((format!("dupgen sz{size} i{index} q{q}"), enc_copy(q, 0, copy_imm5(size, index), 0b0001)));
                cases.push((format!("smov sz{size} i{index} q{q}"), enc_copy(q, 0, copy_imm5(size, index), 0b0101)));
                cases.push((format!("umov sz{size} i{index} q{q}"), enc_copy(q, 0, copy_imm5(size, index), 0b0111)));
            }
            // INS general/element are always 128-bit (Q=1 in the encoding).
            cases.push((format!("insgen sz{size} i{index}"), enc_copy(1, 0, copy_imm5(size, index), 0b0011)));
            // INS element: dest index from imm5, source index from imm4 (per size).
            let src = (index + 1) % lanes;
            cases.push((format!("inselem sz{size} d{index} s{src}"), enc_copy(1, 1, copy_imm5(size, index), src << size)));
        }
    }
    run_family("simd_copy", cases, 8, 0x9001);
}

/// Advanced SIMD two-register miscellaneous: `0 Q U 01110 size 10000 opcode 10 Rn Rd`.
fn enc_two_reg(q: u32, u: u32, size: u32, opcode: u32) -> u32 {
    (q << 30) | (u << 29) | (0b01110 << 24) | (size << 22) | (0b10000 << 17)
        | (opcode << 12) | (0b10 << 10) | (RN << 5) | RD
}

#[test]
fn diff_simd_two_reg_int() {
    // (U, opcode, name) for the integer same-size / REV / NOT-RBIT ops.
    let ops: &[(u32, u32, &str)] = &[
        (0, 0b00000, "rev64"),
        (1, 0b00000, "rev32"),
        (0, 0b00001, "rev16"),
        (0, 0b00011, "suqadd"),
        (1, 0b00011, "usqadd"),
        (0, 0b00100, "cls"),
        (1, 0b00100, "clz"),
        (0, 0b00101, "cnt"),
        (1, 0b00101, "not_rbit"),
        (0, 0b00111, "sqabs"),
        (1, 0b00111, "sqneg"),
        (0, 0b01000, "cmgt0"),
        (1, 0b01000, "cmge0"),
        (0, 0b01001, "cmeq0"),
        (1, 0b01001, "cmle0"),
        (0, 0b01010, "cmlt0"),
        (0, 0b01011, "abs"),
        (1, 0b01011, "neg"),
    ];
    let mut cases: Vec<(String, u32)> = Vec::new();
    for &(u, opcode, name) in ops {
        for size in 0..4 {
            for q in 0..2 {
                cases.push((format!("{name} sz{size} q{q}"), enc_two_reg(q, u, size, opcode)));
            }
        }
    }
    run_family("simd_two_reg_int", cases, 8, 0x6001);
}

#[test]
fn diff_simd_two_reg_widen() {
    // Pairwise-widening, narrowing and shift-long two-reg forms (size 0..2).
    let ops: &[(u32, u32, &str)] = &[
        (0, 0b00010, "saddlp"),
        (1, 0b00010, "uaddlp"),
        (0, 0b00110, "sadalp"),
        (1, 0b00110, "uadalp"),
        (0, 0b10010, "xtn"),
        (1, 0b10010, "sqxtun"),
        (0, 0b10100, "sqxtn"),
        (1, 0b10100, "uqxtn"),
        (1, 0b10011, "shll"),
    ];
    let mut cases: Vec<(String, u32)> = Vec::new();
    for &(u, opcode, name) in ops {
        for size in 0..3 {
            for q in 0..2 {
                cases.push((format!("{name} sz{size} q{q}"), enc_two_reg(q, u, size, opcode)));
            }
        }
    }
    run_family("simd_two_reg_widen", cases, 8, 0x6003);
}

/// Fill registers v0..v2 with finite float lanes (multiples of 0.25, so rounding
/// ties land exactly on .5). If `nonneg`, all lanes are >= 0 (for FSQRT).
fn fill_fp_lanes(st: &mut ArmState, rng: &mut Rng, f64op: bool, nonneg: bool) {
    for r in 0..3usize {
        let mut packed: u128 = 0;
        if f64op {
            for lane in 0..2 {
                let n = (rng.next() % 256) as i64;
                let iv = if nonneg { n } else { n - 128 };
                let val = iv as f64 * 0.25;
                packed |= (val.to_bits() as u128) << (64 * lane);
            }
        } else {
            for lane in 0..4 {
                let n = (rng.next() % 256) as i64;
                let iv = if nonneg { n } else { n - 128 };
                let val = iv as f32 * 0.25;
                packed |= (val.to_bits() as u128) << (32 * lane);
            }
        }
        st.set_vreg(r, packed as u64, (packed >> 64) as u64);
    }
}

/// Build FP two-reg cases for the given (u, sz_hi, opcode, name) ops, covering
/// f32 (2S/4S) and f64 (2D), then drive `n` finite inputs through each.
fn fp_two_reg_batch(
    ops: &[(u32, u32, u32, &str)],
    seed: u64,
    n: usize,
    nonneg: bool,
) -> Vec<(String, u32, ArmState)> {
    let mut cases: Vec<(String, u32, bool)> = Vec::new();
    for &(u, sz_hi, opcode, name) in ops {
        // f32: 2S (q=0) and 4S (q=1)
        for q in 0..2 {
            let size = sz_hi << 1; // sz=0
            cases.push((format!("{name} f32 q{q}"), enc_two_reg(q, u, size, opcode), false));
        }
        // f64: 2D (q=1 only)
        let size = (sz_hi << 1) | 1;
        cases.push((format!("{name} f64"), enc_two_reg(1, u, size, opcode), true));
    }
    let mut rng = Rng::new(seed);
    let mut batch = Vec::new();
    for (label, insn, f64op) in &cases {
        for _ in 0..n {
            let mut st = ArmState::zeroed();
            fill_fp_lanes(&mut st, &mut rng, *f64op, nonneg);
            batch.push((label.clone(), *insn, st));
        }
    }
    batch
}

#[test]
fn diff_simd_two_reg_fp() {
    // (U, sz_hi, opcode, name) -- float-input ops except FSQRT/SCVTF/UCVTF.
    let ops: &[(u32, u32, u32, &str)] = &[
        (0, 1, 0b01111, "fabs"),
        (1, 1, 0b01111, "fneg"),
        (0, 0, 0b11000, "frintn"),
        (0, 1, 0b11000, "frintp"),
        (1, 0, 0b11000, "frinta"),
        (0, 0, 0b11001, "frintm"),
        (0, 1, 0b11001, "frintz"),
        (1, 0, 0b11001, "frintx"),
        (1, 1, 0b11001, "frinti"),
        (0, 0, 0b11010, "fcvtns"),
        (0, 1, 0b11010, "fcvtps"),
        (1, 0, 0b11010, "fcvtnu"),
        (1, 1, 0b11010, "fcvtpu"),
        (0, 0, 0b11011, "fcvtms"),
        (0, 1, 0b11011, "fcvtzs"),
        (1, 0, 0b11011, "fcvtmu"),
        (1, 1, 0b11011, "fcvtzu"),
        (0, 0, 0b11100, "fcvtas"),
        (1, 0, 0b11100, "fcvtau"),
        (0, 1, 0b01100, "fcmgt0"),
        (1, 1, 0b01100, "fcmge0"),
        (0, 1, 0b01101, "fcmeq0"),
        (1, 1, 0b01101, "fcmle0"),
        (0, 1, 0b01110, "fcmlt0"),
    ];
    run_batch("simd_two_reg_fp", fp_two_reg_batch(ops, 0xA001, 12, false));
}

#[test]
fn diff_simd_two_reg_fsqrt() {
    let ops: &[(u32, u32, u32, &str)] = &[(1, 1, 0b11111, "fsqrt")];
    run_batch("simd_two_reg_fsqrt", fp_two_reg_batch(ops, 0xA002, 24, true));
}

#[test]
fn diff_simd_two_reg_cvtf() {
    // SCVTF/UCVTF take integer source lanes.
    let ops: &[(u32, u32, u32, &str)] = &[(0, 0, 0b11101, "scvtf"), (1, 0, 0b11101, "ucvtf")];
    let mut cases: Vec<(String, u32, bool)> = Vec::new();
    for &(u, sz_hi, opcode, name) in ops {
        for q in 0..2 {
            cases.push((format!("{name} 32 q{q}"), enc_two_reg(q, u, sz_hi << 1, opcode), false));
        }
        cases.push((format!("{name} 64"), enc_two_reg(1, u, (sz_hi << 1) | 1, opcode), true));
    }
    let mut rng = Rng::new(0xA003);
    let mut batch = Vec::new();
    for (label, insn, is64) in &cases {
        for _ in 0..16 {
            let mut st = ArmState::zeroed();
            let mut packed: u128 = 0;
            if *is64 {
                for lane in 0..2 {
                    packed |= ((rng.next() as u64) as u128) << (64 * lane);
                }
            } else {
                for lane in 0..4 {
                    packed |= ((rng.next() as u32) as u128) << (32 * lane);
                }
            }
            st.set_vreg(1, packed as u64, (packed >> 64) as u64);
            batch.push((label.clone(), *insn, st));
        }
    }
    run_batch("simd_two_reg_cvtf", batch);
}

/// Advanced SIMD vector x indexed element: `0 Q U 01111 size L M Rm opcode H 0 Rn Rd`.
fn enc_indexed(q: u32, u: u32, size: u32, opcode: u32, vm: u32, index: u32) -> u32 {
    let (rm, mbit, lbit, hbit) = match size {
        0b01 => (vm & 0xF, index & 1, (index >> 1) & 1, (index >> 2) & 1),
        0b10 => (vm & 0xF, (vm >> 4) & 1, index & 1, (index >> 1) & 1),
        0b11 => (vm & 0xF, (vm >> 4) & 1, 0, index & 1),
        _ => (0, 0, 0, 0),
    };
    (q << 30) | (u << 29) | (0b01111 << 24) | (size << 22) | (lbit << 21) | (mbit << 20)
        | (rm << 16) | (opcode << 12) | (hbit << 11) | (RN << 5) | RD
}

#[test]
fn diff_simd_indexed_int() {
    // (U, opcode) for the integer indexed ops; widening forms produce 2x results.
    let ops: &[(u32, u32, &str)] = &[
        (0, 0b1000, "mul"),
        (1, 0b0000, "mla"),
        (1, 0b0100, "mls"),
        (0, 0b1100, "sqdmulh"),
        (0, 0b1101, "sqrdmulh"),
        (1, 0b1101, "sqrdmlah"),
        (1, 0b1111, "sqrdmlsh"),
        (0, 0b0010, "smlal"),
        (1, 0b0010, "umlal"),
        (0, 0b0110, "smlsl"),
        (1, 0b0110, "umlsl"),
        (0, 0b1010, "smull"),
        (1, 0b1010, "umull"),
        (0, 0b0011, "sqdmlal"),
        (0, 0b0111, "sqdmlsl"),
        (0, 0b1011, "sqdmull"),
    ];
    let mut cases: Vec<(String, u32)> = Vec::new();
    for &(u, opcode, name) in ops {
        for &size in &[0b01u32, 0b10] {
            let max_index = if size == 0b01 { 8 } else { 4 };
            for q in 0..2 {
                for &index in &[0u32, max_index - 1] {
                    cases.push((
                        format!("{name} sz{size} q{q} idx{index}"),
                        enc_indexed(q, u, size, opcode, 2, index),
                    ));
                }
            }
        }
    }
    run_family("simd_indexed_int", cases, 8, 0x5001);
}

#[test]
fn diff_simd_indexed_fp() {
    let ops: &[(u32, u32, &str)] = &[
        (0, 0b1001, "fmul"),
        (0, 0b0001, "fmla"),
        (0, 0b0101, "fmls"),
        (1, 0b1001, "fmulx"),
    ];
    let mut cases: Vec<(String, u32)> = Vec::new();
    for &(u, opcode, name) in ops {
        // size 10 = f32 (index 0..3), size 11 = f64 (index 0..1, Q must be 1)
        for &(size, qs, maxidx) in &[(0b10u32, &[0u32, 1][..], 4u32), (0b11u32, &[1u32][..], 2)] {
            for &q in qs {
                for index in 0..maxidx {
                    cases.push((
                        format!("{name} sz{size} q{q} idx{index}"),
                        enc_indexed(q, u, size, opcode, 2, index),
                    ));
                }
            }
        }
    }
    // Clean finite FP inputs in v1 (Rn), v2 (Rm), v0 (Rd accumulator).
    let mut rng = Rng::new(0x5002);
    let mut batch: Vec<(String, u32, ArmState)> = Vec::new();
    for (label, insn) in &cases {
        let f64op = label.contains("sz11");
        for _ in 0..16 {
            let mut st = ArmState::zeroed();
            for r in [0usize, 1, 2] {
                let mut packed: u128 = 0;
                if f64op {
                    for lane in 0..2 {
                        let val = ((rng.next() % 41) as i64 - 20) as f64 * 0.5;
                        packed |= (val.to_bits() as u128) << (64 * lane);
                    }
                } else {
                    for lane in 0..4 {
                        let val = ((rng.next() % 41) as i64 - 20) as f32 * 0.5;
                        packed |= (val.to_bits() as u128) << (32 * lane);
                    }
                }
                st.set_vreg(r, packed as u64, (packed >> 64) as u64);
            }
            batch.push((label.clone(), *insn, st));
        }
    }
    run_batch("simd_indexed_fp", batch);
}

/// FCSEL: scalar FP conditional select. Output is a bit-exact register copy.
#[test]
fn diff_fp_csel() {
    let mut cases: Vec<(String, u32)> = Vec::new();
    for &fp_type in &[0b00u32, 0b01, 0b11] {
        for cond in 0..16u32 {
            let insn = (0b00011110u32 << 24)
                | (fp_type << 22)
                | (1 << 21)
                | (RM << 16)
                | (cond << 12)
                | (0b11 << 10)
                | (RN << 5)
                | RD;
            cases.push((format!("fcsel ty{fp_type} cond{cond}"), insn));
        }
    }
    run_family("fp_csel", cases, 8, 0x3002);
}
