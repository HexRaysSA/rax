//! Hexagon differential test harness: rax interpreter vs. QEMU (hardware oracle).
//!
//! The rax software interpreter (`src/backend/emulator/hexagon/`) is checked
//! against a hardware-semantics reference produced by executing each instruction
//! packet under `qemu-hexagon` (user mode). The reference harness is
//! `tools/hexagon-diff/oracle.s`, assembled+linked on demand into a static
//! Hexagon ELF.
//!
//! For each `(packet, initial architectural state)` pair we:
//!   1. run it on the oracle (R0..R31, P3:0, USR, M0/M1, GP, CS, SA/LC captured),
//!   2. run it on the rax `HexagonVcpu` from the *identical* initial state,
//! then compare the architectural state. Any divergence is an interpreter bug.
//!
//! Test packets are produced by assembling real Hexagon assembly with `llvm-mc`,
//! so the *exact same machine words* are fed to both the oracle and rax: this
//! also exercises rax's decoder, and guarantees the encodings are legal (so the
//! oracle never faults).
//!
//! Robustness (mirrors `tests/arm_diff.rs`): if `qemu-hexagon`, `llvm-mc`, or
//! `ld.lld` are unavailable, every test self-skips so the suite stays green.

#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};

use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

use rax::backend::emulator::hexagon::HexagonVcpu;
use rax::config::{Endianness, HexagonIsa};
use rax::cpu::{CpuState, HexagonRegisters, VCpu, VcpuExit};

// ---------------------------------------------------------------------------
// Wire format -- must match tools/hexagon-diff/gen_oracle.py byte for byte.
// HexState is 44 little-endian u32 (176 bytes).
// ---------------------------------------------------------------------------

const NREG: usize = 32;
// Field indices into the u32 state array.
const I_PRED: usize = 32;
const I_USR: usize = 33;
const I_M0: usize = 34;
const I_M1: usize = 35;
const I_GP: usize = 36;
const I_CS0: usize = 37;
const I_CS1: usize = 38;
const I_SA0: usize = 39;
const I_LC0: usize = 40;
const I_SA1: usize = 41;
const I_LC1: usize = 42;
const I_PC: usize = 43;
const ST_WORDS: usize = 44;

const WIRE_MAGIC: u32 = 0x3158_4548; // 'H','E','X','1'

#[derive(Clone, Copy)]
struct HexState {
    w: [u32; ST_WORDS],
}

impl HexState {
    fn zeroed() -> Self {
        HexState { w: [0; ST_WORDS] }
    }
}

// ---------------------------------------------------------------------------
// Oracle: build on demand, run a whole batch through one qemu invocation.
// ---------------------------------------------------------------------------

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

fn tools_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools/hexagon-diff")
}

/// Build the oracle if needed; `None` if the toolchain is unavailable.
fn oracle_path() -> Option<PathBuf> {
    which("qemu-hexagon")?;
    which("llvm-mc")?;
    which("ld.lld")?;
    let dir = tools_dir();
    let bin = dir.join("oracle");
    let src = dir.join("gen_oracle.py");
    let need_build = match (bin.metadata(), src.metadata()) {
        (Ok(b), Ok(s)) => match (b.modified(), s.modified()) {
            (Ok(bm), Ok(sm)) => bm < sm,
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
            _ => return None,
        }
    }
    if bin.exists() {
        Some(bin)
    } else {
        None
    }
}

fn run_oracle(oracle: &PathBuf, cases: &[(Vec<u32>, HexState)]) -> Option<Vec<HexState>> {
    let mut payload = Vec::with_capacity(8 + cases.len() * 196);
    payload.extend_from_slice(&WIRE_MAGIC.to_le_bytes());
    payload.extend_from_slice(&(cases.len() as u32).to_le_bytes());
    for (words, st) in cases {
        let nwords = words.len().min(4) as u32;
        payload.extend_from_slice(&nwords.to_le_bytes());
        for i in 0..4 {
            let w = words.get(i).copied().unwrap_or(0);
            payload.extend_from_slice(&w.to_le_bytes());
        }
        for v in &st.w {
            payload.extend_from_slice(&v.to_le_bytes());
        }
    }

    let mut child = Command::new("qemu-hexagon")
        // Match the assembler: run the oracle as a v73 core so the V73 audio
        // extension (M7 complex multiply, A7 clip/cround) executes natively.
        .arg("-cpu")
        .arg("v73")
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
        let mut st = HexState::zeroed();
        for k in 0..ST_WORDS {
            st.w[k] = u32::from_le_bytes([
                out[off + 4 * k],
                out[off + 4 * k + 1],
                out[off + 4 * k + 2],
                out[off + 4 * k + 3],
            ]);
        }
        // skip trapped(4) + valid(4)
        off += 176 + 8;
        res.push(st);
    }
    Some(res)
}

// ---------------------------------------------------------------------------
// Assembler: assemble Hexagon packets with llvm-mc, split into per-packet words.
// ---------------------------------------------------------------------------

fn parse_bits(word: u32) -> u32 {
    (word >> 14) & 0x3
}

/// Assemble a list of packet source strings. Each element is one packet (one or
/// more instructions separated by ';' inside the braces, or a multi-line packet).
/// Returns one `Vec<u32>` of machine words per input packet.
fn assemble_packets(packets: &[String]) -> Option<Vec<Vec<u32>>> {
    // Cache keyed by the joined source so repeated families are cheap.
    static CACHE: OnceLock<Mutex<HashMap<String, Vec<Vec<u32>>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let key = packets.join("\n@@@\n");
    if let Some(v) = cache.lock().unwrap().get(&key) {
        return Some(v.clone());
    }

    let src = packets.join("\n");
    let mut child = Command::new("llvm-mc")
        // v73 + audio extension so the M7 complex-multiply / A7 clip family
        // assemble; v73 is a superset of v68 so existing packets are unchanged.
        .args([
            "-triple=hexagon",
            "-mcpu=hexagonv73",
            "-mattr=+audio",
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
        .write_all(src.as_bytes())
        .ok()?;
    let mut out = String::new();
    child.stdout.take().unwrap().read_to_string(&mut out).ok()?;
    if !child.wait().ok()?.success() {
        return None;
    }

    // Collect all encoding bytes in order, regroup into 32-bit words.
    let mut words: Vec<u32> = Vec::new();
    for line in out.lines() {
        if let Some(idx) = line.find("encoding: [") {
            let rest = &line[idx + "encoding: [".len()..];
            let end = rest.find(']')?;
            let bytes_str = &rest[..end];
            let bytes: Vec<u8> = bytes_str
                .split(',')
                .filter_map(|t| {
                    let t = t.trim();
                    let t = t.strip_prefix("0x").unwrap_or(t);
                    u8::from_str_radix(t, 16).ok()
                })
                .collect();
            for chunk in bytes.chunks(4) {
                if chunk.len() == 4 {
                    words.push(
                        chunk[0] as u32
                            | (chunk[1] as u32) << 8
                            | (chunk[2] as u32) << 16
                            | (chunk[3] as u32) << 24,
                    );
                }
            }
        }
    }

    // Split the word stream into packets: a word with parse bits 0b11 (end) or
    // 0b00 (duplex, always terminal) ends the current packet.
    let mut grouped: Vec<Vec<u32>> = Vec::new();
    let mut cur: Vec<u32> = Vec::new();
    for w in words {
        cur.push(w);
        let pb = parse_bits(w);
        if pb == 0b11 || pb == 0b00 {
            grouped.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        grouped.push(cur);
    }
    if grouped.len() != packets.len() {
        // Assembly produced a different packet count than requested; treat as
        // a generation error rather than silently misaligning labels.
        return None;
    }
    cache.lock().unwrap().insert(key, grouped.clone());
    Some(grouped)
}

/// Encoding of `{ trap0(#0) }` used as the rax-side run terminator.
fn trap0_word() -> u32 {
    static W: OnceLock<u32> = OnceLock::new();
    *W.get_or_init(|| {
        assemble_packets(&["{ trap0(#0) }".to_string()]).expect("assemble trap0")[0][0]
    })
}

// ---------------------------------------------------------------------------
// rax: run one packet from an identical initial state.
// ---------------------------------------------------------------------------

const CODE_ADDR: u32 = 0x1000;

fn rax_regs_from_state(st: &HexState) -> HexagonRegisters {
    let mut regs = HexagonRegisters::default();
    for i in 0..NREG {
        regs.r[i] = st.w[i];
    }
    for i in 0..4 {
        regs.p[i] = ((st.w[I_PRED] >> (8 * i)) & 0xff) as u8;
    }
    regs.c[8] = st.w[I_USR];
    regs.c[6] = st.w[I_M0];
    regs.c[7] = st.w[I_M1];
    regs.c[11] = st.w[I_GP];
    regs.c[12] = st.w[I_CS0];
    regs.c[13] = st.w[I_CS1];
    regs.c[0] = st.w[I_SA0];
    regs.c[1] = st.w[I_LC0];
    regs.c[2] = st.w[I_SA1];
    regs.c[3] = st.w[I_LC1];
    regs.set_pc(CODE_ADDR);
    regs
}

/// Pack rax's 8-bit predicate registers into the hardware C4 (P3:0) layout.
fn rax_pred_byte(regs: &HexagonRegisters) -> u32 {
    let mut v = 0u32;
    for i in 0..4 {
        v |= (regs.p[i] as u32) << (8 * i);
    }
    v
}

/// Returns `Some(out_state)` if rax executed the packet, `None` if it rejected
/// the encoding or errored.
fn run_rax(words: &[u32], st: &HexState) -> Option<HexState> {
    let regions = vec![(GuestAddress(0), 0x10000usize)];
    let mem = Arc::new(GuestMemoryMmap::<()>::from_ranges(&regions).ok()?);

    // [test packet words][trap0]
    let mut off = CODE_ADDR;
    for &w in words {
        mem.write_slice(&w.to_le_bytes(), GuestAddress(off as u64)).ok()?;
        off += 4;
    }
    mem.write_slice(&trap0_word().to_le_bytes(), GuestAddress(off as u64))
        .ok()?;

    let mut vcpu = HexagonVcpu::new(0, mem.clone(), HexagonIsa::V68, Endianness::Little);
    vcpu.set_state(&CpuState::hexagon(rax_regs_from_state(st))).ok()?;

    let mut iters = 0;
    loop {
        iters += 1;
        if iters > 64 {
            return None;
        }
        match vcpu.run() {
            Ok(VcpuExit::Shutdown) => break,
            Ok(_) => return None, // unexpected MMIO/halt for reg-only tests
            Err(_) => return None,
        }
    }

    let state = vcpu.get_state().ok()?;
    let regs = match state {
        CpuState::Hexagon(s) => s.regs,
        _ => return None,
    };
    let mut out = HexState::zeroed();
    for i in 0..NREG {
        out.w[i] = regs.r[i];
    }
    out.w[I_PRED] = rax_pred_byte(&regs);
    out.w[I_USR] = regs.c[8];
    out.w[I_M0] = regs.c[6];
    out.w[I_M1] = regs.c[7];
    out.w[I_GP] = regs.c[11];
    out.w[I_CS0] = regs.c[12];
    out.w[I_CS1] = regs.c[13];
    out.w[I_SA0] = regs.c[0];
    out.w[I_LC0] = regs.c[1];
    out.w[I_SA1] = regs.c[2];
    out.w[I_LC1] = regs.c[3];
    Some(out)
}

// ---------------------------------------------------------------------------
// Comparison.
// ---------------------------------------------------------------------------

struct Mismatch {
    label: String,
    asm: String,
    detail: String,
}

/// Which architectural fields to compare. Reg-only ALU affects r[], predicates
/// and USR; we ignore PC (run-relative) and modifier/loop regs unless asked.
fn compare_case(
    label: &str,
    asm: &str,
    words: &[u32],
    input: &HexState,
    oracle: &HexState,
    mismatches: &mut Vec<Mismatch>,
) {
    let rax = match run_rax(words, input) {
        Some(s) => s,
        None => {
            mismatches.push(Mismatch {
                label: label.into(),
                asm: asm.into(),
                detail: "hw executed but rax rejected the encoding (unimplemented/err)".into(),
            });
            return;
        }
    };

    let mut diffs = Vec::new();
    for i in 0..NREG {
        if rax.w[i] != oracle.w[i] {
            diffs.push(format!("r{i}: rax={:#010x} hw={:#010x}", rax.w[i], oracle.w[i]));
        }
    }
    if rax.w[I_PRED] != oracle.w[I_PRED] {
        diffs.push(format!(
            "P3:0: rax={:#010x} hw={:#010x}",
            rax.w[I_PRED], oracle.w[I_PRED]
        ));
    }
    if rax.w[I_USR] != oracle.w[I_USR] {
        diffs.push(format!(
            "USR: rax={:#010x} hw={:#010x}",
            rax.w[I_USR], oracle.w[I_USR]
        ));
    }

    if !diffs.is_empty() {
        mismatches.push(Mismatch {
            label: label.into(),
            asm: asm.into(),
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
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn interesting32(&mut self) -> u32 {
        match self.next() % 8 {
            0 => 0,
            1 => u32::MAX,
            2 => 1,
            3 => 0x8000_0000,
            4 => 0x7fff_ffff,
            5 => (self.next() & 0xff) as u32,
            6 => (self.next() & 0xffff) as u32,
            _ => self.next() as u32,
        }
    }
}

fn gen_input(rng: &mut Rng) -> HexState {
    let mut st = HexState::zeroed();
    for i in 0..NREG {
        st.w[i] = rng.interesting32();
    }
    // Each of P0..P3 is independently 0x00 or 0xff (scalar predicate values).
    let mut pred = 0u32;
    for i in 0..4 {
        if rng.next() & 1 == 1 {
            pred |= 0xffu32 << (8 * i);
        }
    }
    st.w[I_PRED] = pred;
    st.w[I_USR] = 0; // default rounding/saturation state
    st.w[I_PC] = 0;
    st
}

// ---------------------------------------------------------------------------
// Test driver.
// ---------------------------------------------------------------------------

/// Run a family: each (label, asm-packet) assembled, driven with `n_inputs`
/// random states, compared against the oracle. Self-skips if toolchain absent.
fn run_family(name: &str, cases: Vec<(String, String)>, n_inputs: usize, seed: u64) {
    let oracle = match oracle_path() {
        Some(p) => p,
        None => {
            eprintln!("[hexagon_diff] {name}: qemu-hexagon/llvm-mc/lld unavailable -> skipping");
            return;
        }
    };

    let asms: Vec<String> = cases.iter().map(|(_, a)| a.clone()).collect();
    let words_per = match assemble_packets(&asms) {
        Some(w) => w,
        None => {
            eprintln!("[hexagon_diff] {name}: llvm-mc assembly failed -> skipping");
            return;
        }
    };

    let mut rng = Rng::new(seed);
    let mut batch: Vec<(String, String, Vec<u32>, HexState)> = Vec::new();
    for ((label, asm), words) in cases.iter().zip(words_per.iter()) {
        for _ in 0..n_inputs {
            batch.push((label.clone(), asm.clone(), words.clone(), gen_input(&mut rng)));
        }
    }

    let ocases: Vec<(Vec<u32>, HexState)> =
        batch.iter().map(|(_, _, w, s)| (w.clone(), *s)).collect();
    let outs = match run_oracle(&oracle, &ocases) {
        Some(o) => o,
        None => {
            eprintln!("[hexagon_diff] {name}: oracle run failed -> skipping");
            return;
        }
    };
    assert_eq!(outs.len(), batch.len());

    let mut mismatches = Vec::new();
    for ((label, asm, words, st), out) in batch.iter().zip(outs.iter()) {
        compare_case(label, asm, words, st, out, &mut mismatches);
    }

    if !mismatches.is_empty() {
        use std::collections::BTreeMap;
        let mut by_label: BTreeMap<String, usize> = BTreeMap::new();
        for m in &mismatches {
            *by_label.entry(m.label.clone()).or_default() += 1;
        }
        eprintln!(
            "\n==== {name}: {} mismatches across {} cases ====",
            mismatches.len(),
            batch.len()
        );
        eprintln!("-- by encoding --");
        for (label, count) in &by_label {
            eprintln!("  {count:5}x  {label}");
        }
        eprintln!("-- first 25 examples --");
        for m in mismatches.iter().take(25) {
            eprintln!("  [{}] {}: {}", m.label, m.asm, m.detail);
        }
        panic!("{name}: {} divergences vs hardware oracle", mismatches.len());
    }
}

// ---------------------------------------------------------------------------
// Families.
// ---------------------------------------------------------------------------

/// Core 32-bit ALU register-register forms that rax already implements.
fn alu_rr_cases() -> Vec<(String, String)> {
    let mut v = Vec::new();
    for (name, asm) in [
        ("add", "{ r0 = add(r1,r2) }"),
        ("sub", "{ r0 = sub(r1,r2) }"),
        ("and", "{ r0 = and(r1,r2) }"),
        ("or", "{ r0 = or(r1,r2) }"),
        ("xor", "{ r0 = xor(r1,r2) }"),
        ("mpyi", "{ r0 = mpyi(r1,r2) }"),
    ] {
        v.push((name.to_string(), asm.to_string()));
    }
    v
}

#[test]
fn diff_alu_rr() {
    run_family("alu_rr", alu_rr_cases(), 30, 0x1001);
}

#[test]
fn diff_alu_imm() {
    let cases = vec![
        ("addi".to_string(), "{ r0 = add(r1,#10) }".to_string()),
        ("addi_neg".to_string(), "{ r0 = add(r1,#-7) }".to_string()),
        ("andi".to_string(), "{ r0 = and(r1,#255) }".to_string()),
    ];
    run_family("alu_imm", cases, 30, 0x1002);
}

#[test]
fn diff_cmp() {
    let cases = vec![
        ("cmpeq".to_string(), "{ p0 = cmp.eq(r1,r2) }".to_string()),
        ("cmpgt".to_string(), "{ p0 = cmp.gt(r1,r2) }".to_string()),
        ("cmpgtu".to_string(), "{ p0 = cmp.gtu(r1,r2) }".to_string()),
    ];
    run_family("cmp", cases, 30, 0x1003);
}

/// Multi-instruction VLIW packet semantics: parallel register writes (all read
/// the OLD register file), in-packet `.new` predicate forwarding, and
/// conditional (predicated) parallel execution. These exercise the foundational
/// packet commit model, not just individual instructions.
#[test]
fn diff_packets() {
    let cases = vec![
        // Parallel ALU writes commit together.
        ("par2".to_string(), "{ r0 = add(r2,r3); r1 = sub(r4,r5) }".to_string()),
        ("par3".to_string(), "{ r0 = add(r2,r3); r1 = and(r4,r5); r6 = xor(r7,r8) }".to_string()),
        // Register swap: both transfers read the OLD values.
        ("swap".to_string(), "{ r0 = r1; r1 = r0 }".to_string()),
        // Producer + consumer of the same OLD register (consumer sees old r0).
        ("readold".to_string(), "{ r0 = add(r2,r3); r1 = add(r0,r4) }".to_string()),
        // In-packet .new predicate forwarding across the predicated ALU family.
        ("dn_add_t".to_string(), "{ p0 = cmp.gt(r2,r3); if (p0.new) r0 = add(r4,r5) }".to_string()),
        ("dn_add_f".to_string(), "{ p0 = cmp.gt(r2,r3); if (!p0.new) r0 = add(r4,r5) }".to_string()),
        ("dn_addi".to_string(), "{ p0 = cmp.gt(r2,r3); if (p0.new) r0 = add(r4,#5) }".to_string()),
        ("dn_sub".to_string(), "{ p0 = cmp.gt(r2,r3); if (p0.new) r0 = sub(r4,r5) }".to_string()),
        ("dn_and".to_string(), "{ p0 = cmp.gt(r2,r3); if (p0.new) r0 = and(r4,r5) }".to_string()),
        ("dn_or".to_string(), "{ p0 = cmp.gt(r2,r3); if (!p0.new) r0 = or(r4,r5) }".to_string()),
        ("dn_xor".to_string(), "{ p0 = cmp.gt(r2,r3); if (p0.new) r0 = xor(r4,r5) }".to_string()),
        ("dn_movi".to_string(), "{ p0 = cmp.gt(r2,r3); if (p0.new) r0 = #42 }".to_string()),
        ("dn_aslh".to_string(), "{ p0 = cmp.gt(r2,r3); if (p0.new) r0 = aslh(r4) }".to_string()),
        ("dn_sxtb".to_string(), "{ p0 = cmp.gt(r2,r3); if (!p0.new) r0 = sxtb(r4) }".to_string()),
        ("dn_zxth".to_string(), "{ p0 = cmp.gt(r2,r3); if (p0.new) r0 = zxth(r4) }".to_string()),
        // Conditional parallel execution (exactly one of the two writes r0).
        ("cond_both".to_string(), "{ if (p0) r0 = r2; if (!p0) r0 = r3 }".to_string()),
        // Old-predicate condition consumed in the same packet as a compare to a
        // *different* predicate (no forwarding hazard).
        ("mixed".to_string(), "{ p1 = cmp.eq(r2,r3); r0 = add(r4,r5); r6 = sub(r7,r8) }".to_string()),
    ];
    run_family("packets", cases, 25, 0x7ac);
}

// ---------------------------------------------------------------------------
// Spec corpus survey: read tools/hexagon-diff/cases.txt (generated from the
// Hexagon spec) and categorise every register-only instruction as
//   ok        -- rax matches the oracle on all inputs,
//   diverged  -- rax executes but disagrees (an interpreter bug),
//   rejected  -- rax rejects the encoding (unimplemented / decode gap).
// Report-only (`#[ignore]`): run with `cargo test --test hexagon_diff survey
// -- --ignored --nocapture` to see the coverage worklist.
// ---------------------------------------------------------------------------

fn read_corpus() -> Vec<(String, String, Vec<u32>)> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools/hexagon-diff/cases.txt");
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for line in text.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() != 3 {
            continue;
        }
        let words: Vec<u32> = parts[2]
            .split(',')
            .filter_map(|w| u32::from_str_radix(w.trim(), 16).ok())
            .collect();
        if !words.is_empty() {
            out.push((parts[0].to_string(), parts[1].to_string(), words));
        }
    }
    out
}

#[test]
fn diff_shift_reg() {
    let cases = vec![
        ("asl_r_r".to_string(), "{ r0 = asl(r1,r2) }".to_string()),
        ("asr_r_r".to_string(), "{ r0 = asr(r1,r2) }".to_string()),
        ("lsr_r_r".to_string(), "{ r0 = lsr(r1,r2) }".to_string()),
    ];
    run_family("shift_reg", cases, 40, 0x1004);
}

/// V73 scalar register-arithmetic gap-fill: M7 complex multiplies, A7
/// clip/vclip/cround (64-bit convergent round), and the C2 conditional `.new`
/// combine. (C4_addipc is excluded: its result is `PC + #u` and the oracle's
/// link address differs from the harness's fixed CODE_ADDR, so absolute results
/// can never match — it is implemented but cannot be diff-verified here.)
fn scalar_alu_ext_cases() -> Vec<(String, String)> {
    let mut v = Vec::new();
    for (name, asm) in [
        // M7 dcmpy: 64-bit complex multiply (real/imag, conjugate, +acc).
        ("dcmpyrw", "{ r5:4 = cmpyrw(r1:0,r3:2) }"),
        ("dcmpyrwc", "{ r5:4 = cmpyrw(r1:0,r3:2*) }"),
        ("dcmpyiw", "{ r5:4 = cmpyiw(r1:0,r3:2) }"),
        ("dcmpyiwc", "{ r5:4 = cmpyiw(r1:0,r3:2*) }"),
        ("dcmpyrw_acc", "{ r5:4 += cmpyrw(r1:0,r3:2) }"),
        ("dcmpyrwc_acc", "{ r5:4 += cmpyrw(r1:0,r3:2*) }"),
        ("dcmpyiw_acc", "{ r5:4 += cmpyiw(r1:0,r3:2) }"),
        ("dcmpyiwc_acc", "{ r5:4 += cmpyiw(r1:0,r3:2*) }"),
        // M7 wcmpy: 32-bit saturating complex multiply (:<<1:sat[:rnd]).
        ("wcmpyrw", "{ r4 = cmpyrw(r1:0,r3:2):<<1:sat }"),
        ("wcmpyrwc", "{ r4 = cmpyrw(r1:0,r3:2*):<<1:sat }"),
        ("wcmpyiw", "{ r4 = cmpyiw(r1:0,r3:2):<<1:sat }"),
        ("wcmpyiwc", "{ r4 = cmpyiw(r1:0,r3:2*):<<1:sat }"),
        ("wcmpyrw_rnd", "{ r4 = cmpyrw(r1:0,r3:2):<<1:rnd:sat }"),
        ("wcmpyrwc_rnd", "{ r4 = cmpyrw(r1:0,r3:2*):<<1:rnd:sat }"),
        ("wcmpyiw_rnd", "{ r4 = cmpyiw(r1:0,r3:2):<<1:rnd:sat }"),
        ("wcmpyiwc_rnd", "{ r4 = cmpyiw(r1:0,r3:2*):<<1:rnd:sat }"),
        // A7 clip / vclip (signed (#u+1)-bit clamp).
        ("clip0", "{ r4 = clip(r5,#0) }"),
        ("clip5", "{ r4 = clip(r5,#5) }"),
        ("clip31", "{ r4 = clip(r5,#31) }"),
        ("vclip5", "{ r5:4 = vclip(r7:6,#5) }"),
        ("vclip31", "{ r5:4 = vclip(r7:6,#31) }"),
        // A7 croundd (64-bit convergent round, imm and reg shift counts).
        ("croundd_ri", "{ r5:4 = cround(r7:6,#5) }"),
        ("croundd_ri0", "{ r5:4 = cround(r7:6,#0) }"),
        ("croundd_rr", "{ r5:4 = cround(r7:6,r2) }"),
        // C2 conditional .new combine.
        ("ccombinewnewt", "{ p0 = cmp.gt(r2,r3); if (p0.new) r5:4 = combine(r6,r7) }"),
        ("ccombinewnewf", "{ p0 = cmp.gt(r2,r3); if (!p0.new) r5:4 = combine(r6,r7) }"),
    ] {
        v.push((name.to_string(), asm.to_string()));
    }
    v
}

#[test]
fn diff_scalar_alu_ext() {
    run_family("scalar_alu_ext", scalar_alu_ext_cases(), 40, 0x7373);
}

/// Per-instruction survey outcome.
#[derive(Default, Clone)]
struct Stat {
    diverged: u32,
    rejected: u32,
    example: String,
}

/// Run the whole spec corpus (N inputs per instruction) through the oracle and
/// rax, classifying each tag. Returns `None` if the toolchain/corpus is absent.
fn corpus_results(n_inputs: usize, seed: u64) -> Option<std::collections::BTreeMap<String, Stat>> {
    use std::collections::BTreeMap;
    let oracle = oracle_path()?;
    let corpus = read_corpus();
    if corpus.is_empty() {
        return None;
    }

    let mut rng = Rng::new(seed);
    let mut ocases: Vec<(Vec<u32>, HexState)> = Vec::new();
    let mut meta: Vec<usize> = Vec::new();
    for (idx, (_, _, words)) in corpus.iter().enumerate() {
        for _ in 0..n_inputs {
            let st = gen_input(&mut rng);
            ocases.push((words.clone(), st));
            meta.push(idx);
        }
    }
    let outs = run_oracle(&oracle, &ocases)?;

    let mut stats: BTreeMap<String, Stat> = BTreeMap::new();
    for (i, (words, st)) in ocases.iter().enumerate() {
        let (tag, asm, _) = &corpus[meta[i]];
        let entry = stats.entry(tag.clone()).or_default();
        match run_rax(words, st) {
            None => entry.rejected += 1,
            Some(rax) => {
                let mut diffs = Vec::new();
                for r in 0..NREG {
                    if rax.w[r] != outs[i].w[r] {
                        diffs.push(format!("r{r}:rax={:#x},hw={:#x}", rax.w[r], outs[i].w[r]));
                    }
                }
                if rax.w[I_PRED] != outs[i].w[I_PRED] {
                    diffs.push(format!("P:rax={:#x},hw={:#x}", rax.w[I_PRED], outs[i].w[I_PRED]));
                }
                if rax.w[I_USR] != outs[i].w[I_USR] {
                    diffs.push(format!("USR:rax={:#x},hw={:#x}", rax.w[I_USR], outs[i].w[I_USR]));
                }
                if !diffs.is_empty() {
                    entry.diverged += 1;
                    if entry.example.is_empty() {
                        entry.example = format!("{asm}  ->  {}", diffs.join(" "));
                    }
                }
            }
        }
    }
    Some(stats)
}

#[test]
#[ignore]
fn survey_spec_corpus() {
    let stats = match corpus_results(5, 0xC0FFEE) {
        Some(s) => s,
        None => {
            eprintln!("[hexagon_diff] survey: toolchain/corpus unavailable -> skipping");
            return;
        }
    };
    let (mut n_ok, mut n_div, mut n_rej) = (0, 0, 0);
    let mut diverged = Vec::new();
    let mut rejected = Vec::new();
    for (tag, s) in &stats {
        if s.diverged > 0 {
            n_div += 1;
            diverged.push((tag.clone(), s.example.clone()));
        } else if s.rejected > 0 {
            n_rej += 1;
            rejected.push(tag.clone());
        } else {
            n_ok += 1;
        }
    }
    eprintln!("\n==== Hexagon spec-corpus survey ({} instructions) ====", stats.len());
    eprintln!("  OK (rax == hw):       {n_ok}");
    eprintln!("  DIVERGED (rax bug):   {n_div}");
    eprintln!("  REJECTED (unimpl):    {n_rej}");
    if !diverged.is_empty() {
        eprintln!("\n-- DIVERGED (implemented but wrong) --");
        for (tag, ex) in diverged.iter().take(60) {
            eprintln!("  {tag:24}  {ex}");
        }
    }
    eprintln!("\n-- REJECTED (unimplemented), first 100 --");
    for tag in rejected.iter().take(400) {
        eprint!("{tag} ");
    }
    eprintln!();
}

/// Strict regression guard: no *implemented* instruction may diverge from the
/// hardware oracle. Unimplemented (rejected) instructions are allowed; this
/// test grows stronger automatically as coverage expands.
#[test]
fn diff_corpus_no_divergence() {
    let stats = match corpus_results(5, 0xD1FF) {
        Some(s) => s,
        None => {
            eprintln!("[hexagon_diff] corpus guard: toolchain/corpus unavailable -> skipping");
            return;
        }
    };
    let diverged: Vec<_> = stats
        .iter()
        .filter(|(_, s)| s.diverged > 0)
        .map(|(t, s)| format!("  {t:24}  {}", s.example))
        .collect();
    if !diverged.is_empty() {
        eprintln!(
            "\n==== {} implemented instructions diverge from hardware ====",
            diverged.len()
        );
        for line in &diverged {
            eprintln!("{line}");
        }
        panic!("{} Hexagon instructions diverge from the oracle", diverged.len());
    }
}
