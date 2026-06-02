//! Hexagon floating-point differential test harness: rax vs. QEMU oracle.
//!
//! Modeled on `tests/hexagon_diff.rs`, but specialised for the float (`F2_*`)
//! arithmetic instructions. The shared register-only corpus feeds RANDOM bit
//! patterns into operand registers, which for floating-point ops means the
//! inputs are almost always NaN/inf — useless for verifying the finite
//! arithmetic, rounding, and USR exception-flag behavior that is the whole
//! point of the float frontier.
//!
//! Instead we drive a curated table of CLEAN finite f32/f64 values (0, ±1, ±2,
//! ±0.5, small integers, fractions, a few values whose products/sums are
//! inexact so the inexact/overflow/underflow flags get exercised) into the
//! operand registers. Each pair (or triple, for FMA) is packed into the GPRs,
//! the packet runs on BOTH the oracle and the rax `HexagonVcpu`, and we compare
//! the result register(s) AND the USR FP exception flags bit-for-bit.
//!
//! Self-skips (stays green) if `qemu-hexagon`, `llvm-mc`, or `ld.lld` are
//! unavailable, exactly like the sibling harnesses.

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
// Wire format -- identical to tools/hexagon-diff/gen_oracle.py (reg-only).
// HexState is 44 little-endian u32 (176 bytes).
// ---------------------------------------------------------------------------

const NREG: usize = 32;
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
const ST_WORDS: usize = 44;

const WIRE_MAGIC: u32 = 0x3158_4548; // 'H','E','X','1'

// USR FP sticky exception bits (only these are produced by the float ops; the
// rounding-mode and other USR bits stay 0 across these tests).
const USR_FP_MASK: u32 = 0b11_1110; // bits 1..5: invalid/divz/ovf/unf/inexact

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
        off += 176 + 8; // skip trapped(4) + valid(4)
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

fn assemble_packets(packets: &[String]) -> Option<Vec<Vec<u32>>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Vec<Vec<u32>>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let key = packets.join("\n@@@\n");
    if let Some(v) = cache.lock().unwrap().get(&key) {
        return Some(v.clone());
    }

    let src = packets.join("\n");
    let mut child = Command::new("llvm-mc")
        .args(["-triple=hexagon", "-mcpu=hexagonv68", "-show-encoding"])
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
        return None;
    }
    cache.lock().unwrap().insert(key, grouped.clone());
    Some(grouped)
}

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

fn run_rax(words: &[u32], st: &HexState) -> Option<HexState> {
    let regions = vec![(GuestAddress(0), 0x10000usize)];
    let mem = Arc::new(GuestMemoryMmap::<()>::from_ranges(&regions).ok()?);

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
            Ok(_) => return None,
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
    let mut pred = 0u32;
    for i in 0..4 {
        pred |= (regs.p[i] as u32) << (8 * i);
    }
    out.w[I_PRED] = pred;
    out.w[I_USR] = regs.c[8];
    Some(out)
}

// ---------------------------------------------------------------------------
// Operand tables.
//
// Mostly clean finite values whose sums/products are exact, plus values that
// force inexact / overflow / underflow, plus the IEEE special values (±0, ±inf,
// denormals, quiet & signaling NaNs). Mixing the specials in means the NaN/inf
// canonicalisation and the invalid-flag paths get differentially checked too,
// not just the finite arithmetic + rounding flags.
// ---------------------------------------------------------------------------

/// f32 bit patterns.
fn f32_values() -> Vec<u32> {
    let mut v: Vec<u32> = [
        0.0_f32, -0.0, 1.0, -1.0, 2.0, -2.0, 0.5, -0.5, 3.0, -2.5, 4.0, 0.25, 100.0, -100.0, 1.5,
        0.125, 8.0, 16.0, 1000.0, -7.0, 10.0, 0.1, // 0.1 is inexact in binary -> exercises inexact
        3.141_592_7, 1e30, 1e-30, 1e38, // big/tiny -> overflow/underflow on mul/add
    ]
    .iter()
    .map(|f| f.to_bits())
    .collect();
    // IEEE special bit patterns.
    v.extend_from_slice(&[
        0x7f80_0000, // +inf
        0xff80_0000, // -inf
        0x0000_0001, // smallest +denormal
        0x8000_0001, // smallest -denormal
        0x007f_ffff, // largest +denormal
        0x7fc0_0000, // canonical qNaN
        0x7fa0_0000, // sNaN (top mantissa bit clear)
    ]);
    v
}

/// f64 bit patterns, analogous to the f32 table.
fn f64_values() -> Vec<u64> {
    let mut v: Vec<u64> = [
        0.0_f64, -0.0, 1.0, -1.0, 2.0, -2.0, 0.5, -0.5, 3.0, -2.5, 4.0, 0.25, 100.0, -100.0, 1.5,
        0.125, 8.0, 16.0, 1000.0, -7.0, 10.0, 0.1, 3.141_592_653_589_793, 1e300, 1e-300, 1e308,
    ]
    .iter()
    .map(|f| f.to_bits())
    .collect();
    v.extend_from_slice(&[
        0x7ff0_0000_0000_0000, // +inf
        0xfff0_0000_0000_0000, // -inf
        0x0000_0000_0000_0001, // smallest +denormal
        0x8000_0000_0000_0001, // smallest -denormal
        0x000f_ffff_ffff_ffff, // largest +denormal
        0x7ff8_0000_0000_0000, // canonical qNaN
        0x7ff4_0000_0000_0000, // sNaN (top mantissa bit clear)
    ]);
    v
}

// ---------------------------------------------------------------------------
// Mismatch tracking.
// ---------------------------------------------------------------------------

struct Mismatch {
    label: String,
    asm: String,
    detail: String,
}

/// Compare `out_regs` plus the USR FP exception bits.
fn compare(
    label: &str,
    asm: &str,
    out_regs: &[usize],
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
    for &r in out_regs {
        if rax.w[r] != oracle.w[r] {
            diffs.push(format!("r{r}: rax={:#010x} hw={:#010x}", rax.w[r], oracle.w[r]));
        }
    }
    let rax_fp = rax.w[I_USR] & USR_FP_MASK;
    let hw_fp = oracle.w[I_USR] & USR_FP_MASK;
    if rax_fp != hw_fp {
        diffs.push(format!("USR(fp): rax={rax_fp:#04x} hw={hw_fp:#04x}"));
    }
    if !diffs.is_empty() {
        mismatches.push(Mismatch {
            label: label.into(),
            asm: asm.into(),
            detail: format!("in[{}] {}", fmt_in(input, out_regs), diffs.join("  |  ")),
        });
    }
}

fn fmt_in(st: &HexState, _out: &[usize]) -> String {
    // Dump the few low registers that carry operands (r0..r9 cover all our
    // single/double/triple-operand encodings).
    let mut s = String::new();
    for i in 0..10 {
        s.push_str(&format!("r{i}={:#010x} ", st.w[i]));
    }
    s
}

fn report_and_panic(name: &str, batch_len: usize, mismatches: Vec<Mismatch>) {
    if mismatches.is_empty() {
        return;
    }
    use std::collections::BTreeMap;
    let mut by_label: BTreeMap<String, usize> = BTreeMap::new();
    for m in &mismatches {
        *by_label.entry(m.label.clone()).or_default() += 1;
    }
    eprintln!(
        "\n==== {name}: {} mismatches across {} cases ====",
        mismatches.len(),
        batch_len
    );
    eprintln!("-- by encoding --");
    for (label, count) in &by_label {
        eprintln!("  {count:5}x  {label}");
    }
    eprintln!("-- first 30 examples --");
    for m in mismatches.iter().take(30) {
        eprintln!("  [{}] {}: {}", m.label, m.asm, m.detail);
    }
    panic!("{name}: {} divergences vs hardware oracle", mismatches.len());
}

// ---------------------------------------------------------------------------
// Test families.
// ---------------------------------------------------------------------------

/// f32 binary op `Rd = op(Rs, Rt)` driven with every clean (Rs, Rt) pair.
/// Operands go in r2 (Rs) and r3 (Rt); result in r1 (Rd).
fn run_sf_binary(name: &str, asm: &str) {
    let oracle = match oracle_path() {
        Some(p) => p,
        None => {
            eprintln!("[hexagon_float_diff] {name}: toolchain unavailable -> skipping");
            return;
        }
    };
    let words = match assemble_packets(&[asm.to_string()]) {
        Some(w) => w.into_iter().next().unwrap(),
        None => {
            eprintln!("[hexagon_float_diff] {name}: assembly failed -> skipping");
            return;
        }
    };
    let vals = f32_values();
    let mut cases: Vec<(Vec<u32>, HexState)> = Vec::new();
    for &a in &vals {
        for &b in &vals {
            let mut st = HexState::zeroed();
            st.w[2] = a;
            st.w[3] = b;
            cases.push((words.clone(), st));
        }
    }
    let outs = match run_oracle(&oracle, &cases) {
        Some(o) => o,
        None => {
            eprintln!("[hexagon_float_diff] {name}: oracle run failed -> skipping");
            return;
        }
    };
    let mut mismatches = Vec::new();
    for ((w, st), out) in cases.iter().zip(outs.iter()) {
        compare(name, asm, &[1], w, st, out, &mut mismatches);
    }
    let n = cases.len();
    report_and_panic(name, n, mismatches);
}

/// f32 FMA `Rx op= sfmpy(Rs, Rt)` driven with clean (Rx, Rs, Rt) triples.
/// Rx in r1 (read-modify, also the result), Rs in r2, Rt in r3. To keep the
/// case count manageable we sample a smaller accumulator set against all (s,t).
fn run_sf_fma(name: &str, asm: &str) {
    let oracle = match oracle_path() {
        Some(p) => p,
        None => {
            eprintln!("[hexagon_float_diff] {name}: toolchain unavailable -> skipping");
            return;
        }
    };
    let words = match assemble_packets(&[asm.to_string()]) {
        Some(w) => w.into_iter().next().unwrap(),
        None => {
            eprintln!("[hexagon_float_diff] {name}: assembly failed -> skipping");
            return;
        }
    };
    let vals = f32_values();
    // Accumulator subset (indices into vals): 0,1,2,3,8,9,21,22 covers zero,
    // ±1, ±2, 3, -2.5, 0.1, pi.
    let acc_idx = [0usize, 1, 2, 3, 8, 9, 21, 22];
    let mut cases: Vec<(Vec<u32>, HexState)> = Vec::new();
    for &xi in &acc_idx {
        let x = vals[xi];
        for &a in &vals {
            for &b in &vals {
                let mut st = HexState::zeroed();
                st.w[1] = x;
                st.w[2] = a;
                st.w[3] = b;
                cases.push((words.clone(), st));
            }
        }
    }
    let outs = match run_oracle(&oracle, &cases) {
        Some(o) => o,
        None => {
            eprintln!("[hexagon_float_diff] {name}: oracle run failed -> skipping");
            return;
        }
    };
    let mut mismatches = Vec::new();
    for ((w, st), out) in cases.iter().zip(outs.iter()) {
        compare(name, asm, &[1], w, st, out, &mut mismatches);
    }
    let n = cases.len();
    report_and_panic(name, n, mismatches);
}

/// f64 binary op `Rdd = op(Rss, Rtt)`. Rss = r3:r2, Rtt = r5:r4, Rdd = r1:r0.
fn run_df_binary(name: &str, asm: &str) {
    let oracle = match oracle_path() {
        Some(p) => p,
        None => {
            eprintln!("[hexagon_float_diff] {name}: toolchain unavailable -> skipping");
            return;
        }
    };
    let words = match assemble_packets(&[asm.to_string()]) {
        Some(w) => w.into_iter().next().unwrap(),
        None => {
            eprintln!("[hexagon_float_diff] {name}: assembly failed -> skipping");
            return;
        }
    };
    let vals = f64_values();
    let mut cases: Vec<(Vec<u32>, HexState)> = Vec::new();
    for &a in &vals {
        for &b in &vals {
            let mut st = HexState::zeroed();
            st.w[2] = a as u32;
            st.w[3] = (a >> 32) as u32;
            st.w[4] = b as u32;
            st.w[5] = (b >> 32) as u32;
            cases.push((words.clone(), st));
        }
    }
    let outs = match run_oracle(&oracle, &cases) {
        Some(o) => o,
        None => {
            eprintln!("[hexagon_float_diff] {name}: oracle run failed -> skipping");
            return;
        }
    };
    let mut mismatches = Vec::new();
    for ((w, st), out) in cases.iter().zip(outs.iter()) {
        compare(name, asm, &[0, 1], w, st, out, &mut mismatches);
    }
    let n = cases.len();
    report_and_panic(name, n, mismatches);
}

/// f64 multiply-fixup family: pure bit-pattern ops with no rounding/flags.
/// Rss = r3:r2, Rtt = r5:r4, Rdd = r1:r0.
fn run_df_mpy_fix(name: &str, asm: &str) {
    run_df_binary(name, asm);
}

/// dfmpyll / dfmpylh accumulate forms.  dfmpyll: Rdd = dfmpyll(Rss,Rtt).
/// dfmpylh: Rxx += dfmpylh(Rss,Rtt). Use r1:r0 as Rxx/Rdd, r3:r2 = Rss,
/// r5:r4 = Rtt. For the accumulate form we also seed r1:r0.
fn run_df_mpyll_lh(name: &str, asm: &str, accumulate: bool) {
    let oracle = match oracle_path() {
        Some(p) => p,
        None => {
            eprintln!("[hexagon_float_diff] {name}: toolchain unavailable -> skipping");
            return;
        }
    };
    let words = match assemble_packets(&[asm.to_string()]) {
        Some(w) => w.into_iter().next().unwrap(),
        None => {
            eprintln!("[hexagon_float_diff] {name}: assembly failed -> skipping");
            return;
        }
    };
    let vals = f64_values();
    let mut cases: Vec<(Vec<u32>, HexState)> = Vec::new();
    for &a in &vals {
        for &b in &vals {
            let mut st = HexState::zeroed();
            if accumulate {
                // a small accumulator (use the integer 1<<40 to keep it simple)
                st.w[0] = 0x0000_0000;
                st.w[1] = 0x0000_0100;
            }
            st.w[2] = a as u32;
            st.w[3] = (a >> 32) as u32;
            st.w[4] = b as u32;
            st.w[5] = (b >> 32) as u32;
            cases.push((words.clone(), st));
        }
    }
    let outs = match run_oracle(&oracle, &cases) {
        Some(o) => o,
        None => {
            eprintln!("[hexagon_float_diff] {name}: oracle run failed -> skipping");
            return;
        }
    };
    let mut mismatches = Vec::new();
    for ((w, st), out) in cases.iter().zip(outs.iter()) {
        compare(name, asm, &[0, 1], w, st, out, &mut mismatches);
    }
    let n = cases.len();
    report_and_panic(name, n, mismatches);
}

/// dfmpyhh accumulate form: Rxx = dfmpyhh(Rss,Rtt,Rxx). Rxx=r1:0 (also the
/// result), Rss=r3:2, Rtt=r5:4. Because dfmpyhh adds the 64-bit accumulator into
/// the product significand at a fixed sub-ULP weight, we test every (Rss,Rtt)
/// pair against a curated set of accumulators spanning the fold positions (zero,
/// a single low bit, the round/sticky boundary, the high partial-product weight,
/// and all-ones) so the rounding and inexact-flag paths are differentially
/// checked.
fn run_df_mpyhh(name: &str, asm: &str) {
    let oracle = match oracle_path() {
        Some(p) => p,
        None => {
            eprintln!("[hexagon_float_diff] {name}: toolchain unavailable -> skipping");
            return;
        }
    };
    let words = match assemble_packets(&[asm.to_string()]) {
        Some(w) => w.into_iter().next().unwrap(),
        None => {
            eprintln!("[hexagon_float_diff] {name}: assembly failed -> skipping");
            return;
        }
    };
    let vals = f64_values();
    // Accumulators covering: nothing, lone low bit, a value entirely below the
    // round bit, the round/sticky boundary, the high partial weight, all-ones.
    let accs: [u64; 6] = [
        0,
        0x0000_0001_0000_0000,
        0x0000_000f_ffff_ffff,
        0x0080_0000_0000_0000,
        0xdead_beef_cafe_0000,
        0xffff_ffff_ffff_ffff,
    ];
    let mut cases: Vec<(Vec<u32>, HexState)> = Vec::new();
    for &a in &vals {
        for &b in &vals {
            for &acc in &accs {
                let mut st = HexState::zeroed();
                st.w[0] = acc as u32;
                st.w[1] = (acc >> 32) as u32;
                st.w[2] = a as u32;
                st.w[3] = (a >> 32) as u32;
                st.w[4] = b as u32;
                st.w[5] = (b >> 32) as u32;
                cases.push((words.clone(), st));
            }
        }
    }
    let outs = match run_oracle(&oracle, &cases) {
        Some(o) => o,
        None => {
            eprintln!("[hexagon_float_diff] {name}: oracle run failed -> skipping");
            return;
        }
    };
    let mut mismatches = Vec::new();
    for ((w, st), out) in cases.iter().zip(outs.iter()) {
        compare(name, asm, &[0, 1], w, st, out, &mut mismatches);
    }
    let n = cases.len();
    report_and_panic(name, n, mismatches);
}

// ---- single precision ----

#[test]
fn diff_sfadd() {
    run_sf_binary("sfadd", "{ r1 = sfadd(r2,r3) }");
}

#[test]
fn diff_sfsub() {
    run_sf_binary("sfsub", "{ r1 = sfsub(r2,r3) }");
}

#[test]
fn diff_sfmpy() {
    run_sf_binary("sfmpy", "{ r1 = sfmpy(r2,r3) }");
}

#[test]
fn diff_sffma() {
    run_sf_fma("sffma", "{ r1 += sfmpy(r2,r3) }");
}

#[test]
fn diff_sffms() {
    run_sf_fma("sffms", "{ r1 -= sfmpy(r2,r3) }");
}

// ---- double precision ----

#[test]
fn diff_dfadd() {
    run_df_binary("dfadd", "{ r1:0 = dfadd(r3:2,r5:4) }");
}

#[test]
fn diff_dfsub() {
    run_df_binary("dfsub", "{ r1:0 = dfsub(r3:2,r5:4) }");
}

#[test]
fn diff_dfmpyfix() {
    run_df_mpy_fix("dfmpyfix", "{ r1:0 = dfmpyfix(r3:2,r5:4) }");
}

#[test]
fn diff_dfmpyll() {
    run_df_mpyll_lh("dfmpyll", "{ r1:0 = dfmpyll(r3:2,r5:4) }", false);
}

#[test]
fn diff_dfmpylh() {
    run_df_mpyll_lh("dfmpylh", "{ r1:0 += dfmpylh(r3:2,r5:4) }", true);
}

#[test]
fn diff_dfmpyhh() {
    // dfmpyhh is the high-half step of the f64 multiply: Rxx = dfmpyhh(Rss,Rtt,Rxx).
    // Unlike ll/lh it is a true IEEE op (rounds, raises USR flags, flushes
    // subnormal inputs), so it needs the accumulator seeded across a range of
    // bit-weights to exercise the rounding boundary. We drive every (Rss,Rtt)
    // pair against a small set of accumulators that cover the acc fold positions.
    run_df_mpyhh("dfmpyhh", "{ r1:0 += dfmpyhh(r3:2,r5:4) }");
}
