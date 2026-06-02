//! HVX load/store differential test harness: rax vs. qemu-hexagon. Verifies HVX
//! `vmem` loads/stores against `tools/hexagon-diff/oracle_hvx_mem`, which carries
//! both the vector register file and a 128-byte-aligned memory arena
//! (`g_varena`). The test points a base GPR at the arena, runs a vmem packet on
//! the oracle and on rax's `HexagonVcpu`, and compares all V registers, GPRs and
//! the arena. Self-skips if the toolchain is unavailable.

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

const NREG: usize = 32;
const I_PRED: usize = 32;
const ST_WORDS: usize = 44;
const VREGS: usize = 32;
const VWORDS: usize = 32;
const ARENA: usize = 512;
const VOFF: usize = 256;
const AOFF: usize = VOFF + VREGS * VWORDS * 4; // 4352
const QSRC_OFF: usize = AOFF + ARENA; // 4864 (Q0..Q3 mask-source vectors)
const QSRC_VECS: usize = 4;
const IN_SIZE: usize = QSRC_OFF + QSRC_VECS * 128; // InCase carries the qsrc block
const OUT_SIZE: usize = AOFF + ARENA; // OutCase does not (Q is not captured)
const WIRE_MAGIC: u32 = 0x3158_4548;
const CODE_ADDR: u32 = 0x1000;
const BASE_REG: usize = 4; // r4 points at the arena

#[derive(Clone)]
struct Case {
    words: Vec<u32>,
    st: [u32; ST_WORDS],
    v: [[u32; VWORDS]; VREGS],
    arena: [u8; ARENA],
    /// Per-byte LSB seeds Q0..Q3 (the OLD vector predicates). Each [128] vector
    /// maps to one Q register: byte i's bit 0 = Q.bit[i].
    qsrc: [[u8; 128]; QSRC_VECS],
}

#[derive(Clone)]
struct Out {
    st: [u32; ST_WORDS],
    v: [[u32; VWORDS]; VREGS],
    arena: [u8; ARENA],
}

fn which(prog: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|d| d.join(prog)).find(|c| c.is_file())
}

/// Build oracle_hvx_mem; return (path, g_varena address).
fn oracle() -> Option<(PathBuf, u32)> {
    which("qemu-hexagon")?;
    which("llvm-mc")?;
    which("ld.lld")?;
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools/hexagon-diff");
    let bin = dir.join("oracle_hvx_mem");
    let src = dir.join("gen_oracle_hvx_mem.py");
    let need = match (bin.metadata(), src.metadata()) {
        (Ok(b), Ok(s)) => match (b.modified(), s.modified()) {
            (Ok(bm), Ok(sm)) => bm < sm,
            _ => true,
        },
        _ => true,
    };
    if need {
        let ok = Command::new("bash")
            .arg(dir.join("build_hvx_mem.sh"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            return None;
        }
    }
    let nm = which("llvm-nm").map(|_| "llvm-nm").or(which("nm").map(|_| "nm"))?;
    let out = Command::new(nm).arg(&bin).output().ok()?;
    let addr = String::from_utf8_lossy(&out.stdout).lines().find_map(|l| {
        let mut it = l.split_whitespace();
        let a = it.next()?;
        let _t = it.next()?;
        (it.next() == Some("g_varena")).then(|| u32::from_str_radix(a, 16).ok())?
    })?;
    Some((bin, addr))
}

fn run_oracle(bin: &PathBuf, cases: &[Case]) -> Option<Vec<Out>> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&WIRE_MAGIC.to_le_bytes());
    payload.extend_from_slice(&(cases.len() as u32).to_le_bytes());
    for c in cases {
        let mut buf = vec![0u8; IN_SIZE];
        buf[0..4].copy_from_slice(&(c.words.len().min(4) as u32).to_le_bytes());
        for i in 0..4 {
            let w = c.words.get(i).copied().unwrap_or(0);
            buf[4 + i * 4..8 + i * 4].copy_from_slice(&w.to_le_bytes());
        }
        for k in 0..ST_WORDS {
            buf[20 + k * 4..24 + k * 4].copy_from_slice(&c.st[k].to_le_bytes());
        }
        for r in 0..VREGS {
            for w in 0..VWORDS {
                let o = VOFF + (r * VWORDS + w) * 4;
                buf[o..o + 4].copy_from_slice(&c.v[r][w].to_le_bytes());
            }
        }
        buf[AOFF..AOFF + ARENA].copy_from_slice(&c.arena);
        for k in 0..QSRC_VECS {
            let o = QSRC_OFF + k * 128;
            buf[o..o + 128].copy_from_slice(&c.qsrc[k]);
        }
        payload.extend_from_slice(&buf);
    }
    let mut child = Command::new("qemu-hexagon")
        .arg(bin)
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
    let count = u32::from_le_bytes([out[4], out[5], out[6], out[7]]) as usize;
    if count != cases.len() {
        return None;
    }
    let mut res = Vec::with_capacity(count);
    let mut off = 8;
    for _ in 0..count {
        let mut st = [0u32; ST_WORDS];
        for k in 0..ST_WORDS {
            st[k] = u32::from_le_bytes([
                out[off + 4 * k],
                out[off + 4 * k + 1],
                out[off + 4 * k + 2],
                out[off + 4 * k + 3],
            ]);
        }
        let mut v = [[0u32; VWORDS]; VREGS];
        for r in 0..VREGS {
            for w in 0..VWORDS {
                let o = off + VOFF + (r * VWORDS + w) * 4;
                v[r][w] = u32::from_le_bytes([out[o], out[o + 1], out[o + 2], out[o + 3]]);
            }
        }
        let mut arena = [0u8; ARENA];
        arena.copy_from_slice(&out[off + AOFF..off + AOFF + ARENA]);
        off += OUT_SIZE;
        res.push(Out { st, v, arena });
    }
    Some(res)
}

fn assemble(packets: &[String]) -> Option<Vec<Vec<u32>>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Vec<Vec<u32>>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let key = packets.join("\n@@@\n");
    if let Some(v) = cache.lock().unwrap().get(&key) {
        return Some(v.clone());
    }
    let mut child = Command::new("llvm-mc")
        .args(["-triple=hexagon", "-mcpu=hexagonv68", "-mhvx", "-show-encoding"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.take().unwrap().write_all(packets.join("\n").as_bytes()).ok()?;
    let mut out = String::new();
    child.stdout.take().unwrap().read_to_string(&mut out).ok()?;
    if !child.wait().ok()?.success() {
        return None;
    }
    let mut bytes = Vec::new();
    for line in out.lines() {
        if let Some(i) = line.find("encoding: [") {
            let rest = &line[i + 11..];
            let end = rest.find(']')?;
            for t in rest[..end].split(',') {
                let t = t.trim().strip_prefix("0x").unwrap_or(t.trim());
                if let Ok(b) = u8::from_str_radix(t, 16) {
                    bytes.push(b);
                }
            }
        }
    }
    let mut grouped = Vec::new();
    let mut cur = Vec::new();
    let mut acc = Vec::new();
    for b in bytes {
        acc.push(b);
        if acc.len() == 4 {
            let w = acc[0] as u32 | (acc[1] as u32) << 8 | (acc[2] as u32) << 16 | (acc[3] as u32) << 24;
            acc.clear();
            cur.push(w);
            let pb = (w >> 14) & 3;
            if pb == 0b11 || pb == 0b00 {
                grouped.push(std::mem::take(&mut cur));
            }
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
    *W.get_or_init(|| assemble(&["{ trap0(#0) }".to_string()]).expect("trap0")[0][0])
}

fn run_rax(words: &[u32], c: &Case, varena: u32) -> Option<Out> {
    let regions = vec![(GuestAddress(0), 0x20_0000usize)];
    let mem = Arc::new(GuestMemoryMmap::<()>::from_ranges(&regions).ok()?);
    let mut off = CODE_ADDR;
    for &w in words {
        mem.write_slice(&w.to_le_bytes(), GuestAddress(off as u64)).ok()?;
        off += 4;
    }
    mem.write_slice(&trap0_word().to_le_bytes(), GuestAddress(off as u64)).ok()?;
    mem.write_slice(&c.arena, GuestAddress(varena as u64)).ok()?;

    let mut regs = HexagonRegisters::default();
    for i in 0..NREG {
        regs.r[i] = c.st[i];
    }
    for i in 0..4 {
        regs.p[i] = ((c.st[I_PRED] >> (8 * i)) & 0xff) as u8;
    }
    regs.v = c.v;
    // OLD vector predicates Q0..Q3 from the per-byte LSB of the source vectors
    // (matching the oracle's vandvrt seeding).
    for k in 0..QSRC_VECS {
        let mut q = [0u32; 4];
        for i in 0..128 {
            if c.qsrc[k][i] & 1 == 1 {
                q[i / 32] |= 1u32 << (i % 32);
            }
        }
        regs.q[k] = q;
    }
    regs.set_pc(CODE_ADDR);

    let mut vcpu = HexagonVcpu::new(0, mem.clone(), HexagonIsa::V68, Endianness::Little);
    vcpu.set_state(&CpuState::hexagon(regs)).ok()?;
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
    let regs = match vcpu.get_state().ok()? {
        CpuState::Hexagon(s) => s.regs,
        _ => return None,
    };
    let mut st = [0u32; ST_WORDS];
    for i in 0..NREG {
        st[i] = regs.r[i];
    }
    let mut arena = [0u8; ARENA];
    mem.read_slice(&mut arena, GuestAddress(varena as u64)).ok()?;
    Some(Out { st, v: regs.v, arena })
}

struct Rng(u64);
impl Rng {
    fn new(s: u64) -> Self {
        Rng(s ^ 0x9e37_79b9_7f4a_7c15)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

fn run_family(name: &str, cases: &[(&str, &str)], n: usize, seed: u64) {
    run_family_q(name, cases, n, seed, false);
}

/// As `run_family`, but when `qsrc_random` is set the OLD vector predicates
/// Q0..Q3 are seeded from random per-byte LSBs (wired into the oracle via
/// `vandvrt` and into rax via `regs.q`). Used to verify Q-masked vmem stores
/// that read the architectural (OLD) Q rather than an in-packet `.new` Q.
fn run_family_q(name: &str, cases: &[(&str, &str)], n: usize, seed: u64, qsrc_random: bool) {
    let (bin, varena) = match oracle() {
        Some(x) => x,
        None => {
            eprintln!("[hexagon_hvx_mem_diff] {name}: toolchain unavailable -> skipping");
            return;
        }
    };
    let asms: Vec<String> = cases.iter().map(|(_, a)| a.to_string()).collect();
    let words_per = match assemble(&asms) {
        Some(w) => w,
        None => {
            eprintln!("[hexagon_hvx_mem_diff] {name}: assembly failed -> skipping");
            return;
        }
    };
    let mut rng = Rng::new(seed);
    let mut batch = Vec::new();
    let mut labels = Vec::new();
    for ((label, _), words) in cases.iter().zip(words_per.iter()) {
        for _ in 0..n {
            let mut st = [0u32; ST_WORDS];
            for r in 0..NREG {
                st[r] = rng.next() as u32;
            }
            st[BASE_REG] = varena; // base points at the (128-aligned) arena
            // Each scalar predicate P0..P3 independently 0x00 / 0xff.
            let mut pred = 0u32;
            for k in 0..4 {
                if rng.next() & 1 == 1 {
                    pred |= 0xffu32 << (8 * k);
                }
            }
            st[I_PRED] = pred;
            let mut v = [[0u32; VWORDS]; VREGS];
            for r in 0..VREGS {
                for w in 0..VWORDS {
                    v[r][w] = rng.next() as u32;
                }
            }
            let mut arena = [0u8; ARENA];
            for b in arena.iter_mut() {
                *b = rng.next() as u8;
            }
            let mut qsrc = [[0u8; 128]; QSRC_VECS];
            if qsrc_random {
                for q in qsrc.iter_mut() {
                    for b in q.iter_mut() {
                        *b = rng.next() as u8;
                    }
                }
            }
            labels.push(*label);
            batch.push(Case { words: words.clone(), st, v, arena, qsrc });
        }
    }
    let outs = match run_oracle(&bin, &batch) {
        Some(o) => o,
        None => {
            eprintln!("[hexagon_hvx_mem_diff] {name}: oracle failed -> skipping");
            return;
        }
    };
    let mut mismatches = Vec::new();
    for (i, c) in batch.iter().enumerate() {
        let rax = match run_rax(&c.words, c, varena) {
            Some(r) => r,
            None => {
                mismatches.push(format!("[{}] rax rejected", labels[i]));
                continue;
            }
        };
        let mut diffs = Vec::new();
        for vr in 0..VREGS {
            if rax.v[vr] != outs[i].v[vr] {
                let w = (0..VWORDS).find(|&w| rax.v[vr][w] != outs[i].v[vr][w]).unwrap();
                diffs.push(format!("v{vr}.w[{w}]:rax={:#x},hw={:#x}", rax.v[vr][w], outs[i].v[vr][w]));
                break;
            }
        }
        if rax.arena != outs[i].arena {
            let j = (0..ARENA).find(|&j| rax.arena[j] != outs[i].arena[j]).unwrap();
            diffs.push(format!("arena[{j}]:rax={:#x},hw={:#x}", rax.arena[j], outs[i].arena[j]));
        }
        for r in 0..NREG {
            if rax.st[r] != outs[i].st[r] {
                diffs.push(format!("r{r}:rax={:#x},hw={:#x}", rax.st[r], outs[i].st[r]));
            }
        }
        if !diffs.is_empty() {
            mismatches.push(format!("[{}] {}", labels[i], diffs.join(" ")));
        }
    }
    if !mismatches.is_empty() {
        eprintln!("\n==== {name}: {} mismatches ====", mismatches.len());
        for m in mismatches.iter().take(20) {
            eprintln!("  {m}");
        }
        panic!("{name}: {} HVX-mem divergences vs oracle", mismatches.len());
    }
}

#[test]
fn diff_hvx_load() {
    // base r4 = g_varena (128-aligned); offsets in vector units stay in arena.
    run_family(
        "hvx_load",
        &[
            ("vL32b_ai_0", "{ v0 = vmem(r4+#0) }"),
            ("vL32b_ai_1", "{ v0 = vmem(r4+#1) }"),
            ("vL32b_nt", "{ v0 = vmem(r4+#2):nt }"),
            ("vL32Ub", "{ v0 = vmemu(r4+#0) }"),
            ("vL32b_cur", "{ v0.cur = vmem(r4+#1) }"),
            ("vL32b_tmp", "{ v0.tmp = vmem(r4+#2) }"),
        ],
        8,
        0xa10,
    );
}

#[test]
fn diff_hvx_store() {
    run_family(
        "hvx_store",
        &[
            ("vS32b_ai_0", "{ vmem(r4+#0) = v1 }"),
            ("vS32b_ai_1", "{ vmem(r4+#1) = v2 }"),
            ("vS32b_nt", "{ vmem(r4+#2):nt = v3 }"),
            ("vS32Ub", "{ vmemu(r4+#3) = v4 }"),
        ],
        8,
        0xa20,
    );
}

#[test]
fn diff_hvx_store_pred() {
    // Scalar-predicated vector stores: if (p0[!]) vmem(...) = Vs (or CANCEL).
    run_family(
        "hvx_store_pred",
        &[
            ("vS32b_pred", "{ if (p0) vmem(r4+#0) = v1 }"),
            ("vS32b_npred", "{ if (!p0) vmem(r4+#1) = v2 }"),
            ("vS32b_pred_pi", "{ if (p0) vmem(r4++#1) = v1 }"),
            ("vS32b_npred_pi", "{ if (!p0) vmem(r4++#1) = v2 }"),
        ],
        12,
        0xa40,
    );
}

#[test]
fn diff_hvx_store_qmask() {
    // Byte-masked vector stores read the ARCHITECTURAL (OLD) vector predicate Q,
    // not an in-packet `.new` Q. We seed Q0..Q3 from random per-byte LSBs (the
    // `qsrc` block) on both the oracle (via vandvrt) and rax, then byte-mask the
    // store of Vs: lanes where Q==sense are written, the rest keep memory.
    run_family_q(
        "hvx_store_qmask",
        &[
            ("vS32b_qpred", "{ if (q0) vmem(r4+#0) = v1 }"),
            ("vS32b_nqpred", "{ if (!q0) vmem(r4+#1) = v2 }"),
            ("vS32b_qpred_q1", "{ if (q1) vmem(r4+#2) = v3 }"),
            ("vS32b_qpred_pi", "{ if (q2) vmem(r4++#1) = v4 }"),
            ("vS32b_nqpred_pi", "{ if (!q3) vmem(r4++#1) = v5 }"),
        ],
        12,
        0xa50,
        true,
    );
}

#[test]
fn diff_hvx_load_pi() {
    // post-increment: r4 advances by one vector (128 bytes).
    run_family(
        "hvx_load_pi",
        &[
            ("vL32b_pi", "{ v0 = vmem(r4++#1) }"),
            ("vS32b_pi", "{ vmem(r4++#1) = v1 }"),
        ],
        8,
        0xa30,
    );
}

#[test]
fn diff_hvx_hist() {
    // HVX histogram family. The input is a `.tmp` vector load that MUST live in
    // the same packet as the histogram op (qemu asserts exactly one `.tmp` load;
    // a bare `{ vhist }` faults). We load V0.tmp from the 128-aligned arena (r4),
    // which rax forwards into its per-packet scratch buffer (matching qemu's
    // tmp_VRegs[0]); the op then tallies those bytes into bins spread across the
    // register file. The Qv-gated forms read the OLD architectural Q, seeded via
    // the `qsrc` block on both the oracle (vandvrt) and rax — so `run_family_q`.
    run_family_q(
        "hvx_hist",
        &[
            ("vhist", "{ v0.tmp = vmem(r4+#0); vhist }"),
            ("vhistq", "{ v0.tmp = vmem(r4+#0); vhist(q0) }"),
            ("vwhist128", "{ v0.tmp = vmem(r4+#0); vwhist128 }"),
            ("vwhist128m", "{ v0.tmp = vmem(r4+#0); vwhist128(#1) }"),
            ("vwhist128q", "{ v0.tmp = vmem(r4+#0); vwhist128(q0) }"),
            ("vwhist128qm", "{ v0.tmp = vmem(r4+#0); vwhist128(q0,#1) }"),
            ("vwhist256", "{ v0.tmp = vmem(r4+#0); vwhist256 }"),
            ("vwhist256_sat", "{ v0.tmp = vmem(r4+#0); vwhist256:sat }"),
            ("vwhist256q", "{ v0.tmp = vmem(r4+#0); vwhist256(q0) }"),
            ("vwhist256q_sat", "{ v0.tmp = vmem(r4+#0); vwhist256(q0):sat }"),
        ],
        8,
        0x4157,
        true,
    );
}
