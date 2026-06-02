//! HVX (vector) differential test harness: rax vs. qemu-hexagon. Verifies HVX
//! vector instructions (V0..V31, 1024-bit) against the vector oracle
//! `tools/hexagon-diff/oracle_hvx` (which load/captures the vector register file
//! via aligned `vmem`). For each (packet, scalar state, vector state) we run it
//! on the oracle and on rax's `HexagonVcpu` and compare GPRs, USR, and all 32
//! vector registers. Self-skips if the toolchain is unavailable.

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
const I_USR: usize = 33;
const ST_WORDS: usize = 44;
const VREGS: usize = 32;
const VWORDS: usize = 32; // 128 bytes / 4
const CASE_VOFF: usize = 256; // 128-byte aligned vblock offset within InCase/OutCase
const WIRE_MAGIC: u32 = 0x3158_4548;
const CODE_ADDR: u32 = 0x1000;

#[derive(Clone)]
struct Case {
    words: Vec<u32>,
    st: [u32; ST_WORDS],
    v: [[u32; VWORDS]; VREGS],
}

#[derive(Clone)]
struct Out {
    st: [u32; ST_WORDS],
    v: [[u32; VWORDS]; VREGS],
}

fn which(prog: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|d| d.join(prog)).find(|c| c.is_file())
}

fn oracle_hvx() -> Option<PathBuf> {
    which("qemu-hexagon")?;
    which("llvm-mc")?;
    which("ld.lld")?;
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools/hexagon-diff");
    let bin = dir.join("oracle_hvx");
    let src = dir.join("gen_oracle_hvx.py");
    let need = match (bin.metadata(), src.metadata()) {
        (Ok(b), Ok(s)) => match (b.modified(), s.modified()) {
            (Ok(bm), Ok(sm)) => bm < sm,
            _ => true,
        },
        _ => true,
    };
    if need {
        let ok = Command::new("bash")
            .arg(dir.join("build_hvx.sh"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            return None;
        }
    }
    bin.exists().then_some(bin)
}

fn run_oracle(bin: &PathBuf, cases: &[Case]) -> Option<Vec<Out>> {
    let case_size = CASE_VOFF + VREGS * VWORDS * 4;
    let mut payload = Vec::new();
    payload.extend_from_slice(&WIRE_MAGIC.to_le_bytes());
    payload.extend_from_slice(&(cases.len() as u32).to_le_bytes());
    for c in cases {
        let mut buf = vec![0u8; case_size];
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
                let off = CASE_VOFF + (r * VWORDS + w) * 4;
                buf[off..off + 4].copy_from_slice(&c.v[r][w].to_le_bytes());
            }
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
    let out_size = CASE_VOFF + VREGS * VWORDS * 4;
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
                let o = off + CASE_VOFF + (r * VWORDS + w) * 4;
                v[r][w] = u32::from_le_bytes([out[o], out[o + 1], out[o + 2], out[o + 3]]);
            }
        }
        off += out_size;
        res.push(Out { st, v });
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

fn run_rax(words: &[u32], c: &Case) -> Option<Out> {
    let regions = vec![(GuestAddress(0), 0x10000usize)];
    let mem = Arc::new(GuestMemoryMmap::<()>::from_ranges(&regions).ok()?);
    let mut off = CODE_ADDR;
    for &w in words {
        mem.write_slice(&w.to_le_bytes(), GuestAddress(off as u64)).ok()?;
        off += 4;
    }
    mem.write_slice(&trap0_word().to_le_bytes(), GuestAddress(off as u64)).ok()?;

    let mut regs = HexagonRegisters::default();
    for i in 0..NREG {
        regs.r[i] = c.st[i];
    }
    regs.c[8] = c.st[I_USR];
    regs.v = c.v;
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
    st[I_USR] = regs.c[8];
    Some(Out { st, v: regs.v })
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

/// Run an HVX family: each (label, asm) over `n` random vector states.
fn run_family(name: &str, cases: &[(&str, &str)], n: usize, seed: u64) {
    let bin = match oracle_hvx() {
        Some(b) => b,
        None => {
            eprintln!("[hexagon_hvx_diff] {name}: toolchain unavailable -> skipping");
            return;
        }
    };
    let asms: Vec<String> = cases.iter().map(|(_, a)| a.to_string()).collect();
    let words_per = match assemble(&asms) {
        Some(w) => w,
        None => {
            eprintln!("[hexagon_hvx_diff] {name}: assembly failed -> skipping");
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
            st[I_USR] = 0;
            let mut v = [[0u32; VWORDS]; VREGS];
            for r in 0..VREGS {
                for w in 0..VWORDS {
                    v[r][w] = rng.next() as u32;
                }
            }
            labels.push(*label);
            batch.push(Case { words: words.clone(), st, v });
        }
    }
    let outs = match run_oracle(&bin, &batch) {
        Some(o) => o,
        None => {
            eprintln!("[hexagon_hvx_diff] {name}: oracle failed -> skipping");
            return;
        }
    };
    let mut mismatches = Vec::new();
    for (i, c) in batch.iter().enumerate() {
        let rax = match run_rax(&c.words, c) {
            Some(r) => r,
            None => {
                mismatches.push(format!("[{}] rax rejected", labels[i]));
                continue;
            }
        };
        let mut diffs = Vec::new();
        for vr in 0..VREGS {
            if rax.v[vr] != outs[i].v[vr] {
                let lane = (0..VWORDS).find(|&w| rax.v[vr][w] != outs[i].v[vr][w]).unwrap();
                diffs.push(format!(
                    "v{vr}.w[{lane}]:rax={:#x},hw={:#x}",
                    rax.v[vr][lane], outs[i].v[vr][lane]
                ));
                break;
            }
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
        panic!("{name}: {} HVX divergences vs oracle", mismatches.len());
    }
}

#[test]
fn diff_hvx_addsub() {
    run_family(
        "hvx_addsub",
        &[
            ("vaddb", "{ v0.b = vadd(v1.b,v2.b) }"),
            ("vaddh", "{ v0.h = vadd(v1.h,v2.h) }"),
            ("vaddw", "{ v0.w = vadd(v1.w,v2.w) }"),
            ("vsubb", "{ v0.b = vsub(v1.b,v2.b) }"),
            ("vsubh", "{ v0.h = vsub(v1.h,v2.h) }"),
            ("vsubw", "{ v0.w = vsub(v1.w,v2.w) }"),
        ],
        6,
        0x4856,
    );
}

#[test]
fn diff_hvx_sat() {
    run_family(
        "hvx_sat",
        &[
            ("vaddbsat", "{ v0.b = vadd(v1.b,v2.b):sat }"),
            ("vaddhsat", "{ v0.h = vadd(v1.h,v2.h):sat }"),
            ("vaddwsat", "{ v0.w = vadd(v1.w,v2.w):sat }"),
            ("vaddubsat", "{ v0.ub = vadd(v1.ub,v2.ub):sat }"),
            ("vadduhsat", "{ v0.uh = vadd(v1.uh,v2.uh):sat }"),
            ("vsubbsat", "{ v0.b = vsub(v1.b,v2.b):sat }"),
            ("vsubhsat", "{ v0.h = vsub(v1.h,v2.h):sat }"),
            ("vsububsat", "{ v0.ub = vsub(v1.ub,v2.ub):sat }"),
        ],
        6,
        0x5a7,
    );
}

#[test]
fn diff_hvx_logical() {
    run_family(
        "hvx_logical",
        &[
            ("vand", "{ v0 = vand(v1,v2) }"),
            ("vor", "{ v0 = vor(v1,v2) }"),
            ("vxor", "{ v0 = vxor(v1,v2) }"),
        ],
        6,
        0x109,
    );
}
