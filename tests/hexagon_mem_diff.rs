//! Hexagon memory differential test harness: rax vs. qemu-hexagon, with a memory
//! arena. Verifies load/store semantics (the reg-only `hexagon_diff` harness
//! excludes memory). The oracle is `tools/hexagon-diff/oracle_mem` (built on
//! demand); its `g_arena` symbol gives a fixed guest address that both the
//! oracle and rax use as the load/store base region.
//!
//! For each (packet, initial state, arena) we run it on the oracle and on rax's
//! `HexagonVcpu` from the identical state, then compare all GPRs, predicates,
//! USR, and the 256-byte arena. Self-skips if the toolchain is unavailable.

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
const I_USR: usize = 33;
const I_GP: usize = 36; // C11 (GP), per the oracle HexState layout.
const ST_WORDS: usize = 44;
/// Sentinel `base_reg` meaning "the address base is GP (C11)", not a GPR.
const BASE_GP: usize = usize::MAX;
const ARENA: usize = 256;
const WIRE_MAGIC: u32 = 0x3158_4548;
const CODE_ADDR: u32 = 0x1000;
/// Offset added to g_arena for the load/store base register, leaving room for
/// both negative and positive displacements inside the arena.
const BASE_OFF: u32 = 64;

#[derive(Clone)]
struct Case {
    words: Vec<u32>,
    st: [u32; ST_WORDS],
    arena: [u8; ARENA],
}

#[derive(Clone)]
struct Out {
    st: [u32; ST_WORDS],
    arena: [u8; ARENA],
}

fn which(prog: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(prog))
        .find(|c| c.is_file())
}

fn tools_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools/hexagon-diff")
}

/// Build oracle_mem; return (path, g_arena address). `None` if unavailable.
fn oracle_mem() -> Option<(PathBuf, u32)> {
    which("qemu-hexagon")?;
    which("llvm-mc")?;
    which("ld.lld")?;
    let dir = tools_dir();
    let bin = dir.join("oracle_mem");
    let src = dir.join("gen_oracle_mem.py");
    let need = match (bin.metadata(), src.metadata()) {
        (Ok(b), Ok(s)) => match (b.modified(), s.modified()) {
            (Ok(bm), Ok(sm)) => bm < sm,
            _ => true,
        },
        _ => true,
    };
    if need {
        let ok = Command::new("bash")
            .arg(dir.join("build_mem.sh"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            return None;
        }
    }
    // Read g_arena's address from the ELF symbol table.
    let nm = which("llvm-nm").map(|_| "llvm-nm").or(which("nm").map(|_| "nm"))?;
    let out = Command::new(nm).arg(&bin).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let addr = text.lines().find_map(|l| {
        let mut it = l.split_whitespace();
        let a = it.next()?;
        let _ty = it.next()?;
        if it.next() == Some("g_arena") {
            u32::from_str_radix(a, 16).ok()
        } else {
            None
        }
    })?;
    Some((bin, addr))
}

fn run_oracle(bin: &PathBuf, cases: &[Case]) -> Option<Vec<Out>> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&WIRE_MAGIC.to_le_bytes());
    payload.extend_from_slice(&(cases.len() as u32).to_le_bytes());
    for c in cases {
        payload.extend_from_slice(&(c.words.len().min(4) as u32).to_le_bytes());
        for i in 0..4 {
            payload.extend_from_slice(&c.words.get(i).copied().unwrap_or(0).to_le_bytes());
        }
        for v in &c.st {
            payload.extend_from_slice(&v.to_le_bytes());
        }
        payload.extend_from_slice(&c.arena);
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
        let mut arena = [0u8; ARENA];
        arena.copy_from_slice(&out[off + 184..off + 184 + ARENA]);
        off += 440;
        res.push(Out { st, arena });
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
        .write_all(packets.join("\n").as_bytes())
        .ok()?;
    let mut out = String::new();
    child.stdout.take().unwrap().read_to_string(&mut out).ok()?;
    if !child.wait().ok()?.success() {
        return None;
    }
    let mut words = Vec::new();
    for line in out.lines() {
        if let Some(i) = line.find("encoding: [") {
            let rest = &line[i + 11..];
            let end = rest.find(']')?;
            for t in rest[..end].split(',') {
                let t = t.trim().strip_prefix("0x").unwrap_or(t.trim());
                if let Ok(b) = u8::from_str_radix(t, 16) {
                    words.push(b);
                }
            }
        }
    }
    let mut grouped = Vec::new();
    let mut cur = Vec::new();
    let mut acc = Vec::new();
    for b in words {
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

fn run_rax(words: &[u32], c: &Case, arena_addr: u32) -> Option<Out> {
    let regions = vec![(GuestAddress(0), 0x20_0000usize)];
    let mem = Arc::new(GuestMemoryMmap::<()>::from_ranges(&regions).ok()?);
    let mut off = CODE_ADDR;
    for &w in words {
        mem.write_slice(&w.to_le_bytes(), GuestAddress(off as u64)).ok()?;
        off += 4;
    }
    mem.write_slice(&trap0_word().to_le_bytes(), GuestAddress(off as u64)).ok()?;
    mem.write_slice(&c.arena, GuestAddress(arena_addr as u64)).ok()?;

    let mut regs = HexagonRegisters::default();
    for i in 0..NREG {
        regs.r[i] = c.st[i];
    }
    for i in 0..4 {
        regs.p[i] = ((c.st[I_PRED] >> (8 * i)) & 0xff) as u8;
    }
    regs.c[8] = c.st[I_USR];
    regs.c[11] = c.st[I_GP]; // GP, for GP-relative addressing
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
    let mut pred = 0u32;
    for i in 0..4 {
        pred |= (regs.p[i] as u32) << (8 * i);
    }
    st[I_PRED] = pred;
    st[I_USR] = regs.c[8];
    let mut arena = [0u8; ARENA];
    mem.read_slice(&mut arena, GuestAddress(arena_addr as u64)).ok()?;
    Some(Out { st, arena })
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

/// Run a memory family: each (label, asm) over `n` random states/arenas.
/// `base_reg` is the GPR the instruction uses as its address base (set to
/// g_arena+BASE_OFF). Asserts no divergence vs the oracle.
fn run_family(name: &str, cases: &[(&str, &str)], base_reg: usize, n: usize, seed: u64) {
    let (bin, arena_addr) = match oracle_mem() {
        Some(x) => x,
        None => {
            eprintln!("[hexagon_mem_diff] {name}: toolchain unavailable -> skipping");
            return;
        }
    };
    let asms: Vec<String> = cases.iter().map(|(_, a)| a.to_string()).collect();
    let words_per = match assemble(&asms) {
        Some(w) => w,
        None => {
            eprintln!("[hexagon_mem_diff] {name}: assembly failed -> skipping");
            return;
        }
    };
    let base = arena_addr + BASE_OFF;
    let mut rng = Rng::new(seed);
    let mut labels = Vec::new();
    let mut batch = Vec::new();
    for ((label, _), words) in cases.iter().zip(words_per.iter()) {
        for _ in 0..n {
            let mut st = [0u32; ST_WORDS];
            for r in 0..NREG {
                st[r] = rng.next() as u32;
            }
            // Point the address base (a GPR, or GP) into the arena.
            if base_reg == BASE_GP {
                st[I_GP] = base;
            } else {
                st[base_reg] = base;
            }
            st[I_USR] = 0;
            // Each predicate P0..P3 independently 0x00 / 0xff (drives predicated ops).
            let mut pred = 0u32;
            for k in 0..4 {
                if rng.next() & 1 == 1 {
                    pred |= 0xffu32 << (8 * k);
                }
            }
            st[I_PRED] = pred;
            let mut arena = [0u8; ARENA];
            for b in arena.iter_mut() {
                *b = rng.next() as u8;
            }
            labels.push(*label);
            batch.push(Case { words: words.clone(), st, arena });
        }
    }
    let outs = match run_oracle(&bin, &batch) {
        Some(o) => o,
        None => {
            eprintln!("[hexagon_mem_diff] {name}: oracle failed -> skipping");
            return;
        }
    };
    let mut mismatches = Vec::new();
    for (i, c) in batch.iter().enumerate() {
        let rax = match run_rax(&c.words, c, arena_addr) {
            Some(r) => r,
            None => {
                mismatches.push(format!("[{}] rax rejected", labels[i]));
                continue;
            }
        };
        let mut diffs = Vec::new();
        for r in 0..NREG {
            if rax.st[r] != outs[i].st[r] {
                diffs.push(format!("r{r}:rax={:#x},hw={:#x}", rax.st[r], outs[i].st[r]));
            }
        }
        if rax.st[I_USR] != outs[i].st[I_USR] {
            diffs.push(format!("USR:rax={:#x},hw={:#x}", rax.st[I_USR], outs[i].st[I_USR]));
        }
        if rax.st[I_PRED] != outs[i].st[I_PRED] {
            diffs.push(format!("P:rax={:#x},hw={:#x}", rax.st[I_PRED], outs[i].st[I_PRED]));
        }
        if rax.arena != outs[i].arena {
            let j = (0..ARENA).find(|&j| rax.arena[j] != outs[i].arena[j]).unwrap();
            diffs.push(format!("arena[{j}]:rax={:#x},hw={:#x}", rax.arena[j], outs[i].arena[j]));
        }
        if !diffs.is_empty() {
            mismatches.push(format!("[{}] {}", labels[i], diffs.join(" ")));
        }
    }
    if !mismatches.is_empty() {
        eprintln!("\n==== {name}: {} mismatches ====", mismatches.len());
        for m in mismatches.iter().take(25) {
            eprintln!("  {m}");
        }
        panic!("{name}: {} memory divergences vs oracle", mismatches.len());
    }
}

// Base register is r4 (field 's' for _io loads/stores); store src is r5.
#[test]
fn diff_mem_load_io() {
    run_family(
        "load_io",
        &[
            ("loadrb", "{ r0 = memb(r4+#1) }"),
            ("loadrub", "{ r0 = memub(r4+#1) }"),
            ("loadrh", "{ r0 = memh(r4+#2) }"),
            ("loadruh", "{ r0 = memuh(r4+#2) }"),
            ("loadri", "{ r0 = memw(r4+#4) }"),
            ("loadrd", "{ r1:0 = memd(r4+#8) }"),
            ("loadrb0", "{ r0 = memb(r4+#0) }"),
            ("loadri0", "{ r0 = memw(r4+#0) }"),
        ],
        4,
        12,
        0x1111,
    );
}

#[test]
fn diff_mem_store_io() {
    run_family(
        "store_io",
        &[
            ("storerb", "{ memb(r4+#1) = r5 }"),
            ("storerh", "{ memh(r4+#2) = r5 }"),
            ("storeri", "{ memw(r4+#4) = r5 }"),
            ("storerd", "{ memd(r4+#8) = r5:4 }"),
            ("storerb0", "{ memb(r4+#0) = r5 }"),
            ("storeri0", "{ memw(r4+#0) = r5 }"),
        ],
        4,
        12,
        0x2222,
    );
}

#[test]
fn diff_mem_pred() {
    // Predicated loads/stores (p0 drives whether the access happens). The store
    // src is r5; predicate p0 comes from the random input state.
    run_family(
        "mem_pred",
        &[
            ("ploadrit", "{ if (p0) r0 = memw(r4+#0) }"),
            ("ploadrif", "{ if (!p0) r0 = memw(r4+#0) }"),
            ("ploadrbt", "{ if (p0) r0 = memb(r4+#0) }"),
            ("pstorerit", "{ if (p0) memw(r4+#0) = r5 }"),
            ("pstorerif", "{ if (!p0) memw(r4+#0) = r5 }"),
            ("pstorerbt", "{ if (p0) memb(r4+#0) = r5 }"),
        ],
        4,
        16,
        0x4444,
    );
}

#[test]
fn diff_mem_absolute() {
    // Absolute addressing: `memX(##addr)` (a GP-form load/store with a constant
    // extender; the extended immediate is the full byte address, GP unused).
    // The address is baked into the asm at the (runtime) arena location.
    let (bin, arena_addr) = match oracle_mem() {
        Some(x) => x,
        None => {
            eprintln!("[hexagon_mem_diff] absolute: toolchain unavailable -> skipping");
            return;
        }
    };
    // Word-aligned target within the arena.
    let waddr = arena_addr + 16;
    let baddr = arena_addr + 5;
    let asms = vec![
        format!("{{ r0 = memw(##0x{waddr:x}) }}"),
        format!("{{ r0 = memb(##0x{baddr:x}) }}"),
        format!("{{ r0 = memub(##0x{baddr:x}) }}"),
        format!("{{ memw(##0x{waddr:x}) = r5 }}"),
        format!("{{ memb(##0x{baddr:x}) = r5 }}"),
    ];
    let labels = ["loadw", "loadb", "loadub", "storew", "storeb"];
    let words_per = match assemble(&asms) {
        Some(w) => w,
        None => {
            eprintln!("[hexagon_mem_diff] absolute: assembly failed -> skipping");
            return;
        }
    };
    let mut rng = Rng::new(0x9b9b);
    let mut batch = Vec::new();
    let mut lbl = Vec::new();
    for (i, words) in words_per.iter().enumerate() {
        for _ in 0..12 {
            let mut st = [0u32; ST_WORDS];
            for r in 0..NREG {
                st[r] = rng.next() as u32;
            }
            let mut arena = [0u8; ARENA];
            for b in arena.iter_mut() {
                *b = rng.next() as u8;
            }
            lbl.push(labels[i]);
            batch.push(Case { words: words.clone(), st, arena });
        }
    }
    let outs = match run_oracle(&bin, &batch) {
        Some(o) => o,
        None => {
            eprintln!("[hexagon_mem_diff] absolute: oracle failed -> skipping");
            return;
        }
    };
    let mut mismatches = Vec::new();
    for (i, c) in batch.iter().enumerate() {
        let rax = match run_rax(&c.words, c, arena_addr) {
            Some(r) => r,
            None => {
                mismatches.push(format!("[{}] rax rejected", lbl[i]));
                continue;
            }
        };
        let mut diffs = Vec::new();
        for r in 0..NREG {
            if rax.st[r] != outs[i].st[r] {
                diffs.push(format!("r{r}:rax={:#x},hw={:#x}", rax.st[r], outs[i].st[r]));
            }
        }
        if rax.arena != outs[i].arena {
            let j = (0..ARENA).find(|&j| rax.arena[j] != outs[i].arena[j]).unwrap();
            diffs.push(format!("arena[{j}]:rax={:#x},hw={:#x}", rax.arena[j], outs[i].arena[j]));
        }
        if !diffs.is_empty() {
            mismatches.push(format!("[{}] {}", lbl[i], diffs.join(" ")));
        }
    }
    if !mismatches.is_empty() {
        eprintln!("\n==== absolute: {} mismatches ====", mismatches.len());
        for m in mismatches.iter().take(20) {
            eprintln!("  {m}");
        }
        panic!("absolute: {} divergences vs oracle", mismatches.len());
    }
}

#[test]
fn diff_mem_gp() {
    // GP-relative loads/stores: the address base is the GP control register.
    run_family(
        "mem_gp",
        &[
            ("loadrigp", "{ r0 = memw(gp+#4) }"),
            ("loadrbgp", "{ r0 = memb(gp+#1) }"),
            ("loadrubgp", "{ r0 = memub(gp+#1) }"),
            ("loadrhgp", "{ r0 = memh(gp+#2) }"),
            ("loadrdgp", "{ r1:0 = memd(gp+#8) }"),
            ("storerigp", "{ memw(gp+#4) = r5 }"),
            ("storerbgp", "{ memb(gp+#1) = r5 }"),
            ("storerdgp", "{ memd(gp+#8) = r5:4 }"),
        ],
        BASE_GP,
        12,
        0x6767,
    );
}

#[test]
fn diff_mem_memop() {
    // Read-modify-write memops. Base is r4, register source is r5.
    run_family(
        "mem_memop",
        &[
            ("addw", "{ memw(r4+#0) += r5 }"),
            ("subw", "{ memw(r4+#4) -= r5 }"),
            ("andw", "{ memw(r4+#0) &= r5 }"),
            ("orw", "{ memw(r4+#0) |= r5 }"),
            ("addh", "{ memh(r4+#2) += r5 }"),
            ("addb", "{ memb(r4+#1) += r5 }"),
            ("iaddw", "{ memw(r4+#8) += #5 }"),
            ("isubw", "{ memw(r4+#8) -= #5 }"),
            ("setbitw", "{ memw(r4+#0) = setbit(#3) }"),
            ("clrbitw", "{ memw(r4+#0) = clrbit(#17) }"),
            ("setbitb", "{ memb(r4+#0) = setbit(#2) }"),
        ],
        4,
        12,
        0x8989,
    );
}

#[test]
fn diff_mem_load_pi() {
    // post-increment: base in r4 is updated; src/dst register also changes.
    run_family(
        "load_pi",
        &[
            ("loadrb_pi", "{ r0 = memb(r4++#1) }"),
            ("loadri_pi", "{ r0 = memw(r4++#4) }"),
            ("loadrd_pi", "{ r1:0 = memd(r4++#8) }"),
        ],
        4,
        12,
        0x3333,
    );
}
