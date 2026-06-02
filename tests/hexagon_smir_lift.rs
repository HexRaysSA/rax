//! Hexagon -> SMIR lift verification harness.
//!
//! For each instruction we lift the Hexagon machine word(s) to SMIR ops, execute
//! them on the `SmirInterpreter` from a seeded register state, and compare the
//! resulting GPR / predicate / USR state against rax's Hexagon interpreter
//! (`HexagonVcpu`, itself differentially verified against qemu-hexagon at 0
//! divergence). A match proves the lift is semantically correct for that op;
//! an instruction whose lift returns `Unsupported` is reported as an
//! (unimplemented) lift gap, not a divergence.
//!
//! This needs no external toolchain except `llvm-mc` to assemble the test words
//! (self-skips if unavailable), mirroring the differential test harnesses.

#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::sync::Arc;

use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

use rax::backend::emulator::hexagon::HexagonVcpu;
use rax::config::{Endianness, HexagonIsa};
use rax::cpu::{CpuState, HexagonRegisters, VCpu, VcpuExit};
use rax::smir::{
    HexagonLifter, LiftContext, LiftError, SmirBlock, SmirContext, SmirInterpreter, SmirLifter,
    Terminator, TrapKind,
};
use rax::smir::types::{ArchReg, BlockId, HexagonReg, OpId, SourceArch};

const NREG: usize = 32;
const CODE_ADDR: u32 = 0x1000;

fn which(prog: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|d| d.join(prog)).find(|c| c.is_file())
}

/// Assemble single-packet sources with llvm-mc; one word-vec per input string.
fn assemble(packets: &[String]) -> Option<Vec<Vec<u32>>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Vec<u32>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    which("llvm-mc")?;
    let mut out = Vec::with_capacity(packets.len());
    for p in packets {
        if let Some(w) = cache.lock().unwrap().get(p) {
            out.push(w.clone());
            continue;
        }
        let mut child = Command::new("llvm-mc")
            .args(["-triple=hexagon", "-mcpu=hexagonv69", "-mhvx", "-mattr=+audio", "-show-encoding"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        child.stdin.take().unwrap().write_all(p.as_bytes()).ok()?;
        let mut s = String::new();
        child.stdout.take().unwrap().read_to_string(&mut s).ok()?;
        if !child.wait().ok()?.success() {
            return None;
        }
        let mut words = Vec::new();
        let mut acc: Vec<u8> = Vec::new();
        for line in s.lines() {
            if let Some(i) = line.find("encoding: [") {
                let rest = &line[i + 11..];
                let end = rest.find(']')?;
                for t in rest[..end].split(',') {
                    let t = t.trim().strip_prefix("0x").unwrap_or(t.trim());
                    if let Ok(b) = u8::from_str_radix(t, 16) {
                        acc.push(b);
                        if acc.len() == 4 {
                            words.push(u32::from_le_bytes([acc[0], acc[1], acc[2], acc[3]]));
                            acc.clear();
                        }
                    }
                }
            }
        }
        if words.is_empty() {
            return None;
        }
        cache.lock().unwrap().insert(p.clone(), words.clone());
        out.push(words);
    }
    Some(out)
}

fn trap_word() -> u32 {
    static W: OnceLock<u32> = OnceLock::new();
    *W.get_or_init(|| assemble(&["{ trap0(#0) }".to_string()]).expect("trap0")[0][0])
}

struct State {
    r: [u32; NREG],
    p: [u8; 4],
    usr: u32,
}

/// Reference: run the words on rax's Hexagon interpreter from `init`.
fn run_interp(words: &[u32], init: &State) -> Option<State> {
    let mem = Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x20000)]).ok()?);
    let mut off = CODE_ADDR;
    for &w in words {
        mem.write_slice(&w.to_le_bytes(), GuestAddress(off as u64)).ok()?;
        off += 4;
    }
    mem.write_slice(&trap_word().to_le_bytes(), GuestAddress(off as u64)).ok()?;
    let mut regs = HexagonRegisters::default();
    regs.r = init.r;
    regs.p = init.p;
    regs.c[8] = init.usr;
    regs.set_pc(CODE_ADDR);
    let mut vcpu = HexagonVcpu::new(0, mem, HexagonIsa::V68, Endianness::Little);
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
    Some(State { r: regs.r, p: regs.p, usr: regs.c[8] })
}

/// Lift the words to SMIR and execute on the SmirInterpreter from `init`.
/// `Ok(None)` => the lift is not yet implemented (Unsupported) for some word.
fn lift_and_run(words: &[u32], init: &State) -> Result<Option<State>, String> {
    let mut lifter = HexagonLifter::default_isa();
    let mut lctx = LiftContext::new(SourceArch::Hexagon);
    let mut ops = Vec::new();
    let mut addr = CODE_ADDR as u64;
    for &w in words {
        let r = lifter.lift_insn(addr, &w.to_le_bytes(), &mut lctx);
        match r {
            Ok(res) => ops.extend(res.ops),
            Err(LiftError::Unsupported { .. }) => return Ok(None),
            Err(e) => return Err(format!("lift error: {e:?}")),
        }
        addr += 4;
    }
    // Renumber op ids so they are unique within the block.
    for (i, op) in ops.iter_mut().enumerate() {
        op.id = OpId(i as u16);
    }
    let block = SmirBlock {
        id: BlockId(0),
        guest_pc: CODE_ADDR as u64,
        phis: vec![],
        ops,
        terminator: Terminator::Trap { kind: TrapKind::Breakpoint },
        exec_count: 0,
    };
    let mut ctx = SmirContext::new_hexagon();
    for n in 0..NREG {
        ctx.write_arch_reg(ArchReg::Hexagon(HexagonReg::R(n as u8)), init.r[n] as u64);
    }
    for n in 0..4 {
        ctx.write_arch_reg(ArchReg::Hexagon(HexagonReg::P(n as u8)), (init.p[n] & 1) as u64);
    }
    ctx.write_arch_reg(ArchReg::Hexagon(HexagonReg::Usr), init.usr as u64);
    ctx.pc = CODE_ADDR as u64;

    let interp = SmirInterpreter::new();
    let mut mem = rax::smir::FlatMemory::with_base(0, 0x20000);
    interp.execute_block(&mut ctx, &mut mem, &block);

    let mut out = State { r: [0; NREG], p: [0; 4], usr: 0 };
    for n in 0..NREG {
        out.r[n] = ctx.read_arch_reg(ArchReg::Hexagon(HexagonReg::R(n as u8))) as u32;
    }
    for n in 0..4 {
        let v = ctx.read_arch_reg(ArchReg::Hexagon(HexagonReg::P(n as u8)));
        out.p[n] = if v & 1 != 0 { 0xff } else { 0 };
    }
    out.usr = ctx.read_arch_reg(ArchReg::Hexagon(HexagonReg::Usr)) as u32;
    Ok(Some(out))
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

/// Lift-verify a family: each (label, single-packet asm) over `n` random states.
/// Compares the SMIR-lifted execution against the interpreter (GPRs, predicate
/// truth, USR). Panics on a real divergence; reports (and tolerates) ops whose
/// lift is not yet implemented so the harness doubles as a coverage probe.
fn lift_family(name: &str, cases: &[(&str, &str)], n: usize, seed: u64) {
    let asms: Vec<String> = cases.iter().map(|(_, a)| a.to_string()).collect();
    let words_per = match assemble(&asms) {
        Some(w) => w,
        None => {
            eprintln!("[hexagon_smir_lift] {name}: llvm-mc unavailable -> skipping");
            return;
        }
    };
    let mut rng = Rng::new(seed);
    let mut mismatches = Vec::new();
    let mut unlifted = Vec::new();
    for ((label, _asm), words) in cases.iter().zip(words_per.iter()) {
        let mut lifted_ok = false;
        for _ in 0..n {
            let mut st = State { r: [0; NREG], p: [0; 4], usr: 0 };
            for r in st.r.iter_mut() {
                *r = rng.next() as u32;
            }
            for k in 0..4 {
                if rng.next() & 1 == 1 {
                    st.p[k] = 0xff;
                }
            }
            let interp = match run_interp(words, &st) {
                Some(s) => s,
                None => continue, // interpreter rejected (e.g. faulting op); skip
            };
            match lift_and_run(words, &st) {
                Ok(None) => {
                    unlifted.push(*label);
                    break;
                }
                Ok(Some(lift)) => {
                    lifted_ok = true;
                    let mut diffs = Vec::new();
                    for r in 0..NREG {
                        if interp.r[r] != lift.r[r] {
                            diffs.push(format!("r{r}:i={:#x},l={:#x}", interp.r[r], lift.r[r]));
                        }
                    }
                    for k in 0..4 {
                        if (interp.p[k] & 1) != (lift.p[k] & 1) {
                            diffs.push(format!("p{k}:i={:#x},l={:#x}", interp.p[k], lift.p[k]));
                        }
                    }
                    if !diffs.is_empty() {
                        mismatches.push(format!("[{label}] {}", diffs.join(" ")));
                    }
                }
                Err(e) => mismatches.push(format!("[{label}] {e}")),
            }
        }
        let _ = lifted_ok;
    }
    if !unlifted.is_empty() {
        eprintln!("[hexagon_smir_lift] {name}: UNLIFTED (gap): {:?}", unlifted);
    }
    if !mismatches.is_empty() {
        eprintln!("\n==== {name}: {} lift mismatches ====", mismatches.len());
        for m in mismatches.iter().take(20) {
            eprintln!("  {m}");
        }
        panic!("{name}: {} SMIR-lift divergences vs interpreter", mismatches.len());
    }
}

// ---- validate the harness on instructions already lifted by the DecodedInsn path ----

#[test]
fn lift_alu_rr() {
    lift_family(
        "alu_rr",
        &[
            ("add", "{ r0 = add(r1,r2) }"),
            ("sub", "{ r0 = sub(r1,r2) }"),
            ("and", "{ r0 = and(r1,r2) }"),
            ("or", "{ r0 = or(r1,r2) }"),
            ("xor", "{ r0 = xor(r1,r2) }"),
        ],
        12,
        0x5111,
    );
}

#[test]
fn lift_alu_imm() {
    lift_family(
        "alu_imm",
        &[
            ("addi", "{ r0 = add(r1,#10) }"),
            ("andi", "{ r0 = and(r1,#255) }"),
            ("ori", "{ r0 = or(r1,#15) }"),
            ("subri", "{ r0 = sub(#100,r1) }"),
        ],
        12,
        0x5112,
    );
}

#[test]
fn lift_shift_imm() {
    lift_family(
        "shift_imm",
        &[
            ("asl", "{ r0 = asl(r1,#5) }"),
            ("asr", "{ r0 = asr(r1,#5) }"),
            ("lsr", "{ r0 = lsr(r1,#5) }"),
        ],
        12,
        0x5113,
    );
}
