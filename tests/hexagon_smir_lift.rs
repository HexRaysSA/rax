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
    ArchRegState, HexagonLifter, LiftContext, LiftError, SmirBlock, SmirContext, SmirInterpreter,
    SmirLifter, Terminator, TrapKind,
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

#[derive(Clone)]
struct State {
    r: [u32; NREG],
    p: [u8; 4],
    usr: u32,
    /// HVX vector registers V0-31 (1024-bit each, 32 LE u32 words) — interp layout.
    v: [[u32; 32]; 32],
    /// HVX vector predicate registers Q0-3 (128-bit each, 4 u32 words).
    q: [[u32; 4]; 4],
}

impl State {
    fn zeroed() -> Self {
        State { r: [0; NREG], p: [0; 4], usr: 0, v: [[0; 32]; 32], q: [[0; 4]; 4] }
    }
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
    regs.v = init.v;
    regs.q = init.q;
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
    Some(State { r: regs.r, p: regs.p, usr: regs.c[8], v: regs.v, q: regs.q })
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
    // Seed HVX V/Q (1024-bit V as 16 u64 lanes; 128-bit Q in lanes 0-1).
    if let ArchRegState::Hexagon(hex) = &mut ctx.arch_regs {
        for n in 0..32 {
            let mut lanes = [0u64; 16];
            for (j, lane) in lanes.iter_mut().enumerate() {
                *lane = init.v[n][2 * j] as u64 | ((init.v[n][2 * j + 1] as u64) << 32);
            }
            hex.set_v(n as u8, lanes);
        }
        for n in 0..4 {
            let mut lanes = [0u64; 16];
            lanes[0] = init.q[n][0] as u64 | ((init.q[n][1] as u64) << 32);
            lanes[1] = init.q[n][2] as u64 | ((init.q[n][3] as u64) << 32);
            hex.set_q(n as u8, lanes);
        }
    }
    ctx.pc = CODE_ADDR as u64;

    let interp = SmirInterpreter::new();
    let mut mem = rax::smir::FlatMemory::with_base(0, 0x20000);
    interp.execute_block(&mut ctx, &mut mem, &block);

    let mut out = State::zeroed();
    for n in 0..NREG {
        out.r[n] = ctx.read_arch_reg(ArchReg::Hexagon(HexagonReg::R(n as u8))) as u32;
    }
    for n in 0..4 {
        let v = ctx.read_arch_reg(ArchReg::Hexagon(HexagonReg::P(n as u8)));
        out.p[n] = if v & 1 != 0 { 0xff } else { 0 };
    }
    out.usr = ctx.read_arch_reg(ArchReg::Hexagon(HexagonReg::Usr)) as u32;
    if let ArchRegState::Hexagon(hex) = &ctx.arch_regs {
        for n in 0..32 {
            let lanes = hex.get_v(n as u8);
            for (j, lane) in lanes.iter().enumerate() {
                out.v[n][2 * j] = *lane as u32;
                out.v[n][2 * j + 1] = (*lane >> 32) as u32;
            }
        }
        for n in 0..4 {
            let lanes = hex.get_q(n as u8);
            out.q[n][0] = lanes[0] as u32;
            out.q[n][1] = (lanes[0] >> 32) as u32;
            out.q[n][2] = lanes[1] as u32;
            out.q[n][3] = (lanes[1] >> 32) as u32;
        }
    }
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
            let mut st = State::zeroed();
            for r in st.r.iter_mut() {
                *r = rng.next() as u32;
            }
            for k in 0..4 {
                if rng.next() & 1 == 1 {
                    st.p[k] = 0xff;
                }
            }
            for vv in st.v.iter_mut() {
                for w in vv.iter_mut() {
                    *w = rng.next() as u32;
                }
            }
            for qq in st.q.iter_mut() {
                for w in qq.iter_mut() {
                    *w = rng.next() as u32;
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
                    for vn in 0..32 {
                        if interp.v[vn] != lift.v[vn] {
                            diffs.push(format!(
                                "v{vn}:i={:08x?},l={:08x?}",
                                &interp.v[vn][..4],
                                &lift.v[vn][..4]
                            ));
                        }
                    }
                    for qn in 0..4 {
                        if interp.q[qn] != lift.q[qn] {
                            diffs.push(format!(
                                "q{qn}:i={:08x?},l={:08x?}",
                                interp.q[qn], lift.q[qn]
                            ));
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

// ---- newly-lifted scalar register opcodes (re-decoded from Unknown) ----

#[test]
fn lift_a2_pair_logical() {
    lift_family(
        "a2_pair_logical",
        &[
            ("addp", "{ r1:0 = add(r3:2, r5:4) }"),
            ("subp", "{ r1:0 = sub(r3:2, r5:4) }"),
            ("andp", "{ r1:0 = and(r3:2, r5:4) }"),
            ("orp", "{ r1:0 = or(r3:2, r5:4) }"),
            ("xorp", "{ r1:0 = xor(r3:2, r5:4) }"),
            ("negp", "{ r1:0 = neg(r3:2) }"),
            ("notp", "{ r1:0 = not(r3:2) }"),
            ("andnp", "{ r1:0 = and(r3:2, ~r5:4) }"),
            ("ornp", "{ r1:0 = or(r3:2, ~r5:4) }"),
            ("sxtw", "{ r1:0 = sxtw(r2) }"),
        ],
        20,
        0x6201,
    );
}

#[test]
fn lift_a2_minmax() {
    lift_family(
        "a2_minmax",
        &[
            ("max", "{ r0 = max(r1,r2) }"),
            ("maxu", "{ r0 = maxu(r1,r2) }"),
            ("min", "{ r0 = min(r1,r2) }"),
            ("minu", "{ r0 = minu(r1,r2) }"),
            ("maxp", "{ r1:0 = max(r3:2, r5:4) }"),
            ("maxup", "{ r1:0 = maxu(r3:2, r5:4) }"),
            ("minp", "{ r1:0 = min(r3:2, r5:4) }"),
            ("minup", "{ r1:0 = minu(r3:2, r5:4) }"),
        ],
        20,
        0x6202,
    );
}

#[test]
fn lift_a2_misc() {
    lift_family(
        "a2_misc",
        &[
            ("orir", "{ r0 = or(r1,#129) }"),
            ("subri", "{ r0 = sub(#100,r1) }"),
            ("aslh", "{ r0 = aslh(r1) }"),
            ("asrh", "{ r0 = asrh(r1) }"),
            ("nop", "{ nop }"),
            ("andn", "{ r0 = and(r1, ~r2) }"),
            ("orn", "{ r0 = or(r1, ~r2) }"),
        ],
        20,
        0x6203,
    );
}

#[test]
fn lift_a2_combine() {
    lift_family(
        "a2_combine",
        &[
            ("combinew", "{ r1:0 = combine(r2,r3) }"),
            ("combineii", "{ r1:0 = combine(#7,#100) }"),
            ("combineri", "{ r1:0 = combine(r2,#5) }"),
            ("combineir", "{ r1:0 = combine(#5,r2) }"),
            ("combine_hh", "{ r0 = combine(r1.h,r2.h) }"),
            ("combine_hl", "{ r0 = combine(r1.h,r2.l) }"),
            ("combine_lh", "{ r0 = combine(r1.l,r2.h) }"),
            ("combine_ll", "{ r0 = combine(r1.l,r2.l) }"),
        ],
        20,
        0x6204,
    );
}

#[test]
fn lift_a4_rcmp() {
    lift_family(
        "a4_rcmp",
        &[
            ("rcmpeq", "{ r0 = cmp.eq(r1,r2) }"),
            ("rcmpneq", "{ r0 = !cmp.eq(r1,r2) }"),
            ("rcmpeqi", "{ r0 = cmp.eq(r1,#5) }"),
            ("rcmpneqi", "{ r0 = !cmp.eq(r1,#5) }"),
        ],
        20,
        0x6205,
    );
}

#[test]
fn lift_c2_cmp_extra() {
    lift_family(
        "c2_cmp_extra",
        &[
            ("cmpneq", "{ p0 = !cmp.eq(r1,r2) }"),
            ("cmplte", "{ p0 = !cmp.gt(r1,r2) }"),
            ("cmplteu", "{ p0 = !cmp.gtu(r1,r2) }"),
            ("cmpeqp", "{ p0 = cmp.eq(r1:0, r3:2) }"),
            ("cmpgtp", "{ p0 = cmp.gt(r1:0, r3:2) }"),
            ("cmpgtup", "{ p0 = cmp.gtu(r1:0, r3:2) }"),
            ("cmpltei", "{ p0 = !cmp.gt(r1,#5) }"),
            ("cmplteui", "{ p0 = !cmp.gtu(r1,#5) }"),
        ],
        20,
        0x6206,
    );
}

#[test]
fn lift_c2_bitstest() {
    lift_family(
        "c2_bitstest",
        &[
            ("bitsset", "{ p0 = bitsset(r1,r2) }"),
            ("bitsclr", "{ p0 = bitsclr(r1,r2) }"),
            ("bitsclri", "{ p0 = bitsclr(r1,#5) }"),
            ("nbitsset", "{ p0 = !bitsset(r1,r2) }"),
            ("nbitsclr", "{ p0 = !bitsclr(r1,r2) }"),
            ("nbitsclri", "{ p0 = !bitsclr(r1,#5) }"),
        ],
        20,
        0x6207,
    );
}

#[test]
fn lift_c2_mux() {
    lift_family(
        "c2_mux",
        &[
            ("mux", "{ r0 = mux(p0,r1,r2) }"),
            ("muxir", "{ r0 = mux(p0,r1,#5) }"),
            ("muxri", "{ r0 = mux(p0,#5,r1) }"),
            ("muxii", "{ r0 = mux(p0,#7,#9) }"),
        ],
        20,
        0x6208,
    );
}

#[test]
fn lift_c2_predlogic() {
    lift_family(
        "c2_predlogic",
        &[
            ("and", "{ p0 = and(p1,p2) }"),
            ("or", "{ p0 = or(p1,p2) }"),
            ("xor", "{ p0 = xor(p1,p2) }"),
            ("not", "{ p0 = not(p1) }"),
            ("andn", "{ p0 = and(p1,!p2) }"),
            ("orn", "{ p0 = or(p1,!p2) }"),
            ("tfrrp", "{ p0 = r1 }"),
        ],
        20,
        0x6209,
    );
}

#[test]
fn lift_s2_shift_pair() {
    lift_family(
        "s2_shift_pair",
        &[
            ("asl_i_p", "{ r1:0 = asl(r3:2,#5) }"),
            ("asr_i_p", "{ r1:0 = asr(r3:2,#5) }"),
            ("lsr_i_p", "{ r1:0 = lsr(r3:2,#5) }"),
            ("rol_i_r", "{ r0 = rol(r1,#5) }"),
            ("rol_i_p", "{ r1:0 = rol(r3:2,#5) }"),
        ],
        20,
        0x620a,
    );
}

#[test]
fn lift_s2_bitmanip() {
    lift_family(
        "s2_bitmanip",
        &[
            ("setbit_i", "{ r0 = setbit(r1,#5) }"),
            ("clrbit_i", "{ r0 = clrbit(r1,#5) }"),
            ("togglebit_i", "{ r0 = togglebit(r1,#5) }"),
            ("tstbit_i", "{ p0 = tstbit(r1,#5) }"),
            ("ntstbit_i", "{ p0 = !tstbit(r1,#5) }"),
            ("extractu", "{ r0 = extractu(r1,#8,#4) }"),
            ("extractu2", "{ r0 = extractu(r1,#13,#11) }"),
            ("insert", "{ r0 = insert(r1,#8,#4) }"),
            ("insert2", "{ r0 = insert(r1,#17,#9) }"),
            ("cl0", "{ r0 = cl0(r1) }"),
            ("cl1", "{ r0 = cl1(r1) }"),
            ("ct0", "{ r0 = ct0(r1) }"),
            ("ct1", "{ r0 = ct1(r1) }"),
            ("brev", "{ r0 = brev(r1) }"),
            ("vsplatrb", "{ r0 = vsplatb(r1) }"),
            ("vsplatrh", "{ r1:0 = vsplath(r2) }"),
        ],
        20,
        0x620b,
    );
}

#[test]
fn lift_s4_addasl() {
    lift_family(
        "s4_addasl",
        &[("addasl", "{ r0 = addasl(r1,r2,#3) }")],
        20,
        0x620c,
    );
}

#[test]
fn lift_m2_mpy() {
    lift_family(
        "m2_mpy",
        &[
            ("dpmpyss", "{ r1:0 = mpy(r2,r3) }"),
            ("dpmpyuu", "{ r1:0 = mpyu(r2,r3) }"),
            ("dpmpyss_acc", "{ r1:0 += mpy(r2,r3) }"),
            ("dpmpyss_nac", "{ r1:0 -= mpy(r2,r3) }"),
            ("dpmpyuu_acc", "{ r1:0 += mpyu(r2,r3) }"),
            ("dpmpyuu_nac", "{ r1:0 -= mpyu(r2,r3) }"),
            ("dpmpyss_rnd", "{ r0 = mpy(r1,r2):rnd }"),
            ("mpy_up", "{ r0 = mpy(r1,r2) }"),
            ("mpyu_up", "{ r0 = mpyu(r1,r2) }"),
            ("mpysu_up", "{ r0 = mpysu(r1,r2) }"),
            ("mpy_up_s1", "{ r0 = mpy(r1,r2):<<1 }"),
            ("mpysip", "{ r0 = mpyi(r1,#100) }"),
            ("mpysin", "{ r0 = mpyi(r1,#-100) }"),
            ("maci", "{ r0 += mpyi(r1,r2) }"),
            ("mnaci", "{ r0 -= mpyi(r1,r2) }"),
            ("macsip", "{ r0 += mpyi(r1,#100) }"),
            ("macsin", "{ r0 -= mpyi(r1,#100) }"),
            ("acci", "{ r0 += add(r1,r2) }"),
            ("accii", "{ r0 += add(r1,#5) }"),
            ("nacci", "{ r0 -= add(r1,r2) }"),
            ("naccii", "{ r0 -= add(r1,#5) }"),
            ("subacc", "{ r0 += sub(r2,r1) }"),
            ("xor_xacc", "{ r0 ^= xor(r1,r2) }"),
            ("m4_xor_xacc", "{ r1:0 ^= xor(r3:2,r5:4) }"),
        ],
        20,
        0x620d,
    );
}

// ---- HVX harness readiness probe (not a lift assertion) ----
// Confirms the V/Q-extended harness can drive a real HVX packet end-to-end:
// the assembler emits HVX encodings, the interpreter executes from seeded V
// state and mutates V, and the lifter is reached (Unsupported until HVX is
// lifted). This proves the oracle plumbing before the HVX lift wave.
#[test]
fn hvx_harness_probe() {
    let asms = vec!["{ v2.w = vadd(v0.w,v1.w) }".to_string()];
    let words_per = match assemble(&asms) {
        Some(w) => w,
        None => {
            eprintln!("[hvx_harness_probe] llvm-mc unavailable/assemble-failed -> skipping");
            return;
        }
    };
    let words = &words_per[0];
    let mut rng = Rng::new(0x4242);
    let mut st = State::zeroed();
    for vv in st.v.iter_mut() {
        for w in vv.iter_mut() {
            *w = rng.next() as u32;
        }
    }
    let interp = run_interp(words, &st).expect("interp must execute HVX vadd from seeded V");
    // v2 = v0 + v1 lane-wise (32-bit words); prove the interp actually mutated V2.
    for j in 0..32 {
        let expect = st.v[0][j].wrapping_add(st.v[1][j]);
        assert_eq!(interp.v[2][j], expect, "interp HVX vadd.w lane {j}");
    }
    // The lifter is reached; HVX is not yet lifted, so expect Unsupported (Ok(None)).
    match lift_and_run(words, &st) {
        Ok(None) => eprintln!("[hvx_harness_probe] HVX vadd: UNLIFTED (expected until lifted)"),
        Ok(Some(_)) => eprintln!("[hvx_harness_probe] HVX vadd is now lifted"),
        Err(e) => panic!("lift error on HVX vadd: {e}"),
    }
}

// ---- HVX (V6_*) elementwise integer vector lift verification ----
// Each family compares the SMIR-lifted V/Q state against the qemu-verified
// HexagonVcpu interpreter (lift_family now also compares V0-31 / Q0-3).

#[test]
fn lift_hvx_vadd() {
    lift_family(
        "hvx_vadd",
        &[
            ("vaddb", "{ v2.b = vadd(v0.b,v1.b) }"),
            ("vaddh", "{ v2.h = vadd(v0.h,v1.h) }"),
            ("vaddw", "{ v2.w = vadd(v0.w,v1.w) }"),
        ],
        12,
        0x7001,
    );
}

#[test]
fn lift_hvx_vsub() {
    lift_family(
        "hvx_vsub",
        &[
            ("vsubb", "{ v2.b = vsub(v0.b,v1.b) }"),
            ("vsubh", "{ v2.h = vsub(v0.h,v1.h) }"),
            ("vsubw", "{ v2.w = vsub(v0.w,v1.w) }"),
        ],
        12,
        0x7002,
    );
}

#[test]
fn lift_hvx_vmaxu() {
    // Unsigned vector max only — the SMIR VMax does an unsigned lane compare.
    lift_family(
        "hvx_vmaxu",
        &[
            ("vmaxub", "{ v2.ub = vmax(v0.ub,v1.ub) }"),
            ("vmaxuh", "{ v2.uh = vmax(v0.uh,v1.uh) }"),
        ],
        12,
        0x7003,
    );
}

#[test]
fn lift_hvx_vshift() {
    // Logical-left (vasl) and logical-right (vlsr) shift-by-scalar only.
    lift_family(
        "hvx_vshift",
        &[
            ("vaslh", "{ v2.h = vasl(v0.h,r1) }"),
            ("vaslw", "{ v2.w = vasl(v0.w,r1) }"),
            ("vlsrb", "{ v2.ub = vlsr(v0.ub,r1) }"),
            ("vlsrh", "{ v2.uh = vlsr(v0.uh,r1) }"),
            ("vlsrw", "{ v2.uw = vlsr(v0.uw,r1) }"),
        ],
        12,
        0x7004,
    );
}

#[test]
fn lift_hvx_vassign() {
    lift_family(
        "hvx_vassign",
        &[("vassign", "{ v2 = v0 }")],
        12,
        0x7005,
    );
}

#[test]
fn lift_hvx_vmpyih() {
    // Non-widening per-halfword integer multiply keeping the low 16 bits.
    // VMul (wrapping_mul on zero-extended lanes, masked to 16b) is bit-exact
    // with the signed sem multiply because low product bits are sign-agnostic.
    lift_family(
        "hvx_vmpyih",
        &[("vmpyih", "{ v2.h = vmpyi(v0.h,v1.h) }")],
        12,
        0x7006,
    );
}

// ---- Wave 2: VLane-based HVX elementwise lifts ----

#[test]
fn lift_hvx_vlogical() {
    // Bitwise vand/vor/vxor over the full 1024-bit vector (VLane And/Or/Xor).
    lift_family(
        "hvx_vlogical",
        &[
            ("vand", "{ v2 = vand(v0,v1) }"),
            ("vor", "{ v2 = vor(v0,v1) }"),
            ("vxor", "{ v2 = vxor(v0,v1) }"),
        ],
        12,
        0x7007,
    );
}

#[test]
fn lift_hvx_vminmax_signed() {
    // Signed per-lane min/max (VLane Min/Max signed:true).
    lift_family(
        "hvx_vminmax_signed",
        &[
            ("vmaxb", "{ v2.b = vmax(v0.b,v1.b) }"),
            ("vmaxh", "{ v2.h = vmax(v0.h,v1.h) }"),
            ("vmaxw", "{ v2.w = vmax(v0.w,v1.w) }"),
            ("vminb", "{ v2.b = vmin(v0.b,v1.b) }"),
            ("vminh", "{ v2.h = vmin(v0.h,v1.h) }"),
            ("vminw", "{ v2.w = vmin(v0.w,v1.w) }"),
        ],
        12,
        0x7008,
    );
}

#[test]
fn lift_hvx_vminu() {
    // Unsigned per-lane min (vminub/vminuh) — VLane Min signed:false.
    // (vmaxub/vmaxuh are lifted in Wave 1 via VMax.)
    lift_family(
        "hvx_vminu",
        &[
            ("vminub", "{ v2.ub = vmin(v0.ub,v1.ub) }"),
            ("vminuh", "{ v2.uh = vmin(v0.uh,v1.uh) }"),
        ],
        12,
        0x7009,
    );
}

#[test]
fn lift_hvx_vsat_signed() {
    // Signed saturating add/sub, single vector (VLane AddSat/SubSat signed:true).
    lift_family(
        "hvx_vsat_signed",
        &[
            ("vaddbsat", "{ v2.b = vadd(v0.b,v1.b):sat }"),
            ("vaddhsat", "{ v2.h = vadd(v0.h,v1.h):sat }"),
            ("vaddwsat", "{ v2.w = vadd(v0.w,v1.w):sat }"),
            ("vsubbsat", "{ v2.b = vsub(v0.b,v1.b):sat }"),
            ("vsubhsat", "{ v2.h = vsub(v0.h,v1.h):sat }"),
            ("vsubwsat", "{ v2.w = vsub(v0.w,v1.w):sat }"),
        ],
        12,
        0x700a,
    );
}

#[test]
fn lift_hvx_vsat_unsigned() {
    // Unsigned saturating add/sub, single vector (VLane AddSat/SubSat signed:false).
    // (vsubuwsat has no single-vector form; only the _dv pair form exists.)
    lift_family(
        "hvx_vsat_unsigned",
        &[
            ("vaddubsat", "{ v2.ub = vadd(v0.ub,v1.ub):sat }"),
            ("vadduhsat", "{ v2.uh = vadd(v0.uh,v1.uh):sat }"),
            ("vadduwsat", "{ v2.uw = vadd(v0.uw,v1.uw):sat }"),
            ("vsububsat", "{ v2.ub = vsub(v0.ub,v1.ub):sat }"),
            ("vsubuhsat", "{ v2.uh = vsub(v0.uh,v1.uh):sat }"),
        ],
        12,
        0x700b,
    );
}

#[test]
fn lift_hvx_vsat_dv() {
    // Dual-vector saturating add/sub: Vdd = op(Vuu, Vvv) emits two VLane ops
    // over the even/odd register of each pair.
    lift_family(
        "hvx_vsat_dv",
        &[
            // signed
            ("vaddbsat_dv", "{ v3:2.b = vadd(v1:0.b,v5:4.b):sat }"),
            ("vaddhsat_dv", "{ v3:2.h = vadd(v1:0.h,v5:4.h):sat }"),
            ("vaddwsat_dv", "{ v3:2.w = vadd(v1:0.w,v5:4.w):sat }"),
            ("vsubbsat_dv", "{ v3:2.b = vsub(v1:0.b,v5:4.b):sat }"),
            ("vsubhsat_dv", "{ v3:2.h = vsub(v1:0.h,v5:4.h):sat }"),
            ("vsubwsat_dv", "{ v3:2.w = vsub(v1:0.w,v5:4.w):sat }"),
            // unsigned
            ("vaddubsat_dv", "{ v3:2.ub = vadd(v1:0.ub,v5:4.ub):sat }"),
            ("vadduhsat_dv", "{ v3:2.uh = vadd(v1:0.uh,v5:4.uh):sat }"),
            ("vadduwsat_dv", "{ v3:2.uw = vadd(v1:0.uw,v5:4.uw):sat }"),
            ("vsububsat_dv", "{ v3:2.ub = vsub(v1:0.ub,v5:4.ub):sat }"),
            ("vsubuhsat_dv", "{ v3:2.uh = vsub(v1:0.uh,v5:4.uh):sat }"),
            ("vsubuwsat_dv", "{ v3:2.uw = vsub(v1:0.uw,v5:4.uw):sat }"),
        ],
        12,
        0x700c,
    );
}

#[test]
fn lift_hvx_vavg() {
    // Truncating average (a+b)>>1 (VLane Avg) and rounding (a+b+1)>>1 (AvgRnd),
    // signed and unsigned per lane width.
    lift_family(
        "hvx_vavg",
        &[
            // truncating, unsigned
            ("vavgub", "{ v2.ub = vavg(v0.ub,v1.ub) }"),
            ("vavguh", "{ v2.uh = vavg(v0.uh,v1.uh) }"),
            ("vavguw", "{ v2.uw = vavg(v0.uw,v1.uw) }"),
            // truncating, signed
            ("vavgb", "{ v2.b = vavg(v0.b,v1.b) }"),
            ("vavgh", "{ v2.h = vavg(v0.h,v1.h) }"),
            ("vavgw", "{ v2.w = vavg(v0.w,v1.w) }"),
            // rounding, unsigned
            ("vavgubrnd", "{ v2.ub = vavg(v0.ub,v1.ub):rnd }"),
            ("vavguhrnd", "{ v2.uh = vavg(v0.uh,v1.uh):rnd }"),
            ("vavguwrnd", "{ v2.uw = vavg(v0.uw,v1.uw):rnd }"),
            // rounding, signed
            ("vavgbrnd", "{ v2.b = vavg(v0.b,v1.b):rnd }"),
            ("vavghrnd", "{ v2.h = vavg(v0.h,v1.h):rnd }"),
            ("vavgwrnd", "{ v2.w = vavg(v0.w,v1.w):rnd }"),
        ],
        12,
        0x700d,
    );
}

#[test]
fn lift_hvx_vabsdiff() {
    // Absolute difference |a-b| (VLane AbsDiff). Unsigned: vabsdiffub/uh.
    // Signed: vabsdiffh/w (the signed forms write an unsigned-typed dest in asm).
    lift_family(
        "hvx_vabsdiff",
        &[
            ("vabsdiffub", "{ v2.ub = vabsdiff(v0.ub,v1.ub) }"),
            ("vabsdiffuh", "{ v2.uh = vabsdiff(v0.uh,v1.uh) }"),
            ("vabsdiffh", "{ v2.uh = vabsdiff(v0.h,v1.h) }"),
            ("vabsdiffw", "{ v2.uw = vabsdiff(v0.w,v1.w) }"),
        ],
        12,
        0x700e,
    );
}

// ---- Wave 3: vector-by-vector WIDENING multiplies (OpKind::VWidenMul) ----
// `Vdd.<2w> = vmpy(Vu.<w>,Vv.<w>)`: each pair of adjacent narrow lanes is
// multiplied into a double-width product; even narrow lanes' products -> the
// low dest vector (V[base]), odd lanes' -> the high (V[base+1]). The dest is a
// register PAIR (`v3:2` => base v2, hi v3). Mirrors sem/hvx_mpyv.rs.
#[test]
fn lift_hvx_vmpyv_widen() {
    lift_family(
        "hvx_vmpyv_widen",
        &[
            // signed byte x signed byte -> halfword pair
            ("vmpybv", "{ v3:2.h = vmpy(v0.b,v1.b) }"),
            // unsigned byte x signed byte -> halfword pair
            ("vmpybusv", "{ v3:2.h = vmpy(v0.ub,v1.b) }"),
            // unsigned byte x unsigned byte -> uh pair
            ("vmpyubv", "{ v3:2.uh = vmpy(v0.ub,v1.ub) }"),
            // signed half x signed half -> word pair
            ("vmpyhv", "{ v3:2.w = vmpy(v0.h,v1.h) }"),
            // signed half x unsigned half -> word pair
            ("vmpyhus", "{ v3:2.w = vmpy(v0.h,v1.uh) }"),
            // unsigned half x unsigned half -> uw pair
            ("vmpyuhv", "{ v3:2.uw = vmpy(v0.uh,v1.uh) }"),
        ],
        12,
        0x700f,
    );
}

#[test]
fn lift_hvx_vmpyv_widen_acc() {
    // Accumulate forms (`Vxx += ...`): read-modify-write of the dst pair. The
    // harness seeds all V registers with random values, so v2/v3 are non-zero
    // and the read-modify-write path is exercised.
    lift_family(
        "hvx_vmpyv_widen_acc",
        &[
            ("vmpybv_acc", "{ v3:2.h += vmpy(v0.b,v1.b) }"),
            ("vmpybusv_acc", "{ v3:2.h += vmpy(v0.ub,v1.b) }"),
            ("vmpyubv_acc", "{ v3:2.uh += vmpy(v0.ub,v1.ub) }"),
            ("vmpyhv_acc", "{ v3:2.w += vmpy(v0.h,v1.h) }"),
            ("vmpyhus_acc", "{ v3:2.w += vmpy(v0.h,v1.uh) }"),
            ("vmpyuhv_acc", "{ v3:2.uw += vmpy(v0.uh,v1.uh) }"),
        ],
        12,
        0x7010,
    );
}
