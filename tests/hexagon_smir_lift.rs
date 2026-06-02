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
fn lift_hvx_vshiftv() {
    // Per-lane bidirectional vector-amount shifts: Vd = op(Vu, Vv) where Vu is
    // the value and Vv the signed per-lane amount (sxtn of low log2(bits)+1
    // bits). The harness seeds Vv randomly, so the negative-amount (reverse-
    // direction) path is exercised too.
    lift_family(
        "hvx_vshiftv",
        &[
            ("vaslhv", "{ v2.h = vasl(v0.h,v1.h) }"),
            ("vaslwv", "{ v2.w = vasl(v0.w,v1.w) }"),
            ("vasrhv", "{ v2.h = vasr(v0.h,v1.h) }"),
            ("vasrwv", "{ v2.w = vasr(v0.w,v1.w) }"),
            ("vlsrhv", "{ v2.h = vlsr(v0.h,v1.h) }"),
            ("vlsrwv", "{ v2.w = vlsr(v0.w,v1.w) }"),
        ],
        16,
        0x7104,
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

// ---- Wave 4: HVX horizontal reduce multiplies + scalar splats ----
// `OpKind::VReduceMul` models the vrmpy/vdmpy reduce family: each output lane
// is the sum of `taps` adjacent narrow sub-lane products, so the output lane is
// `src_elem_bits*taps` wide. `OpKind::VBroadcast` splats the low bits of a GPR
// into every lane. Scalar (Rt) reduce forms compose VBroadcast + VReduceMul.
// All non-saturating; matches sem/hvx_rmpy.rs + sem/hvx_perm.rs bit-for-bit.

#[test]
fn lift_hvx_vrmpy_vv() {
    // VECTOR-VECTOR 4-tap byte dot product -> word (single dest vector).
    lift_family(
        "hvx_vrmpy_vv",
        &[
            ("vrmpyubv", "{ v2.uw = vrmpy(v0.ub,v1.ub) }"),
            ("vrmpybv", "{ v2.w = vrmpy(v0.b,v1.b) }"),
            ("vrmpybusv", "{ v2.w = vrmpy(v0.ub,v1.b) }"),
        ],
        12,
        0x7011,
    );
}

#[test]
fn lift_hvx_vrmpy_vv_acc() {
    // Accumulate forms (`Vx += ...`): read-modify-write of the dest vector.
    // The harness seeds V2 with random values, exercising the acc read path.
    lift_family(
        "hvx_vrmpy_vv_acc",
        &[
            ("vrmpyubv_acc", "{ v2.uw += vrmpy(v0.ub,v1.ub) }"),
            ("vrmpybv_acc", "{ v2.w += vrmpy(v0.b,v1.b) }"),
            ("vrmpybusv_acc", "{ v2.w += vrmpy(v0.ub,v1.b) }"),
        ],
        12,
        0x7012,
    );
}

#[test]
fn lift_hvx_vrmpy_scalar() {
    // SCALAR 4-tap vrmpy (Vu.byte * Rt.byte, Rt's 4 bytes reused per word lane)
    // composed as VBroadcast(Rt, I32) + 4-tap byte VReduceMul.
    lift_family(
        "hvx_vrmpy_scalar",
        &[
            ("vrmpyub", "{ v2.uw = vrmpy(v0.ub,r3.ub) }"),
            ("vrmpybus", "{ v2.w = vrmpy(v0.ub,r3.b) }"),
            ("vrmpyub_acc", "{ v2.uw += vrmpy(v0.ub,r3.ub) }"),
            ("vrmpybus_acc", "{ v2.w += vrmpy(v0.ub,r3.b) }"),
        ],
        12,
        0x7013,
    );
}

#[test]
fn lift_hvx_vsplat() {
    // Scalar splat to all lanes: word / half / byte lanes.
    lift_family(
        "hvx_vsplat",
        &[
            ("lvsplatw", "{ v2 = vsplat(r3) }"),
            ("lvsplath", "{ v2.h = vsplat(r3) }"),
            ("lvsplatb", "{ v2.b = vsplat(r3) }"),
        ],
        12,
        0x7014,
    );
}

#[test]
fn lift_hvx_vdmpybus_scalar() {
    // SCALAR 2-tap vdmpybus (Vu.ub * Rt.b -> halfword) composed as
    // VBroadcast(Rt, I32) + 2-tap byte VReduceMul. The I32-broadcast makes the
    // temp's byte n equal Rt.byte[n%4], matching the sem's per-lane Rt reuse.
    lift_family(
        "hvx_vdmpybus_scalar",
        &[
            ("vdmpybus", "{ v2.h = vdmpy(v0.ub,r3.b) }"),
            ("vdmpybus_acc", "{ v2.h += vdmpy(v0.ub,r3.b) }"),
        ],
        12,
        0x7015,
    );
}

// ---- Wave 5: widen-extend pairs, vcombine, vector ASR-by-scalar,
// vector-by-scalar widening multiplies ----

#[test]
fn lift_hvx_vwiden_ext() {
    // Interleaved zero/sign extend a vector into a pair (vzxt/vsxt):
    // vzb/vsb widen byte->half, vzh/vsh widen half->word. Even narrow lanes
    // -> v[base], odd -> v[base+1] (OpKind::VWidenExt interleave:true).
    lift_family(
        "hvx_vwiden_ext",
        &[
            ("vzb", "{ v3:2.uh = vzxt(v0.ub) }"),
            ("vsb", "{ v3:2.h = vsxt(v0.b) }"),
            ("vzh", "{ v3:2.uw = vzxt(v0.uh) }"),
            ("vsh", "{ v3:2.w = vsxt(v0.h) }"),
        ],
        12,
        0x7016,
    );
}

#[test]
fn lift_hvx_vunpack() {
    // Sequential unpack of a vector into a pair (vunpack): the low half of the
    // narrow lanes -> v[base], the high half -> v[base+1]
    // (OpKind::VWidenExt interleave:false), zero/sign per u/s.
    lift_family(
        "hvx_vunpack",
        &[
            ("vunpackub", "{ v3:2.uh = vunpack(v0.ub) }"),
            ("vunpackb", "{ v3:2.h = vunpack(v0.b) }"),
            ("vunpackuh", "{ v3:2.uw = vunpack(v0.uh) }"),
            ("vunpackh", "{ v3:2.w = vunpack(v0.h) }"),
        ],
        12,
        0x7017,
    );
}

#[test]
fn lift_hvx_vcombine() {
    // Vdd = vcombine(Vu, Vv): register-pair copy with low := Vv, high := Vu.
    // Emitted as two VMov copies in that mapping.
    lift_family(
        "hvx_vcombine",
        &[("vcombine", "{ v3:2 = vcombine(v1,v0) }")],
        12,
        0x7018,
    );
}

#[test]
fn lift_hvx_vasr_scalar() {
    // Per-lane arithmetic right shift by scalar Rt (vasrh/vasrw).
    // VShift Asr sign-extends each lane, so this is bit-exact with the sem.
    lift_family(
        "hvx_vasr_scalar",
        &[
            ("vasrh", "{ v2.h = vasr(v0.h,r3) }"),
            ("vasrw", "{ v2.w = vasr(v0.w,r3) }"),
        ],
        12,
        0x7019,
    );
}

#[test]
fn lift_hvx_vmpy_scalar_widen() {
    // Vector-by-SCALAR widening multiply -> register PAIR, composed as
    // VBroadcast(Rt, I32) + VWidenMul. The I32-broadcast reuses Rt's sub-
    // elements per lane exactly as the sem (byte[(2i+k)%4], half[k]).
    lift_family(
        "hvx_vmpy_scalar_widen",
        &[
            ("vmpybus", "{ v3:2.h = vmpy(v0.ub,r3.b) }"),
            ("vmpyub", "{ v3:2.uh = vmpy(v0.ub,r3.ub) }"),
            ("vmpyh", "{ v3:2.w = vmpy(v0.h,r3.h) }"),
            ("vmpyuh", "{ v3:2.uw = vmpy(v0.uh,r3.uh) }"),
        ],
        12,
        0x701a,
    );
}

#[test]
fn lift_hvx_vmpy_scalar_widen_acc() {
    // Accumulate forms (`Vxx += ...`): read-modify-write of the dst pair
    // (VWidenMul acc:true). The harness seeds all V registers non-zero so the
    // read-modify-write path is exercised.
    lift_family(
        "hvx_vmpy_scalar_widen_acc",
        &[
            ("vmpybus_acc", "{ v3:2.h += vmpy(v0.ub,r3.b) }"),
            ("vmpyub_acc", "{ v3:2.uh += vmpy(v0.ub,r3.ub) }"),
            ("vmpyh_acc", "{ v3:2.w += vmpy(v0.h,r3.h) }"),
            ("vmpyuh_acc", "{ v3:2.uw += vmpy(v0.uh,r3.uh) }"),
        ],
        12,
        0x701b,
    );
}

// ---- Wave 6: HVX pack even/odd + saturating narrowing pack ----

#[test]
fn lift_hvx_vpack_evenodd() {
    // vpacke/vpacko: pick the even (e) or odd (o) narrow sub-element of each
    // wide lane. Output low half comes from Vv (second operand), high half from
    // Vu (first). VPack { elem = narrow output element, odd }.
    lift_family(
        "hvx_vpack_evenodd",
        &[
            ("vpackeb", "{ v2.b = vpacke(v0.h,v1.h) }"),
            ("vpackob", "{ v2.b = vpacko(v0.h,v1.h) }"),
            ("vpackeh", "{ v2.h = vpacke(v0.w,v1.w) }"),
            ("vpackoh", "{ v2.h = vpacko(v0.w,v1.w) }"),
        ],
        12,
        0x701c,
    );
}

#[test]
fn lift_hvx_vpack_sat() {
    // Saturating narrowing pack: each signed wide lane is clamped to half width
    // (unsigned range for ub/uh, signed for b/h). Low half from Vv, high from
    // Vu. VPackSat { src_elem = wide source element, to_unsigned }.
    lift_family(
        "hvx_vpack_sat",
        &[
            ("vpackhub_sat", "{ v2.ub = vpack(v0.h,v1.h):sat }"),
            ("vpackhb_sat", "{ v2.b = vpack(v0.h,v1.h):sat }"),
            ("vpackwuh_sat", "{ v2.uh = vpack(v0.w,v1.w):sat }"),
            ("vpackwh_sat", "{ v2.h = vpack(v0.w,v1.w):sat }"),
        ],
        12,
        0x701d,
    );
}

#[test]
fn lift_hvx_vshuff_deal() {
    // Single-vector shuffle/deal of narrow lanes (VShuffle2).
    //   vshuff (deal=false): out[2i]=Vu[i], out[2i+1]=Vu[i+half]
    //   vdeal  (deal=true):  out[i]=Vu[2i], out[i+half]=Vu[2i+1]
    // half = (1024/elem_bits)/2; elem is the lane type (b -> I8, h -> I16).
    lift_family(
        "hvx_vshuff_deal",
        &[
            ("vshuffb", "{ v2.b = vshuff(v0.b) }"),
            ("vshuffh", "{ v2.h = vshuff(v0.h) }"),
            ("vdealb", "{ v2.b = vdeal(v0.b) }"),
            ("vdealh", "{ v2.h = vdeal(v0.h) }"),
        ],
        12,
        0x701e,
    );
}

#[test]
fn lift_hvx_vshuff_eo() {
    // Two-vector even/odd shuffle (VShuffleEO): interleave the even (e) or odd
    // (o) narrow sub-elements of two source vectors.
    //   out[2i] = src2[2i+odd], out[2i+1] = src1[2i+odd]   (src1=Vu, src2=Vv)
    // vshuffe* takes the even sub-element, vshuffo* the odd one.
    lift_family(
        "hvx_vshuff_eo",
        &[
            ("vshuffeb", "{ v2.b = vshuffe(v0.b,v1.b) }"),
            ("vshuffob", "{ v2.b = vshuffo(v0.b,v1.b) }"),
            ("vshufeh", "{ v2.h = vshuffe(v0.h,v1.h) }"),
            ("vshufoh", "{ v2.h = vshuffo(v0.h,v1.h) }"),
        ],
        12,
        0x701f,
    );
}

#[test]
fn lift_hvx_valign() {
    // Byte-align / rotate of the 256-byte concat src1:src2 (VAlign).
    //   out[i] = src2[i+s] when i+s<128, else src1[i+s-128]
    // with byte shift s = (amount & 127) for right forms (valign/valignbi) and
    // s = 128 - (amount & 127) for left forms (vlalign/vlalignbi). src1 = Vu
    // (assembler first vector operand), src2 = Vv (second). vror rotates a single
    // vector: align(Vu, Vu, Rt & 127). Confirmed against sem/hvx_perm.rs.
    lift_family(
        "hvx_valign",
        &[
            ("vror", "{ v2 = vror(v0,r3) }"),
            ("valignb", "{ v2 = valign(v0,v1,r3) }"),
            ("vlalignb", "{ v2 = vlalign(v0,v1,r3) }"),
            ("valignbi", "{ v2 = valign(v0,v1,#3) }"),
            ("vlalignbi", "{ v2 = vlalign(v0,v1,#3) }"),
        ],
        12,
        0x7020,
    );
}

// ---- Wave 9: HVX shift-round-saturate narrowing multiply ----
// `OpKind::VMulShiftSat`: per lane p = ext(src1)*ext(src2) (i64); p <<= shift_left;
// if round add 1<<(out_shift-1); if sat_bits!=0 clamp to signed sat_bits range;
// out lane = (p >> out_shift) masked to src_elem (output elem = src_elem).
// Matches sem/hvx_mpyv.rs bit-for-bit.

#[test]
fn lift_hvx_vmpy_srs_vv() {
    // VECTOR-VECTOR halfword narrowing multiplies (direct VMulShiftSat).
    //   vmpyhvsrs: Vd.h=vmpy(Vu.h,Vv.h):<<1:rnd:sat
    //     signed*signed, <<1, +0x8000 round, sat32, >>16 high-half.
    //   vmpyuhvs:  Vd.uh=vmpy(Vu.uh,Vv.uh):>>16
    //     unsigned*unsigned, no shift/round/sat, >>16 high-half.
    lift_family(
        "hvx_vmpy_srs_vv",
        &[
            ("vmpyhvsrs", "{ v2.h = vmpy(v0.h,v1.h):<<1:rnd:sat }"),
            ("vmpyuhvs", "{ v2.uh = vmpy(v0.uh,v1.uh):>>16 }"),
        ],
        12,
        0x7021,
    );
}

#[test]
fn lift_hvx_vmpy_srs_scalar() {
    // VECTOR-SCALAR halfword narrowing multiplies (VBroadcast(Rt,I32) +
    // VMulShiftSat). Each even halfword lane multiplies by Rt.h[0], each odd by
    // Rt.h[1] (the I32 broadcast makes t.h[2i]=Rt.h[0], t.h[2i+1]=Rt.h[1]).
    //   vmpyhss:  Vd.h=vmpy(Vu.h,Rt.h):<<1:sat       signed*signed, <<1, sat32, >>16
    //   vmpyhsrs: Vd.h=vmpy(Vu.h,Rt.h):<<1:rnd:sat   as above + 0x8000 round
    lift_family(
        "hvx_vmpy_srs_scalar",
        &[
            ("vmpyhss", "{ v2.h = vmpy(v0.h,r3.h):<<1:sat }"),
            ("vmpyhsrs", "{ v2.h = vmpy(v0.h,r3.h):<<1:rnd:sat }"),
        ],
        12,
        0x7022,
    );
}

// ---- Wave 11: HVX vector compares -> Q, vmux, Q-predicate logic ----
// `OpKind::VCmpToQ` builds a Q vector-predicate (1 bit per vector byte) from a
// per-elem-lane compare; `OpKind::VBlend` selects bytes by a Q (vmux);
// Q-predicate bitwise logic is `OpKind::VLane` over the two I64 lanes of a Q.
// The harness seeds Q0-3 randomly so vmux/pred-logic read meaningful masks and
// compares all Q0-3 after, so the Q-producing compares are checked directly.

#[test]
fn lift_hvx_vcmp_to_q() {
    // Qd = vcmp.<cond>(Vu.<t>, Vv.<t>). eq is signedness-agnostic; gt is signed
    // (.b/.h/.w) vs unsigned (.ub/.uh/.uw). Each true lane sets all its per-byte
    // Q bits, so divergence here would catch a wrong cond/elem/lanes mapping.
    lift_family(
        "hvx_vcmp_to_q",
        &[
            ("veqb", "{ q0 = vcmp.eq(v0.b,v1.b) }"),
            ("vgtb", "{ q0 = vcmp.gt(v0.b,v1.b) }"),
            ("vgtub", "{ q0 = vcmp.gt(v0.ub,v1.ub) }"),
            ("veqh", "{ q0 = vcmp.eq(v0.h,v1.h) }"),
            ("vgth", "{ q0 = vcmp.gt(v0.h,v1.h) }"),
            ("vgtuh", "{ q0 = vcmp.gt(v0.uh,v1.uh) }"),
            ("veqw", "{ q0 = vcmp.eq(v0.w,v1.w) }"),
            ("vgtw", "{ q0 = vcmp.gt(v0.w,v1.w) }"),
            ("vgtuw", "{ q0 = vcmp.gt(v0.uw,v1.uw) }"),
        ],
        16,
        0x7023,
    );
}

#[test]
fn lift_hvx_vmux() {
    // Vd.b[i] = Qt.bit[i] ? Vu.b[i] : Vv.b[i]. Reads a (seeded) Q mask.
    lift_family(
        "hvx_vmux",
        &[("vmux", "{ v2 = vmux(q0,v0,v1) }")],
        16,
        0x7024,
    );
}

#[test]
fn lift_hvx_pred_logic() {
    // Qd = OP(Qs, Qt) per-bit over 128 bits, lifted as VLane bitwise on Q regs.
    // pred_not (!a, VLaneOp::Not) and pred_or_n (a|!b, VLaneOp::OrNot) are now
    // lifted too (Wave 12).
    lift_family(
        "hvx_pred_logic",
        &[
            ("pred_and", "{ q0 = and(q1,q2) }"),
            ("pred_or", "{ q0 = or(q1,q2) }"),
            ("pred_xor", "{ q0 = xor(q1,q2) }"),
            ("pred_and_n", "{ q0 = and(q1,!q2) }"),
            ("pred_not", "{ q0 = not(q1) }"),
            ("pred_or_n", "{ q0 = or(q1,!q2) }"),
        ],
        16,
        0x7025,
    );
}

// ---- Wave 12: HVX scalar 2-tap vdmpy halfword reduces -> word ----
// `Vd.w = vdmpy(Vu.h, Rt.<t>)` (and `+=` acc forms), composed as
// VBroadcast(Rt, I32) + 2-tap I16-source VReduceMul. The sat forms clamp the
// accumulated word lane to the signed 32-bit range; the harness seeds hit
// overflow. HVX vector saturation does not touch USR.

#[test]
fn lift_hvx_vdmpyh_scalar() {
    lift_family(
        "hvx_vdmpyh_scalar",
        &[
            // Vu.h(signed) * Rt.b(signed byte) -> word, 2-tap, no sat.
            ("vdmpyhb", "{ v2.w = vdmpy(v0.h,r3.b) }"),
            ("vdmpyhb_acc", "{ v2.w += vdmpy(v0.h,r3.b) }"),
            // Vu.h(signed) * Rt.h(signed) -> word, 2-tap, sat32.
            ("vdmpyhsat", "{ v2.w = vdmpy(v0.h,r3.h):sat }"),
            ("vdmpyhsat_acc", "{ v2.w += vdmpy(v0.h,r3.h):sat }"),
            // Vu.h(signed) * Rt.uh(UNSIGNED) -> word, 2-tap, sat32.
            ("vdmpyhsusat", "{ v2.w = vdmpy(v0.h,r3.uh):sat }"),
            ("vdmpyhsusat_acc", "{ v2.w += vdmpy(v0.h,r3.uh):sat }"),
        ],
        16,
        0x7026,
    );
}

// ---- Wave 14: HVX Q<->V and Q<->R bridge ops (vand* family) ----
// vandvqv/vandvnqv gate Vu by a (seeded) Q mask into Vd; vandqrt/vandnqrt gate
// a per-byte broadcast of Rt by Qu into Vd; vandvrt builds a Q predicate from
// (Vu.ub & Rt.byte) != 0. The harness seeds Q0-3 and V0-31 randomly so both the
// set and clear mask paths (and the negate polarity) are exercised.

#[test]
fn lift_hvx_vand_qv() {
    lift_family(
        "hvx_vand_qv",
        &[
            ("vandvqv", "{ v2 = vand(q0,v1) }"),
            ("vandvnqv", "{ v2 = vand(!q0,v1) }"),
        ],
        16,
        0x7027,
    );
}

#[test]
fn lift_hvx_vand_qr() {
    lift_family(
        "hvx_vand_qr",
        &[
            ("vandqrt", "{ v2 = vand(q0,r3) }"),
            ("vandnqrt", "{ v2 = vand(!q0,r3) }"),
        ],
        16,
        0x7028,
    );
}

#[test]
fn lift_hvx_vand_vr() {
    lift_family(
        "hvx_vand_vr",
        &[("vandvrt", "{ q0 = vand(v1,r3) }")],
        16,
        0x7029,
    );
}

// ---- Wave 15: more HVX integer multiply variants ----
// vmpyuhe (even unsigned-halfword * Rt.uh0) via VBroadcast + VMulEvenWiden;
// vmpyiwb/vmpyiwub/vmpyiwh (word * Rt sub-element, low 32) and vmpyihb (half *
// Rt.b, low 16) via VBroadcast + a 1-tap VReduceMul that reuses the broadcast
// temp's per-lane sub-element exactly as the sem indexes Rt (i%4 / i%2). The
// `_acc` forms seed the dest vector to exercise the read-modify-write path.

#[test]
fn lift_hvx_vmpyuhe() {
    lift_family(
        "hvx_vmpyuhe",
        &[
            ("vmpyuhe", "{ v2.uw = vmpye(v0.uh,r3.uh) }"),
            ("vmpyuhe_acc", "{ v2.uw += vmpye(v0.uh,r3.uh) }"),
        ],
        16,
        0x7030,
    );
}

#[test]
fn lift_hvx_vmpyiw_scalar() {
    lift_family(
        "hvx_vmpyiw_scalar",
        &[
            ("vmpyiwb", "{ v2.w = vmpyi(v0.w,r3.b) }"),
            ("vmpyiwb_acc", "{ v2.w += vmpyi(v0.w,r3.b) }"),
            ("vmpyiwub", "{ v2.w = vmpyi(v0.w,r3.ub) }"),
            ("vmpyiwub_acc", "{ v2.w += vmpyi(v0.w,r3.ub) }"),
            ("vmpyiwh", "{ v2.w = vmpyi(v0.w,r3.h) }"),
            ("vmpyiwh_acc", "{ v2.w += vmpyi(v0.w,r3.h) }"),
        ],
        16,
        0x7031,
    );
}

#[test]
fn lift_hvx_vmpyihb_scalar() {
    lift_family(
        "hvx_vmpyihb_scalar",
        &[
            ("vmpyihb", "{ v2.h = vmpyi(v0.h,r3.b) }"),
            ("vmpyihb_acc", "{ v2.h += vmpyi(v0.h,r3.b) }"),
        ],
        16,
        0x7032,
    );
}

// vmpyie/vmpyio: word * (even/odd) sub-halfword of Vv, low 32, via VMulSubLane.
//   vmpyiewuh:     Vd.w[i] = Vu.w[i] * Vv.uh[even hw of word i]   (even, unsigned)
//   vmpyiewuh_acc: Vx.w[i] += same
//   vmpyiowh:      Vd.w[i] = Vu.w[i] * Vv.h[odd  hw of word i]    (odd, signed)
//   vmpyiewh_acc:  Vx.w[i] += Vu.w[i] * Vv.h[even hw of word i]   (even, signed)
// The `_acc` forms seed the dest vector to exercise the read-modify-write path.
#[test]
fn lift_hvx_vmpyie_vmpyio() {
    lift_family(
        "hvx_vmpyie_vmpyio",
        &[
            ("vmpyiewuh", "{ v2.w = vmpyie(v0.w,v1.uh) }"),
            ("vmpyiewuh_acc", "{ v2.w += vmpyie(v0.w,v1.uh) }"),
            ("vmpyiowh", "{ v2.w = vmpyio(v0.w,v1.h) }"),
            ("vmpyiewh_acc", "{ v2.w += vmpyie(v0.w,v1.h) }"),
        ],
        16,
        0x7033,
    );
}

// ---- Wave 17: vmpa scalar-pair byte/half multiply-add ----
// Source is a register PAIR Vuu = (V[u], V[u+1]); the scalar Rt's 4 sub-bytes
// are reused per output lane. Lowered as VBroadcast(Rt, I32) + VPairReduceMul:
//   dst_lo[i] = Vuu0.narrow[2i]   * Rt.sub[0] + Vuu1.narrow[2i]   * Rt.sub[1]
//   dst_hi[i] = Vuu0.narrow[2i+1] * Rt.sub[2] + Vuu1.narrow[2i+1] * Rt.sub[3]
// The `_acc` forms target the same dst pair, exercising the read-modify-write
// accumulate (wrapping in the low out_elem bits). Note: llvm-mc spells the
// vmpabuu (unsigned * unsigned) destination as `.h` (not `.uh`).
//   vmpabus: Vuu.ub * Rt.b  -> .h    vmpabuu: Vuu.ub * Rt.ub -> .h
//   vmpahb:  Vuu.h  * Rt.b  -> .w    vmpauhb: Vuu.uh * Rt.b  -> .w
#[test]
fn lift_hvx_vmpa_scalar() {
    lift_family(
        "hvx_vmpa_scalar",
        &[
            ("vmpabus", "{ v3:2.h = vmpa(v5:4.ub,r3.b) }"),
            ("vmpabus_acc", "{ v3:2.h += vmpa(v5:4.ub,r3.b) }"),
            ("vmpabuu", "{ v3:2.h = vmpa(v5:4.ub,r3.ub) }"),
            ("vmpabuu_acc", "{ v3:2.h += vmpa(v5:4.ub,r3.ub) }"),
            ("vmpahb", "{ v3:2.w = vmpa(v5:4.h,r3.b) }"),
            ("vmpahb_acc", "{ v3:2.w += vmpa(v5:4.h,r3.b) }"),
            ("vmpauhb", "{ v3:2.w = vmpa(v5:4.uh,r3.b) }"),
            ("vmpauhb_acc", "{ v3:2.w += vmpa(v5:4.uh,r3.b) }"),
        ],
        16,
        0x7034,
    );
}

// Wave 18: vmpa cross-PAIR byte multiply-add. BOTH operands are register
// pairs (Vuu, Vvv); result is a halfword pair. Per lane i (0..64), narrow
// byte lanes 2i / 2i+1 reduce-add across the two pair halves:
//   vmpabusv: Vuu.ub * Vvv.b  -> .h   vmpabuuv: Vuu.ub * Vvv.ub -> .h
#[test]
fn lift_hvx_vmpa_pairpair() {
    lift_family(
        "hvx_vmpa_pairpair",
        &[
            ("vmpabusv", "{ v3:2.h = vmpa(v5:4.ub,v7:6.b) }"),
            ("vmpabuuv", "{ v3:2.h = vmpa(v5:4.ub,v7:6.ub) }"),
        ],
        16,
        0x18a4,
    );
}

// vdealb4w: deal bytes 0,2 of each word from two vectors into one (VDealB4W).
#[test]
fn lift_hvx_vdealb4w() {
    lift_family(
        "hvx_vdealb4w",
        &[("vdealb4w", "{ v2.b = vdeale(v0.b,v1.b) }")],
        16,
        0x18b0,
    );
}

// vmpyewuh / vmpyowh: word * even/odd halfword, fractional (>>16 / <<1:sat >>15).
#[test]
fn lift_hvx_vmpyewuh_vmpyowh() {
    lift_family(
        "hvx_vmpyewuh_vmpyowh",
        &[
            ("vmpyewuh", "{ v2.w = vmpye(v0.w,v1.uh) }"),
            ("vmpyowh", "{ v2.w = vmpyo(v0.w,v1.h):<<1:sat }"),
            ("vmpyowh_rnd", "{ v2.w = vmpyo(v0.w,v1.h):<<1:rnd:sat }"),
            ("vmpyowh_sacc", "{ v2.w += vmpyo(v0.w,v1.h):<<1:sat:shift }"),
            ("vmpyowh_rnd_sacc", "{ v2.w += vmpyo(v0.w,v1.h):<<1:rnd:sat:shift }"),
        ],
        16,
        0x18c0,
    );
}

// vmpyieoh: Vd.w[i] = (Vu.h[even=2i] * Vv.h[odd=2i+1]) << 16, low 32 bits.
// Lowered as VMulSubLaneSh (sub-lanes BOTH operands: even half of Vu, odd half
// of Vv) with shl=16. Both halfwords are signed.
#[test]
fn lift_hvx_vmpyieoh() {
    lift_family(
        "hvx_vmpyieoh",
        &[("vmpyieoh", "{ v2.w = vmpyieo(v0.h,v1.h) }")],
        16,
        0x18c8,
    );
}

// vmpyewuh_64 / vmpyowh_64_acc: even/odd word*half multiply repacked into a
// 64-bit (vector-pair) result. Lowered as VMulWord64Pair (mode 0 / mode 1).
//   vmpyewuh_64:    Vdd = vmpye(Vu.w, Vv.uh)        prod>>16 -> hi, prod<<16 -> lo
//   vmpyowh_64_acc: Vxx += vmpyo(Vu.w, Vv.h)        accumulate into the pair,
//     repacking the low half of the product into the high half of the low reg.
// The _acc form seeds the dest pair (harness randomizes all V), exercising the
// read-modify-write accumulate + repack path.
#[test]
fn lift_hvx_vmpy_word64() {
    lift_family(
        "hvx_vmpy_word64",
        &[
            ("vmpyewuh_64", "{ v3:2 = vmpye(v0.w,v1.uh) }"),
            ("vmpyowh_64_acc", "{ v3:2 += vmpyo(v0.w,v1.h) }"),
        ],
        16,
        0x18c9,
    );
}

// vlut32 byte lookup-table family (VLut). Seeds randomize Vu/Vv/Rt so the
// group-match / nomatch / oracc paths are all exercised.
#[test]
fn lift_hvx_vlutvvb() {
    lift_family(
        "hvx_vlutvvb",
        &[
            ("vlutvvb", "{ v2.b = vlut32(v0.b,v1.b,r3) }"),
            ("vlutvvb_nm", "{ v2.b = vlut32(v0.b,v1.b,r3):nomatch }"),
            ("vlutvvbi", "{ v2.b = vlut32(v0.b,v1.b,#3) }"),
            ("vlutvvb_oracc", "{ v2.b |= vlut32(v0.b,v1.b,r3) }"),
            ("vlutvvb_oracci", "{ v2.b |= vlut32(v0.b,v1.b,#3) }"),
        ],
        16,
        0x18d0,
    );
}

// vlut16 halfword lookup-table -> pair (VLut16).
#[test]
fn lift_hvx_vlutvwh() {
    lift_family(
        "hvx_vlutvwh",
        &[
            ("vlutvwh", "{ v3:2.h = vlut16(v0.b,v1.h,r3) }"),
            ("vlutvwh_nm", "{ v3:2.h = vlut16(v0.b,v1.h,r3):nomatch }"),
            ("vlutvwhi", "{ v3:2.h = vlut16(v0.b,v1.h,#3) }"),
            ("vlutvwh_oracc", "{ v3:2.h |= vlut16(v0.b,v1.h,r3) }"),
            ("vlutvwh_oracci", "{ v3:2.h |= vlut16(v0.b,v1.h,#3) }"),
        ],
        16,
        0x18e0,
    );
}

// vshuffvdd: Rt-controlled byte swap network over a pair (VShuffVdd).
#[test]
fn lift_hvx_vshuffvdd() {
    lift_family(
        "hvx_vshuffvdd",
        &[("vshuffvdd", "{ v3:2 = vshuff(v5,v4,r3) }")],
        16,
        0x18f0,
    );
}

// vdelta/vrdelta: Vv-controlled byte butterfly permute (VDelta).
#[test]
fn lift_hvx_vdelta() {
    lift_family(
        "hvx_vdelta",
        &[
            ("vdelta", "{ v2 = vdelta(v0,v1) }"),
            ("vrdelta", "{ v2 = vrdelta(v0,v1) }"),
        ],
        16,
        0x1900,
    );
}

// ---- Wave 19: cross-register SLIDING-WINDOW reduces (OpKind::VSlideReduceMul).
// Source is a register PAIR Vuu = (V[u], V[u+1]); the window straddles the pair
// boundary so V[u+1] supplies the elements that slide into the high output. Rt
// is I32-broadcast into a temp so its sub-elements are reused per output lane.

// _dv 2-tap sliding (mode 0, pair -> pair):
//   vdmpyhb_dv : Vuu.h  * Rt.b -> .w
//   vdmpybus_dv: Vuu.ub * Rt.b -> .h
#[test]
fn lift_hvx_vdmpy_dv() {
    lift_family(
        "hvx_vdmpy_dv",
        &[
            ("vdmpyhb_dv", "{ v3:2.w = vdmpy(v5:4.h,r6.b) }"),
            ("vdmpyhb_dv_acc", "{ v3:2.w += vdmpy(v5:4.h,r6.b) }"),
            ("vdmpybus_dv", "{ v3:2.h = vdmpy(v5:4.ub,r6.b) }"),
            ("vdmpybus_dv_acc", "{ v3:2.h += vdmpy(v5:4.ub,r6.b) }"),
        ],
        16,
        0x1910,
    );
}

// vtmpy 3-tap sliding with a free (un-multiplied) addend tap (mode 1, pair->pair):
//   vtmpyb  : Vuu.b  * Rt.b -> .h
//   vtmpybus: Vuu.ub * Rt.b -> .h
//   vtmpyhb : Vuu.h  * Rt.b -> .w
#[test]
fn lift_hvx_vtmpy() {
    lift_family(
        "hvx_vtmpy",
        &[
            ("vtmpyb", "{ v3:2.h = vtmpy(v5:4.b,r6.b) }"),
            ("vtmpyb_acc", "{ v3:2.h += vtmpy(v5:4.b,r6.b) }"),
            ("vtmpybus", "{ v3:2.h = vtmpy(v5:4.ub,r6.b) }"),
            ("vtmpybus_acc", "{ v3:2.h += vtmpy(v5:4.ub,r6.b) }"),
            ("vtmpyhb", "{ v3:2.w = vtmpy(v5:4.h,r6.b) }"),
            ("vtmpyhb_acc", "{ v3:2.w += vtmpy(v5:4.h,r6.b) }"),
        ],
        16,
        0x1920,
    );
}

// pair -> SINGLE straddle, saturated (mode 2):
//   vdmpyhisat   : Vuu.h * Rt.h  -> .w :sat
//   vdmpyhsuisat : Vuu.h * Rt.uh -> .w :sat (the #1 is structural, not an operand)
#[test]
fn lift_hvx_vdmpyhisat() {
    lift_family(
        "hvx_vdmpyhisat",
        &[
            ("vdmpyhisat", "{ v2.w = vdmpy(v5:4.h,r6.h):sat }"),
            ("vdmpyhisat_acc", "{ v2.w += vdmpy(v5:4.h,r6.h):sat }"),
            ("vdmpyhsuisat", "{ v2.w = vdmpy(v5:4.h,r6.uh,#1):sat }"),
            ("vdmpyhsuisat_acc", "{ v2.w += vdmpy(v5:4.h,r6.uh,#1):sat }"),
        ],
        16,
        0x1930,
    );
}

// ---- Wave 20: #u1-byte-rotate pair reduce + sum-of-abs-diff
// (OpKind::VRotReduceMulPair). Source AND dest are register PAIRs. Rt is
// I32-broadcast so its sub-bytes/halfwords are reused per output lane.
//
// vrmpyubi/vrmpybusi (+_acc): 4-tap byte word reduce with a #u1 source-select
// (sel = imm ? v1 : v0) and an Rt byte rotate by -imm. ubi = Rt.ub unsigned,
// busi = Rt.b signed. Both #0 and #1 immediates are exercised so the
// source-select and rotate paths are covered.
#[test]
fn lift_hvx_vrmpy_pair_imm() {
    lift_family(
        "hvx_vrmpy_pair_imm",
        &[
            ("vrmpyubi_0", "{ v3:2.uw = vrmpy(v5:4.ub,r6.ub,#0) }"),
            ("vrmpyubi_1", "{ v3:2.uw = vrmpy(v5:4.ub,r6.ub,#1) }"),
            ("vrmpyubi_acc0", "{ v3:2.uw += vrmpy(v5:4.ub,r6.ub,#0) }"),
            ("vrmpyubi_acc1", "{ v3:2.uw += vrmpy(v5:4.ub,r6.ub,#1) }"),
            ("vrmpybusi_0", "{ v3:2.w = vrmpy(v5:4.ub,r6.b,#0) }"),
            ("vrmpybusi_1", "{ v3:2.w = vrmpy(v5:4.ub,r6.b,#1) }"),
            ("vrmpybusi_acc0", "{ v3:2.w += vrmpy(v5:4.ub,r6.b,#0) }"),
            ("vrmpybusi_acc1", "{ v3:2.w += vrmpy(v5:4.ub,r6.b,#1) }"),
        ],
        16,
        0x1940,
    );
}

// vrsadubi (+_acc): SAME byte window/imm-rotate but each tap is |Vuu.ub - Rt.ub|
// (sum of absolute differences). Rt unsigned.
#[test]
fn lift_hvx_vrsad_pair_imm() {
    lift_family(
        "hvx_vrsad_pair_imm",
        &[
            ("vrsadubi_0", "{ v3:2.uw = vrsad(v5:4.ub,r6.ub,#0) }"),
            ("vrsadubi_1", "{ v3:2.uw = vrsad(v5:4.ub,r6.ub,#1) }"),
            ("vrsadubi_acc0", "{ v3:2.uw += vrsad(v5:4.ub,r6.ub,#0) }"),
            ("vrsadubi_acc1", "{ v3:2.uw += vrsad(v5:4.ub,r6.ub,#1) }"),
        ],
        16,
        0x1950,
    );
}

// vdsaduh (+_acc): dual SAD over UNSIGNED halfwords (mode 1, no imm):
//   o0[i] = |v0.uh[2i]-Rt.uh[0]| + |v0.uh[2i+1]-Rt.uh[1]|
//   o1[i] = |v0.uh[2i+1]-Rt.uh[0]| + |v1.uh[2i]-Rt.uh[1]|
#[test]
fn lift_hvx_vdsaduh() {
    lift_family(
        "hvx_vdsaduh",
        &[
            ("vdsaduh", "{ v3:2.uw = vdsad(v5:4.uh,r6.uh) }"),
            ("vdsaduh_acc", "{ v3:2.uw += vdsad(v5:4.uh,r6.uh) }"),
        ],
        16,
        0x1960,
    );
}
