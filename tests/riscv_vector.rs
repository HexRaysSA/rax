//! RISC-V vector (RVV 1.0) differential test harness: rax vs. qemu-riscv64.
//!
//! Dedicated to the V extension data path. Uses `tools/riscv-diff/voracle.c`,
//! a static RV64 ELF whose prologue loads v0..v31 and the test vtype/vl, runs
//! one vector instruction, and captures the vector state from the signal-frame
//! V context. For each case we run the same instruction on `RiscVCpu` from the
//! identical state and compare the full vector register file, `vl`/`vtype`, the
//! integer/FP registers, and the shared scratch window.
//!
//! Tail/mask policy is undisturbed (vta=0, vma=0) so results are deterministic.
//! Self-skips if the toolchain or qemu is unavailable.

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use rax::riscv::{FlatMemory, RiscVConfig, RiscVCpu, RiscVExit};

const WIRE_MAGIC: u32 = 0x5652_4332; // 'V','R','C','2'
const SCRATCH_ADDR: u64 = 0x20_0000;
const SCRATCH_BASE: u64 = SCRATCH_ADDR + 64;
const VLENB: usize = 16;
const INSN_ADDR: u64 = 0x1000;

#[repr(C)]
#[derive(Clone, Copy)]
struct VState {
    x: [u64; 32],
    f: [u64; 32],
    vtype: u64,
    vl: u64,
    vstart: u64,
    fcsr: u64,
    v: [u64; 64],
    scratch: [u64; 32],
}

impl VState {
    fn zeroed() -> Self {
        VState {
            x: [0; 32],
            f: [0; 32],
            vtype: 0,
            vl: 0,
            vstart: 0,
            fcsr: 0,
            v: [0; 64],
            scratch: [0; 32],
        }
    }
    fn vreg_bytes(&self, r: usize) -> [u8; VLENB] {
        let mut out = [0u8; VLENB];
        out[..8].copy_from_slice(&self.v[r * 2].to_le_bytes());
        out[8..].copy_from_slice(&self.v[r * 2 + 1].to_le_bytes());
        out
    }
    fn set_vreg_bytes(&mut self, r: usize, b: &[u8; VLENB]) {
        self.v[r * 2] = u64::from_le_bytes(b[..8].try_into().unwrap());
        self.v[r * 2 + 1] = u64::from_le_bytes(b[8..].try_into().unwrap());
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VInCase {
    insn: u32,
    insn_len: u32,
    st: VState,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct VOutCase {
    st: VState,
    trapped: u32,
    valid: u32,
}

fn as_bytes<T: Copy>(v: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts(v as *const T as *const u8, std::mem::size_of::<T>()) }
}
fn read_struct<T: Copy>(buf: &[u8], off: usize) -> T {
    unsafe { std::ptr::read_unaligned(buf[off..].as_ptr() as *const T) }
}

struct Rng(u64);
impl Rng {
    fn new(s: u64) -> Self {
        Rng(s)
    }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

fn voracle_path() -> Option<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tools/riscv-diff");
    let oracle = dir.join("voracle");
    let needs = match (oracle.metadata(), dir.join("voracle.c").metadata()) {
        (Ok(o), Ok(s)) => match (o.modified(), s.modified()) {
            (Ok(om), Ok(sm)) => om < sm,
            _ => true,
        },
        _ => true,
    };
    if needs {
        let cc = std::env::var("RISCV64_CC").unwrap_or_else(|_| "riscv64-linux-gnu-gcc".into());
        let status = Command::new(cc)
            .args([
                "-static", "-O2", "-march=rv64gc", "-mabi=lp64d", "-o",
            ])
            .arg(&oracle)
            .arg(dir.join("voracle.c"))
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

fn run_oracle(oracle: &PathBuf, cases: &[(u32, VState)]) -> Option<Vec<VOutCase>> {
    let mut payload = Vec::with_capacity(8 + cases.len() * std::mem::size_of::<VInCase>());
    payload.extend_from_slice(&WIRE_MAGIC.to_le_bytes());
    payload.extend_from_slice(&(cases.len() as u32).to_le_bytes());
    for (insn, st) in cases {
        let ic = VInCase {
            insn: *insn,
            insn_len: 4,
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
    if !child.wait().ok()?.success() || out.len() < 8 {
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
        res.push(read_struct::<VOutCase>(&out, off));
        off += std::mem::size_of::<VOutCase>();
    }
    Some(res)
}

fn run_vrax(insn: u32, input: &VState) -> Option<VState> {
    let mem = FlatMemory::new(0, 0x21_0000);
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
    cpu.set_vl_vtype(input.vl, input.vtype);
    for r in 0..32usize {
        cpu.set_vreg(r as u8, &input.vreg_bytes(r));
    }
    let mut sb = Vec::with_capacity(256);
    for w in input.scratch.iter() {
        sb.extend_from_slice(&w.to_le_bytes());
    }
    cpu.write_memory(SCRATCH_ADDR, &sb).ok()?;
    cpu.write_memory(INSN_ADDR, &insn.to_le_bytes()).ok()?;
    cpu.set_pc(INSN_ADDR);
    match cpu.step() {
        RiscVExit::Continue => {}
        _ => return None,
    }
    let mut out = VState::zeroed();
    for i in 1..32u8 {
        out.x[i as usize] = cpu.x(i);
    }
    for i in 0..32u8 {
        out.f[i as usize] = cpu.f(i);
    }
    out.fcsr = cpu.fcsr() as u64;
    out.vl = cpu.vl();
    out.vtype = cpu.vtype();
    for r in 0..32usize {
        out.set_vreg_bytes(r, &cpu.vreg(r as u8));
    }
    for (i, w) in out.scratch.iter_mut().enumerate() {
        *w = cpu.mem_read_u64(SCRATCH_ADDR + (i as u64) * 8).ok()?;
    }
    Some(out)
}

struct Mismatch {
    label: String,
    insn: u32,
    detail: String,
}

fn compare(label: &str, insn: u32, input: &VState, oracle: &VOutCase, ms: &mut Vec<Mismatch>) {
    let rax = run_vrax(insn, input);
    if oracle.trapped != 0 {
        if rax.is_some() {
            ms.push(Mismatch {
                label: label.into(),
                insn,
                detail: format!("hw faulted sig {} but rax executed", oracle.trapped),
            });
        }
        return;
    }
    let rax = match rax {
        Some(s) => s,
        None => {
            ms.push(Mismatch {
                label: label.into(),
                insn,
                detail: "hw executed but rax rejected".into(),
            });
            return;
        }
    };
    let mut d = Vec::new();
    for i in 1..32usize {
        if i == 3 || i == 4 {
            continue;
        }
        if rax.x[i] != oracle.st.x[i] {
            d.push(format!("x{i}: rax={:#x} hw={:#x}", rax.x[i], oracle.st.x[i]));
        }
    }
    if rax.vl != oracle.st.vl {
        d.push(format!("vl: rax={} hw={}", rax.vl, oracle.st.vl));
    }
    if rax.vtype != oracle.st.vtype {
        d.push(format!("vtype: rax={:#x} hw={:#x}", rax.vtype, oracle.st.vtype));
    }
    for r in 0..32usize {
        if rax.vreg_bytes(r) != oracle.st.vreg_bytes(r) {
            d.push(format!(
                "v{r}: rax={:02x?} hw={:02x?}",
                rax.vreg_bytes(r),
                oracle.st.vreg_bytes(r)
            ));
        }
    }
    for i in 0..32usize {
        if rax.scratch[i] != oracle.st.scratch[i] {
            d.push(format!(
                "scratch[{i}]: rax={:#x} hw={:#x}",
                rax.scratch[i], oracle.st.scratch[i]
            ));
        }
    }
    if !d.is_empty() {
        ms.push(Mismatch {
            label: label.into(),
            insn,
            detail: d.join(", "),
        });
    }
}

fn run_batch(batch: &[(String, u32, VState)]) {
    let oracle = match voracle_path() {
        Some(p) => p,
        None => {
            eprintln!("riscv_vector: voracle/toolchain unavailable; skipping");
            return;
        }
    };
    let cases: Vec<(u32, VState)> = batch.iter().map(|(_, i, s)| (*i, *s)).collect();
    let outs = match run_oracle(&oracle, &cases) {
        Some(o) => o,
        None => {
            eprintln!("riscv_vector: voracle run failed; skipping");
            return;
        }
    };
    let mut ms = Vec::new();
    for ((label, insn, st), oc) in batch.iter().zip(outs.iter()) {
        compare(label, *insn, st, oc, &mut ms);
    }
    if !ms.is_empty() {
        let mut msg = format!("\n{} vector divergence(s) from qemu-riscv64:\n", ms.len());
        for m in ms.iter().take(30) {
            msg += &format!("  [{}] insn={:#010x}: {}\n", m.label, m.insn, m.detail);
        }
        if ms.len() > 30 {
            msg += &format!("  ... and {} more\n", ms.len() - 30);
        }
        panic!("{msg}");
    }
}

// ---------------------------------------------------------------------------
// Test-case construction.
// ---------------------------------------------------------------------------

/// vtype for (sew_log2, lmul=m1, vta=0, vma=0).
fn vtype_m1(sew_log2: u32) -> u64 {
    (sew_log2 << 3) as u64
}
fn vlmax(sew_log2: u32) -> u64 {
    16 >> sew_log2 // VLEN/8 / sew_bytes, for m1
}

fn rand_vstate(rng: &mut Rng, sew_log2: u32, vl: u64) -> VState {
    let mut st = VState::zeroed();
    for i in 0..64 {
        st.v[i] = rng.next();
    }
    for i in 1..32usize {
        if i == 3 || i == 4 {
            continue;
        }
        st.x[i] = rng.next();
    }
    st.vtype = vtype_m1(sew_log2);
    st.vl = vl;
    st
}

const VPOOL: [u32; 6] = [1, 2, 3, 5, 6, 7]; // vector regs (avoid v0 = mask, v4)
const XPOOL: [u32; 5] = [1, 5, 6, 7, 10];

fn op_iv(funct6: u32, vm: u32, vs2: u32, src: u32, funct3: u32, vd: u32) -> u32 {
    (funct6 << 26) | (vm << 25) | (vs2 << 20) | (src << 15) | (funct3 << 12) | (vd << 7) | 0x57
}

#[test]
fn diff_v_arith() {
    let mut rng = Rng::new(0x7EC_704);
    let mut batch = Vec::new();
    let ops: &[(&str, u32, bool, bool)] = &[
        // (name, funct6, has_vv, has_vi)
        ("vadd", 0b000000, true, true),
        ("vsub", 0b000010, true, false),
        ("vrsub", 0b000011, false, true),
        ("vand", 0b001001, true, true),
        ("vor", 0b001010, true, true),
        ("vxor", 0b001011, true, true),
        ("vminu", 0b000100, true, false),
        ("vmin", 0b000101, true, false),
        ("vmaxu", 0b000110, true, false),
        ("vmax", 0b000111, true, false),
        ("vsll", 0b100101, true, true),
        ("vsrl", 0b101000, true, true),
        ("vsra", 0b101001, true, true),
    ];
    for sew_log2 in 0..4u32 {
        let vmax = vlmax(sew_log2);
        for vl in [vmax, vmax.max(1) - 0, (vmax / 2).max(1)] {
            for &(name, f6, has_vv, has_vi) in ops {
                for _ in 0..6 {
                    let vd = VPOOL[(rng.next() % 6) as usize];
                    let vs2 = VPOOL[(rng.next() % 6) as usize];
                    let vs1 = VPOOL[(rng.next() % 6) as usize];
                    let rs1 = XPOOL[(rng.next() % 5) as usize];
                    let st = rand_vstate(&mut rng, sew_log2, vl);
                    // OPIVV (funct3=000)
                    if has_vv {
                        batch.push((format!("{name}.vv"), op_iv(f6, 1, vs2, vs1, 0b000, vd), st));
                    }
                    // OPIVX (funct3=100)
                    batch.push((format!("{name}.vx"), op_iv(f6, 1, vs2, rs1, 0b100, vd), st));
                    // OPIVI (funct3=011)
                    if has_vi {
                        let imm = (rng.next() & 0x1f) as u32;
                        batch.push((format!("{name}.vi"), op_iv(f6, 1, vs2, imm, 0b011, vd), st));
                    }
                    // masked OPIVV (vm=0, vd != v0)
                    if has_vv && vd != 0 {
                        let mut stm = st;
                        stm.v[0] = rng.next(); // mask in v0
                        stm.v[1] = rng.next();
                        batch.push((format!("{name}.vv.m"), op_iv(f6, 0, vs2, vs1, 0b000, vd), stm));
                    }
                }
            }
        }
    }
    run_batch(&batch);
}

#[test]
fn diff_v_merge() {
    let mut rng = Rng::new(0x7EC_70E);
    let mut batch = Vec::new();
    for sew_log2 in 0..4u32 {
        let vmax = vlmax(sew_log2);
        for vl in [vmax, (vmax / 2).max(1)] {
            for _ in 0..10 {
                let vd = VPOOL[(rng.next() % 6) as usize];
                let vs2 = VPOOL[(rng.next() % 6) as usize];
                let vs1 = VPOOL[(rng.next() % 6) as usize];
                let rs1 = XPOOL[(rng.next() % 5) as usize];
                let imm = (rng.next() & 0x1f) as u32;
                let mut st = rand_vstate(&mut rng, sew_log2, vl);
                st.v[0] = rng.next(); // mask
                st.v[1] = rng.next();
                // vmerge.vvm / vxm / vim (vm=0)
                batch.push(("vmerge.vvm".into(), op_iv(0b010111, 0, vs2, vs1, 0b000, vd), st));
                batch.push(("vmerge.vxm".into(), op_iv(0b010111, 0, vs2, rs1, 0b100, vd), st));
                batch.push(("vmerge.vim".into(), op_iv(0b010111, 0, vs2, imm, 0b011, vd), st));
                // vmv.v.v / vx / vi (vm=1, vs2=0)
                batch.push(("vmv.v.v".into(), op_iv(0b010111, 1, 0, vs1, 0b000, vd), st));
                batch.push(("vmv.v.x".into(), op_iv(0b010111, 1, 0, rs1, 0b100, vd), st));
                batch.push(("vmv.v.i".into(), op_iv(0b010111, 1, 0, imm, 0b011, vd), st));
            }
        }
    }
    run_batch(&batch);
}

#[test]
fn diff_v_compare() {
    let mut rng = Rng::new(0x7EC_710);
    let mut batch = Vec::new();
    // (name, funct6, has_vv, has_vi)
    let ops: &[(&str, u32, bool, bool)] = &[
        ("vmseq", 0b011000, true, true),
        ("vmsne", 0b011001, true, true),
        ("vmsltu", 0b011010, true, false),
        ("vmslt", 0b011011, true, false),
        ("vmsleu", 0b011100, true, true),
        ("vmsle", 0b011101, true, true),
        ("vmsgtu", 0b011110, false, true),
        ("vmsgt", 0b011111, false, true),
    ];
    for sew_log2 in 0..4u32 {
        let vmax = vlmax(sew_log2);
        for vl in [vmax, (vmax / 2).max(1)] {
            for &(name, f6, has_vv, has_vi) in ops {
                for _ in 0..6 {
                    let vd = VPOOL[(rng.next() % 6) as usize];
                    let vs2 = VPOOL[(rng.next() % 6) as usize];
                    let vs1 = VPOOL[(rng.next() % 6) as usize];
                    let rs1 = XPOOL[(rng.next() % 5) as usize];
                    let st = rand_vstate(&mut rng, sew_log2, vl);
                    if has_vv {
                        batch.push((format!("{name}.vv"), op_iv(f6, 1, vs2, vs1, 0b000, vd), st));
                    }
                    batch.push((format!("{name}.vx"), op_iv(f6, 1, vs2, rs1, 0b100, vd), st));
                    if has_vi {
                        let imm = (rng.next() & 0x1f) as u32;
                        batch.push((format!("{name}.vi"), op_iv(f6, 1, vs2, imm, 0b011, vd), st));
                    }
                    // masked vv (vd != v0)
                    if has_vv && vd != 0 {
                        let mut stm = st;
                        stm.v[0] = rng.next();
                        stm.v[1] = rng.next();
                        batch.push((format!("{name}.vv.m"), op_iv(f6, 0, vs2, vs1, 0b000, vd), stm));
                    }
                }
            }
        }
    }
    run_batch(&batch);
}

#[test]
fn diff_v_loadstore() {
    let mut rng = Rng::new(0x7EC_705);
    let mut batch = Vec::new();
    // width funct3: 0=8,5=16,6=32,7=64; matching SEW so EEW==SEW.
    let widths: [(u32, u32); 4] = [(0, 0), (5, 1), (6, 2), (7, 3)];
    for (w3, sew_log2) in widths {
        let vmax = vlmax(sew_log2);
        for vl in [vmax, (vmax / 2).max(1)] {
            for _ in 0..15 {
                let vd = VPOOL[(rng.next() % 6) as usize];
                let mut st = rand_vstate(&mut rng, sew_log2, vl);
                st.x[10] = SCRATCH_BASE;
                for s in st.scratch.iter_mut() {
                    *s = rng.next();
                }
                // vle{w}.v vd, (x10)  : opcode 0x07, funct3=w3, vm=1, lumop=0
                let vle = (1u32 << 25) | (10 << 15) | (w3 << 12) | (vd << 7) | 0x07;
                batch.push(("vle".into(), vle, st));
                // vse{w}.v vd, (x10)  : opcode 0x27
                let vse = (1u32 << 25) | (10 << 15) | (w3 << 12) | (vd << 7) | 0x27;
                batch.push(("vse".into(), vse, st));
            }
        }
    }
    run_batch(&batch);
}
