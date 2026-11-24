//! Differential tests for the RAX AArch32 user CPU and interpreter against
//! `qemu-arm` (Cortex-A15 user mode), covering ARM and both Thumb widths.
//! The reference harness is `tools/arm-diff/oracle-a32.c`, built on demand into a
//! static 32-bit ARM ELF. This mirrors `tests/suites/differential/arm/aarch64.rs` (the AArch64 harness).
//!
//! Both engines run the same instruction and input. The tests compare R0..R14,
//! successor PC relative to the instruction, CPSR flags and execution state,
//! D0..D31, FPSCR, and the scratch window.
//!
//! The oracle tests require both tools with `A32DIFF_REQUIRE=1`. Otherwise,
//! missing tools skip the external comparison. A broken oracle fails the test.

#![cfg(target_os = "linux")]

use std::ffi::OsStr;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use rax::isa::arm::aarch32::vfp::Fpscr;
use rax::user::cpu::arm::{A32Exit, A32UserCpu};
use rax::user::mm::{AddressSpace, Mapping, Perms, SpaceConfig};

// ---------------------------------------------------------------------------
// Wire format -- must match tools/arm-diff/oracle-a32.c byte for byte.
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
struct ArmState32 {
    r: [u32; 15],       // R0..R14
    pc: u32,            // output: next PC relative to the instruction
    cpsr: u32,          // NZCVQ (31:27) + GE (19:16) + T (5)
    fpscr: u32,         // VFP status/control
    d: [u64; 32],       // D0..D31 (NEON Q0..Q15)
    scratch: [u32; 64], // shared scratch window (256 bytes)
}

/// Address of the shared scratch window (matches oracle-a32.c SCRATCH_ADDR).
const SCRATCH_ADDR: u32 = 0x20_0000;
/// Base pointer tests aim a register at (matches oracle-a32.c SCRATCH_BASE).
const SCRATCH_BASE: u32 = SCRATCH_ADDR + 128;

impl ArmState32 {
    fn zeroed() -> Self {
        ArmState32 {
            r: [0; 15],
            pc: 0,
            cpsr: 0,
            fpscr: 0,
            d: [0; 32],
            scratch: [0; 64],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct InCase32 {
    insn: u32,
    mode: u32, // 0 = ARM, 1 = Thumb16, 2 = Thumb32
    st: ArmState32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct OutCase32 {
    st: ArmState32,
    trapped: u32,
    valid: u32,
}

const WIRE_MAGIC: u32 = 0x3232_3341; // 'A','3','2','2'

// Compile-time guarantee the layout matches the C side.
const _: () = assert!(core::mem::size_of::<ArmState32>() == 584);
const _: () = assert!(core::mem::size_of::<InCase32>() == 592);
const _: () = assert!(core::mem::size_of::<OutCase32>() == 592);

// CPSR bits we compare: NZCVQ (31:27), GE (19:16), and T (5).
const CPSR_CMP_MASK: u32 = 0xf80f_0020;

// ---------------------------------------------------------------------------
// Byte (de)serialisation helpers.
// ---------------------------------------------------------------------------

fn as_bytes<T: Copy>(v: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts(v as *const T as *const u8, std::mem::size_of::<T>()) }
}

fn read_struct<T: Copy>(buf: &[u8], off: usize) -> T {
    assert!(off + std::mem::size_of::<T>() <= buf.len());
    unsafe { std::ptr::read_unaligned(buf[off..].as_ptr() as *const T) }
}

// ---------------------------------------------------------------------------
// Oracle: build on demand, run a whole batch through one qemu invocation.
// ---------------------------------------------------------------------------

fn oracle_path() -> Option<&'static Path> {
    static ORACLE: OnceLock<Option<PathBuf>> = OnceLock::new();
    ORACLE
        .get_or_init(|| {
            let compiler =
                std::env::var_os("ARM32_CC").unwrap_or_else(|| "arm-linux-gnueabihf-gcc".into());
            let missing = [OsStr::new("qemu-arm"), compiler.as_os_str()]
                .into_iter()
                .find(|tool| !tool_available(tool));
            if let Some(tool) = missing {
                assert_ne!(
                    std::env::var_os("A32DIFF_REQUIRE").as_deref(),
                    Some(OsStr::new("1")),
                    "required AArch32 oracle tool {tool:?} is unavailable"
                );
                eprintln!("[arm_diff32] optional oracle tool {tool:?} is unavailable");
                return None;
            }
            let output_dir = Path::new(env!("CARGO_TARGET_TMPDIR"));
            std::fs::create_dir_all(output_dir).expect("create AArch32 oracle build directory");
            let binary = output_dir.join(format!("oracle-a32-{}", std::process::id()));
            let status = Command::new("bash")
                .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tools/arm-diff/build-a32.sh"))
                .arg(&binary)
                .stdout(Stdio::null())
                .status()
                .expect("launch AArch32 oracle build");
            assert!(status.success(), "AArch32 oracle build failed: {status}");
            Some(binary)
        })
        .as_deref()
}

fn tool_available(program: &OsStr) -> bool {
    let path = Path::new(program);
    if path.components().count() > 1 {
        return path.is_file();
    }
    std::env::var_os("PATH")
        .is_some_and(|search| std::env::split_paths(&search).any(|dir| dir.join(path).is_file()))
}

fn run_oracle(oracle: &Path, cases: &[(String, u32, u32, ArmState32)]) -> Vec<OutCase32> {
    let mut payload = Vec::with_capacity(8 + cases.len() * std::mem::size_of::<InCase32>());
    payload.extend_from_slice(&WIRE_MAGIC.to_le_bytes());
    payload.extend_from_slice(&(cases.len() as u32).to_le_bytes());
    for (_, insn, mode, st) in cases {
        let ic = InCase32 {
            insn: *insn,
            mode: *mode,
            st: *st,
        };
        payload.extend_from_slice(as_bytes(&ic));
    }

    let mut child = Command::new("qemu-arm")
        .args(["-cpu", "cortex-a15"])
        .arg(oracle)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("launch the AArch32 oracle under QEMU");
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || stdin.write_all(&payload));
    let output = child
        .wait_with_output()
        .expect("read AArch32 oracle output");
    assert!(
        output.status.success(),
        "AArch32 oracle exited with {}",
        output.status
    );
    writer
        .join()
        .expect("oracle input writer panicked")
        .expect("write AArch32 oracle input");

    let out = output.stdout;
    let record_size = std::mem::size_of::<OutCase32>();
    assert_eq!(
        out.len(),
        8 + cases.len() * record_size,
        "oracle output size"
    );
    assert_eq!(
        u32::from_le_bytes(out[..4].try_into().unwrap()),
        WIRE_MAGIC,
        "oracle wire version"
    );
    assert_eq!(
        u32::from_le_bytes(out[4..8].try_into().unwrap()) as usize,
        cases.len(),
        "oracle record count"
    );
    out[8..]
        .chunks_exact(record_size)
        .zip(cases)
        .map(|(record, (label, ..))| {
            let state = read_struct::<OutCase32>(record, 0);
            assert_eq!(
                state.valid, 1,
                "{label}: QEMU did not capture the VFP frame"
            );
            state
        })
        .collect()
}

// ---------------------------------------------------------------------------
// rax: run one instruction from an identical initial state.
// ---------------------------------------------------------------------------

/// Returns the architectural state after one instruction, or None on a guest trap.
fn run_rax(insn: u32, mode: u32, input: &ArmState32) -> Option<ArmState32> {
    const CODE_ADDR: u64 = 0x10_000;
    const PAGE_SIZE: u64 = 4096;
    let space = AddressSpace::new(SpaceConfig {
        va_limit: 1 << 32,
        arena_bytes: 4 * PAGE_SIZE,
        reserved_phys: Vec::new(),
    })
    .expect("allocate AArch32 test memory");
    let rw = Perms::READ | Perms::WRITE;
    space
        .map(CODE_ADDR, PAGE_SIZE, Mapping::anonymous(rw | Perms::EXEC))
        .expect("map instruction page");
    space
        .map(u64::from(SCRATCH_ADDR), PAGE_SIZE, Mapping::anonymous(rw))
        .expect("map scratch page");
    let (code, width) = match mode {
        0 => (insn.to_le_bytes(), 4),
        1 => (insn.to_le_bytes(), 2),
        2 => (insn.rotate_left(16).to_le_bytes(), 4),
        _ => panic!("unknown AArch32 oracle mode {mode}"),
    };
    space
        .write(CODE_ADDR, &code[..width])
        .expect("install instruction");
    space
        .write(u64::from(SCRATCH_ADDR), as_bytes(&input.scratch))
        .expect("install scratch data");

    let mut cpu = A32UserCpu::new(&space);
    cpu.set_pc(CODE_ADDR);
    let core = cpu.core_mut();
    core.regs[..15].copy_from_slice(&input.r);
    core.cpsr.n = input.cpsr & (1 << 31) != 0;
    core.cpsr.z = input.cpsr & (1 << 30) != 0;
    core.cpsr.c = input.cpsr & (1 << 29) != 0;
    core.cpsr.v = input.cpsr & (1 << 28) != 0;
    core.cpsr.q = input.cpsr & (1 << 27) != 0;
    core.cpsr.ge = ((input.cpsr >> 16) & 0xf) as u8;
    core.cpsr.t = mode != 0;
    core.vfp.dregs = input.d;
    core.vfp.fpscr = Fpscr::from_bits(input.fpscr);

    match cpu.step_instruction() {
        None => (),
        Some(A32Exit::Internal(reason)) => panic!("AArch32 test CPU failed: {reason}"),
        Some(_) => return None,
    }

    let core = cpu.core();
    let mut out = ArmState32::zeroed();
    out.r.copy_from_slice(&core.regs[..15]);
    out.pc = (cpu.pc() as u32).wrapping_sub(CODE_ADDR as u32);
    out.cpsr = core.cpsr.to_u32();
    out.d = core.vfp.dregs;
    out.fpscr = core.vfp.fpscr.bits();
    let mut scratch = [0; 256];
    space
        .read(u64::from(SCRATCH_ADDR), &mut scratch)
        .expect("capture scratch data");
    for (word, bytes) in out.scratch.iter_mut().zip(scratch.chunks_exact(4)) {
        *word = u32::from_le_bytes(bytes.try_into().unwrap());
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Comparison.
// ---------------------------------------------------------------------------

struct Mismatch {
    label: String,
    insn: u32,
    detail: String,
}

fn compare_case(
    label: &str,
    insn: u32,
    mode: u32,
    input: &ArmState32,
    oracle: &OutCase32,
    mismatches: &mut Vec<Mismatch>,
) {
    let rax = run_rax(insn, mode, input);

    if oracle.trapped != 0 {
        if rax.is_some() {
            mismatches.push(Mismatch {
                label: label.into(),
                insn,
                detail: format!(
                    "QEMU faulted (sig {}) but RAX executed the encoding",
                    oracle.trapped
                ),
            });
        }
        return;
    }
    let rax = match rax {
        Some(s) => s,
        None => {
            mismatches.push(Mismatch {
                label: label.into(),
                insn,
                detail: "QEMU executed but RAX rejected the encoding (undefined/err)".into(),
            });
            return;
        }
    };

    let mut diffs = Vec::new();
    for i in 0..15 {
        if rax.r[i] != oracle.st.r[i] {
            diffs.push(format!(
                "r{i}: rax={:#010x} qemu={:#010x}",
                rax.r[i], oracle.st.r[i]
            ));
        }
    }
    let rax_cpsr = rax.cpsr & CPSR_CMP_MASK;
    let hw_cpsr = oracle.st.cpsr & CPSR_CMP_MASK;
    if rax_cpsr != hw_cpsr {
        diffs.push(format!(
            "cpsr(NZCVQ+GE+T): rax={:#010x} qemu={:#010x}",
            rax_cpsr, hw_cpsr
        ));
    }
    if rax.pc != oracle.st.pc {
        diffs.push(format!(
            "pc offset: rax={:#010x} qemu={:#010x}",
            rax.pc, oracle.st.pc
        ));
    }
    if rax.fpscr != oracle.st.fpscr {
        diffs.push(format!(
            "fpscr: rax={:#010x} qemu={:#010x}",
            rax.fpscr, oracle.st.fpscr
        ));
    }
    for r in 0..32 {
        if rax.d[r] != oracle.st.d[r] {
            diffs.push(format!(
                "d{r}: rax={:#018x} qemu={:#018x}",
                rax.d[r], oracle.st.d[r]
            ));
        }
    }
    for i in 0..64 {
        if rax.scratch[i] != oracle.st.scratch[i] {
            diffs.push(format!(
                "scratch[{i}]: rax={:#010x} qemu={:#010x}",
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
            4 => 0x7FFF_FFFF,
            5 => (self.next() & 0xFF) as u32,
            6 => (self.next() & 0xFFFF) as u32,
            _ => self.next() as u32,
        }
    }
}

/// Build a randomised input state. `scratch_reg`, if set, is pointed at the
/// scratch window so load/store families have a valid base.
fn gen_input(rng: &mut Rng, scratch_reg: Option<usize>) -> ArmState32 {
    let mut st = ArmState32::zeroed();
    for i in 0..15 {
        st.r[i] = rng.interesting32();
    }
    // Random NZCVQ (31:27) and GE (19:16).
    st.cpsr = (rng.next() as u32) & (0xF800_0000 | 0x000F_0000);
    st.fpscr = 0;
    for r in 0..32 {
        st.d[r] = rng.next();
    }
    for w in 0..64 {
        st.scratch[w] = rng.interesting32();
    }
    if let Some(reg) = scratch_reg {
        st.r[reg] = SCRATCH_BASE;
    }
    st
}

// ---------------------------------------------------------------------------
// Test driver.
// ---------------------------------------------------------------------------

fn run_batch(name: &str, batch: Vec<(String, u32, u32, ArmState32)>) {
    let oracle = match oracle_path() {
        Some(p) => p,
        None => {
            eprintln!("[arm_diff32] {name}: qemu/cross-toolchain unavailable -> skipping");
            return;
        }
    };

    let outs = run_oracle(oracle, &batch);
    let mut mismatches = Vec::new();
    for ((label, insn, mode, state), out) in batch.iter().zip(&outs) {
        compare_case(label, *insn, *mode, state, out, &mut mismatches);
    }

    if !mismatches.is_empty() {
        use std::collections::BTreeMap;
        // Classify each mismatch.
        let kind = |d: &str| -> &'static str {
            if d.starts_with("QEMU executed but RAX rejected") {
                "decode-gap"
            } else if d.starts_with("QEMU faulted") {
                "over-permissive"
            } else {
                "value"
            }
        };
        // Distinct (label) sets per kind, with a representative.
        let mut by_kind: BTreeMap<&str, usize> = BTreeMap::new();
        let mut distinct: BTreeMap<(&str, String), (usize, u32, String)> = BTreeMap::new();
        for m in &mismatches {
            let k = kind(&m.detail);
            *by_kind.entry(k).or_default() += 1;
            let e = distinct
                .entry((k, m.label.clone()))
                .or_insert((0, m.insn, m.detail.clone()));
            e.0 += 1;
        }
        eprintln!(
            "\n==== {name}: {} mismatches across {} cases ====",
            mismatches.len(),
            batch.len()
        );
        eprintln!("-- by kind --");
        for (k, c) in &by_kind {
            eprintln!("  {c:6}x  {k}");
        }
        eprintln!("-- distinct (kind, encoding): {} --", distinct.len());
        // Print value-mismatches first (most interesting), then decode-gaps.
        for want in ["value", "over-permissive", "decode-gap"] {
            let rows: Vec<_> = distinct.iter().filter(|((k, _), _)| *k == want).collect();
            eprintln!("  == {want} ({} distinct) ==", rows.len());
            for ((_, label), (count, insn, detail)) in rows.iter().take(120) {
                let d = if detail.len() > 200 {
                    &detail[..200]
                } else {
                    detail
                };
                eprintln!("    {count:4}x [{:#010x}] {label}: {d}", insn);
            }
        }
        panic!("{name}: {} mismatches (see above)", mismatches.len());
    }
    eprintln!(
        "[arm_diff32] {name}: {} cases matched QEMU Cortex-A15",
        batch.len()
    );
}

// The generated comprehensive integer sweep table.
include!("../../../generated/arm/oracle_cases/aarch32_sweep.rs");

/// Run the integer sweep filtered to the given modes. An `A32DIFF_FILTER`
/// environment variable (substring match on the label) narrows it further, for
/// fast iteration on one category.
fn integer_sweep(name: &str, modes: &[u8], n_inputs: usize, seed: u64) {
    let filter = std::env::var("A32DIFF_FILTER").ok();
    let mut rng = Rng::new(seed);
    let mut batch = Vec::new();
    for (label, insn, mode) in A32_SWEEP.iter() {
        if !modes.contains(mode) {
            continue;
        }
        if let Some(f) = &filter {
            if !label.contains(f.as_str()) {
                continue;
            }
        }
        for _ in 0..n_inputs {
            let st = gen_input(&mut rng, None);
            batch.push((label.to_string(), *insn, *mode as u32, st));
        }
    }
    run_batch(name, batch);
}

/// Run the memory sweep: r1 points at the scratch window, r2 holds a small
/// offset, so every access stays inside the exchanged scratch region.
fn memory_sweep(name: &str, modes: &[u8], n_inputs: usize, seed: u64) {
    let filter = std::env::var("A32DIFF_FILTER").ok();
    let mut rng = Rng::new(seed);
    let mut batch = Vec::new();
    for (label, insn, mode) in A32_MEM_SWEEP.iter() {
        if !modes.contains(mode) {
            continue;
        }
        if let Some(f) = &filter {
            if !label.contains(f.as_str()) {
                continue;
            }
        }
        for _ in 0..n_inputs {
            let mut st = gen_input(&mut rng, None);
            st.r[1] = SCRATCH_BASE; // base register
            st.r[2] = 8; // small offset register
            batch.push((label.to_string(), *insn, *mode as u32, st));
        }
    }
    run_batch(name, batch);
}

/// A32 (ARM) load/store sweep (single/dual/multiple, all addressing modes).
#[test]
fn diff_a32_memory_sweep() {
    memory_sweep("a32_memory_sweep", &[0], 16, 0xA32_1001);
}

/// T16 (Thumb 16-bit) load/store sweep.
#[test]
fn diff_t16_memory_sweep() {
    memory_sweep("t16_memory_sweep", &[1], 16, 0xA32_1002);
}

/// T32 (Thumb-2 32-bit) load/store sweep.
#[test]
fn diff_t32_memory_sweep() {
    memory_sweep("t32_memory_sweep", &[2], 16, 0xA32_1003);
}

/// A32 (ARM) integer register-data-processing sweep.
#[test]
fn diff_a32_integer_sweep() {
    integer_sweep("a32_integer_sweep", &[0], 24, 0xA32_0001);
}

/// T32 (Thumb-2 32-bit) integer register-data-processing sweep.
#[test]
fn diff_t32_integer_sweep() {
    integer_sweep("t32_integer_sweep", &[2], 24, 0xA32_0002);
}

/// T16 (Thumb 16-bit) integer register-data-processing sweep.
#[test]
fn diff_t16_integer_sweep() {
    integer_sweep("t16_integer_sweep", &[1], 24, 0xA32_0003);
}

struct VfpAuditCase {
    label: &'static str,
    insn: u32,
    inputs: [u32; 2],
    fpscr: u32,
    result: u32,
    flags: u32,
}

const VFP_AUDIT_CASES: [VfpAuditCase; 6] = [
    VfpAuditCase {
        label: "infinity plus one",
        insn: 0xee30_0a20,
        inputs: [0x7f80_0000, 0x3f80_0000],
        fpscr: 0,
        result: 0x7f80_0000,
        flags: 0,
    },
    VfpAuditCase {
        label: "quiet NaN plus one",
        insn: 0xee30_0a20,
        inputs: [0x7fc0_0000, 0x3f80_0000],
        fpscr: 0,
        result: 0x7fc0_0000,
        flags: 0,
    },
    VfpAuditCase {
        label: "one divided by zero",
        insn: 0xee80_0a20,
        inputs: [0x3f80_0000, 0],
        fpscr: 0,
        result: 0x7f80_0000,
        flags: 2,
    },
    VfpAuditCase {
        label: "zero divided by zero",
        insn: 0xee80_0a20,
        inputs: [0, 0],
        fpscr: 0,
        result: 0x7fc0_0000,
        flags: 1,
    },
    VfpAuditCase {
        label: "round toward positive infinity",
        insn: 0xee30_0a20,
        inputs: [0x3f80_0000, 0x3380_0000],
        fpscr: 1 << 22,
        result: 0x3f80_0001,
        flags: 0x10,
    },
    VfpAuditCase {
        label: "flush a subnormal input",
        insn: 0xee30_0a20,
        inputs: [1, 0],
        fpscr: 1 << 24,
        result: 0,
        flags: 0x80,
    },
];

fn vfp_audit_input(case: &VfpAuditCase, ordinal: usize) -> ArmState32 {
    let mut input = gen_input(&mut Rng::new(0xa32_f000 + ordinal as u64), None);
    input.d[0] = (u64::from(case.inputs[1]) << 32) | u64::from(case.inputs[0]);
    input.fpscr = case.fpscr;
    input
}

#[test]
fn rax_vfp_audit_state_is_observable() {
    for mode in [0, 2] {
        for (ordinal, case) in VFP_AUDIT_CASES.iter().enumerate() {
            let input = vfp_audit_input(case, ordinal);
            let output = run_rax(case.insn, mode, &input).expect("allocated VFP instruction");
            let expected_d0 = (input.d[0] & !u64::from(u32::MAX)) | u64::from(case.result);
            assert_eq!(
                (output.d[0], output.fpscr),
                (expected_d0, case.fpscr | case.flags),
                "{}, mode {mode}",
                case.label,
            );
            assert_eq!(output.d[1..], input.d[1..], "{}, mode {mode}", case.label);
            assert_eq!(output.pc, 4, "{}, mode {mode}", case.label);
            assert_eq!(output.cpsr & 0x20 != 0, mode == 2, "{}", case.label);
        }
    }
}

#[test]
fn comparator_reports_each_fp_and_execution_state_difference() {
    let case = &VFP_AUDIT_CASES[2];
    let input = vfp_audit_input(case, 2);
    let mut oracle = OutCase32 {
        st: run_rax(case.insn, 2, &input).expect("allocated VFP instruction"),
        trapped: 0,
        valid: 1,
    };
    oracle.st.d[31] ^= 1;
    oracle.st.fpscr ^= 2;
    oracle.st.pc ^= 2;
    oracle.st.cpsr ^= 1 << 5;
    let mut mismatches = Vec::new();
    compare_case(case.label, case.insn, 2, &input, &oracle, &mut mismatches);
    assert_eq!(mismatches.len(), 1);
    for field in ["d31:", "fpscr:", "pc offset:", "cpsr(NZCVQ+GE+T):"] {
        assert!(mismatches[0].detail.contains(field), "missing {field}");
    }
}

#[test]
fn diff_vfp_audit_replay() {
    let mut batch = Vec::new();
    for (mode, name) in [(0, "A32"), (2, "T32")] {
        for (ordinal, case) in VFP_AUDIT_CASES.iter().enumerate() {
            batch.push((
                format!("{name} {}", case.label),
                case.insn,
                mode,
                vfp_audit_input(case, ordinal),
            ));
        }
    }
    run_batch("vfp_audit_replay", batch);
}
