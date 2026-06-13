//! Generated EVEX differential tests: rax vs. qemu-x86_64.
//!
//! The corpus is scoped to EVEX SIMD handlers that rax dispatches today. It is
//! generated from assembly strings, assembled with LLVM for the rax side, and
//! compiled into a qemu oracle from the same case table.

#![cfg(all(feature = "x86_64-suite", target_os = "linux", target_arch = "x86_64"))]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[path = "x86_64/common/mod.rs"]
mod common;

use common::{Bytes, GuestAddress, Registers, run_until_hlt, setup_vm};

const WIRE_MAGIC: u32 = 0x5845_5645; // 'E','V','E','X'
const ZMM_REGS: usize = 32;
const K_REGS: usize = 8;
const SCRATCH_BYTES: usize = 256;
const SCRATCH_ADDR: u64 = 0x4000;

const LLVM_MATTR: &str = "+avx512f,+avx512bw,+avx512dq,+avx512vl,+avx512fp16,+avx512vnni,+avx512ifma,+avx512vpopcntdq,+avx512vbmi,+avx512bitalg,+avx512bf16,+avxvnni";

#[repr(C)]
#[derive(Clone, Copy)]
struct InCase {
    id: u32,
    reserved: u32,
    zmm: [[u64; 8]; ZMM_REGS],
    k: [u64; K_REGS],
    scratch: [u8; SCRATCH_BYTES],
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct OutCase {
    id: u32,
    valid: u32,
    zmm: [[u64; 8]; ZMM_REGS],
    k: [u64; K_REGS],
    scratch: [u8; SCRATCH_BYTES],
}

#[derive(Clone, Copy)]
enum InputProfile {
    Int,
    F32,
    F64,
    F16,
}

struct CaseSpec {
    label: String,
    asm: String,
    profile: InputProfile,
}

struct DiffCase {
    id: u32,
    label: String,
    asm: String,
    op: Vec<u8>,
    input: InCase,
}

const RM_EXT_REGS: [usize; 4] = [0, 8, 16, 24];
const DST_EXT_REGS: [usize; 2] = [1, 17];
const SRC1_EXT_REGS: [usize; 2] = [2, 18];

fn which(prog: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(prog))
        .find(|candidate| candidate.is_file())
}

fn qemu_path() -> Option<PathBuf> {
    std::env::var_os("QEMU_X86_64")
        .map(PathBuf::from)
        .or_else(|| which("qemu-x86_64"))
}

fn llvm_mc_path() -> Option<PathBuf> {
    std::env::var_os("LLVM_MC")
        .map(PathBuf::from)
        .or_else(|| which("llvm-mc"))
}

fn cc_path() -> Option<PathBuf> {
    std::env::var_os("CC")
        .map(PathBuf::from)
        .or_else(|| which("clang"))
        .or_else(|| which("cc"))
}

fn as_bytes<T: Copy>(value: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts(value as *const T as *const u8, std::mem::size_of::<T>()) }
}

fn read_struct<T: Copy>(buf: &[u8], offset: usize) -> T {
    unsafe { std::ptr::read_unaligned(buf[offset..].as_ptr() as *const T) }
}

fn zmm_to_bytes(value: [u64; 8]) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    for (i, word) in value.iter().enumerate() {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

fn zmm_from_bytes(bytes: [u8; 64]) -> [u64; 8] {
    let mut out = [0u64; 8];
    for (i, chunk) in bytes.chunks_exact(8).enumerate() {
        out[i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    out
}

fn set_zmm_bytes(input: &mut InCase, reg: usize, bytes: [u8; 64]) {
    input.zmm[reg] = zmm_from_bytes(bytes);
}

fn f32_zmm(reg: usize) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    for lane in 0..16 {
        let value = 1.0 + reg as f32 * 0.125 + lane as f32 * 0.0625;
        bytes[lane * 4..lane * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

fn f64_zmm(reg: usize) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    for lane in 0..8 {
        let value = 1.0 + reg as f64 * 0.25 + lane as f64 * 0.125;
        bytes[lane * 8..lane * 8 + 8].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

fn int_zmm(reg: usize) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = ((reg * 11 + i * 7 + 3) & 0x7f) as u8;
    }
    bytes
}

fn f16_zmm(reg: usize) -> [u8; 64] {
    const VALUES: [u16; 8] = [
        0x3c00, 0x4000, 0x4200, 0x4400, 0x4500, 0x4600, 0x4700, 0x4800,
    ];
    let mut bytes = [0u8; 64];
    for lane in 0..32 {
        let value = VALUES[(reg + lane) % VALUES.len()];
        bytes[lane * 2..lane * 2 + 2].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

fn profile_zmm(profile: InputProfile, reg: usize) -> [u8; 64] {
    match profile {
        InputProfile::Int => int_zmm(reg),
        InputProfile::F32 => f32_zmm(reg),
        InputProfile::F64 => f64_zmm(reg),
        InputProfile::F16 => f16_zmm(reg),
    }
}

fn input_for(id: u32, profile: InputProfile) -> InCase {
    let mut input = InCase {
        id,
        reserved: 0,
        zmm: [[0; 8]; ZMM_REGS],
        k: [
            u64::MAX,
            0x5555_5555_5555_5555,
            0xAAAA_AAAA_AAAA_AAAA,
            0x0F0F_0F0F_0F0F_0F0F,
            0x00FF_00FF_00FF_00FF,
            u64::MAX,
            u64::MAX,
            u64::MAX,
        ],
        scratch: [0; SCRATCH_BYTES],
    };

    for reg in 0..ZMM_REGS {
        set_zmm_bytes(&mut input, reg, profile_zmm(profile, reg));
    }

    let scratch_profile = profile_zmm(profile, 31);
    for chunk in input.scratch.chunks_mut(64) {
        chunk.copy_from_slice(&scratch_profile[..chunk.len()]);
    }

    input
}

fn set_regs_zmm(regs: &mut Registers, index: usize, value: [u64; 8]) {
    if index < 16 {
        regs.xmm[index] = [value[0], value[1]];
        regs.ymm_high[index] = [value[2], value[3]];
        regs.zmm_high[index] = [value[4], value[5], value[6], value[7]];
    } else {
        regs.zmm_ext[index - 16] = value;
    }
}

fn get_regs_zmm(regs: &Registers, index: usize) -> [u64; 8] {
    if index < 16 {
        [
            regs.xmm[index][0],
            regs.xmm[index][1],
            regs.ymm_high[index][0],
            regs.ymm_high[index][1],
            regs.zmm_high[index][0],
            regs.zmm_high[index][1],
            regs.zmm_high[index][2],
            regs.zmm_high[index][3],
        ]
    } else {
        regs.zmm_ext[index - 16]
    }
}

fn registers_from_input(input: &InCase) -> Registers {
    let mut regs = Registers {
        rax: SCRATCH_ADDR,
        ..Registers::default()
    };
    for reg in 0..ZMM_REGS {
        set_regs_zmm(&mut regs, reg, input.zmm[reg]);
    }
    regs.k = input.k;
    regs
}

fn mov_imm64(code: &mut Vec<u8>, reg: u8, value: u64) {
    code.push(0x48);
    code.push(0xb8 + reg);
    code.extend_from_slice(&value.to_le_bytes());
}

fn run_rax(case: &DiffCase) -> OutCase {
    let mut code = Vec::new();
    mov_imm64(&mut code, 0, SCRATCH_ADDR);
    code.extend_from_slice(&case.op);
    code.push(0xf4);

    let (mut vcpu, mem) = setup_vm(&code, Some(registers_from_input(&case.input)));
    mem.write_slice(&case.input.scratch, GuestAddress(SCRATCH_ADDR))
        .unwrap();
    let regs = run_until_hlt(&mut vcpu).unwrap();

    let mut scratch = [0u8; SCRATCH_BYTES];
    mem.read_slice(&mut scratch, GuestAddress(SCRATCH_ADDR))
        .unwrap();

    let mut out = OutCase {
        id: case.id,
        valid: 1,
        zmm: [[0; 8]; ZMM_REGS],
        k: regs.k,
        scratch,
    };
    for reg in 0..ZMM_REGS {
        out.zmm[reg] = get_regs_zmm(&regs, reg);
    }
    out
}

fn spec(
    specs: &mut Vec<CaseSpec>,
    label: impl Into<String>,
    asm: impl Into<String>,
    profile: InputProfile,
) {
    specs.push(CaseSpec {
        label: label.into(),
        asm: asm.into(),
        profile,
    });
}

fn add_ternary_family(
    specs: &mut Vec<CaseSpec>,
    mnemonic: &str,
    profile: InputProfile,
    suffixes: &[&str],
) {
    for dst in DST_EXT_REGS {
        for src1 in SRC1_EXT_REGS {
            for rm in RM_EXT_REGS {
                spec(
                    specs,
                    format!("{mnemonic}_dst_zmm{dst}_src1_zmm{src1}_rm_zmm{rm}"),
                    format!("{mnemonic} %zmm{rm}, %zmm{src1}, %zmm{dst}"),
                    profile,
                );
            }
        }
    }
    for dst in DST_EXT_REGS {
        for src1 in SRC1_EXT_REGS {
            spec(
                specs,
                format!("{mnemonic}_dst_zmm{dst}_src1_zmm{src1}_mem"),
                format!("{mnemonic} (%rax), %zmm{src1}, %zmm{dst}"),
                profile,
            );
        }
    }
    for (reg_class, dst, src1, src2) in [
        ("xmm", "%xmm1", "%xmm2", "%xmm16"),
        ("ymm", "%ymm1", "%ymm2", "%ymm16"),
        ("zmm", "%zmm1", "%zmm2", "%zmm16"),
    ] {
        spec(
            specs,
            format!("{mnemonic}_{reg_class}_vl"),
            format!("{mnemonic} {src2}, {src1}, {dst}"),
            profile,
        );
    }
    for suffix in suffixes {
        spec(
            specs,
            format!(
                "{mnemonic}_mask_zmm17_zmm18_zmm16_{}",
                suffix.replace(['%', ' ', '{', '}'], "")
            ),
            format!("{mnemonic} %zmm16, %zmm18, %zmm17 {suffix}"),
            profile,
        );
    }
}

fn add_unary_rm_family(
    specs: &mut Vec<CaseSpec>,
    mnemonic: &str,
    profile: InputProfile,
    suffixes: &[&str],
) {
    for dst in DST_EXT_REGS {
        for rm in RM_EXT_REGS {
            spec(
                specs,
                format!("{mnemonic}_dst_zmm{dst}_rm_zmm{rm}"),
                format!("{mnemonic} %zmm{rm}, %zmm{dst}"),
                profile,
            );
        }
    }
    for dst in DST_EXT_REGS {
        spec(
            specs,
            format!("{mnemonic}_dst_zmm{dst}_mem"),
            format!("{mnemonic} (%rax), %zmm{dst}"),
            profile,
        );
    }
    for (reg_class, dst, src) in [
        ("xmm", "%xmm1", "%xmm16"),
        ("ymm", "%ymm1", "%ymm16"),
        ("zmm", "%zmm1", "%zmm16"),
    ] {
        spec(
            specs,
            format!("{mnemonic}_{reg_class}_vl"),
            format!("{mnemonic} {src}, {dst}"),
            profile,
        );
    }
    for suffix in suffixes {
        spec(
            specs,
            format!(
                "{mnemonic}_mask_zmm17_zmm16_{}",
                suffix.replace(['%', ' ', '{', '}'], "")
            ),
            format!("{mnemonic} %zmm16, %zmm17 {suffix}"),
            profile,
        );
    }
}

fn add_move_family(specs: &mut Vec<CaseSpec>, mnemonic: &str, profile: InputProfile) {
    for dst in DST_EXT_REGS {
        for rm in RM_EXT_REGS {
            spec(
                specs,
                format!("{mnemonic}_load_dst_zmm{dst}_rm_zmm{rm}"),
                format!("{mnemonic} %zmm{rm}, %zmm{dst}"),
                profile,
            );
        }
    }
    for src in DST_EXT_REGS {
        for rm in RM_EXT_REGS {
            spec(
                specs,
                format!("{mnemonic}_store_src_zmm{src}_rm_zmm{rm}"),
                format!("{mnemonic} %zmm{src}, %zmm{rm}"),
                profile,
            );
        }
    }
    for dst in DST_EXT_REGS {
        spec(
            specs,
            format!("{mnemonic}_load_dst_zmm{dst}_mem"),
            format!("{mnemonic} (%rax), %zmm{dst}"),
            profile,
        );
    }
    for src in DST_EXT_REGS {
        spec(
            specs,
            format!("{mnemonic}_store_src_zmm{src}_mem"),
            format!("{mnemonic} %zmm{src}, (%rax)"),
            profile,
        );
    }
    for (reg_class, dst, src) in [
        ("xmm", "%xmm1", "%xmm16"),
        ("ymm", "%ymm1", "%ymm16"),
        ("zmm", "%zmm1", "%zmm16"),
    ] {
        spec(
            specs,
            format!("{mnemonic}_{reg_class}_vl"),
            format!("{mnemonic} {src}, {dst}"),
            profile,
        );
    }
}

fn add_compare_family(specs: &mut Vec<CaseSpec>, mnemonic: &str) {
    for src1 in SRC1_EXT_REGS {
        for rm in RM_EXT_REGS {
            spec(
                specs,
                format!("{mnemonic}_src1_zmm{src1}_rm_zmm{rm}"),
                format!("{mnemonic} %zmm{rm}, %zmm{src1}, %k3"),
                InputProfile::Int,
            );
        }
    }
    for src1 in SRC1_EXT_REGS {
        spec(
            specs,
            format!("{mnemonic}_src1_zmm{src1}_mem"),
            format!("{mnemonic} (%rax), %zmm{src1}, %k3"),
            InputProfile::Int,
        );
    }
    spec(
        specs,
        format!("{mnemonic}_mask_zmm18_zmm16"),
        format!("{mnemonic} %zmm16, %zmm18, %k3 {{%k1}}"),
        InputProfile::Int,
    );
}

fn add_vpcmp_imm_family(specs: &mut Vec<CaseSpec>, mnemonic: &str) {
    for src1 in SRC1_EXT_REGS {
        for rm in RM_EXT_REGS {
            spec(
                specs,
                format!("{mnemonic}_src1_zmm{src1}_rm_zmm{rm}"),
                format!("{mnemonic} $4, %zmm{rm}, %zmm{src1}, %k3"),
                InputProfile::Int,
            );
        }
    }
    for src1 in SRC1_EXT_REGS {
        spec(
            specs,
            format!("{mnemonic}_src1_zmm{src1}_mem"),
            format!("{mnemonic} $0, (%rax), %zmm{src1}, %k3"),
            InputProfile::Int,
        );
    }
    spec(
        specs,
        format!("{mnemonic}_mask_zmm18_zmm16"),
        format!("{mnemonic} $0, %zmm16, %zmm18, %k3 {{%k1}}"),
        InputProfile::Int,
    );
}

fn add_broadcast_family(specs: &mut Vec<CaseSpec>, mnemonic: &str, src_reg: &str) {
    for dst in DST_EXT_REGS {
        for rm in RM_EXT_REGS {
            spec(
                specs,
                format!("{mnemonic}_dst_zmm{dst}_rm_{src_reg}{rm}"),
                format!("{mnemonic} %{src_reg}{rm}, %zmm{dst}"),
                InputProfile::Int,
            );
        }
    }
    for dst in DST_EXT_REGS {
        spec(
            specs,
            format!("{mnemonic}_dst_zmm{dst}_mem"),
            format!("{mnemonic} (%rax), %zmm{dst}"),
            InputProfile::Int,
        );
    }
    spec(
        specs,
        format!("{mnemonic}_mask_zmm17_{src_reg}16"),
        format!("{mnemonic} %{src_reg}16, %zmm17 {{%k1}}"),
        InputProfile::Int,
    );
}

fn generated_specs() -> Vec<CaseSpec> {
    let mut specs = Vec::new();
    let masked = ["{%k1}", "{%k2} {z}"];

    for mnemonic in ["vmovups", "vmovaps"] {
        add_move_family(&mut specs, mnemonic, InputProfile::F32);
    }
    for mnemonic in ["vmovupd", "vmovapd"] {
        add_move_family(&mut specs, mnemonic, InputProfile::F64);
    }

    for mnemonic in ["vaddps", "vmulps", "vsubps", "vdivps", "vxorps"] {
        add_ternary_family(&mut specs, mnemonic, InputProfile::F32, &masked);
    }
    for mnemonic in ["vaddpd", "vmulpd", "vsubpd", "vdivpd", "vxorpd"] {
        add_ternary_family(&mut specs, mnemonic, InputProfile::F64, &masked);
    }

    for mnemonic in [
        "vmovdqa32",
        "vmovdqa64",
        "vmovdqu8",
        "vmovdqu16",
        "vmovdqu32",
        "vmovdqu64",
    ] {
        add_move_family(&mut specs, mnemonic, InputProfile::Int);
        spec(
            &mut specs,
            format!("{mnemonic}_masked_load_zmm17_zmm16"),
            format!("{mnemonic} %zmm16, %zmm17 {{%k1}}"),
            InputProfile::Int,
        );
        spec(
            &mut specs,
            format!("{mnemonic}_masked_store_zmm17_zmm16"),
            format!("{mnemonic} %zmm17, %zmm16 {{%k1}}"),
            InputProfile::Int,
        );
        spec(
            &mut specs,
            format!("{mnemonic}_masked_mem_load_zmm17"),
            format!("{mnemonic} (%rax), %zmm17 {{%k1}}"),
            InputProfile::Int,
        );
        spec(
            &mut specs,
            format!("{mnemonic}_masked_mem_store_zmm17"),
            format!("{mnemonic} %zmm17, (%rax) {{%k1}}"),
            InputProfile::Int,
        );
    }

    for mnemonic in [
        "vpandd", "vpandq", "vpandnd", "vpandnq", "vpord", "vporq", "vpxord", "vpxorq", "vpaddb",
        "vpaddw", "vpaddd", "vpaddq", "vpsubb", "vpsubw", "vpsubd", "vpsubq", "vpmullw", "vpmulld",
        "vpmullq",
    ] {
        add_ternary_family(&mut specs, mnemonic, InputProfile::Int, &masked);
    }

    for mnemonic in [
        "vpcmpeqb", "vpcmpeqw", "vpcmpeqd", "vpcmpeqq", "vpcmpgtb", "vpcmpgtw", "vpcmpgtd",
        "vpcmpgtq",
    ] {
        add_compare_family(&mut specs, mnemonic);
    }
    for mnemonic in [
        "vpcmpub", "vpcmpuw", "vpcmpud", "vpcmpuq", "vpcmpb", "vpcmpw", "vpcmpd", "vpcmpq",
    ] {
        add_vpcmp_imm_family(&mut specs, mnemonic);
    }

    for mnemonic in ["vpsrld", "vpsrad", "vpsraq", "vpslld", "vpsrlq", "vpsllq"] {
        for dst in DST_EXT_REGS {
            for rm in RM_EXT_REGS {
                spec(
                    &mut specs,
                    format!("{mnemonic}_imm_dst_zmm{dst}_rm_zmm{rm}"),
                    format!("{mnemonic} $3, %zmm{rm}, %zmm{dst}"),
                    InputProfile::Int,
                );
            }
            spec(
                &mut specs,
                format!("{mnemonic}_imm_dst_zmm{dst}_mem"),
                format!("{mnemonic} $3, (%rax), %zmm{dst}"),
                InputProfile::Int,
            );
        }
        spec(
            &mut specs,
            format!("{mnemonic}_imm_mask_zmm17_zmm16"),
            format!("{mnemonic} $3, %zmm16, %zmm17 {{%k1}}"),
            InputProfile::Int,
        );
    }
    for mnemonic in ["vpsrld", "vpsrad", "vpsraq", "vpslld", "vpsrlq", "vpsllq"] {
        for dst in DST_EXT_REGS {
            for src1 in SRC1_EXT_REGS {
                for count in RM_EXT_REGS {
                    spec(
                        &mut specs,
                        format!("{mnemonic}_var_dst_zmm{dst}_src1_zmm{src1}_count_xmm{count}"),
                        format!("{mnemonic} %xmm{count}, %zmm{src1}, %zmm{dst}"),
                        InputProfile::Int,
                    );
                }
                spec(
                    &mut specs,
                    format!("{mnemonic}_var_dst_zmm{dst}_src1_zmm{src1}_mem_count"),
                    format!("{mnemonic} (%rax), %zmm{src1}, %zmm{dst}"),
                    InputProfile::Int,
                );
            }
        }
    }

    for (mnemonic, src_reg) in [
        ("vbroadcastss", "xmm"),
        ("vbroadcastsd", "xmm"),
        ("vpbroadcastb", "xmm"),
        ("vpbroadcastw", "xmm"),
        ("vpbroadcastd", "xmm"),
        ("vpbroadcastq", "xmm"),
    ] {
        add_broadcast_family(&mut specs, mnemonic, src_reg);
    }

    for mnemonic in ["vexpandps", "vexpandpd", "vpexpandd", "vpexpandq"] {
        add_unary_rm_family(&mut specs, mnemonic, InputProfile::Int, &masked);
    }
    for mnemonic in ["vcompressps", "vcompresspd", "vpcompressd", "vpcompressq"] {
        for src in DST_EXT_REGS {
            for rm in RM_EXT_REGS {
                spec(
                    &mut specs,
                    format!("{mnemonic}_src_zmm{src}_rm_zmm{rm}"),
                    format!("{mnemonic} %zmm{src}, %zmm{rm} {{%k1}}"),
                    InputProfile::Int,
                );
            }
            spec(
                &mut specs,
                format!("{mnemonic}_src_zmm{src}_mem"),
                format!("{mnemonic} %zmm{src}, (%rax) {{%k1}}"),
                InputProfile::Int,
            );
        }
    }

    for mnemonic in [
        "vpdpbusd",
        "vpdpbusds",
        "vpdpwssd",
        "vpdpwssds",
        "vpmadd52luq",
        "vpmadd52huq",
        "vpermb",
        "vpermi2b",
        "vpermt2b",
        "vdpbf16ps",
        "vmpsadbw",
        "vpdpbssd",
        "vpdpbssds",
        "vpdpbsud",
        "vpdpbsuds",
        "vpdpbuud",
        "vpdpbuuds",
        "vpdpwsud",
        "vpdpwsuds",
        "vpdpwusd",
        "vpdpwusds",
        "vpdpwuud",
        "vpdpwuuds",
    ] {
        let imm = if mnemonic == "vmpsadbw" { "$3, " } else { "" };
        for dst in DST_EXT_REGS {
            for src1 in SRC1_EXT_REGS {
                for rm in RM_EXT_REGS {
                    spec(
                        &mut specs,
                        format!("{mnemonic}_dst_zmm{dst}_src1_zmm{src1}_rm_zmm{rm}"),
                        format!("{mnemonic} {imm}%zmm{rm}, %zmm{src1}, %zmm{dst}"),
                        InputProfile::Int,
                    );
                }
                spec(
                    &mut specs,
                    format!("{mnemonic}_dst_zmm{dst}_src1_zmm{src1}_mem"),
                    format!("{mnemonic} {imm}(%rax), %zmm{src1}, %zmm{dst}"),
                    InputProfile::Int,
                );
            }
        }
    }

    for mnemonic in ["vpopcntb", "vpopcntw", "vpopcntd", "vpopcntq"] {
        add_unary_rm_family(&mut specs, mnemonic, InputProfile::Int, &[]);
    }
    for src1 in SRC1_EXT_REGS {
        for rm in RM_EXT_REGS {
            spec(
                &mut specs,
                format!("vpshufbitqmb_src1_zmm{src1}_rm_zmm{rm}"),
                format!("vpshufbitqmb %zmm{rm}, %zmm{src1}, %k3"),
                InputProfile::Int,
            );
        }
        spec(
            &mut specs,
            format!("vpshufbitqmb_src1_zmm{src1}_mem"),
            format!("vpshufbitqmb (%rax), %zmm{src1}, %k3"),
            InputProfile::Int,
        );
    }
    spec(
        &mut specs,
        "vpshufbitqmb_mask_zmm18_zmm16",
        "vpshufbitqmb %zmm16, %zmm18, %k3 {%k1}",
        InputProfile::Int,
    );

    for dst in DST_EXT_REGS {
        for rm in RM_EXT_REGS {
            spec(
                &mut specs,
                format!("vcvtneps2bf16_dst_ymm{dst}_rm_zmm{rm}"),
                format!("vcvtneps2bf16 %zmm{rm}, %ymm{dst}"),
                InputProfile::F32,
            );
        }
        spec(
            &mut specs,
            format!("vcvtneps2bf16_dst_ymm{dst}_mem"),
            format!("vcvtneps2bf16 (%rax), %ymm{dst}"),
            InputProfile::F32,
        );
    }
    for dst in DST_EXT_REGS {
        for src1 in SRC1_EXT_REGS {
            for rm in RM_EXT_REGS {
                spec(
                    &mut specs,
                    format!("vcvtne2ps2bf16_dst_zmm{dst}_src1_zmm{src1}_rm_zmm{rm}"),
                    format!("vcvtne2ps2bf16 %zmm{rm}, %zmm{src1}, %zmm{dst}"),
                    InputProfile::F32,
                );
            }
            spec(
                &mut specs,
                format!("vcvtne2ps2bf16_dst_zmm{dst}_src1_zmm{src1}_mem"),
                format!("vcvtne2ps2bf16 (%rax), %zmm{src1}, %zmm{dst}"),
                InputProfile::F32,
            );
        }
    }
    for mnemonic in ["vcvttps2ibs", "vcvttps2iubs"] {
        add_unary_rm_family(&mut specs, mnemonic, InputProfile::F32, &[]);
    }
    for mnemonic in ["vcvttpd2qqs", "vcvttpd2uqqs"] {
        add_unary_rm_family(&mut specs, mnemonic, InputProfile::F64, &[]);
    }

    for mnemonic in ["vminmaxps", "vminmaxpd"] {
        let profile = if mnemonic.ends_with("ps") {
            InputProfile::F32
        } else {
            InputProfile::F64
        };
        for dst in DST_EXT_REGS {
            for src1 in SRC1_EXT_REGS {
                for rm in RM_EXT_REGS {
                    spec(
                        &mut specs,
                        format!("{mnemonic}_dst_zmm{dst}_src1_zmm{src1}_rm_zmm{rm}"),
                        format!("{mnemonic} $0, %zmm{rm}, %zmm{src1}, %zmm{dst}"),
                        profile,
                    );
                }
                spec(
                    &mut specs,
                    format!("{mnemonic}_dst_zmm{dst}_src1_zmm{src1}_mem"),
                    format!("{mnemonic} $1, (%rax), %zmm{src1}, %zmm{dst}"),
                    profile,
                );
            }
        }
    }
    for dst in DST_EXT_REGS {
        for src1 in SRC1_EXT_REGS {
            for rm in RM_EXT_REGS {
                spec(
                    &mut specs,
                    format!("vminmaxss_dst_xmm{dst}_src1_xmm{src1}_rm_xmm{rm}"),
                    format!("vminmaxss $0, %xmm{rm}, %xmm{src1}, %xmm{dst}"),
                    InputProfile::F32,
                );
                spec(
                    &mut specs,
                    format!("vminmaxsd_dst_xmm{dst}_src1_xmm{src1}_rm_xmm{rm}"),
                    format!("vminmaxsd $0, %xmm{rm}, %xmm{src1}, %xmm{dst}"),
                    InputProfile::F64,
                );
            }
        }
    }

    for mnemonic in ["vaddph", "vmulph", "vsubph", "vdivph"] {
        add_ternary_family(&mut specs, mnemonic, InputProfile::F16, &[]);
    }

    specs
}

fn parse_encoding(text: &str) -> Option<Vec<u8>> {
    let start = text.find("encoding: [")? + "encoding: [".len();
    let rest = &text[start..];
    let end = rest.find(']')?;
    let mut bytes = Vec::new();
    for token in rest[..end].split(',') {
        let token = token.trim().trim_start_matches("0x");
        bytes.push(u8::from_str_radix(token, 16).ok()?);
    }
    Some(bytes)
}

fn assemble_case(llvm_mc: &Path, asm: &str) -> Option<Vec<u8>> {
    let mut child = Command::new(llvm_mc)
        .args([
            "-triple=x86_64",
            "-mcpu=skylake-avx512",
            "-mattr",
            LLVM_MATTR,
            "-x86-asm-syntax=att",
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
        .write_all(format!("{asm}\n").as_bytes())
        .ok()?;

    let output = child.wait_with_output().ok()?;
    if !output.status.success() {
        return None;
    }
    parse_encoding(&String::from_utf8_lossy(&output.stdout))
}

fn assembled_cases(llvm_mc: &Path) -> Vec<DiffCase> {
    let mut cases = Vec::new();
    let mut failures = Vec::new();
    let specs = generated_specs();

    for spec in specs {
        let Some(op) = assemble_case(llvm_mc, &spec.asm) else {
            failures.push(format!("{}: {}", spec.label, spec.asm));
            continue;
        };
        assert!(
            op.first() == Some(&0x62),
            "{} assembled outside EVEX encoding: {:02x?}",
            spec.label,
            op
        );
        let id = cases.len() as u32;
        cases.push(DiffCase {
            id,
            label: spec.label,
            asm: spec.asm,
            op,
            input: input_for(id, spec.profile),
        });
    }

    assert!(
        failures.is_empty(),
        "EVEX differential corpus failed to assemble:\n{}",
        failures.join("\n")
    );

    cases
}

fn c_byte_directive(bytes: &[u8]) -> String {
    let mut text = String::from(".byte ");
    for (i, byte) in bytes.iter().enumerate() {
        if i > 0 {
            text.push_str(", ");
        }
        text.push_str(&format!("0x{byte:02x}"));
    }
    text
}

fn write_cases_inc(build_dir: &Path, cases: &[DiffCase]) -> Option<PathBuf> {
    let cases_inc = build_dir.join("cases.inc");
    let mut text = String::new();
    for case in cases {
        text.push_str(&format!(
            "        case {}:\n            RUN_OP(\"{}\"); /* {} */\n            break;\n",
            case.id,
            c_byte_directive(&case.op),
            case.label
        ));
    }
    std::fs::write(&cases_inc, text).ok()?;
    Some(cases_inc)
}

fn oracle_path(cases: &[DiffCase]) -> Option<PathBuf> {
    let cc = cc_path()?;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let src = root.join("tools/x86_64-evex-diff/oracle.c");
    let build_dir = root.join("target/x86_64-evex-diff");
    let oracle = build_dir.join("oracle");
    std::fs::create_dir_all(&build_dir).ok()?;
    let cases_inc = write_cases_inc(&build_dir, cases)?;

    let include_arg = format!("-DEVEX_DIFF_CASES_INC=\"{}\"", cases_inc.display());
    let status = Command::new(cc)
        .args([
            "-O2",
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-mavx512f",
            "-mavx512bw",
            "-mavx512dq",
            "-mavx512vl",
            "-mavx512fp16",
            "-mavx512vnni",
            "-mavx512ifma",
            "-mavx512vpopcntdq",
            "-mavx512vbmi",
            "-mavx512bitalg",
            "-mavx512bf16",
            "-mavxvnni",
            "-o",
        ])
        .arg(&oracle)
        .arg(&include_arg)
        .arg(&src)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()?;
    if !status.success() {
        return None;
    }

    oracle.exists().then_some(oracle)
}

fn run_oracle(qemu: &Path, oracle: &Path, cases: &[DiffCase]) -> Option<Vec<OutCase>> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&WIRE_MAGIC.to_le_bytes());
    payload.extend_from_slice(&(cases.len() as u32).to_le_bytes());
    for case in cases {
        payload.extend_from_slice(as_bytes(&case.input));
    }

    let mut child = Command::new(qemu)
        .args(["-cpu", "max"])
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

    let magic = u32::from_le_bytes(out[0..4].try_into().unwrap());
    let count = u32::from_le_bytes(out[4..8].try_into().unwrap()) as usize;
    if magic != WIRE_MAGIC || count != cases.len() {
        return None;
    }

    let expected_len = 8 + count * std::mem::size_of::<OutCase>();
    if out.len() != expected_len {
        return None;
    }

    let mut outputs = Vec::with_capacity(count);
    let mut offset = 8;
    for _ in 0..count {
        outputs.push(read_struct::<OutCase>(&out, offset));
        offset += std::mem::size_of::<OutCase>();
    }
    Some(outputs)
}

fn assert_same_snapshot(case: &DiffCase, rax: &OutCase, oracle: &OutCase) {
    assert_eq!(rax.id, oracle.id, "{}: case id", case.label);
    assert_eq!(rax.zmm, oracle.zmm, "{}: ZMM snapshot", case.label);
    assert_eq!(rax.k, oracle.k, "{}: opmask snapshot", case.label);
    assert_eq!(
        rax.scratch, oracle.scratch,
        "{}: scratch memory snapshot",
        case.label
    );
}

#[test]
fn qemu_evex_generated_corpus_matches_rax() {
    let Some(qemu) = qemu_path() else {
        eprintln!("[skip] qemu-x86_64 unavailable; skipping EVEX differential corpus");
        return;
    };
    let Some(llvm_mc) = llvm_mc_path() else {
        eprintln!("[skip] llvm-mc unavailable; skipping EVEX differential corpus");
        return;
    };

    let cases = assembled_cases(&llvm_mc);
    if cases.is_empty() {
        eprintln!("[skip] llvm-mc did not assemble any EVEX differential cases");
        return;
    }

    let Some(oracle) = oracle_path(&cases) else {
        eprintln!("[skip] EVEX oracle build failed or compiler unavailable");
        return;
    };
    let Some(outputs) = run_oracle(&qemu, &oracle, &cases) else {
        eprintln!("[skip] qemu-x86_64 could not run the EVEX oracle");
        return;
    };

    let mut compared = 0usize;
    let mut qemu_unsupported = 0usize;
    for (case, oracle) in cases.iter().zip(outputs.iter()) {
        assert_eq!(oracle.id, case.id, "{}: oracle case id", case.label);
        if oracle.valid == 0 {
            qemu_unsupported += 1;
            continue;
        }
        let rax = run_rax(case);
        assert_same_snapshot(case, &rax, oracle);
        compared += 1;
    }

    if compared == 0 {
        eprintln!(
            "[skip] qemu rejected all {} generated EVEX differential cases",
            qemu_unsupported
        );
    } else {
        eprintln!("[info] compared {compared} EVEX cases; qemu rejected {qemu_unsupported}");
    }
}
