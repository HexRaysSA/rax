use crate::common::{run_until_hlt, setup_vm};
use rax::cpu::Registers;

fn pattern(tag: u64) -> [u64; 8] {
    [
        0x0011_2233_4455_6600 | tag,
        0x1011_2233_4455_6600 | tag,
        0x2011_2233_4455_6600 | tag,
        0x3011_2233_4455_6600 | tag,
        0x4011_2233_4455_6600 | tag,
        0x5011_2233_4455_6600 | tag,
        0x6011_2233_4455_6600 | tag,
        0x7011_2233_4455_6600 | tag,
    ]
}

fn zmm_from_bytes(bytes: [u8; 64]) -> [u64; 8] {
    let mut out = [0u64; 8];
    for (i, chunk) in bytes.chunks_exact(8).enumerate() {
        out[i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    out
}

fn splat_f32(value: f32) -> [u64; 8] {
    let mut bytes = [0u8; 64];
    for chunk in bytes.chunks_exact_mut(4) {
        chunk.copy_from_slice(&value.to_le_bytes());
    }
    zmm_from_bytes(bytes)
}

fn set_zmm(regs: &mut Registers, index: usize, value: [u64; 8]) {
    if index < 16 {
        regs.xmm[index] = [value[0], value[1]];
        regs.ymm_high[index] = [value[2], value[3]];
        regs.zmm_high[index] = [value[4], value[5], value[6], value[7]];
    } else {
        regs.zmm_ext[index - 16] = value;
    }
}

fn get_zmm(regs: &Registers, index: usize) -> [u64; 8] {
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

fn run_one(op: &[u8], regs: Registers) -> Registers {
    let mut code = Vec::from(op);
    code.push(0xf4);
    let (mut vcpu, _) = setup_vm(&code, Some(regs));
    run_until_hlt(&mut vcpu).unwrap()
}

#[test]
fn test_evex_rm_register_decode_stays_centralized() {
    let dispatch = include_str!("../../../../src/backend/emulator/x86_64/dispatch/evex.rs");
    let raw_b_only_decode = "if !evex.b { rm + 8 } else { rm }";

    assert_eq!(
        dispatch.matches(raw_b_only_decode).count(),
        1,
        "EVEX vector r/m register decode must go through evex_rm_vec_reg so EVEX.X is not dropped"
    );
}

#[test]
fn test_evex_vector_vvvv_decode_stays_centralized() {
    let dispatch = include_str!("../../../../src/backend/emulator/x86_64/dispatch/evex.rs");

    assert!(
        !dispatch.contains("(evex.vvvv ^ 0xF) as usize"),
        "EVEX vector vvvv decode must use ctx.evex_vvvv() so EVEX.V' is not dropped"
    );
}

#[test]
fn test_evex_rm_register_uses_x_b_for_vmovaps_source() {
    // Encodings from:
    //   llvm-mc -triple=x86_64 -mcpu=skylake-avx512 -show-encoding
    let cases: &[(&str, &[u8], usize)] = &[
        ("zmm0", &[0x62, 0xf1, 0x7c, 0x48, 0x28, 0xc8], 0),
        ("zmm8", &[0x62, 0xd1, 0x7c, 0x48, 0x28, 0xc8], 8),
        ("zmm16", &[0x62, 0xb1, 0x7c, 0x48, 0x28, 0xc8], 16),
        ("zmm24", &[0x62, 0x91, 0x7c, 0x48, 0x28, 0xc8], 24),
    ];

    for (name, op, src_index) in cases {
        let mut regs = Registers::default();
        let values = [
            (0, pattern(0x00)),
            (1, pattern(0x01)),
            (8, pattern(0x08)),
            (16, pattern(0x10)),
            (24, pattern(0x18)),
        ];
        for (index, value) in values {
            set_zmm(&mut regs, index, value);
        }

        let final_regs = run_one(op, regs);
        assert_eq!(
            get_zmm(&final_regs, 1),
            pattern(*src_index as u64),
            "VMOVAPS zmm1,{name} must use EVEX.X:EVEX.B:ModRM.rm for the r/m register"
        );
    }
}

#[test]
fn test_evex_rm_register_uses_x_b_for_vaddps_src2() {
    // VADDPS zmm1,zmm2,zmm16 and zmm1,zmm2,zmm24. If EVEX.X is dropped, these
    // read zmm0/zmm8 instead and the result changes.
    let cases: &[(&str, &[u8], [u64; 8])] = &[
        (
            "zmm16",
            &[0x62, 0xb1, 0x6c, 0x48, 0x58, 0xc8],
            splat_f32(3.0),
        ),
        (
            "zmm24",
            &[0x62, 0x91, 0x6c, 0x48, 0x58, 0xc8],
            splat_f32(5.0),
        ),
    ];

    for (name, op, expected) in cases {
        let mut regs = Registers::default();
        set_zmm(&mut regs, 0, splat_f32(-64.0));
        set_zmm(&mut regs, 2, splat_f32(1.0));
        set_zmm(&mut regs, 8, splat_f32(-128.0));
        set_zmm(&mut regs, 16, splat_f32(2.0));
        set_zmm(&mut regs, 24, splat_f32(4.0));

        let final_regs = run_one(op, regs);
        assert_eq!(
            get_zmm(&final_regs, 1),
            *expected,
            "VADDPS zmm1,zmm2,{name} must use EVEX.X:EVEX.B:ModRM.rm for src2"
        );
    }
}
