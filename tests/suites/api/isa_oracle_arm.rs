//! ARM operation contracts, kept in semantic siblings.

#[path = "isa_oracle_arm_resize.rs"]
mod resize;
#[path = "isa_oracle_arm_saturating.rs"]
mod saturating;
#[path = "isa_oracle_arm_scalar_simd.rs"]
mod scalar_simd;

use rax::oracle::{ArmState, OracleIsa, OracleOptions, decode_to_json};

#[test]
fn decodes_arm_aarch64_instruction() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::Arm;
    opts.arm_state = ArmState::Aarch64;

    let value = decode_to_json(&[0x20, 0x00, 0x80, 0xd2], &opts).unwrap();
    assert_eq!(value["isa"], "arm");
    assert_eq!(value["decoded_ops"][0]["mnemonic"], "movz");
}

#[test]
fn decodes_arm_aarch64_non_temporal_pairs() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::Arm;
    opts.arm_state = ArmState::Aarch64;

    let cases = [
        (0x2840_0820u32, "ldnp"),
        (0xa840_0820u32, "ldnp"),
        (0x2800_0820u32, "stnp"),
        (0xa800_0820u32, "stnp"),
        (0x6940_0820u32, "ldpsw"),
        (0x6840_0820u32, "unknown"),
    ];

    for (raw, mnemonic) in cases {
        let value = decode_to_json(&raw.to_le_bytes(), &opts).unwrap();
        assert_eq!(value["decoded_ops"][0]["mnemonic"], mnemonic);
    }
}

#[test]
fn decodes_arm_aarch64_bti_hints() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::Arm;
    opts.arm_state = ArmState::Aarch64;

    let bti = [
        0xd503_241fu32,
        0xd503_245fu32,
        0xd503_249fu32,
        0xd503_24dfu32,
    ];
    for raw in bti {
        let value = decode_to_json(&raw.to_le_bytes(), &opts).unwrap();
        assert_eq!(value["decoded_ops"][0]["mnemonic"], "bti");
    }

    for (raw, mnemonic) in [(0xd503_231fu32, "paciaz"), (0xd503_235fu32, "pacibz")] {
        let value = decode_to_json(&raw.to_le_bytes(), &opts).unwrap();
        assert_eq!(value["decoded_ops"][0]["mnemonic"], mnemonic);
    }
}

#[test]
fn decodes_arm_aarch64_prfm_literal() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::Arm;
    opts.arm_state = ArmState::Aarch64;

    let cases = [
        (0xd800_0000u32, "Prfop(PLDL1KEEP)", "Label(0)"),
        (0xd800_0075u32, "Prfop(PSTL3STRM)", "Label(12)"),
        (0xd8ff_ffffu32, "Prfop(Raw(31))", "Label(-4)"),
    ];

    for (raw, prfop, label) in cases {
        let value = decode_to_json(&raw.to_le_bytes(), &opts).unwrap();
        let op = &value["decoded_ops"][0];
        assert_eq!(op["mnemonic"], "prfm");
        assert_eq!(op["operands"][0], prfop);
        assert_eq!(op["operands"][1], label);
    }
}

#[test]
fn decodes_arm_aarch64_prfm_memory_forms() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::Arm;
    opts.arm_state = ArmState::Aarch64;

    let cases = [
        (0xf980_0020u32, "Prfop(PLDL1KEEP)", "offset: Imm(0)"),
        (0xf980_0c35u32, "Prfop(PSTL3STRM)", "offset: Imm(24)"),
        (0xf89f_8022u32, "Prfop(PLDL2KEEP)", "offset: Imm(-8)"),
        (0xf8a2_5824u32, "Prfop(PLDL3KEEP)", "extend_type: UXTW"),
        (0xf8a2_e832u32, "Prfop(PSTL2KEEP)", "extend_type: SXTX"),
    ];

    for (raw, prfop, mem_fragment) in cases {
        let value = decode_to_json(&raw.to_le_bytes(), &opts).unwrap();
        let op = &value["decoded_ops"][0];
        assert_eq!(op["mnemonic"], "prfm");
        assert_eq!(op["operands"][0], prfop);
        let mem = op["operands"][1].as_str().unwrap();
        assert!(mem.contains(mem_fragment), "{mem}");
    }

    for raw in [
        0xf880_8420u32, // post-index prefetch pattern is undefined
        0xf880_8c20u32, // pre-index prefetch pattern is undefined
        0xf8a2_0820u32, // register-offset sub-word extend is undefined
        0xf9c0_0020u32, // size=11/opc=11 is undefined
    ] {
        let value = decode_to_json(&raw.to_le_bytes(), &opts).unwrap();
        assert_eq!(value["decoded_ops"][0]["mnemonic"], "unknown");
    }
}

#[test]
fn decodes_arm_aarch64_ldst_register_offset_forms() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::Arm;
    opts.arm_state = ArmState::Aarch64;

    let cases = [
        (0xf862_5820u32, "ldr", "extend_type: UXTW", "shift: 3"),
        (0xb822_c820u32, "str", "extend_type: SXTW", "shift: 0"),
        (0x38a2_e820u32, "ldrsb", "extend_type: SXTX", "shift: 0"),
        (0x78e2_5820u32, "ldrsh", "extend_type: UXTW", "shift: 1"),
        (0xf840_8820u32, "ldtr", "offset: Imm(8)", "mode: Offset"),
    ];

    for (raw, mnemonic, mem_fragment, shift_fragment) in cases {
        let value = decode_to_json(&raw.to_le_bytes(), &opts).unwrap();
        let op = &value["decoded_ops"][0];
        assert_eq!(op["mnemonic"], mnemonic);
        let mem = op["operands"][1].as_str().unwrap();
        assert!(mem.contains(mem_fragment), "{mem}");
        assert!(mem.contains(shift_fragment), "{mem}");
    }

    let value = decode_to_json(&0xf862_0820u32.to_le_bytes(), &opts).unwrap();
    assert_eq!(value["decoded_ops"][0]["mnemonic"], "unknown");
}

#[test]
fn pauth_decoding_reports_exact_frontiers_and_transfers() {
    let opts = OracleOptions {
        isa: OracleIsa::Arm,
        arm_state: ArmState::Aarch64,
        ..OracleOptions::default()
    };
    for (raw, mnemonic, flow) in [
        (0xd71f_081f_u32, "braa", "indirect_branch"),
        (0xd61f_081f, "braaz", "indirect_branch"),
        (0xd63f_081f, "blraaz", "indirect_call"),
        (0xd65f_0bff, "retaa", "return"),
        (0xd69f_0bff, "eretaa", "exception_return"),
        (0xf820_17e6, "ldraa", "fallthrough"),
        (0xf8a0_17e6, "ldrab", "fallthrough"),
    ] {
        let record = decode_to_json(&raw.to_le_bytes(), &opts).unwrap();
        assert_eq!(record["decoded_ops"][0]["mnemonic"], mnemonic);
        assert_eq!(record["control_flow"]["kind"], flow);
        assert_eq!(record["smir"]["available"], true);
        assert!(record["smir"]["error"].is_string(), "{raw:#010x}");
        assert!(
            record["smir"]["debug"]
                .as_str()
                .unwrap()
                .starts_with("Unsupported")
        );
        assert!(record["smir"]["ops"].is_null());
        if flow != "fallthrough" {
            assert_eq!(record["control_flow"]["authenticated"], true);
        }
    }
}
