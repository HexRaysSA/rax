use rax::isa::riscv::Xlen;
use rax::oracle::{
    ArmState, MAX_ORACLE_SEED_MEMORY_SIZE, OracleIsa, OracleMemorySeed, OracleOptions, OracleSeed,
    RiscVIsaProfile, decode_to_json, decode_to_json_with_seed, parse_hex_bytes,
};

#[path = "isa_oracle_arm.rs"]
mod arm;
#[path = "isa_oracle_cache_maintenance.rs"]
mod cache_maintenance;
#[path = "isa_oracle_fma.rs"]
mod fma;
#[path = "isa_oracle_gs_base.rs"]
mod gs_base;
#[path = "isa_oracle_hexagon_alignment.rs"]
mod hexagon_alignment;
#[path = "isa_oracle_hexagon_packet.rs"]
mod hexagon_packet;
#[path = "isa_oracle_int3.rs"]
mod int3;
#[path = "isa_oracle_invpcid.rs"]
mod invpcid;
#[path = "isa_oracle_packed_string.rs"]
mod packed_string;
#[path = "isa_oracle_xop.rs"]
mod xop;

#[test]
fn parses_hex_bytes_with_prefixes_and_separators() {
    let bytes = parse_hex_bytes("0x90, 48-b8").unwrap();
    assert_eq!(bytes, vec![0x90, 0x48, 0xb8]);
}

#[test]
fn decodes_hexagon_packet() {
    let word = 0x5400c000u32.to_le_bytes();
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::Hexagon;

    let value = decode_to_json(&word, &opts).unwrap();
    assert_eq!(value["isa"], "hexagon");
    assert_eq!(value["packet_flags"]["end_seen"], true);
    assert_eq!(value["decoded_ops"][0]["opcode"], "J2_trap0");
}

#[test]
fn decodes_riscv_instruction() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::RiscV;
    opts.riscv_xlen = Xlen::Rv64;
    opts.riscv_isa = RiscVIsaProfile::Rv64Gc;

    let value = decode_to_json(&[0x93, 0x00, 0x10, 0x00], &opts).unwrap();
    assert_eq!(value["isa"], "riscv");
    assert_eq!(value["decoded_ops"][0]["op"], "Addi");
}

#[test]
fn decodes_x86_with_smir_lift() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let value = decode_to_json(&[0x90], &opts).unwrap();
    assert_eq!(value["isa"], "x86_64");
    assert_eq!(value["smir"]["available"], true);
}

#[test]
fn emits_structured_avx10_2_fp16_and_bf16_saturation_smir() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    for (bytes, fp_elem, round, truncate, side_effects) in [
        (
            &[0x62, 0xF5, 0x7C, 0x08, 0x68, 0xCA][..],
            "F16",
            "RoundTowardZero",
            true,
            true,
        ),
        (
            &[0x62, 0xF5, 0x7F, 0x08, 0x69, 0xCA][..],
            "BF16",
            "RoundNearest",
            false,
            false,
        ),
    ] {
        let value = decode_to_json(bytes, &opts).unwrap();
        let smir = &value["smir"];
        assert_eq!(smir["available"], true, "{bytes:02X?}");
        assert_eq!(smir["bytes_consumed"], bytes.len(), "{bytes:02X?}");
        assert_eq!(smir["control_flow"]["kind"], "fallthrough", "{bytes:02X?}");
        assert!(smir.get("error").is_none(), "{bytes:02X?}: {smir}");

        let ops = smir["ops"].as_array().unwrap();
        assert_eq!(ops.len(), 1, "{bytes:02X?}: {smir}");
        let op = &ops[0];
        assert_eq!(op["kind"]["opcode"], "vcvt_fp_to_int_sat");
        assert_eq!(op["kind"]["dst"]["name"], "xmm1");
        assert_eq!(op["kind"]["src"]["name"], "xmm2");
        assert_eq!(op["kind"]["fp_elem"], fp_elem);
        assert_eq!(op["kind"]["int_elem"], "I8");
        assert_eq!(op["kind"]["width"], "V128");
        assert_eq!(op["kind"]["round"], round);
        assert_eq!(op["kind"]["truncate"], truncate);
        assert_eq!(op["kind"]["suppress_exceptions"], false);
        assert_eq!(op["side_effects"], side_effects);
        assert_eq!(op["memory"]["reads"], false);
        assert_eq!(op["memory"]["writes"], false);
    }
}

#[test]
fn emits_structured_avx10_2_scalar_saturation_smir() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    for (bytes, elem, int_width, signed, sae, side_effects) in [
        (
            &[0x62, 0xF5, 0x7E, 0x08, 0x6C, 0xC2][..],
            "F32",
            "W32",
            false,
            false,
            true,
        ),
        (
            &[0x62, 0xF5, 0xFF, 0x18, 0x6D, 0xC2][..],
            "F64",
            "W64",
            true,
            true,
            false,
        ),
    ] {
        let value = decode_to_json(bytes, &opts).unwrap();
        let smir = &value["smir"];
        assert_eq!(smir["available"], true, "{bytes:02X?}");
        assert_eq!(smir["bytes_consumed"], bytes.len(), "{bytes:02X?}");
        assert_eq!(smir["control_flow"]["kind"], "fallthrough");
        assert!(smir.get("error").is_none(), "{bytes:02X?}: {smir}");

        let ops = smir["ops"].as_array().unwrap();
        assert_eq!(ops.len(), 1, "{bytes:02X?}: {smir}");
        let op = &ops[0];
        assert_eq!(op["kind"]["opcode"], "x86_scalar_fp_to_int_sat");
        assert_eq!(op["kind"]["dst"]["name"], "rax");
        assert_eq!(op["kind"]["src"]["name"], "xmm2");
        assert_eq!(op["kind"]["elem"], elem);
        assert_eq!(op["kind"]["int_width"], int_width);
        assert_eq!(op["kind"]["signed"], signed);
        assert_eq!(op["kind"]["suppress_exceptions"], sae);
        assert_eq!(op["side_effects"], side_effects);
        assert_eq!(op["memory"]["reads"], false);
        assert_eq!(op["memory"]["writes"], false);
    }
}

#[test]
fn emits_structured_x86_opmask_smir() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let binary = decode_to_json(&[0xC5, 0xF4, 0x41, 0xDA], &opts).unwrap();
    let op = &binary["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_opmask");
    assert_eq!(op["kind"]["op"]["operation"], "binary");
    assert_eq!(op["kind"]["op"]["kind"], "and");
    assert_eq!(op["kind"]["op"]["width"], "W16");
    assert_eq!(op["kind"]["op"]["dst"]["name"], "k3");
    assert_eq!(op["kind"]["op"]["src1"]["name"], "k1");
    assert_eq!(op["kind"]["op"]["src2"]["name"], "k2");
    assert_eq!(op["writes"][0]["name"], "k3");
    assert_eq!(op["memory"]["reads"], false);
    assert_eq!(op["memory"]["writes"], false);

    let store = decode_to_json(&[0xC4, 0xE1, 0xF8, 0x91, 0x68, 0x08], &opts).unwrap();
    let op = &store["smir"]["ops"][0];
    assert_eq!(op["kind"]["op"]["operation"], "move_from_mask");
    assert_eq!(op["kind"]["op"]["src"]["name"], "k5");
    assert_eq!(op["kind"]["op"]["dst"]["kind"], "memory");
    assert_eq!(op["kind"]["op"]["dst"]["addr"]["kind"], "base_offset");
    assert_eq!(op["kind"]["op"]["dst"]["addr"]["base"]["name"], "rax");
    assert_eq!(op["kind"]["op"]["dst"]["addr"]["offset"], 8);
    assert_eq!(op["kind"]["op"]["width"], "W64");
    assert_eq!(op["memory"]["reads"], false);
    assert_eq!(op["memory"]["writes"], true);
    assert_eq!(op["side_effects"], true);
}

#[test]
fn emits_exact_string_port_io_handoff_metadata() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let value = decode_to_json(&[0xF3, 0x64, 0x67, 0x66, 0x6F], &opts).unwrap();
    let smir = &value["smir"];
    assert_eq!(smir["available"], true);
    assert_eq!(smir["bytes_consumed"], 5);
    assert_eq!(smir["ops"], serde_json::json!([]));
    assert_eq!(smir["control_flow"]["kind"], "trap");
    assert_eq!(
        smir["control_flow"]["trap"],
        "X86StringIo { kind: Outs, width: B2, address_width: W32, repeated: true, \
         memory_segment: Fs, fault_pc: 4096, return_pc: 4101, requires_apx: false }"
    );
    assert_eq!(smir["ends_block"], true);
    assert_eq!(smir["ends_function"], true);
}

#[test]
fn reports_x86_ud0_as_an_exact_two_byte_invalid_opcode_trap() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let value = decode_to_json(&[0x0F, 0xFF, 0x04, 0x25, 0x78, 0x56, 0x34, 0x12], &opts).unwrap();
    let smir = &value["smir"];
    assert_eq!(smir["available"], true);
    assert_eq!(smir["bytes_consumed"], 2);
    assert_eq!(smir["ops"].as_array().unwrap().len(), 0);
    assert_eq!(smir["control_flow"]["kind"], "trap");
    assert_eq!(smir["control_flow"]["trap"], "InvalidOpcode");
    assert_eq!(smir["ends_block"], true);
    assert_eq!(smir["ends_function"], true);
}

#[test]
fn reports_reserved_x86_two_byte_opcodes_as_exact_invalid_opcode_traps() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    for (bytes, expected_len) in [
        (&[0x0F, 0x04][..], 2),
        (&[0x66, 0x0F, 0x0A], 3),
        (&[0xF0, 0x0F, 0x0C], 3),
        (&[0xD5, 0x80, 0x04], 3),
        (&[0x66, 0xD5, 0x80, 0x0A], 4),
        (&[0x0F, 0x0C, 0x04, 0x25, 0x78, 0x56, 0x34, 0x12], 2),
    ] {
        let value = decode_to_json(bytes, &opts).unwrap();
        let smir = &value["smir"];
        assert_eq!(smir["available"], true, "{bytes:02X?}");
        assert_eq!(smir["bytes_consumed"], expected_len, "{bytes:02X?}");
        assert_eq!(smir["ops"], serde_json::json!([]), "{bytes:02X?}");
        assert_eq!(smir["control_flow"]["kind"], "trap", "{bytes:02X?}");
        assert_eq!(
            smir["control_flow"]["trap"], "InvalidOpcode",
            "{bytes:02X?}"
        );
        assert_eq!(smir["ends_block"], true, "{bytes:02X?}");
        assert_eq!(smir["ends_function"], true, "{bytes:02X?}");
    }
}

#[test]
fn reports_profile_disabled_ptwrite_as_an_exact_invalid_opcode_trap() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    for bytes in [
        &[0xF3, 0x0F, 0xAE, 0xE0][..],
        &[0xF3, 0x48, 0x0F, 0xAE, 0xE0],
        &[0xF3, 0x0F, 0xAE, 0x64, 0x24, 0x7F],
        &[0x67, 0xF3, 0x0F, 0xAE, 0x25, 0x78, 0x56, 0x34, 0x12],
        &[0xF3, 0xD5, 0x90, 0xAE, 0xE0],
        &[0xF3, 0xD5, 0x80, 0xAE, 0x20],
        &[0xF0, 0xF3, 0x0F, 0xAE, 0xE0],
    ] {
        let value = decode_to_json(bytes, &opts).unwrap();
        let smir = &value["smir"];
        assert_eq!(smir["available"], true, "{bytes:02X?}");
        assert_eq!(smir["bytes_consumed"], bytes.len(), "{bytes:02X?}");
        assert_eq!(smir["ops"], serde_json::json!([]), "{bytes:02X?}");
        assert_eq!(smir["control_flow"]["kind"], "trap", "{bytes:02X?}");
        assert_eq!(
            smir["control_flow"]["trap"], "InvalidOpcode",
            "{bytes:02X?}"
        );
        assert_eq!(smir["ends_block"], true, "{bytes:02X?}");
        assert_eq!(smir["ends_function"], true, "{bytes:02X?}");
    }
}

#[test]
fn reports_residual_group15_forms_without_an_unsupported_frontier() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    for bytes in [
        &[0x66, 0x0F, 0xAE, 0xE9][..],
        &[0xF2, 0x0F, 0xAE, 0xEF],
        &[0x66, 0x0F, 0xAE, 0xFF],
        &[0xF3, 0x0F, 0xAE, 0xF9],
        &[0xF3, 0x0F, 0xAE, 0x10],
    ] {
        let value = decode_to_json(bytes, &opts).unwrap();
        let smir = &value["smir"];
        assert_eq!(smir["available"], true, "{bytes:02X?}");
        assert_eq!(smir["bytes_consumed"], bytes.len(), "{bytes:02X?}");
        assert_eq!(smir["control_flow"]["kind"], "fallthrough", "{bytes:02X?}");
    }

    for bytes in [
        &[0x0F, 0xAE, 0xD0][..],
        &[0xF2, 0x0F, 0xAE, 0xE0],
        &[0x66, 0xF3, 0x0F, 0xAE, 0xC0],
        &[0xF0, 0x0F, 0xAE, 0xF0],
    ] {
        let value = decode_to_json(bytes, &opts).unwrap();
        let smir = &value["smir"];
        assert_eq!(smir["available"], true, "{bytes:02X?}");
        assert_eq!(smir["bytes_consumed"], bytes.len(), "{bytes:02X?}");
        assert_eq!(smir["ops"], serde_json::json!([]), "{bytes:02X?}");
        assert_eq!(smir["control_flow"]["kind"], "trap", "{bytes:02X?}");
        assert_eq!(
            smir["control_flow"]["trap"], "InvalidOpcode",
            "{bytes:02X?}"
        );
    }
}

#[test]
fn reports_reserved_x87_cells_as_exact_traps_and_transcendentals_as_smir() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    for bytes in [
        &[0xD9, 0x0D, 0x78, 0x56, 0x34, 0x12][..],
        &[0xD9, 0xD1],
        &[0xDA, 0xE0],
        &[0xDB, 0xE5],
        &[0xDD, 0xF0],
        &[0xDE, 0xD8],
        &[0xDF, 0xC8],
        &[0xD5, 0x00, 0xDF, 0xE1],
        &[0xF0, 0xD9, 0xD0],
    ] {
        let value = decode_to_json(bytes, &opts).unwrap();
        let smir = &value["smir"];
        assert_eq!(smir["available"], true, "{bytes:02X?}");
        assert_eq!(smir["bytes_consumed"], bytes.len(), "{bytes:02X?}");
        assert_eq!(smir["ops"], serde_json::json!([]), "{bytes:02X?}");
        assert_eq!(smir["control_flow"]["kind"], "trap", "{bytes:02X?}");
        assert_eq!(
            smir["control_flow"]["trap"], "InvalidOpcode",
            "{bytes:02X?}"
        );
        assert_eq!(smir["ends_block"], true, "{bytes:02X?}");
        assert_eq!(smir["ends_function"], true, "{bytes:02X?}");
    }

    for (modrm, kind) in [
        (0xF0, "Transcendental(Exp2MinusOne)"),
        (0xF1, "Transcendental(YLog2X)"),
        (0xF2, "Transcendental(Tangent)"),
        (0xF3, "Transcendental(Arctangent)"),
        (0xF9, "Transcendental(YLog2Xp1)"),
        (0xFB, "Transcendental(SineCosine)"),
        (0xFE, "Transcendental(Sine)"),
        (0xFF, "Transcendental(Cosine)"),
    ] {
        let bytes = [0xD9, modrm];
        let value = decode_to_json(&bytes, &opts).unwrap();
        let smir = &value["smir"];
        assert_eq!(smir["available"], true, "{bytes:02X?}");
        assert_eq!(smir["bytes_consumed"], 2, "{bytes:02X?}");
        assert_eq!(smir["control_flow"]["kind"], "fallthrough", "{bytes:02X?}");
        assert!(smir.get("error").is_none(), "{bytes:02X?}: {smir}");
        let ops = smir["ops"].as_array().unwrap();
        assert_eq!(ops.len(), 1, "{bytes:02X?}: {smir}");
        let op = &ops[0];
        assert_eq!(op["kind"]["opcode"], "x86_x87_data", "{bytes:02X?}");
        assert_eq!(op["kind"]["kind"], kind, "{bytes:02X?}");
        assert_eq!(op["kind"]["addr"], serde_json::Value::Null, "{bytes:02X?}");
        assert_eq!(op["kind"]["st"], modrm & 7, "{bytes:02X?}");
        assert_eq!(op["kind"]["fop"], 0x0100 | modrm as u16, "{bytes:02X?}");
        assert_eq!(op["side_effects"], true, "{bytes:02X?}");
        assert_eq!(op["memory"]["reads"], false, "{bytes:02X?}");
        assert_eq!(op["memory"]["writes"], false, "{bytes:02X?}");
    }
}

#[test]
fn reports_exact_hypercall_hint_and_unsupported_alias_profiles() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    for bytes in [&[0x0F, 0x01, 0xC1][..], &[0x0F, 0x01, 0xD9]] {
        let value = decode_to_json(bytes, &opts).unwrap();
        let smir = &value["smir"];
        assert_eq!(smir["available"], true, "{bytes:02X?}");
        assert_eq!(smir["bytes_consumed"], bytes.len(), "{bytes:02X?}");
        assert_eq!(smir["ops"], serde_json::json!([]), "{bytes:02X?}");
        assert_eq!(smir["control_flow"]["kind"], "fallthrough");
        assert_eq!(smir["ends_block"], false);
        assert_eq!(smir["ends_function"], false);
    }

    for bytes in [
        &[0xF2, 0x0F, 0x01, 0xD9][..],
        &[0xF3, 0x0F, 0x01, 0xD9],
        &[0xD5, 0x80, 0x01, 0xD9],
    ] {
        let value = decode_to_json(bytes, &opts).unwrap();
        let smir = &value["smir"];
        assert_eq!(smir["available"], true, "{bytes:02X?}");
        assert_eq!(smir["bytes_consumed"], bytes.len(), "{bytes:02X?}");
        assert_eq!(smir["ops"], serde_json::json!([]), "{bytes:02X?}");
        assert_eq!(smir["control_flow"]["kind"], "trap");
        assert_eq!(smir["control_flow"]["trap"], "InvalidOpcode");
        assert_eq!(smir["ends_block"], true);
        assert_eq!(smir["ends_function"], true);
    }
}

#[test]
fn reports_disabled_vmx_controls_as_exact_invalid_opcode_traps() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    for bytes in [
        &[0x0F, 0x01, 0xC2][..], // VMLAUNCH
        &[0x0F, 0x01, 0xC3],     // VMRESUME
        &[0x0F, 0x01, 0xC4],     // VMXOFF
        &[0x0F, 0x01, 0xD4],     // VMFUNC
        &[0xD5, 0x80, 0x01, 0xC2],
        &[0xD5, 0x80, 0x01, 0xC3],
        &[0xD5, 0x80, 0x01, 0xC4],
        &[0xD5, 0x80, 0x01, 0xD4],
    ] {
        let value = decode_to_json(bytes, &opts).unwrap();
        let smir = &value["smir"];
        assert_eq!(smir["available"], true, "{bytes:02X?}");
        assert_eq!(smir["bytes_consumed"], bytes.len(), "{bytes:02X?}");
        assert_eq!(smir["ops"], serde_json::json!([]), "{bytes:02X?}");
        assert_eq!(smir["control_flow"]["kind"], "trap", "{bytes:02X?}");
        assert_eq!(
            smir["control_flow"]["trap"], "InvalidOpcode",
            "{bytes:02X?}"
        );
        assert_eq!(smir["ends_block"], true, "{bytes:02X?}");
        assert_eq!(smir["ends_function"], true, "{bytes:02X?}");
    }
}

#[test]
fn reports_disabled_svm_controls_as_exact_invalid_opcode_traps() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    for modrm in [0xD8, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF] {
        for bytes in [vec![0x0F, 0x01, modrm], vec![0xD5, 0x80, 0x01, modrm]] {
            let value = decode_to_json(&bytes, &opts).unwrap();
            let smir = &value["smir"];
            assert_eq!(smir["available"], true, "{bytes:02X?}");
            assert_eq!(smir["bytes_consumed"], bytes.len(), "{bytes:02X?}");
            assert_eq!(smir["ops"], serde_json::json!([]), "{bytes:02X?}");
            assert_eq!(smir["control_flow"]["kind"], "trap", "{bytes:02X?}");
            assert_eq!(
                smir["control_flow"]["trap"], "InvalidOpcode",
                "{bytes:02X?}"
            );
            assert_eq!(smir["ends_block"], true, "{bytes:02X?}");
            assert_eq!(smir["ends_function"], true, "{bytes:02X?}");
        }
    }
}

#[test]
fn reports_disabled_sgx_roots_as_exact_invalid_opcode_traps() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    for modrm in [0xC0, 0xCF, 0xD7] {
        for bytes in [vec![0x0F, 0x01, modrm], vec![0xD5, 0x80, 0x01, modrm]] {
            let value = decode_to_json(&bytes, &opts).unwrap();
            let smir = &value["smir"];
            assert_eq!(smir["available"], true, "{bytes:02X?}");
            assert_eq!(smir["bytes_consumed"], bytes.len(), "{bytes:02X?}");
            assert_eq!(smir["ops"], serde_json::json!([]), "{bytes:02X?}");
            assert_eq!(smir["control_flow"]["kind"], "trap", "{bytes:02X?}");
            assert_eq!(
                smir["control_flow"]["trap"], "InvalidOpcode",
                "{bytes:02X?}"
            );
            assert_eq!(smir["ends_block"], true, "{bytes:02X?}");
            assert_eq!(smir["ends_function"], true, "{bytes:02X?}");
        }
    }
}

#[test]
fn reports_disabled_pconfig_as_an_exact_invalid_opcode_trap() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    for bytes in [
        &[0x0F, 0x01, 0xC5][..],
        &[0x66, 0x0F, 0x01, 0xC5],
        &[0xF2, 0x0F, 0x01, 0xC5],
        &[0xF3, 0x0F, 0x01, 0xC5],
        &[0xC5, 0xF8, 0x01, 0xC5],
        &[0xC4, 0xE1, 0x78, 0x01, 0xC5],
        &[0x62, 0xF1, 0x7C, 0x08, 0x01, 0xC5],
        &[0xD5, 0x80, 0x01, 0xC5],
    ] {
        let value = decode_to_json(bytes, &opts).unwrap();
        let smir = &value["smir"];
        assert_eq!(smir["available"], true, "{bytes:02X?}");
        assert_eq!(smir["bytes_consumed"], bytes.len(), "{bytes:02X?}");
        assert_eq!(smir["ops"], serde_json::json!([]), "{bytes:02X?}");
        assert_eq!(smir["control_flow"]["kind"], "trap", "{bytes:02X?}");
        assert_eq!(
            smir["control_flow"]["trap"], "InvalidOpcode",
            "{bytes:02X?}"
        );
        assert_eq!(smir["ends_block"], true, "{bytes:02X?}");
        assert_eq!(smir["ends_function"], true, "{bytes:02X?}");
    }
}

#[test]
fn reports_disabled_msr_extensions_as_exact_invalid_opcode_traps() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    for bytes in [
        &[0x0F, 0x01, 0xC6][..],
        &[0xF2, 0x0F, 0x01, 0xC6],
        &[0xF3, 0x0F, 0x01, 0xC6],
        &[0x66, 0x0F, 0x01, 0xC6],
        &[0xC5, 0xF8, 0x01, 0xC6],
        &[0xC4, 0xE1, 0x78, 0x01, 0xC6],
        &[0x62, 0xF1, 0x7C, 0x08, 0x01, 0xC6],
        &[0xD5, 0x80, 0x01, 0xC6],
    ] {
        let value = decode_to_json(bytes, &opts).unwrap();
        let smir = &value["smir"];
        assert_eq!(smir["available"], true, "{bytes:02X?}");
        assert_eq!(smir["bytes_consumed"], bytes.len(), "{bytes:02X?}");
        assert_eq!(smir["ops"], serde_json::json!([]), "{bytes:02X?}");
        assert_eq!(smir["control_flow"]["kind"], "trap", "{bytes:02X?}");
        assert_eq!(
            smir["control_flow"]["trap"], "InvalidOpcode",
            "{bytes:02X?}"
        );
        assert_eq!(smir["ends_block"], true, "{bytes:02X?}");
        assert_eq!(smir["ends_function"], true, "{bytes:02X?}");
    }
}

#[test]
fn emits_structured_smir_ops() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let value = decode_to_json(&[0xb8, 0x34, 0x12, 0x00, 0x00], &opts).unwrap();
    let op = &value["smir"]["ops"][0];

    assert_eq!(op["opcode"], "mov");
    assert_eq!(op["kind"]["opcode"], "mov");
    assert_eq!(op["kind"]["dst"]["kind"], "arch");
    assert_eq!(op["kind"]["dst"]["name"], "rax");
    assert_eq!(op["kind"]["src"]["kind"], "imm");
    assert_eq!(op["kind"]["src"]["value"], 0x1234);
    assert!(op.get("debug").is_none());
}

#[test]
fn emits_exact_fsgsbase_state_direction_width_and_apx_metadata() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let read = decode_to_json(&[0xF3, 0xD5, 0x99, 0xAE, 0xCF], &opts).unwrap();
    assert_eq!(read["smir"]["available"], true);
    assert_eq!(read["smir"]["bytes_consumed"], 5);
    let op = &read["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_fsgsbase");
    assert_eq!(op["kind"]["operand"]["name"], "r31");
    assert_eq!(op["kind"]["base"]["name"], "gs_base");
    assert_eq!(op["kind"]["write"], false);
    assert_eq!(op["kind"]["width"], "W64");
    assert_eq!(op["kind"]["requires_apx"], true);
    assert_eq!(op["writes"][0]["name"], "r31");
    assert_eq!(op["memory"]["reads"], false);
    assert_eq!(op["memory"]["writes"], false);
    assert_eq!(op["side_effects"], true);

    let write = decode_to_json(&[0xF3, 0x0F, 0xAE, 0xD0], &opts).unwrap();
    let op = &write["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_fsgsbase");
    assert_eq!(op["kind"]["operand"]["name"], "rax");
    assert_eq!(op["kind"]["base"]["name"], "fs_base");
    assert_eq!(op["kind"]["write"], true);
    assert_eq!(op["kind"]["width"], "W32");
    assert_eq!(op["kind"]["requires_apx"], false);
    assert_eq!(op["writes"][0]["name"], "fs_base");
}

#[test]
fn emits_exact_pkru_state_direction_and_implicit_register_metadata() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let read = decode_to_json(&[0x0F, 0x01, 0xEE], &opts).unwrap();
    assert_eq!(read["smir"]["available"], true);
    assert_eq!(read["smir"]["bytes_consumed"], 3);
    let op = &read["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_pkru");
    assert_eq!(op["kind"]["eax"]["name"], "rax");
    assert_eq!(op["kind"]["ecx"]["name"], "rcx");
    assert_eq!(op["kind"]["edx"]["name"], "rdx");
    assert_eq!(op["kind"]["pkru"]["name"], "pkru");
    assert_eq!(op["kind"]["write"], false);
    assert_eq!(op["writes"][0]["name"], "rax");
    assert_eq!(op["writes"][1]["name"], "rdx");
    assert_eq!(op["side_effects"], true);

    let write = decode_to_json(&[0x0F, 0x01, 0xEF], &opts).unwrap();
    let op = &write["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_pkru");
    assert_eq!(op["kind"]["write"], true);
    assert_eq!(op["writes"][0]["name"], "pkru");
    assert_eq!(op["memory"]["reads"], false);
    assert_eq!(op["memory"]["writes"], false);
}

#[test]
fn emits_exact_clac_stac_guest_ac_metadata() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    for (modrm, value) in [(0xCA, false), (0xCB, true)] {
        let decoded = decode_to_json(&[0x0F, 0x01, modrm], &opts).unwrap();
        assert_eq!(decoded["smir"]["available"], true);
        assert_eq!(decoded["smir"]["bytes_consumed"], 3);
        let op = &decoded["smir"]["ops"][0];
        assert_eq!(op["kind"]["opcode"], "set_ac");
        assert_eq!(op["kind"]["value"], value);
        assert_eq!(op["writes"].as_array().unwrap().len(), 0);
        assert_eq!(op["memory"]["reads"], false);
        assert_eq!(op["memory"]["writes"], false);
        assert_eq!(op["side_effects"], true);
    }
}

#[test]
fn emits_exact_clts_guest_cr0_state_metadata() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let decoded = decode_to_json(&[0x0F, 0x06], &opts).unwrap();
    assert_eq!(decoded["smir"]["available"], true);
    assert_eq!(decoded["smir"]["bytes_consumed"], 2);
    let op = &decoded["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_clts");
    assert!(op["reads"].is_null());
    assert_eq!(op["writes"].as_array().unwrap().len(), 0);
    assert_eq!(op["memory"]["reads"], false);
    assert_eq!(op["memory"]["writes"], false);
    assert_eq!(op["side_effects"], true);
}

#[test]
fn emits_exact_rdmsr_wrmsr_metadata_and_frontiers() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let read = decode_to_json(&[0x0F, 0x32], &opts).unwrap();
    assert_eq!(read["smir"]["available"], true);
    assert_eq!(read["smir"]["bytes_consumed"], 2);
    let op = &read["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_msr");
    assert_eq!(op["kind"]["eax"]["name"], "rax");
    assert_eq!(op["kind"]["ecx"]["name"], "rcx");
    assert_eq!(op["kind"]["edx"]["name"], "rdx");
    assert_eq!(op["kind"]["write"], false);
    assert_eq!(op["kind"]["next_pc"], 0x1002);
    assert_eq!(op["writes"][0]["name"], "rax");
    assert_eq!(op["writes"][1]["name"], "rdx");
    assert_eq!(op["side_effects"], true);

    let write = decode_to_json(&[0x66, 0x0F, 0x30], &opts).unwrap();
    assert_eq!(write["smir"]["available"], true);
    assert_eq!(write["smir"]["bytes_consumed"], 3);
    let op = &write["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_msr");
    assert_eq!(op["kind"]["write"], true);
    assert_eq!(op["kind"]["next_pc"], 0x1003);
    assert_eq!(op["writes"].as_array().unwrap().len(), 0);
    assert_eq!(op["memory"]["reads"], false);
    assert_eq!(op["memory"]["writes"], false);
    assert_eq!(op["side_effects"], true);
}

#[test]
fn emits_exact_mov_from_control_register_metadata() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let decoded = decode_to_json(&[0x45, 0x0F, 0x20, 0xC7], &opts).unwrap();
    assert_eq!(decoded["smir"]["available"], true);
    assert_eq!(decoded["smir"]["bytes_consumed"], 4);
    let op = &decoded["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_read_control");
    assert_eq!(op["kind"]["control"], "Cr8");
    assert_eq!(op["kind"]["dst"]["arch"], "x86_64");
    assert_eq!(op["kind"]["dst"]["name"], "r15");
    assert!(op["reads"].is_null());
    assert_eq!(op["writes"].as_array().unwrap().len(), 1);
    assert_eq!(op["memory"]["reads"], false);
    assert_eq!(op["memory"]["writes"], false);
    assert_eq!(op["side_effects"], true);
}

#[test]
fn emits_exact_smsw_register_and_memory_metadata() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let register = decode_to_json(&[0xD5, 0x91, 0x01, 0xE7], &opts).unwrap();
    assert_eq!(register["smir"]["available"], true);
    assert_eq!(register["smir"]["bytes_consumed"], 4);
    let op = &register["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_smsw");
    assert_eq!(op["kind"]["target"]["kind"], "register");
    assert_eq!(op["kind"]["target"]["dst"]["name"], "r31");
    assert_eq!(op["kind"]["target"]["width"], "W32");
    assert_eq!(op["kind"]["requires_apx"], true);
    assert_eq!(op["writes"][0]["name"], "r31");
    assert_eq!(op["memory"]["writes"], false);
    assert_eq!(op["side_effects"], true);

    let memory = decode_to_json(&[0x48, 0x0F, 0x01, 0x60, 0x08], &opts).unwrap();
    assert_eq!(memory["smir"]["available"], true);
    assert_eq!(memory["smir"]["bytes_consumed"], 5);
    let op = &memory["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_smsw");
    assert_eq!(op["kind"]["target"]["kind"], "memory");
    assert_eq!(op["kind"]["requires_apx"], false);
    assert_eq!(op["memory"]["reads"], false);
    assert_eq!(op["memory"]["writes"], true);
    assert_eq!(op["side_effects"], true);
}

#[test]
fn emits_exact_sldt_str_selector_target_width_and_apx_metadata() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let register = decode_to_json(&[0xD5, 0x91, 0x00, 0xCF], &opts).unwrap();
    assert_eq!(register["smir"]["available"], true);
    assert_eq!(register["smir"]["bytes_consumed"], 4);
    let op = &register["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_system_selector_store");
    assert_eq!(op["kind"]["selector"], "Tr");
    assert_eq!(op["kind"]["target"]["kind"], "register");
    assert_eq!(op["kind"]["target"]["dst"]["name"], "r31");
    assert_eq!(op["kind"]["target"]["width"], "W32");
    assert_eq!(op["kind"]["requires_apx"], true);
    assert_eq!(op["writes"][0]["name"], "r31");
    assert_eq!(op["memory"]["reads"], false);
    assert_eq!(op["memory"]["writes"], false);
    assert_eq!(op["side_effects"], true);

    let memory = decode_to_json(&[0x48, 0x0F, 0x00, 0x40, 0x08], &opts).unwrap();
    assert_eq!(memory["smir"]["available"], true);
    assert_eq!(memory["smir"]["bytes_consumed"], 5);
    let op = &memory["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_system_selector_store");
    assert_eq!(op["kind"]["selector"], "Ldtr");
    assert_eq!(op["kind"]["target"]["kind"], "memory");
    assert_eq!(op["kind"]["target"]["width"], "B2");
    assert_eq!(op["kind"]["target"]["addr"]["kind"], "base_offset");
    assert_eq!(op["kind"]["target"]["addr"]["base"]["name"], "rax");
    assert_eq!(op["kind"]["target"]["addr"]["offset"], 8);
    assert_eq!(op["kind"]["requires_apx"], false);
    assert_eq!(op["writes"].as_array().unwrap().len(), 0);
    assert_eq!(op["memory"]["reads"], false);
    assert_eq!(op["memory"]["writes"], true);
    assert_eq!(op["side_effects"], true);
}

#[test]
fn emits_exact_verr_verw_source_access_flags_and_apx_metadata() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let register = decode_to_json(&[0xD5, 0x91, 0x00, 0xE7], &opts).unwrap();
    assert_eq!(register["smir"]["available"], true);
    assert_eq!(register["smir"]["bytes_consumed"], 4);
    let op = &register["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_selector_verify");
    assert_eq!(op["kind"]["kind"], "Read");
    assert_eq!(op["kind"]["source"]["kind"], "register");
    assert_eq!(op["kind"]["source"]["src"]["name"], "r31");
    assert_eq!(op["kind"]["source"]["width"], "W16");
    assert_eq!(op["kind"]["requires_apx"], true);
    assert_eq!(op["kind"]["next_pc"], 0x1004);
    assert!(op["reads"].is_null());
    assert_eq!(op["writes"].as_array().unwrap().len(), 0);
    assert_eq!(op["memory"]["reads"], true);
    assert_eq!(op["memory"]["writes"], false);
    assert_eq!(op["side_effects"], true);

    let memory = decode_to_json(&[0x36, 0x0F, 0x00, 0x68, 0x08], &opts).unwrap();
    assert_eq!(memory["smir"]["available"], true);
    assert_eq!(memory["smir"]["bytes_consumed"], 5);
    let op = &memory["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_selector_verify");
    assert_eq!(op["kind"]["kind"], "Write");
    assert_eq!(op["kind"]["source"]["kind"], "memory");
    assert_eq!(op["kind"]["source"]["width"], "B2");
    assert_eq!(op["kind"]["source"]["stack_segment"], true);
    assert_eq!(op["kind"]["source"]["addr"]["kind"], "base_offset");
    assert_eq!(op["kind"]["source"]["addr"]["base"]["name"], "rax");
    assert_eq!(op["kind"]["source"]["addr"]["offset"], 8);
    assert_eq!(op["kind"]["requires_apx"], false);
    assert_eq!(op["kind"]["next_pc"], 0x1005);
    assert_eq!(op["writes"].as_array().unwrap().len(), 0);
    assert_eq!(op["memory"]["reads"], true);
    assert_eq!(op["memory"]["writes"], false);
    assert_eq!(op["side_effects"], true);
}

#[test]
fn emits_exact_lar_lsl_destination_source_width_flags_and_apx_metadata() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let register = decode_to_json(&[0xD5, 0xD5, 0x02, 0xF7], &opts).unwrap();
    assert_eq!(register["smir"]["available"], true);
    assert_eq!(register["smir"]["bytes_consumed"], 4);
    let op = &register["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_selector_query");
    assert_eq!(op["kind"]["kind"], "AccessRights");
    assert_eq!(op["kind"]["dst"]["name"], "r30");
    assert_eq!(op["kind"]["source"]["kind"], "register");
    assert_eq!(op["kind"]["source"]["src"]["name"], "r31");
    assert_eq!(op["kind"]["source"]["width"], "W16");
    assert_eq!(op["kind"]["width"], "W32");
    assert_eq!(op["kind"]["requires_apx"], true);
    assert_eq!(op["kind"]["next_pc"], 0x1004);
    assert_eq!(op["writes"][0]["name"], "r30");
    assert_eq!(op["memory"]["reads"], true);
    assert_eq!(op["memory"]["writes"], false);
    assert_eq!(op["side_effects"], true);

    let memory = decode_to_json(&[0x36, 0x48, 0x0F, 0x03, 0x50, 0x08], &opts).unwrap();
    assert_eq!(memory["smir"]["available"], true);
    assert_eq!(memory["smir"]["bytes_consumed"], 6);
    let op = &memory["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_selector_query");
    assert_eq!(op["kind"]["kind"], "Limit");
    assert_eq!(op["kind"]["dst"]["name"], "rdx");
    assert_eq!(op["kind"]["source"]["kind"], "memory");
    assert_eq!(op["kind"]["source"]["width"], "B2");
    assert_eq!(op["kind"]["source"]["stack_segment"], true);
    assert_eq!(op["kind"]["source"]["addr"]["kind"], "base_offset");
    assert_eq!(op["kind"]["source"]["addr"]["base"]["name"], "rax");
    assert_eq!(op["kind"]["source"]["addr"]["offset"], 8);
    assert_eq!(op["kind"]["width"], "W64");
    assert_eq!(op["kind"]["requires_apx"], false);
    assert_eq!(op["kind"]["next_pc"], 0x1006);
    assert_eq!(op["writes"][0]["name"], "rdx");
    assert_eq!(op["memory"]["reads"], true);
    assert_eq!(op["memory"]["writes"], false);
    assert_eq!(op["side_effects"], true);
}

#[test]
fn emits_exact_push_fs_gs_atomic_stack_width_and_apx_metadata() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let legacy = decode_to_json(&[0x0F, 0xA0], &opts).unwrap();
    assert_eq!(legacy["smir"]["available"], true);
    assert_eq!(legacy["smir"]["bytes_consumed"], 2);
    let op = &legacy["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_system_selector_store");
    assert_eq!(op["kind"]["selector"], "Fs");
    assert_eq!(op["kind"]["target"]["kind"], "stack");
    assert_eq!(op["kind"]["target"]["stack_pointer"]["name"], "rsp");
    assert_eq!(op["kind"]["target"]["width"], "B8");
    assert_eq!(op["kind"]["target"]["commit"], "after_write");
    assert_eq!(op["kind"]["requires_apx"], false);
    assert_eq!(op["writes"][0]["name"], "rsp");
    assert_eq!(op["memory"]["reads"], false);
    assert_eq!(op["memory"]["writes"], true);
    assert_eq!(op["side_effects"], true);

    let rex2_w = decode_to_json(&[0x66, 0xD5, 0x88, 0xA8], &opts).unwrap();
    assert_eq!(rex2_w["smir"]["available"], true);
    assert_eq!(rex2_w["smir"]["bytes_consumed"], 4);
    let op = &rex2_w["smir"]["ops"][0];
    assert_eq!(op["kind"]["selector"], "Gs");
    assert_eq!(op["kind"]["target"]["kind"], "stack");
    assert_eq!(op["kind"]["target"]["width"], "B8");
    assert_eq!(op["kind"]["requires_apx"], true);
}

#[test]
fn emits_exact_pop_fs_gs_atomic_stack_width_frontier_and_apx_metadata() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let legacy = decode_to_json(&[0x0F, 0xA1], &opts).unwrap();
    assert_eq!(legacy["smir"]["available"], true);
    assert_eq!(legacy["smir"]["bytes_consumed"], 2);
    let op = &legacy["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_system_selector_load");
    assert_eq!(op["kind"]["selector"], "Fs");
    assert_eq!(op["kind"]["source"]["kind"], "stack");
    assert_eq!(op["kind"]["source"]["stack_pointer"]["name"], "rsp");
    assert_eq!(op["kind"]["source"]["width"], "B8");
    assert_eq!(op["kind"]["source"]["commit"], "after_selector_load");
    assert_eq!(op["kind"]["requires_apx"], false);
    assert_eq!(op["kind"]["next_pc"], 0x1002);
    assert!(op["reads"].is_null());
    assert_eq!(op["writes"][0]["name"], "rsp");
    assert_eq!(op["memory"]["reads"], true);
    assert_eq!(op["memory"]["writes"], true);
    assert_eq!(op["side_effects"], true);

    let rex2_w = decode_to_json(&[0x66, 0xD5, 0x88, 0xA9], &opts).unwrap();
    assert_eq!(rex2_w["smir"]["available"], true);
    assert_eq!(rex2_w["smir"]["bytes_consumed"], 4);
    let op = &rex2_w["smir"]["ops"][0];
    assert_eq!(op["kind"]["selector"], "Gs");
    assert_eq!(op["kind"]["source"]["kind"], "stack");
    assert_eq!(op["kind"]["source"]["width"], "B8");
    assert_eq!(op["kind"]["requires_apx"], true);
    assert_eq!(op["kind"]["next_pc"], 0x1004);
}

#[test]
fn emits_exact_lss_lfs_lgs_atomic_far_pointer_width_destination_and_apx_metadata() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let legacy = decode_to_json(&[0x66, 0x0F, 0xB4, 0x0C, 0x24], &opts).unwrap();
    assert_eq!(legacy["smir"]["available"], true);
    assert_eq!(legacy["smir"]["bytes_consumed"], 5);
    let op = &legacy["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_system_selector_load");
    assert_eq!(op["kind"]["selector"], "Fs");
    assert_eq!(op["kind"]["source"]["kind"], "far_pointer");
    assert_eq!(op["kind"]["source"]["addr"]["kind"], "direct");
    assert_eq!(op["kind"]["source"]["addr"]["reg"]["name"], "rsp");
    assert_eq!(op["kind"]["source"]["dst"]["name"], "rcx");
    assert_eq!(op["kind"]["source"]["offset_width"], "W16");
    assert_eq!(op["kind"]["source"]["selector_width"], "B2");
    assert_eq!(op["kind"]["source"]["stack_segment"], true);
    assert_eq!(op["kind"]["source"]["commit"], "after_selector_load");
    assert_eq!(op["kind"]["requires_apx"], false);
    assert_eq!(op["kind"]["next_pc"], 0x1005);
    assert_eq!(op["writes"][0]["name"], "rcx");
    assert_eq!(op["memory"]["reads"], true);
    assert_eq!(op["memory"]["writes"], true);
    assert_eq!(op["side_effects"], true);

    let rex2 = decode_to_json(&[0xD5, 0xDC, 0xB2, 0x38], &opts).unwrap();
    assert_eq!(rex2["smir"]["available"], true);
    assert_eq!(rex2["smir"]["bytes_consumed"], 4);
    let op = &rex2["smir"]["ops"][0];
    assert_eq!(op["kind"]["selector"], "Ss");
    assert_eq!(op["kind"]["source"]["kind"], "far_pointer");
    assert_eq!(op["kind"]["source"]["addr"]["kind"], "direct");
    assert_eq!(op["kind"]["source"]["addr"]["reg"]["name"], "r16");
    assert_eq!(op["kind"]["source"]["dst"]["name"], "r31");
    assert_eq!(op["kind"]["source"]["offset_width"], "W64");
    assert_eq!(op["kind"]["source"]["stack_segment"], false);
    assert_eq!(op["kind"]["requires_apx"], true);
    assert_eq!(op["kind"]["next_pc"], 0x1004);
    assert_eq!(op["writes"][0]["name"], "r31");
}

#[test]
fn emits_exact_lldt_ltr_source_hidden_state_handoff_busy_and_apx_metadata() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let register = decode_to_json(&[0xD5, 0x91, 0x00, 0xD7], &opts).unwrap();
    assert_eq!(register["smir"]["available"], true);
    assert_eq!(register["smir"]["bytes_consumed"], 4);
    let op = &register["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_system_selector_load");
    assert_eq!(op["kind"]["selector"], "Ldtr");
    assert_eq!(op["kind"]["source"]["kind"], "register");
    assert_eq!(op["kind"]["source"]["src"]["name"], "r31");
    assert_eq!(op["kind"]["source"]["width"], "W16");
    assert_eq!(op["kind"]["requires_apx"], true);
    assert_eq!(op["kind"]["next_pc"], 0x1004);
    assert!(op["reads"].is_null());
    assert_eq!(op["writes"].as_array().unwrap().len(), 0);
    assert_eq!(op["memory"]["reads"], true);
    assert_eq!(op["memory"]["writes"], false);
    assert_eq!(op["side_effects"], true);

    let memory = decode_to_json(&[0x48, 0x0F, 0x00, 0x50, 0x08], &opts).unwrap();
    assert_eq!(memory["smir"]["available"], true);
    assert_eq!(memory["smir"]["bytes_consumed"], 5);
    let op = &memory["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_system_selector_load");
    assert_eq!(op["kind"]["selector"], "Ldtr");
    assert_eq!(op["kind"]["source"]["kind"], "memory");
    assert_eq!(op["kind"]["source"]["width"], "B2");
    assert_eq!(op["kind"]["source"]["addr"]["kind"], "base_offset");
    assert_eq!(op["kind"]["source"]["addr"]["base"]["name"], "rax");
    assert_eq!(op["kind"]["source"]["addr"]["offset"], 8);
    assert_eq!(op["kind"]["requires_apx"], false);
    assert_eq!(op["kind"]["next_pc"], 0x1005);
    assert_eq!(op["memory"]["reads"], true);
    assert_eq!(op["memory"]["writes"], false);
    assert_eq!(op["side_effects"], true);

    let ltr = decode_to_json(&[0x48, 0x0F, 0x00, 0x58, 0x08], &opts).unwrap();
    assert_eq!(ltr["smir"]["available"], true);
    assert_eq!(ltr["smir"]["bytes_consumed"], 5);
    let op = &ltr["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_system_selector_load");
    assert_eq!(op["kind"]["selector"], "Tr");
    assert_eq!(op["kind"]["source"]["kind"], "memory");
    assert_eq!(op["kind"]["source"]["width"], "B2");
    assert_eq!(op["kind"]["source"]["addr"]["kind"], "base_offset");
    assert_eq!(op["kind"]["source"]["addr"]["base"]["name"], "rax");
    assert_eq!(op["kind"]["source"]["addr"]["offset"], 8);
    assert_eq!(op["kind"]["requires_apx"], false);
    assert_eq!(op["kind"]["next_pc"], 0x1005);
    assert_eq!(op["memory"]["reads"], true);
    assert_eq!(op["memory"]["writes"], true);
    assert_eq!(op["side_effects"], true);
}

#[test]
fn emits_exact_mov_sreg_source_width_stack_descriptor_effects_and_apx_metadata() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let register = decode_to_json(&[0xD5, 0x55, 0x8E, 0xE7], &opts).unwrap();
    assert_eq!(register["smir"]["available"], true);
    assert_eq!(register["smir"]["bytes_consumed"], 4);
    let op = &register["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_system_selector_load");
    assert_eq!(op["kind"]["selector"], "Fs");
    assert_eq!(op["kind"]["source"]["kind"], "register");
    assert_eq!(op["kind"]["source"]["src"]["name"], "r31");
    assert_eq!(op["kind"]["source"]["width"], "W16");
    assert_eq!(op["kind"]["requires_apx"], true);
    assert_eq!(op["kind"]["next_pc"], 0x1004);
    assert!(op["reads"].is_null());
    assert_eq!(op["writes"].as_array().unwrap().len(), 0);
    assert_eq!(op["memory"]["reads"], true);
    assert_eq!(op["memory"]["writes"], true);
    assert_eq!(op["side_effects"], true);

    let memory = decode_to_json(&[0x48, 0x8E, 0x5C, 0x24, 0x08], &opts).unwrap();
    assert_eq!(memory["smir"]["available"], true);
    assert_eq!(memory["smir"]["bytes_consumed"], 5);
    let op = &memory["smir"]["ops"][0];
    assert_eq!(op["kind"]["selector"], "Ds");
    assert_eq!(op["kind"]["source"]["kind"], "memory");
    assert_eq!(op["kind"]["source"]["width"], "B8");
    assert_eq!(op["kind"]["source"]["stack_segment"], true);
    assert_eq!(op["kind"]["source"]["addr"]["kind"], "base_offset");
    assert_eq!(op["kind"]["source"]["addr"]["base"]["name"], "rsp");
    assert_eq!(op["kind"]["source"]["addr"]["offset"], 8);
    assert_eq!(op["kind"]["next_pc"], 0x1005);

    for modrm in [0xC8, 0xF0, 0xF8] {
        let invalid = decode_to_json(&[0x8E, modrm], &opts).unwrap();
        assert_eq!(invalid["smir"]["available"], true);
        assert_eq!(invalid["smir"]["bytes_consumed"], 2);
        assert_eq!(invalid["smir"]["ops"].as_array().unwrap().len(), 0);
        assert_eq!(invalid["smir"]["control_flow"]["kind"], "trap");
        assert_eq!(invalid["smir"]["control_flow"]["trap"], "InvalidOpcode");
    }
}

#[test]
fn emits_exact_far_jump_pointer_target_descriptor_and_handoff_metadata() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let decoded = decode_to_json(&[0x48, 0xFF, 0x68, 0x08], &opts).unwrap();
    assert_eq!(decoded["smir"]["available"], true);
    assert_eq!(decoded["smir"]["bytes_consumed"], 4);
    let op = &decoded["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_far_jump");
    assert_eq!(op["kind"]["addr"]["kind"], "base_offset");
    assert_eq!(op["kind"]["addr"]["base"]["name"], "rax");
    assert_eq!(op["kind"]["addr"]["offset"], 8);
    assert_eq!(op["kind"]["target"]["name"], "rip");
    assert_eq!(op["kind"]["offset_width"], "W64");
    assert_eq!(op["kind"]["requires_apx"], false);
    assert_eq!(op["kind"]["stack_segment"], false);
    assert_eq!(op["kind"]["next_pc"], 0x1004);
    assert!(op["reads"].is_null());
    assert_eq!(op["writes"][0]["name"], "rip");
    assert_eq!(op["memory"]["reads"], true);
    assert_eq!(op["memory"]["writes"], true);
    assert_eq!(op["side_effects"], true);
    assert_eq!(decoded["smir"]["control_flow"]["kind"], "indirect_branch");
    assert_eq!(decoded["smir"]["ends_block"], true);
    assert_eq!(decoded["smir"]["ends_function"], false);

    let stack = decode_to_json(&[0x48, 0xFF, 0x6C, 0x24, 0x08], &opts).unwrap();
    assert_eq!(stack["smir"]["ops"][0]["kind"]["stack_segment"], true);
}

#[test]
fn emits_exact_sysenter_sysexit_dynamic_state_and_handoff_metadata() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    for (bytes, kind, operand64) in [
        (&[0x0F, 0x34][..], "Sysenter", false),
        (&[0x48, 0x0F, 0x35][..], "Sysexit", true),
    ] {
        let decoded = decode_to_json(bytes, &opts).unwrap();
        assert_eq!(decoded["smir"]["available"], true);
        assert_eq!(decoded["smir"]["bytes_consumed"], bytes.len());
        let op = &decoded["smir"]["ops"][0];
        assert_eq!(op["kind"]["opcode"], "x86_fast_system_transfer");
        assert_eq!(op["kind"]["kind"], kind);
        assert_eq!(op["kind"]["target"]["name"], "rip");
        assert_eq!(op["kind"]["stack_pointer"]["name"], "rsp");
        assert_eq!(op["kind"]["return_target"]["name"], "rdx");
        assert_eq!(op["kind"]["return_stack_pointer"]["name"], "rcx");
        assert_eq!(op["kind"]["operand64"], operand64);
        assert_eq!(op["kind"]["next_pc"], 0x1000 + bytes.len() as u64);
        assert!(op["reads"].is_null());
        assert_eq!(op["writes"][0]["name"], "rip");
        assert_eq!(op["writes"][1]["name"], "rsp");
        assert_eq!(op["memory"]["reads"], false);
        assert_eq!(op["memory"]["writes"], false);
        assert_eq!(op["side_effects"], true);
        assert_eq!(decoded["smir"]["control_flow"]["kind"], "indirect_branch");
        assert_eq!(decoded["smir"]["ends_block"], true);
        assert_eq!(decoded["smir"]["ends_function"], false);
    }
}

#[test]
fn emits_exact_far_call_pointer_frame_target_and_handoff_metadata() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let decoded = decode_to_json(&[0x48, 0xFF, 0x58, 0x08], &opts).unwrap();
    assert_eq!(decoded["smir"]["available"], true);
    assert_eq!(decoded["smir"]["bytes_consumed"], 4);
    let op = &decoded["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_far_call");
    assert_eq!(op["kind"]["addr"]["kind"], "base_offset");
    assert_eq!(op["kind"]["addr"]["base"]["name"], "rax");
    assert_eq!(op["kind"]["addr"]["offset"], 8);
    assert_eq!(op["kind"]["target"]["name"], "rip");
    assert_eq!(op["kind"]["offset_width"], "W64");
    assert_eq!(op["kind"]["requires_apx"], false);
    assert_eq!(op["kind"]["stack_segment"], false);
    assert_eq!(op["kind"]["next_pc"], 0x1004);
    assert!(op["reads"].is_null());
    assert_eq!(op["writes"][0]["name"], "rip");
    assert_eq!(op["memory"]["reads"], true);
    assert_eq!(op["memory"]["writes"], true);
    assert_eq!(op["side_effects"], true);
    assert_eq!(decoded["smir"]["control_flow"]["kind"], "indirect_branch");
    assert_eq!(decoded["smir"]["ends_block"], true);
    assert_eq!(decoded["smir"]["ends_function"], false);

    let stack = decode_to_json(&[0x48, 0xFF, 0x5C, 0x24, 0x08], &opts).unwrap();
    assert_eq!(stack["smir"]["ops"][0]["kind"]["stack_segment"], true);
}

#[test]
fn emits_exact_far_return_frame_target_and_handoff_metadata() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let decoded = decode_to_json(&[0x48, 0xCA, 0x34, 0x12], &opts).unwrap();
    assert_eq!(decoded["smir"]["available"], true);
    assert_eq!(decoded["smir"]["bytes_consumed"], 4);
    let op = &decoded["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_far_return");
    assert_eq!(op["kind"]["target"]["name"], "rip");
    assert_eq!(op["kind"]["offset_width"], "W64");
    assert_eq!(op["kind"]["pop_bytes"], 0x1234);
    assert_eq!(op["kind"]["requires_apx"], false);
    assert_eq!(op["kind"]["next_pc"], 0x1004);
    assert!(op["reads"].is_null());
    assert_eq!(op["writes"][0]["name"], "rip");
    assert_eq!(op["memory"]["reads"], true);
    assert_eq!(op["memory"]["writes"], true);
    assert_eq!(op["side_effects"], true);
    assert_eq!(decoded["smir"]["control_flow"]["kind"], "indirect_branch");
    assert_eq!(decoded["smir"]["ends_block"], true);
    assert_eq!(decoded["smir"]["ends_function"], false);

    let apx = decode_to_json(&[0xD5, 0x18, 0xCB], &opts).unwrap();
    assert_eq!(apx["smir"]["ops"][0]["kind"]["requires_apx"], true);
    assert_eq!(apx["smir"]["ops"][0]["kind"]["offset_width"], "W64");
}

#[test]
fn emits_exact_descriptor_table_memory_table_handoff_and_apx_metadata() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let sidt = decode_to_json(&[0x48, 0x0F, 0x01, 0x48, 0x08], &opts).unwrap();
    assert_eq!(sidt["smir"]["available"], true);
    assert_eq!(sidt["smir"]["bytes_consumed"], 5);
    let op = &sidt["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_descriptor_table_store");
    assert_eq!(op["kind"]["table"], "Idt");
    assert_eq!(op["kind"]["addr"]["kind"], "base_offset");
    assert_eq!(op["kind"]["addr"]["base"]["name"], "rax");
    assert_eq!(op["kind"]["addr"]["offset"], 8);
    assert_eq!(op["kind"]["requires_apx"], false);
    assert!(op["reads"].is_null());
    assert_eq!(op["writes"].as_array().unwrap().len(), 0);
    assert_eq!(op["memory"]["reads"], false);
    assert_eq!(op["memory"]["writes"], true);
    assert_eq!(op["side_effects"], true);

    let sgdt = decode_to_json(&[0xD5, 0xB3, 0x01, 0x04, 0xD1], &opts).unwrap();
    assert_eq!(sgdt["smir"]["available"], true);
    let op = &sgdt["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_descriptor_table_store");
    assert_eq!(op["kind"]["table"], "Gdt");
    assert_eq!(op["kind"]["requires_apx"], true);
    assert_eq!(op["kind"]["addr"]["base"]["name"], "r25");
    assert_eq!(op["kind"]["addr"]["index"]["name"], "r26");
    assert_eq!(op["kind"]["addr"]["scale"], 8);

    let lidt = decode_to_json(&[0x48, 0x0F, 0x01, 0x58, 0x08], &opts).unwrap();
    assert_eq!(lidt["smir"]["available"], true);
    assert_eq!(lidt["smir"]["bytes_consumed"], 5);
    let op = &lidt["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_descriptor_table_load");
    assert_eq!(op["kind"]["table"], "Idt");
    assert_eq!(op["kind"]["addr"]["kind"], "base_offset");
    assert_eq!(op["kind"]["addr"]["base"]["name"], "rax");
    assert_eq!(op["kind"]["addr"]["offset"], 8);
    assert_eq!(op["kind"]["requires_apx"], false);
    assert_eq!(op["kind"]["next_pc"], 0x1005);
    assert!(op["reads"].is_null());
    assert_eq!(op["writes"].as_array().unwrap().len(), 0);
    assert_eq!(op["memory"]["reads"], true);
    assert_eq!(op["memory"]["writes"], false);
    assert_eq!(op["side_effects"], true);

    let lgdt = decode_to_json(&[0xD5, 0xB3, 0x01, 0x14, 0xD1], &opts).unwrap();
    assert_eq!(lgdt["smir"]["available"], true);
    assert_eq!(lgdt["smir"]["bytes_consumed"], 5);
    let op = &lgdt["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_descriptor_table_load");
    assert_eq!(op["kind"]["table"], "Gdt");
    assert_eq!(op["kind"]["requires_apx"], true);
    assert_eq!(op["kind"]["next_pc"], 0x1005);
    assert_eq!(op["kind"]["addr"]["base"]["name"], "r25");
    assert_eq!(op["kind"]["addr"]["index"]["name"], "r26");
    assert_eq!(op["kind"]["addr"]["scale"], 8);
    assert_eq!(op["memory"]["reads"], true);
    assert_eq!(op["memory"]["writes"], false);
    assert_eq!(op["side_effects"], true);
}

#[test]
fn emits_exact_lmsw_register_memory_and_handoff_metadata() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let register = decode_to_json(&[0xD5, 0x91, 0x01, 0xF7], &opts).unwrap();
    assert_eq!(register["smir"]["available"], true);
    assert_eq!(register["smir"]["bytes_consumed"], 4);
    let op = &register["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_lmsw");
    assert_eq!(op["kind"]["source"]["kind"], "register");
    assert_eq!(op["kind"]["source"]["src"]["name"], "r31");
    assert_eq!(op["kind"]["source"]["width"], "W16");
    assert_eq!(op["kind"]["requires_apx"], true);
    assert_eq!(op["kind"]["next_pc"], 0x1004);
    assert!(op["reads"].is_null());
    assert_eq!(op["writes"].as_array().unwrap().len(), 0);
    assert_eq!(op["memory"]["reads"], false);
    assert_eq!(op["memory"]["writes"], false);
    assert_eq!(op["side_effects"], true);

    let memory = decode_to_json(&[0x48, 0x0F, 0x01, 0x70, 0x08], &opts).unwrap();
    assert_eq!(memory["smir"]["available"], true);
    assert_eq!(memory["smir"]["bytes_consumed"], 5);
    let op = &memory["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_lmsw");
    assert_eq!(op["kind"]["source"]["kind"], "memory");
    assert_eq!(op["kind"]["source"]["width"], "B2");
    assert_eq!(op["kind"]["source"]["addr"]["kind"], "base_offset");
    assert_eq!(op["kind"]["source"]["addr"]["base"]["name"], "rax");
    assert_eq!(op["kind"]["source"]["addr"]["offset"], 8);
    assert_eq!(op["kind"]["requires_apx"], false);
    assert_eq!(op["kind"]["next_pc"], 0x1005);
    assert_eq!(op["memory"]["reads"], true);
    assert_eq!(op["memory"]["writes"], false);
    assert_eq!(op["side_effects"], true);
}

#[test]
fn emits_exact_mov_to_control_register_metadata_and_handoff_frontier() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let decoded = decode_to_json(&[0x49, 0x0F, 0x22, 0xE6], &opts).unwrap();
    assert_eq!(decoded["smir"]["available"], true);
    assert_eq!(decoded["smir"]["bytes_consumed"], 4);
    let op = &decoded["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_write_control");
    assert_eq!(op["kind"]["control"], "Cr4");
    assert_eq!(op["kind"]["src"]["arch"], "x86_64");
    assert_eq!(op["kind"]["src"]["name"], "r14");
    assert_eq!(op["kind"]["next_pc"], 0x1004);
    assert!(op["reads"].is_null());
    assert_eq!(op["writes"].as_array().unwrap().len(), 0);
    assert_eq!(op["memory"]["reads"], false);
    assert_eq!(op["memory"]["writes"], false);
    assert_eq!(op["side_effects"], true);
}

#[test]
fn emits_exact_mov_from_debug_register_metadata_and_instruction_boundary() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let decoded = decode_to_json(&[0x49, 0x0F, 0x21, 0xFE], &opts).unwrap();
    assert_eq!(decoded["smir"]["available"], true);
    assert_eq!(decoded["smir"]["bytes_consumed"], 4);
    let op = &decoded["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_read_debug");
    assert_eq!(op["kind"]["debug"], "Dr7");
    assert_eq!(op["kind"]["dst"]["arch"], "x86_64");
    assert_eq!(op["kind"]["dst"]["name"], "r14");
    assert!(op["reads"].is_null());
    assert_eq!(op["writes"].as_array().unwrap().len(), 1);
    assert_eq!(op["memory"]["reads"], false);
    assert_eq!(op["memory"]["writes"], false);
    assert_eq!(op["side_effects"], true);
}

#[test]
fn emits_exact_mov_to_debug_register_metadata_and_instruction_boundary() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let decoded = decode_to_json(&[0x49, 0x0F, 0x23, 0xFE], &opts).unwrap();
    assert_eq!(decoded["smir"]["available"], true);
    assert_eq!(decoded["smir"]["bytes_consumed"], 4);
    let op = &decoded["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_write_debug");
    assert_eq!(op["kind"]["debug"], "Dr7");
    assert_eq!(op["kind"]["src"]["arch"], "x86_64");
    assert_eq!(op["kind"]["src"]["name"], "r14");
    assert!(op["reads"].is_null());
    assert_eq!(op["writes"].as_array().unwrap().len(), 0);
    assert_eq!(op["memory"]["reads"], false);
    assert_eq!(op["memory"]["writes"], false);
    assert_eq!(op["side_effects"], true);
}

#[test]
fn emits_exact_rdtsc_and_rdtscp_destination_metadata() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let rdtsc = decode_to_json(&[0x0F, 0x31], &opts).unwrap();
    assert_eq!(rdtsc["smir"]["available"], true);
    assert_eq!(rdtsc["smir"]["bytes_consumed"], 2);
    let op = &rdtsc["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_read_tsc");
    assert_eq!(op["kind"]["dst_lo"]["name"], "rax");
    assert_eq!(op["kind"]["dst_hi"]["name"], "rdx");
    assert!(op["kind"]["dst_aux"].is_null());
    assert_eq!(op["writes"][0]["name"], "rax");
    assert_eq!(op["writes"][1]["name"], "rdx");
    assert_eq!(op["side_effects"], true);

    let rdtscp = decode_to_json(&[0x0F, 0x01, 0xF9], &opts).unwrap();
    assert_eq!(rdtscp["smir"]["available"], true);
    assert_eq!(rdtscp["smir"]["bytes_consumed"], 3);
    let op = &rdtscp["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_read_tsc");
    assert_eq!(op["kind"]["dst_lo"]["name"], "rax");
    assert_eq!(op["kind"]["dst_hi"]["name"], "rdx");
    assert_eq!(op["kind"]["dst_aux"]["name"], "rcx");
    assert_eq!(op["writes"][0]["name"], "rax");
    assert_eq!(op["writes"][1]["name"], "rdx");
    assert_eq!(op["writes"][2]["name"], "rcx");
    assert_eq!(op["memory"]["reads"], false);
    assert_eq!(op["memory"]["writes"], false);
    assert_eq!(op["side_effects"], true);
}

#[test]
fn emits_exact_rdpmc_selector_and_destination_metadata() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let decoded = decode_to_json(&[0x0F, 0x33], &opts).unwrap();
    assert_eq!(decoded["smir"]["available"], true);
    assert_eq!(decoded["smir"]["bytes_consumed"], 2);
    let op = &decoded["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_read_pmc");
    assert_eq!(op["kind"]["selector"]["name"], "rcx");
    assert_eq!(op["kind"]["dst_lo"]["name"], "rax");
    assert_eq!(op["kind"]["dst_hi"]["name"], "rdx");
    assert!(op["reads"].is_null());
    assert_eq!(op["writes"][0]["name"], "rax");
    assert_eq!(op["writes"][1]["name"], "rdx");
    assert_eq!(op["memory"]["reads"], false);
    assert_eq!(op["memory"]["writes"], false);
    assert_eq!(op["side_effects"], true);
}

#[test]
fn emits_and_executes_exact_swapgs_state_dataflow() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let decoded = decode_to_json(&[0x0F, 0x01, 0xF8], &opts).unwrap();
    assert_eq!(decoded["smir"]["available"], true);
    assert_eq!(decoded["smir"]["bytes_consumed"], 3);
    let op = &decoded["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_swapgs");
    assert_eq!(op["kind"]["gs_base"]["name"], "gs_base");
    assert_eq!(op["kind"]["kernel_gs_base"]["name"], "kernel_gs_base");
    assert_eq!(op["writes"][0]["name"], "gs_base");
    assert_eq!(op["writes"][1]["name"], "kernel_gs_base");
    assert_eq!(op["memory"]["reads"], false);
    assert_eq!(op["memory"]["writes"], false);
    assert_eq!(op["side_effects"], true);

    let seed = OracleSeed {
        regs: vec![
            ("gs_base".to_string(), 0x0000_7FFF_1234_5000),
            ("kernel_gs_base".to_string(), 0xFFFF_8000_ABCD_E000),
        ],
        memory: vec![],
        memory_size: None,
    };
    let executed = decode_to_json_with_seed(&[0x0F, 0x01, 0xF8], &opts, Some(&seed)).unwrap();
    assert_eq!(executed["side_effects"]["available"], true);
    assert_eq!(
        executed["side_effects"]["changed_regs"]["gs_base"]["after"],
        "0xffff8000abcde000"
    );
    assert_eq!(
        executed["side_effects"]["changed_regs"]["kernel_gs_base"]["after"],
        "0x7fff12345000"
    );
}

#[test]
fn emits_and_executes_exact_monitor_mwait_semantics() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let monitor = decode_to_json(&[0x0F, 0x01, 0xC8], &opts).unwrap();
    assert_eq!(monitor["smir"]["available"], true);
    assert_eq!(monitor["smir"]["bytes_consumed"], 3);
    let op = &monitor["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_monitor_mwait");
    assert_eq!(op["kind"]["rcx"]["name"], "rcx");
    assert_eq!(op["kind"]["hint"]["name"], "rdx");
    assert_eq!(op["kind"]["stack_segment"], false);
    assert!(!op["kind"]["addr"].is_null());
    assert_eq!(op["writes"].as_array().unwrap().len(), 0);
    assert_eq!(op["memory"]["reads"], true);
    assert_eq!(op["memory"]["writes"], false);
    assert_eq!(op["side_effects"], true);

    let mwait = decode_to_json(&[0x0F, 0x01, 0xC9], &opts).unwrap();
    let op = &mwait["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_monitor_mwait");
    assert_eq!(op["kind"]["rcx"]["name"], "rcx");
    assert_eq!(op["kind"]["hint"]["name"], "rax");
    assert_eq!(op["kind"]["stack_segment"], false);
    assert!(op["kind"]["addr"].is_null());
    assert_eq!(op["memory"]["reads"], false);
    assert_eq!(op["memory"]["writes"], false);
    assert_eq!(op["side_effects"], true);

    let ss_monitor = decode_to_json(&[0x36, 0x0F, 0x01, 0xC8], &opts).unwrap();
    assert_eq!(ss_monitor["smir"]["ops"][0]["kind"]["stack_segment"], true);

    let seed = OracleSeed {
        regs: vec![
            ("rax".to_string(), 0x20),
            ("rcx".to_string(), 0),
            ("rdx".to_string(), 0xA5A5),
        ],
        memory: vec![OracleMemorySeed {
            addr: 0x20,
            bytes: vec![0x5A],
        }],
        memory_size: Some(0x100),
    };
    let executed = decode_to_json_with_seed(&[0x0F, 0x01, 0xC8], &opts, Some(&seed)).unwrap();
    assert_eq!(executed["side_effects"]["available"], true);
    assert_eq!(
        executed["side_effects"]["changed_regs"]
            .as_object()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        executed["side_effects"]["changed_memory"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn emits_exact_waitpkg_register_address_deadline_and_apx_metadata() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let monitor = decode_to_json(&[0x36, 0xF3, 0x0F, 0xAE, 0xF0], &opts).unwrap();
    assert_eq!(monitor["smir"]["available"], true);
    assert_eq!(monitor["smir"]["bytes_consumed"], 5);
    let op = &monitor["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_waitpkg_umonitor");
    assert_eq!(op["kind"]["addr"]["kind"], "direct");
    assert_eq!(op["kind"]["addr"]["reg"]["name"], "rax");
    assert_eq!(op["kind"]["stack_segment"], true);
    assert_eq!(op["writes"].as_array().unwrap().len(), 0);
    assert_eq!(op["memory"]["reads"], true);
    assert_eq!(op["memory"]["writes"], false);
    assert_eq!(op["side_effects"], true);

    let wait = decode_to_json(&[0xF2, 0x0F, 0xAE, 0xF1], &opts).unwrap();
    assert_eq!(wait["smir"]["available"], true);
    assert_eq!(wait["smir"]["bytes_consumed"], 4);
    let op = &wait["smir"]["ops"][0];
    assert_eq!(op["kind"]["opcode"], "x86_waitpkg_umwait");
    assert_eq!(op["kind"]["control"]["name"], "rcx");
    assert_eq!(op["kind"]["deadline_low"]["name"], "rax");
    assert_eq!(op["kind"]["deadline_high"]["name"], "rdx");
    assert_eq!(op["memory"]["reads"], false);
    assert_eq!(op["memory"]["writes"], false);
    assert_eq!(op["side_effects"], true);

    let pause = decode_to_json(&[0x66, 0xD5, 0x90, 0xAE, 0xF0], &opts).unwrap();
    assert_eq!(pause["smir"]["available"], true);
    assert_eq!(pause["smir"]["bytes_consumed"], 5);
    assert_eq!(pause["smir"]["ops"][0]["kind"]["opcode"], "x86_require_apx");
    let op = &pause["smir"]["ops"][1];
    assert_eq!(op["kind"]["opcode"], "x86_waitpkg_tpause");
    assert_eq!(op["kind"]["control"]["name"], "r16");
    assert_eq!(op["kind"]["deadline_low"]["name"], "rax");
    assert_eq!(op["kind"]["deadline_high"]["name"], "rdx");
    assert_eq!(op["writes"].as_array().unwrap().len(), 0);
    assert_eq!(op["memory"]["reads"], false);
    assert_eq!(op["side_effects"], true);
}

#[test]
fn emits_exact_legacy_pcmpxstrx_semantics() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let explicit = decode_to_json(&[0x66, 0x4D, 0x0F, 0x3A, 0x61, 0xD1, 0xFD], &opts).unwrap();
    assert_eq!(explicit["smir"]["available"], true);
    assert_eq!(explicit["smir"]["bytes_consumed"], 7);
    let op = explicit["smir"]["ops"]
        .as_array()
        .unwrap()
        .iter()
        .find(|op| op["kind"]["opcode"] == "x86_packed_string_compare")
        .unwrap();
    assert_eq!(op["kind"]["dst"]["name"], "rcx");
    assert_eq!(op["kind"]["src1"]["name"], "xmm10");
    assert_eq!(op["kind"]["src2"]["name"], "xmm9");
    assert_eq!(op["kind"]["len1"]["name"], "rax");
    assert_eq!(op["kind"]["len2"]["name"], "rdx");
    assert_eq!(op["kind"]["length_width"], "W64");
    assert_eq!(op["kind"]["kind"], "ExplicitIndex");
    assert_eq!(op["kind"]["imm"], 0xFD);
    assert_eq!(op["writes"][0]["name"], "rcx");

    let implicit = decode_to_json(&[0x66, 0x0F, 0x3A, 0x62, 0xD1, 0x40], &opts).unwrap();
    assert_eq!(implicit["smir"]["bytes_consumed"], 6);
    let op = implicit["smir"]["ops"]
        .as_array()
        .unwrap()
        .iter()
        .find(|op| op["kind"]["opcode"] == "x86_packed_string_compare")
        .unwrap();
    assert_eq!(op["kind"]["dst"]["name"], "xmm0");
    assert_eq!(op["kind"]["len1"], serde_json::Value::Null);
    assert_eq!(op["kind"]["len2"], serde_json::Value::Null);
    assert_eq!(op["kind"]["kind"], "ImplicitMask");
}

#[test]
fn emits_complete_non_transactional_rtm_semantics() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let xabort = decode_to_json(&[0xc6, 0xf8, 0x42], &opts).unwrap();
    assert_eq!(xabort["smir"]["bytes_consumed"], 3);
    assert_eq!(xabort["smir"]["control_flow"]["kind"], "fallthrough");
    assert_eq!(xabort["smir"]["ops"], serde_json::json!([]));

    let xbegin_rel32 = decode_to_json(&[0xc7, 0xf8, 0x05, 0x00, 0x00, 0x00], &opts).unwrap();
    assert_eq!(xbegin_rel32["smir"]["bytes_consumed"], 6);
    assert_eq!(xbegin_rel32["smir"]["control_flow"]["kind"], "branch");
    assert_eq!(xbegin_rel32["smir"]["control_flow"]["target"], "0x100b");
    assert_eq!(xbegin_rel32["smir"]["ops"][0]["kind"]["opcode"], "mov");
    assert_eq!(xbegin_rel32["smir"]["ops"][0]["kind"]["dst"]["name"], "rax");
    assert_eq!(xbegin_rel32["smir"]["ops"][0]["kind"]["src"]["value"], 0);
    assert_eq!(xbegin_rel32["smir"]["ops"][0]["kind"]["width"], "W32");

    let xbegin_rel16 = decode_to_json(&[0x66, 0xc7, 0xf8, 0xfb, 0xff], &opts).unwrap();
    assert_eq!(xbegin_rel16["smir"]["bytes_consumed"], 5);
    assert_eq!(xbegin_rel16["smir"]["control_flow"]["target"], "0x1000");

    let xtest = decode_to_json(&[0x0f, 0x01, 0xd6], &opts).unwrap();
    assert_eq!(xtest["smir"]["bytes_consumed"], 3);
    assert_eq!(xtest["smir"]["ops"][0]["kind"]["opcode"], "x86_xtest");
    assert_eq!(xtest["smir"]["ops"][0]["side_effects"], true);

    let xend = decode_to_json(&[0x0f, 0x01, 0xd5], &opts).unwrap();
    assert_eq!(xend["smir"]["bytes_consumed"], 3);
    assert_eq!(xend["smir"]["control_flow"]["kind"], "trap");
    assert_eq!(xend["smir"]["control_flow"]["trap"], "GeneralProtection");
    assert_eq!(xend["smir"]["ops"], serde_json::json!([]));

    opts.pc = 0x0000_7fff_ffff_fffa;
    let noncanonical_xbegin = decode_to_json(&[0xc7, 0xf8, 0x00, 0x00, 0x00, 0x00], &opts).unwrap();
    assert_eq!(noncanonical_xbegin["smir"]["bytes_consumed"], 6);
    assert_eq!(
        noncanonical_xbegin["smir"]["control_flow"]["trap"],
        "GeneralProtection"
    );
    assert_eq!(noncanonical_xbegin["smir"]["ops"], serde_json::json!([]));
}

#[test]
fn emits_evex_sqrt_embedded_rounding_and_sae_semantics() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    for (p2, round) in [
        (0x18, "RoundNearest"),
        (0x38, "RoundDown"),
        (0x58, "RoundUp"),
        (0x78, "RoundTowardZero"),
    ] {
        let value = decode_to_json(&[0x62, 0xF1, 0x7C, p2, 0x51, 0xC1], &opts).unwrap();
        assert_eq!(value["smir"]["available"], true);
        assert_eq!(value["smir"]["bytes_consumed"], 6);
        assert_eq!(value["smir"]["control_flow"]["kind"], "fallthrough");
        let op = value["smir"]["ops"]
            .as_array()
            .unwrap()
            .iter()
            .find(|op| op["kind"]["opcode"] == "x86_sqrt")
            .unwrap();
        assert_eq!(op["kind"]["dst"]["name"], "zmm0");
        assert_eq!(op["kind"]["src"]["name"], "zmm1");
        assert_eq!(op["kind"]["elem"], "F32");
        assert_eq!(op["kind"]["lanes"], 16);
        assert_eq!(op["kind"]["round"], round);
        assert_eq!(op["kind"]["suppress_exceptions"], true);
        assert_eq!(op["side_effects"], false);
    }

    let scalar = decode_to_json(&[0x62, 0xF1, 0xFF, 0x18, 0x51, 0xC1], &opts).unwrap();
    let op = scalar["smir"]["ops"]
        .as_array()
        .unwrap()
        .iter()
        .find(|op| op["kind"]["opcode"] == "x86_sqrt")
        .unwrap();
    assert_eq!(op["kind"]["src"]["name"], "xmm1");
    assert_eq!(op["kind"]["elem"], "F64");
    assert_eq!(op["kind"]["lanes"], 1);
    assert_eq!(op["kind"]["round"], "RoundNearest");
    assert_eq!(op["kind"]["suppress_exceptions"], true);
}

#[test]
fn emits_evex_scalar_binary_embedded_rounding_and_sae_semantics() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    for (p2, round) in [
        (0x18, "RoundNearest"),
        (0x38, "RoundDown"),
        (0x58, "RoundUp"),
        (0x78, "RoundTowardZero"),
    ] {
        let value = decode_to_json(&[0x62, 0xF1, 0x7E, p2, 0x58, 0xD1], &opts).unwrap();
        assert_eq!(value["smir"]["available"], true);
        assert_eq!(value["smir"]["bytes_consumed"], 6);
        let op = value["smir"]["ops"]
            .as_array()
            .unwrap()
            .iter()
            .find(|op| op["kind"]["opcode"] == "x86_fp_binary")
            .unwrap();
        assert_eq!(op["kind"]["src1"]["name"], "xmm0");
        assert_eq!(op["kind"]["src2"]["name"], "xmm1");
        assert_eq!(op["kind"]["elem"], "F32");
        assert_eq!(op["kind"]["lanes"], 1);
        assert_eq!(op["kind"]["op"], "Add");
        assert_eq!(op["kind"]["round"], round);
        assert_eq!(op["kind"]["suppress_exceptions"], true);
        assert_eq!(op["side_effects"], false);
    }

    let sae = decode_to_json(&[0x62, 0xF1, 0xFF, 0x18, 0x5F, 0xD1], &opts).unwrap();
    let op = sae["smir"]["ops"]
        .as_array()
        .unwrap()
        .iter()
        .find(|op| op["kind"]["opcode"] == "x86_fp_binary")
        .unwrap();
    assert_eq!(op["kind"]["elem"], "F64");
    assert_eq!(op["kind"]["op"], "Max");
    assert_eq!(op["kind"]["round"], "Dynamic");
    assert_eq!(op["kind"]["suppress_exceptions"], true);
}

#[test]
fn emits_atomic_register_movd_q_and_keeps_memory_effects_explicit() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    for (bytes, dst, src, width, zero_upper) in [
        (&[0x66, 0x0F, 0x6E, 0xC1][..], "xmm0", "rcx", "W32", false),
        (
            &[0xC4, 0xE1, 0xF9, 0x7E, 0xC1][..],
            "rcx",
            "xmm0",
            "W64",
            false,
        ),
        (
            &[0x62, 0xC1, 0x7D, 0x08, 0x6E, 0xC8][..],
            "xmm17",
            "r8",
            "W32",
            true,
        ),
    ] {
        let value = decode_to_json(bytes, &opts).unwrap();
        let kind = &value["smir"]["ops"][0]["kind"];
        assert_eq!(kind["opcode"], "x86_movd_q");
        assert_eq!(kind["dst"]["name"], dst);
        assert_eq!(kind["src"]["name"], src);
        assert_eq!(kind["width"], width);
        assert_eq!(kind["zero_upper"], zero_upper);
    }

    let memory = decode_to_json(&[0x66, 0x0F, 0x6E, 0x00], &opts).unwrap();
    let opcodes = memory["smir"]["ops"]
        .as_array()
        .unwrap()
        .iter()
        .map(|op| op["kind"]["opcode"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(opcodes.contains(&"load"));
    assert!(!opcodes.contains(&"x86_movd_q"));
}

#[test]
fn emits_riscv_architectural_smir_destinations() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::RiscV;
    opts.riscv_xlen = Xlen::Rv64;
    opts.riscv_isa = RiscVIsaProfile::Rv64Gc;

    // addi x1, x0, 1
    let value = decode_to_json(&[0x93, 0x00, 0x10, 0x00], &opts).unwrap();
    let op = &value["smir"]["ops"][0];

    assert_eq!(op["kind"]["dst"]["kind"], "arch");
    assert_eq!(op["kind"]["dst"]["arch"], "riscv");
    assert_eq!(op["kind"]["dst"]["name"], "x1");
    assert_eq!(value["smir"]["arch_outputs"], serde_json::json!([]));
}

#[test]
fn reports_seeded_side_effects() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let seed = OracleSeed {
        regs: vec![("rax".to_string(), 0)],
        memory: vec![],
        memory_size: None,
    };
    let value =
        decode_to_json_with_seed(&[0xb8, 0x34, 0x12, 0x00, 0x00], &opts, Some(&seed)).unwrap();

    assert_eq!(value["side_effects"]["available"], true);
    assert_eq!(
        value["side_effects"]["changed_regs"]["rax"]["after"],
        "0x1234"
    );
}

#[test]
fn reports_seeded_riscv_side_effects() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::RiscV;
    opts.riscv_xlen = Xlen::Rv64;
    opts.riscv_isa = RiscVIsaProfile::Rv64Gc;

    let seed = OracleSeed {
        regs: vec![("x1".to_string(), 5)],
        memory: vec![],
        memory_size: None,
    };
    // addi x1, x1, 1
    let value = decode_to_json_with_seed(&[0x93, 0x80, 0x10, 0x00], &opts, Some(&seed)).unwrap();

    assert_eq!(value["side_effects"]["available"], true);
    assert_eq!(value["side_effects"]["changed_regs"]["x1"]["after"], "0x6");
}

#[test]
fn rejects_oversized_oracle_seed_memory_size() {
    let value = serde_json::json!({
        "memory_size": MAX_ORACLE_SEED_MEMORY_SIZE + 1,
    });
    let err = OracleSeed::from_json(&value).unwrap_err();
    assert!(err.contains("seed.memory_size"), "{err}");
    assert!(err.contains("oracle seed memory limit"), "{err}");
}

#[test]
fn rejects_sparse_oracle_seed_memory_span_before_allocation() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::X86_64;

    let seed = OracleSeed {
        regs: vec![],
        memory: vec![
            OracleMemorySeed {
                addr: 0,
                bytes: vec![0],
            },
            OracleMemorySeed {
                addr: (MAX_ORACLE_SEED_MEMORY_SIZE as u64) + 1,
                bytes: vec![0],
            },
        ],
        memory_size: None,
    };
    let value = decode_to_json_with_seed(&[0x90], &opts, Some(&seed)).unwrap();
    let err = value["side_effects"]["error"].as_str().unwrap();
    assert!(err.contains("seeded memory span"), "{err}");
    assert!(err.contains("oracle seed memory limit"), "{err}");
}

#[test]
fn decodes_ebpf_and_solana_sbpf_with_seeded_side_effects() {
    use rax::isa::ebpf::decode::{EbpfDialect, SbpfVersion};

    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::Ebpf;
    opts.ebpf_dialect = EbpfDialect::Rfc9669;

    // add64 r1, 42
    let bytes = [0x07, 0x01, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00];
    let seed = OracleSeed {
        regs: vec![("r1".to_string(), 100)],
        memory: vec![],
        memory_size: None,
    };
    let value = decode_to_json_with_seed(&bytes, &opts, Some(&seed)).unwrap();
    assert_eq!(value["isa"], "ebpf");
    assert_eq!(value["dialect"], "rfc9669");
    assert_eq!(value["decoded_ops"][0]["mnemonic"], "add64");
    assert_eq!(value["smir"]["available"], true);
    assert_eq!(value["side_effects"]["available"], true);
    assert_eq!(value["side_effects"]["changed_regs"]["r1"]["after"], "0x8e");

    // Solana SBPF V2: sub64 r1, 100 (swapped operands: r1 = 100 - r1)
    let mut sbpf_opts = OracleOptions::default();
    sbpf_opts.isa = OracleIsa::Ebpf;
    sbpf_opts.ebpf_dialect = EbpfDialect::Solana(SbpfVersion::V2);
    let sub_bytes = [0x17, 0x01, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00];
    let sub_seed = OracleSeed {
        regs: vec![("r1".to_string(), 30)],
        memory: vec![],
        memory_size: None,
    };
    let sbpf_val = decode_to_json_with_seed(&sub_bytes, &sbpf_opts, Some(&sub_seed)).unwrap();
    assert_eq!(sbpf_val["dialect"], "sbpf-v2");
    assert_eq!(
        sbpf_val["side_effects"]["changed_regs"]["r1"]["after"],
        "0x46"
    );
}
