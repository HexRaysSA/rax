use rax::isa_oracle::{
    decode_to_json, decode_to_json_with_seed, parse_hex_bytes, ArmState, OracleIsa, OracleOptions,
    OracleSeed, RiscVIsaProfile,
};
use rax::riscv::Xlen;

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
fn decodes_arm_aarch64_instruction() {
    let mut opts = OracleOptions::default();
    opts.isa = OracleIsa::Arm;
    opts.arm_state = ArmState::Aarch64;

    let value = decode_to_json(&[0x20, 0x00, 0x80, 0xd2], &opts).unwrap();
    assert_eq!(value["isa"], "arm");
    assert_eq!(value["decoded_ops"][0]["mnemonic"], "movz");
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
