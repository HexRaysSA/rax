//! Effective-address prefix coverage for standalone VEX lifters.

use super::*;
use crate::smir::interpret::{BlockResult, SmirInterpreter};
use crate::smir::ir::context::{ArchRegState, ExitReason, SmirContext};
use crate::smir::ir::flags::MaterializedFlags;
use crate::smir::ir::memory::FlatMemory;

const MEMORY_CASES: &[(&str, &[u8])] = &[
    ("VPERM2I128", &[0xC4, 0xE3, 0x7D, 0x46, 0x00, 0x82]),
    ("VPDPBUUD", &[0xC4, 0xE2, 0x78, 0x50, 0x00]),
    ("VPUNPCKLBW", &[0xC5, 0xF1, 0x60, 0x00]),
    ("VPACKSSWB", &[0xC5, 0xF1, 0x63, 0x00]),
    ("VPSHUFB", &[0xC4, 0xE2, 0x71, 0x00, 0x00]),
    ("VPHADDW", &[0xC4, 0xE2, 0x71, 0x01, 0x00]),
    ("VPMADDUBSW", &[0xC4, 0xE2, 0x71, 0x04, 0x00]),
    ("VPSIGNB", &[0xC4, 0xE2, 0x71, 0x08, 0x00]),
    ("VPMULHRSW", &[0xC4, 0xE2, 0x71, 0x0B, 0x00]),
    ("VPABSB", &[0xC4, 0xE2, 0x79, 0x1C, 0x00]),
    ("VPTEST", &[0xC4, 0xE2, 0x79, 0x17, 0x00]),
    ("VTESTPS", &[0xC4, 0xE2, 0x79, 0x0E, 0x00]),
    ("VPHMINPOSUW", &[0xC4, 0xE2, 0x79, 0x41, 0x00]),
    ("VSM3MSG1", &[0xC4, 0xE2, 0x78, 0xDA, 0x00]),
    ("VSM3RNDS2", &[0xC4, 0xE3, 0x79, 0xDE, 0x00, 0x00]),
    ("VSM4KEY4", &[0xC4, 0xE2, 0x7A, 0xDA, 0x00]),
    ("VCVTNEEBF162PS", &[0xC4, 0xE2, 0x7A, 0xB0, 0x00]),
    ("VDPPS", &[0xC4, 0xE3, 0x79, 0x40, 0x00, 0x00]),
    ("VROUNDPS", &[0xC4, 0xE3, 0x79, 0x08, 0x00, 0x00]),
];

const VECTOR_CRYPTO_MEMORY_CASES: &[(&str, &[u8])] = &[
    ("VAESENC", &[0xC4, 0xE2, 0x71, 0xDC, 0x00]),
    ("VAESKEYGENASSIST", &[0xC4, 0xE3, 0x79, 0xDF, 0x00, 0x01]),
    ("VGF2P8MULB", &[0xC4, 0xE2, 0x71, 0xCF, 0x00]),
    ("VEX VPCLMULQDQ", &[0xC4, 0xE3, 0x71, 0x44, 0x00, 0x00]),
    (
        "EVEX VPCLMULQDQ",
        &[0x62, 0xF3, 0x75, 0x48, 0x44, 0x00, 0x00],
    ),
];

const EVEX_DOT_MUL_MEMORY_CASES: &[(&str, &[u8])] = &[
    ("VDPBF16PS", &[0x62, 0xF2, 0x76, 0x48, 0x52, 0x00]),
    ("VP4DPWSSD", &[0x62, 0xF2, 0x5F, 0x48, 0x52, 0x00]),
    ("VP4DPWSSDS", &[0x62, 0xF2, 0x5F, 0x48, 0x53, 0x00]),
    ("VPMADDUBSW", &[0x62, 0xF2, 0x75, 0x48, 0x04, 0x00]),
    ("VPMULHRSW", &[0x62, 0xF2, 0x75, 0x48, 0x0B, 0x00]),
];

type EvexApxMemoryCase = (&'static str, &'static [u8], &'static [u8], &'static [u8]);

const EVEX_VECTOR_CRYPTO_APX_CASES: &[EvexApxMemoryCase] = &[
    (
        "EVEX VAESENC",
        &[0x62, 0xF2, 0x75, 0x08, 0xDC, 0x00],
        &[0x62, 0xFA, 0x75, 0x08, 0xDC, 0x00],
        &[0x62, 0xF2, 0x71, 0x08, 0xDC, 0x04, 0x20],
    ),
    (
        "EVEX VGF2P8MULB",
        &[0x62, 0xF2, 0x75, 0x08, 0xCF, 0x00],
        &[0x62, 0xFA, 0x75, 0x08, 0xCF, 0x00],
        &[0x62, 0xF2, 0x71, 0x08, 0xCF, 0x04, 0x20],
    ),
    (
        "EVEX VPCLMULQDQ",
        &[0x62, 0xF3, 0x75, 0x08, 0x44, 0x00, 0x00],
        &[0x62, 0xFB, 0x75, 0x08, 0x44, 0x00, 0x00],
        &[0x62, 0xF3, 0x71, 0x08, 0x44, 0x04, 0x20, 0x00],
    ),
];

const EVEX_DOT_MUL_APX_CASES: &[EvexApxMemoryCase] = &[
    (
        "VDPBF16PS",
        &[0x62, 0xF2, 0x76, 0x48, 0x52, 0x00],
        &[0x62, 0xFA, 0x76, 0x48, 0x52, 0x00],
        &[0x62, 0xF2, 0x72, 0x48, 0x52, 0x04, 0x20],
    ),
    (
        "VP4DPWSSD",
        &[0x62, 0xF2, 0x5F, 0x48, 0x52, 0x00],
        &[0x62, 0xFA, 0x5F, 0x48, 0x52, 0x00],
        &[0x62, 0xF2, 0x5B, 0x48, 0x52, 0x04, 0x20],
    ),
    (
        "VP4DPWSSDS",
        &[0x62, 0xF2, 0x5F, 0x48, 0x53, 0x00],
        &[0x62, 0xFA, 0x5F, 0x48, 0x53, 0x00],
        &[0x62, 0xF2, 0x5B, 0x48, 0x53, 0x04, 0x20],
    ),
    (
        "VPMADDUBSW",
        &[0x62, 0xF2, 0x75, 0x48, 0x04, 0x00],
        &[0x62, 0xFA, 0x75, 0x48, 0x04, 0x00],
        &[0x62, 0xF2, 0x71, 0x48, 0x04, 0x04, 0x20],
    ),
    (
        "VPMULHRSW",
        &[0x62, 0xF2, 0x75, 0x48, 0x0B, 0x00],
        &[0x62, 0xFA, 0x75, 0x48, 0x0B, 0x00],
        &[0x62, 0xF2, 0x71, 0x48, 0x0B, 0x04, 0x20],
    ),
];

const EVEX_SCALAR_MOVE_APX_CASES: &[EvexApxMemoryCase] = &[
    (
        "VMOVSS",
        &[0x62, 0xF1, 0x7E, 0x08, 0x10, 0x00],
        &[0x62, 0xF9, 0x7E, 0x08, 0x10, 0x00],
        &[0x62, 0xF1, 0x7A, 0x08, 0x10, 0x04, 0x20],
    ),
    (
        "VMOVSD",
        &[0x62, 0xF1, 0xFF, 0x08, 0x10, 0x00],
        &[0x62, 0xF9, 0xFF, 0x08, 0x10, 0x00],
        &[0x62, 0xF1, 0xFB, 0x08, 0x10, 0x04, 0x20],
    ),
];

fn with_legacy_prefixes(prefixes: &[u8], instruction: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(prefixes.len() + instruction.len());
    bytes.extend_from_slice(prefixes);
    bytes.extend_from_slice(instruction);
    bytes
}

fn memory_address(name: &str, bytes: &[u8]) -> Address {
    let result =
        lift_single(bytes).unwrap_or_else(|error| panic!("{name} {bytes:02X?}: {error:?}"));
    assert_eq!(result.bytes_consumed, bytes.len(), "{name} {bytes:02X?}");

    let addresses = result
        .ops
        .iter()
        .filter_map(|op| match &op.kind {
            OpKind::Load { addr, .. } | OpKind::VLoad { addr, .. } => Some(addr),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        addresses.len(),
        1,
        "{name} {bytes:02X?}: expected one memory-source load, got {:?}",
        result.ops
    );
    addresses[0].clone()
}

fn segment_address(segment: X86Reg) -> Address {
    Address::SegmentRel {
        segment: VReg::Arch(ArchReg::X86(segment)),
        base: Some(x86_gpr(0)),
        index: None,
        scale: 1,
        disp: 0,
    }
}

fn vector_memory_function(bytes: &[u8]) -> SmirFunction {
    let result = lift_single(bytes).expect("lift vector memory form");
    let mut block = SmirBlock::new(BlockId(0), 0x1000);
    block.ops = result.ops;
    block.set_terminator(Terminator::Trap {
        kind: TrapKind::Halt,
    });
    let mut function = SmirFunction::new(FunctionId(0), block.id, 0x1000);
    function.add_block(block);
    function
}

#[test]
fn standalone_vex_memory_families_preserve_address_size_and_segment_prefixes() {
    for &(name, instruction) in MEMORY_CASES {
        assert_eq!(
            memory_address(name, instruction),
            Address::Direct(x86_gpr(0)),
            "{name}: default [rax]"
        );
        assert_eq!(
            memory_address(name, &with_legacy_prefixes(&[0x67], instruction)),
            Address::X86Addr32(Box::new(Address::Direct(x86_gpr(0)))),
            "{name}: addr32 [eax]"
        );
        assert_eq!(
            memory_address(name, &with_legacy_prefixes(&[0x64], instruction)),
            segment_address(X86Reg::FsBase),
            "{name}: fs:[rax]"
        );
        assert_eq!(
            memory_address(name, &with_legacy_prefixes(&[0x65, 0x67], instruction)),
            Address::X86Addr32(Box::new(segment_address(X86Reg::GsBase))),
            "{name}: gs:[eax]"
        );
    }
}

#[test]
fn vector_crypto_memory_families_preserve_address_size_and_segment_prefixes() {
    for &(name, instruction) in VECTOR_CRYPTO_MEMORY_CASES {
        assert_eq!(
            memory_address(name, &with_legacy_prefixes(&[0x67], instruction)),
            Address::X86Addr32(Box::new(Address::Direct(x86_gpr(0)))),
            "{name}: addr32 [eax]"
        );
        assert_eq!(
            memory_address(name, &with_legacy_prefixes(&[0x64], instruction)),
            segment_address(X86Reg::FsBase),
            "{name}: fs:[rax]"
        );
        assert_eq!(
            memory_address(name, &with_legacy_prefixes(&[0x65, 0x67], instruction)),
            Address::X86Addr32(Box::new(segment_address(X86Reg::GsBase))),
            "{name}: gs:[eax]"
        );
    }
}

#[test]
fn evex_dot_mul_memory_families_preserve_address_size_and_segment_prefixes() {
    for &(name, instruction) in EVEX_DOT_MUL_MEMORY_CASES {
        assert_eq!(
            memory_address(name, instruction),
            Address::Direct(x86_gpr(0)),
            "{name}: default [rax]"
        );
        assert_eq!(
            memory_address(name, &with_legacy_prefixes(&[0x67], instruction)),
            Address::X86Addr32(Box::new(Address::Direct(x86_gpr(0)))),
            "{name}: addr32 [eax]"
        );
        assert_eq!(
            memory_address(name, &with_legacy_prefixes(&[0x64], instruction)),
            segment_address(X86Reg::FsBase),
            "{name}: fs:[rax]"
        );
        assert_eq!(
            memory_address(name, &with_legacy_prefixes(&[0x65, 0x67], instruction)),
            Address::X86Addr32(Box::new(segment_address(X86Reg::GsBase))),
            "{name}: gs:[eax]"
        );
    }
}

fn assert_evex_apx_memory_extensions(cases: &[EvexApxMemoryCase]) {
    for &(name, standard_bytes, base_bytes, index_bytes) in cases {
        let standard = lift_single(standard_bytes).unwrap();
        assert!(
            standard
                .ops
                .iter()
                .all(|op| !matches!(op.kind, OpKind::X86RequireApx)),
            "{name}: ordinary EVEX address must not require APX"
        );
        for bytes in [base_bytes, index_bytes] {
            let extended = lift_single(bytes).unwrap();
            assert!(
                matches!(
                    extended.ops.first(),
                    Some(SmirOp {
                        kind: OpKind::X86RequireApx,
                        ..
                    })
                ),
                "{name}: extended address must guard before memory"
            );
            assert_eq!(
                extended
                    .ops
                    .iter()
                    .filter(|op| matches!(op.kind, OpKind::X86RequireApx))
                    .count(),
                1,
                "{name}: extended address must have one APX guard"
            );
            for (index, op) in extended.ops.iter().enumerate() {
                assert_eq!(op.id, OpId(index as u16), "{name}: operation IDs");
            }
        }
        assert_eq!(
            memory_address(name, base_bytes),
            Address::Direct(x86_gpr(16)),
            "{name}: [r16]"
        );
        assert_eq!(
            memory_address(name, index_bytes),
            Address::BaseIndexScale {
                base: Some(x86_gpr(0)),
                index: x86_gpr(20),
                scale: 1,
                disp: 0,
                disp_size: DispSize::Auto,
            },
            "{name}: [rax+r20]"
        );
    }
}

#[test]
fn evex_scalar_moves_preserve_and_guard_apx_base_and_index_extensions() {
    assert_evex_apx_memory_extensions(EVEX_SCALAR_MOVE_APX_CASES);
}

#[test]
fn evex_vsib_ignores_x4_and_requires_apx_only_for_an_egpr_base() {
    // Intel APX 355828-007US section 3.1.2.3.3/Table 3.3 keeps VIDX in
    // EVEX.V4:X3:SIB.index. Unused X4 is ignored; only an actual EGPR
    // base selected by B4 requires APX_F.
    for (name, opcode) in [("VGATHERDPS", 0x92), ("VSCATTERDPS", 0xA2)] {
        for (p0, expected_base) in [(0xF2, x86_gpr(0)), (0xFA, x86_gpr(16))] {
            let bytes = [0x62, p0, 0x79, 0x09, opcode, 0x04, 0x08];
            let result = lift_single(&bytes)
                .unwrap_or_else(|error| panic!("{name} {bytes:02X?}: {error:?}"));
            assert_eq!(result.bytes_consumed, bytes.len(), "{name} {bytes:02X?}");
            let requires_apx = p0 & 0x08 != 0;
            assert_eq!(
                matches!(
                    result.ops.first().map(|op| &op.kind),
                    Some(OpKind::X86RequireApx)
                ),
                requires_apx,
                "{name} {bytes:02X?}: {:#?}",
                result.ops
            );
            assert_eq!(
                result
                    .ops
                    .iter()
                    .filter(|op| matches!(op.kind, OpKind::X86RequireApx))
                    .count(),
                usize::from(requires_apx),
                "{name} {bytes:02X?}"
            );

            let sources = result
                .ops
                .iter()
                .flat_map(|op| op.kind.source_vregs())
                .collect::<Vec<_>>();
            assert!(
                sources.contains(&expected_base),
                "{name} {bytes:02X?}: {sources:?}"
            );
            assert!(
                sources.contains(&VReg::Arch(ArchReg::X86(X86Reg::Xmm(1)))),
                "{name} {bytes:02X?}: VSIB index {sources:?}"
            );
            assert!(
                !sources.iter().any(|register| {
                    matches!(
                        register,
                        VReg::Arch(ArchReg::X86(register))
                            if register.gpr_index() == Some(17)
                    )
                }),
                "{name} {bytes:02X?}: X4 incorrectly extended VIDX"
            );
        }
    }
}

#[test]
fn evex_vector_crypto_memory_preserves_apx_base_and_index_extension_bits() {
    assert_evex_apx_memory_extensions(EVEX_VECTOR_CRYPTO_APX_CASES);
}

#[test]
fn evex_dot_mul_memory_preserves_apx_base_and_index_extension_bits() {
    assert_evex_apx_memory_extensions(EVEX_DOT_MUL_APX_CASES);
}

fn assert_evex_apx_guard_fault_precedence(cases: &[EvexApxMemoryCase]) {
    for &(name, _, base_bytes, index_bytes) in cases {
        for (address, bytes) in [("[r16]", base_bytes), ("[rax+r20]", index_bytes)] {
            let original = vector_memory_function(bytes);
            let mut optimized = original.clone();
            crate::smir::optimize::optimize_function(
                &mut optimized,
                crate::smir::optimize::OptLevel::O2,
            );

            for (level, function) in [("O0", &original), ("O2", &optimized)] {
                assert!(matches!(
                    function.entry_block().unwrap().ops.first(),
                    Some(SmirOp {
                        kind: OpKind::X86RequireApx,
                        ..
                    })
                ));
                for enabled in [false, true] {
                    let mut context = SmirContext::new_x86_64();
                    context.write_vreg(x86_gpr(0), 0);
                    context.write_vreg(x86_gpr(16), 0x200);
                    context.write_vreg(x86_gpr(20), 0x200);
                    context.flags.materialized = MaterializedFlags::from_rflags(0xCD7);
                    let ArchRegState::X86_64(x86) = &mut context.arch_regs else {
                        unreachable!()
                    };
                    x86.apx_enabled = enabled;
                    let destination = VReg::Arch(ArchReg::X86(X86Reg::Xmm(0)));
                    let sentinel = [0x0123_4567_89AB_CDEF_u64; 16];
                    SmirInterpreter::write_vec(&mut context, destination, sentinel);

                    let execution = SmirInterpreter::new().execute_block(
                        &mut context,
                        &mut FlatMemory::new(0x40),
                        function.entry_block().unwrap(),
                    );
                    if enabled {
                        assert!(
                            matches!(
                                execution,
                                BlockResult::Exit(ExitReason::MemoryFault {
                                    addr: 0x200,
                                    write: false,
                                })
                            ),
                            "{name} {address} {level}: {execution:?}"
                        );
                    } else {
                        assert!(
                            matches!(
                                execution,
                                BlockResult::Exit(ExitReason::Undefined { addr: 0x1000, .. })
                            ),
                            "{name} {address} {level}: {execution:?}"
                        );
                    }
                    assert_eq!(
                        SmirInterpreter::read_vec(&context, destination),
                        sentinel,
                        "{name} {address} {level}: destination committed"
                    );
                    assert_eq!(
                        context.flags.materialized.to_rflags(),
                        0xCD7,
                        "{name} {address} {level}: flags changed"
                    );
                }
            }
        }
    }
}

#[test]
fn evex_vector_crypto_apx_guard_survives_o2_and_precedes_memory_faults() {
    assert_evex_apx_guard_fault_precedence(EVEX_VECTOR_CRYPTO_APX_CASES);
}

#[test]
fn evex_dot_mul_apx_guard_survives_o2_and_precedes_memory_faults() {
    assert_evex_apx_guard_fault_precedence(EVEX_DOT_MUL_APX_CASES);
}
