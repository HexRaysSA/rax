//! MMX lowering at Rust helper-call boundaries.

use super::*;
use crate::smir::lower::X86_GUEST_MM_OFFSET;
use crate::smir::lower::x86_64::test_support::host_c_call_opcode;

fn mm_state_encoding(index: u8, base: PhysReg, store: bool) -> Vec<u8> {
    let mut bytes = vec![0x0F, if store { 0x7F } else { 0x6F }];
    bytes.push(0x80 | ((index & 7) << 3) | base.low3());
    bytes.extend_from_slice(&(X86_GUEST_MM_OFFSET + i32::from(index) * 8).to_le_bytes());
    bytes
}

pub(super) fn assert_mmx_helper_boundary(bytes: &[u8], name: &str) {
    let store = mm_state_encoding(0, PhysReg::Rax, true);
    let load = mm_state_encoding(0, PhysReg::Rcx, false);
    let store_pos = bytes
        .windows(store.len())
        .position(|window| window == store)
        .expect("MM0 store position");
    let emms_pos = bytes
        .windows(2)
        .position(|window| window == [0x0F, 0x77])
        .expect("EMMS position");
    let call_pos = bytes
        .windows(host_c_call_opcode().len())
        .position(|window| window == host_c_call_opcode())
        .expect("indirect helper call position");
    let first_load_pos = bytes
        .windows(load.len())
        .position(|window| window == load)
        .expect("MM0 reload position");
    assert!(
        store_pos < emms_pos && emms_pos < call_pos && call_pos < first_load_pos,
        "{name} must spill, execute EMMS, call Rust, then reload MMX"
    );
    assert_eq!(
        bytes
            .windows(store.len())
            .filter(|window| *window == store)
            .count(),
        1,
        "{name} must publish MM0 exactly once: {bytes:02X?}"
    );
    assert_eq!(
        bytes
            .windows(load.len())
            .filter(|window| *window == load)
            .count(),
        2,
        "{name} must reload MM0 on success and failure: {bytes:02X?}"
    );
    assert_eq!(
        bytes
            .windows(2)
            .filter(|window| *window == [0x0F, 0x77])
            .count(),
        1,
        "{name} must execute one host-only EMMS before the Rust call: {bytes:02X?}"
    );
}

#[test]
fn mmx_helper_state_uses_exact_full_file_movq_and_host_emms_encodings() {
    let mut lowerer = X86_64Lowerer::new();
    lowerer.emit_helper_mmx_state(PhysReg::Rax, true);
    let stores = lowerer.code.data().to_vec();
    for index in 0..8 {
        let expected = mm_state_encoding(index, PhysReg::Rax, true);
        assert!(
            stores
                .windows(expected.len())
                .any(|window| window == expected),
            "missing MM{index} store {expected:02X?} in {stores:02X?}"
        );
    }
    assert_eq!(&stores[stores.len() - 2..], &[0x0F, 0x77]);

    lowerer.code.clear();
    lowerer.emit_helper_mmx_state(PhysReg::Rcx, false);
    let loads = lowerer.code.data();
    for index in 0..8 {
        let expected = mm_state_encoding(index, PhysReg::Rcx, false);
        assert!(
            loads
                .windows(expected.len())
                .any(|window| window == expected),
            "missing MM{index} load {expected:02X?} in {loads:02X?}"
        );
    }
    assert!(!loads.windows(2).any(|window| window == [0x0F, 0x77]));
}

#[test]
fn mmx_state_wraps_every_rust_helper_boundary_on_both_return_paths() {
    let rax = VReg::Arch(ArchReg::X86(X86Reg::Rax));
    let rbx = VReg::Arch(ArchReg::X86(X86Reg::Rbx));
    let address = Address::Direct(rbx);

    let mut scalar = X86_64Lowerer::new();
    scalar.set_preserve_mmx_helpers(true);
    scalar
        .emit_jit_mem_op(
            0x1000,
            true,
            Some(rax),
            None,
            None,
            None,
            None,
            &address,
            MemWidth::B8,
            SignExtend::Zero,
            0,
        )
        .unwrap();
    assert_mmx_helper_boundary(scalar.code.data(), "scalar MMU helper");

    let mut vector = X86_64Lowerer::new();
    vector.set_preserve_mmx_helpers(true);
    vector
        .emit_jit_vector_mem_op(
            0x1000,
            true,
            VReg::Arch(ArchReg::X86(X86Reg::Xmm(0))),
            &address,
            VecWidth::V128,
            Some(X86OpHint::SseMov {
                prefix: X86SsePrefix::None,
                opcode: 0x6F,
            }),
        )
        .unwrap();
    assert_mmx_helper_boundary(vector.code.data(), "vector MMU helper");

    let mut pair = X86_64Lowerer::new();
    pair.set_preserve_mmx_helpers(true);
    pair.emit_jit_pair_op(0x1000, true, rax, rbx).unwrap();
    assert_mmx_helper_boundary(pair.code.data(), "paired MMU helper");

    let mut call = X86_64Lowerer::new();
    call.set_preserve_mmx_helpers(true);
    let continuation = BlockId(7);
    call.block_guest_pcs.insert(continuation, 0x2000);
    call.emit_jit_call_op(&CallTarget::GuestAddr(0x1800), continuation, 0x17fb)
        .unwrap();
    assert_mmx_helper_boundary(call.code.data(), "interpreter call helper");
}

fn lower_mmx_movq_memory(is_load: bool) -> Vec<u8> {
    let mm7 = VReg::Arch(ArchReg::X86(X86Reg::Mm(7)));
    let address = Address::BaseOffset {
        base: VReg::Arch(ArchReg::X86(X86Reg::Rbx)),
        offset: 8,
        disp_size: DispSize::Disp8,
    };
    let mut builder = FunctionBuilder::new(FunctionId(0), 0x1000);
    builder.push_op(
        0x1000,
        if is_load {
            OpKind::VLoad {
                dst: mm7,
                addr: address,
                width: VecWidth::V64,
            }
        } else {
            OpKind::VStore {
                src: mm7,
                addr: address,
                width: VecWidth::V64,
            }
        },
    );
    builder.push_op(
        0x1000,
        OpKind::X86X87Control {
            kind: X86X87ControlKind::EnterMmx,
            addr: None,
        },
    );
    builder.set_terminator(Terminator::Return { values: vec![] });
    let mut function = builder.finish();
    function.blocks[0].ops[0].x86_hint = Some(X86OpHint::SseMov {
        prefix: X86SsePrefix::None,
        opcode: if is_load { 0x6F } else { 0x7F },
    });

    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_mem_helpers(true);
    lowerer.set_preserve_mmx_helpers(true);
    let result = lowerer.lower_function(&function).unwrap();
    assert!(result.relocations.is_empty());
    lowerer.finalize().unwrap()
}

#[test]
fn mmx_movq_memory_uses_scalar_helper_and_fault_safe_stack_staging() {
    let load = lower_mmx_movq_memory(true);
    assert!(
        load.windows(5)
            .any(|window| window == [0x48, 0x89, 0x44, 0x24, 0x10]),
        "load result must stage at the outer host-stack slot: {load:02X?}"
    );
    assert!(
        load.windows(4)
            .any(|window| window == [0x0F, 0x6F, 0x3C, 0x24]),
        "load must commit the staged value to MM7: {load:02X?}"
    );
    assert_eq!(
        load.windows(5)
            .filter(|window| *window == [0x48, 0x8D, 0x64, 0x24, 0x10])
            .count(),
        2,
        "success and fault paths must each release the outer stack slot"
    );
    assert_mmx_helper_boundary(&load, "MMX MOVQ load helper");

    let store = lower_mmx_movq_memory(false);
    assert!(
        store
            .windows(4)
            .any(|window| window == [0x0F, 0x7F, 0x3C, 0x24]),
        "store must stage MM7 before host EMMS: {store:02X?}"
    );
    assert!(
        store
            .windows(5)
            .any(|window| window == [0x48, 0x8B, 0x54, 0x24, 0x10]),
        "store helper must read the staged outer slot: {store:02X?}"
    );
    assert_eq!(
        store
            .windows(5)
            .filter(|window| *window == [0x48, 0x8D, 0x64, 0x24, 0x10])
            .count(),
        2,
        "success and fault paths must each release the outer stack slot"
    );
    assert_mmx_helper_boundary(&store, "MMX MOVQ store helper");
}

#[cfg(feature = "smir-jit")]
fn lower_lifted_mmx_memory(bytes: &[u8], level: crate::smir::optimize::OptLevel) -> Vec<u8> {
    let mut code = bytes.to_vec();
    code.extend_from_slice(&[0xEB, 0x00]);
    let reader = TestReader {
        base: 0x1000,
        bytes: code,
    };
    let mut lifter = X86_64Lifter::strict();
    let mut context = LiftContext::new(SourceArch::X86_64);
    let mut block = lifter
        .lift_block(0x1000, &reader, &mut context)
        .unwrap_or_else(|error| panic!("lift MMX memory form {bytes:02X?}: {error:?}"));
    block.set_terminator(Terminator::Return { values: vec![] });
    let block_id = block.id;
    let mut function = SmirFunction::new(FunctionId(0), block_id, 0x1000);
    function.add_block(block);
    crate::smir::optimize::optimize_function(&mut function, level);
    let excluded = std::collections::HashMap::new();
    assert!(
        crate::smir::lower::runtime::is_native_clobber_safe_excluding(&function, &excluded, true),
        "helper gate rejected {bytes:02X?} after {level:?}: {:?}",
        function.blocks[0].ops
    );
    assert!(
        crate::smir::lower::runtime::x86_native_mmx_pairs_valid_excluding(&function, &excluded),
        "MMX pair gate rejected {bytes:02X?} after {level:?}"
    );

    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_mem_helpers(true);
    lowerer.set_preserve_mmx_helpers(true);
    let result = lowerer
        .lower_function(&function)
        .unwrap_or_else(|error| panic!("lower {bytes:02X?} after {level:?}: {error:?}"));
    assert!(result.relocations.is_empty());
    lowerer
        .finalize()
        .unwrap_or_else(|error| panic!("finalize {bytes:02X?} after {level:?}: {error:?}"))
}

#[test]
#[cfg(feature = "smir-jit")]
fn mmx_scalar_memory_transfers_emit_exact_width_direction_and_fault_boundaries() {
    for (guest, host, helper_width, is_load, name) in [
        (
            &[0x0F, 0x6E, 0x1B][..],
            &[0x0F, 0x6E, 0x1C, 0x24][..],
            4u8,
            true,
            "MOVD mm3,m32",
        ),
        (
            &[0x0F, 0x7E, 0x1B][..],
            &[0x0F, 0x7E, 0x1C, 0x24][..],
            4u8,
            false,
            "MOVD m32,mm3",
        ),
        (
            &[0x48, 0x0F, 0x6E, 0x1B][..],
            &[0x48, 0x0F, 0x6E, 0x1C, 0x24][..],
            8u8,
            true,
            "MOVQ mm3,m64",
        ),
        (
            &[0x48, 0x0F, 0x7E, 0x1B][..],
            &[0x48, 0x0F, 0x7E, 0x1C, 0x24][..],
            8u8,
            false,
            "MOVQ m64,mm3",
        ),
    ] {
        for level in [
            crate::smir::optimize::OptLevel::O0,
            crate::smir::optimize::OptLevel::O1,
            crate::smir::optimize::OptLevel::O2,
        ] {
            let code = lower_lifted_mmx_memory(guest, level);
            assert!(
                code.windows(host.len()).any(|window| window == host),
                "missing {name} host replay after {level:?}: {code:02X?}"
            );
            assert!(
                code.windows(5).any(|window| {
                    window
                        == [
                            if is_load { 0xBA } else { 0xB9 },
                            helper_width,
                            0x00,
                            0x00,
                            0x00,
                        ]
                }),
                "missing {name} helper width after {level:?}: {code:02X?}"
            );
            assert_eq!(
                code.windows(5)
                    .filter(|window| *window == [0x48, 0x8D, 0x64, 0x24, 0x10])
                    .count(),
                2,
                "{name} after {level:?}: both success and fault paths must release the stack slot"
            );
            if is_load {
                assert!(
                    code.windows(5)
                        .any(|window| window == [0x48, 0x89, 0x44, 0x24, 0x10]),
                    "{name}: helper result must stage in the outer slot"
                );
            } else {
                assert!(
                    code.windows(5)
                        .any(|window| window == [0x48, 0x8B, 0x54, 0x24, 0x10]),
                    "{name}: helper must read the staged outer slot"
                );
            }
            assert_mmx_helper_boundary(&code, name);
        }
    }
}

#[test]
#[cfg(feature = "smir-jit")]
fn mmx_movntq_uses_exact_helper_width_and_fault_safe_stack_staging() {
    for level in [
        crate::smir::optimize::OptLevel::O0,
        crate::smir::optimize::OptLevel::O1,
        crate::smir::optimize::OptLevel::O2,
    ] {
        let code = lower_lifted_mmx_memory(&[0x0F, 0xE7, 0x3B], level);
        assert!(
            code.windows(4)
                .any(|window| window == [0x0F, 0x7F, 0x3C, 0x24]),
            "MOVNTQ must stage MM7 before host EMMS after {level:?}: {code:02X?}"
        );
        assert!(
            code.windows(5)
                .any(|window| window == [0xB9, 0x08, 0x00, 0x00, 0x00]),
            "MOVNTQ must request an exact 8-byte store after {level:?}: {code:02X?}"
        );
        assert_eq!(
            code.windows(5)
                .filter(|window| *window == [0x48, 0x8D, 0x64, 0x24, 0x10])
                .count(),
            2,
            "MOVNTQ success and fault paths must release the stack slot after {level:?}"
        );
        assert_mmx_helper_boundary(&code, "MOVNTQ helper");
    }
}

#[test]
#[cfg(feature = "smir-jit")]
fn mmx_maskmovq_emits_ordered_predicated_byte_helpers_and_fault_cleanup() {
    for level in [
        crate::smir::optimize::OptLevel::O0,
        crate::smir::optimize::OptLevel::O1,
        crate::smir::optimize::OptLevel::O2,
    ] {
        let code = lower_lifted_mmx_memory(&[0x0F, 0xF7, 0xC1], level);
        assert!(
            code.windows(4)
                .any(|window| window == [0x0F, 0x7F, 0x04, 0x24]),
            "MASKMOVQ must stage MM0 data after {level:?}: {code:02X?}"
        );
        assert!(
            code.windows(5)
                .any(|window| window == [0x0F, 0x7F, 0x4C, 0x24, 0x08]),
            "MASKMOVQ must stage MM1 mask after {level:?}: {code:02X?}"
        );
        for lane in 0..8u8 {
            let test = [0xF6, 0x44, 0x24, 0x10 + lane, 0x80];
            assert!(
                code.windows(test.len()).any(|window| window == test),
                "MASKMOVQ lane {lane} must test its mask MSB after {level:?}: {code:02X?}"
            );
        }
        assert_eq!(
            code.windows(5)
                .filter(|window| *window == [0xB9, 0x01, 0x00, 0x00, 0x00])
                .count(),
            8,
            "MASKMOVQ must emit one exact 1-byte helper per lane after {level:?}"
        );

        let mm0_store = mm_state_encoding(0, PhysReg::Rax, true);
        let mm0_load = mm_state_encoding(0, PhysReg::Rcx, false);
        assert_eq!(
            code.windows(mm0_store.len())
                .filter(|window| *window == mm0_store)
                .count(),
            8,
            "each MASKMOVQ lane helper must publish MMX state after {level:?}"
        );
        assert_eq!(
            code.windows(mm0_load.len())
                .filter(|window| *window == mm0_load)
                .count(),
            16,
            "each MASKMOVQ lane helper must restore MMX on success and fault after {level:?}"
        );
        assert_eq!(
            code.windows(2)
                .filter(|window| *window == [0x0F, 0x77])
                .count(),
            8,
            "each MASKMOVQ lane helper must execute host-only EMMS after {level:?}"
        );
        assert_eq!(
            code.windows(5)
                .filter(|window| *window == [0x48, 0x8D, 0x64, 0x24, 0x10])
                .count(),
            9,
            "eight lane-fault paths plus success must release the MASKMOVQ slot after {level:?}"
        );
    }
}

#[test]
#[cfg(feature = "smir-jit")]
fn mmx_maskmovq_addr32_emits_wrapping_edi_before_optional_segment_base() {
    for level in [
        crate::smir::optimize::OptLevel::O0,
        crate::smir::optimize::OptLevel::O1,
        crate::smir::optimize::OptLevel::O2,
    ] {
        let addr32 = lower_lifted_mmx_memory(&[0x67, 0x0F, 0xF7, 0xC1], level);
        assert!(
            addr32
                .windows(2)
                .filter(|window| *window == [0x89, 0xF6])
                .count()
                >= 8,
            "each addr32 MASKMOVQ lane must zero-extend EDI in ESI after {level:?}: {addr32:02X?}"
        );
        assert!(
            addr32.windows(3).any(|window| window == [0x83, 0xC6, 0x07]),
            "addr32 MASKMOVQ lane 7 must add modulo 2^32 after {level:?}: {addr32:02X?}"
        );

        let fs_addr32 = lower_lifted_mmx_memory(&[0x64, 0x67, 0x0F, 0xF7, 0xC1], level);
        assert!(
            fs_addr32
                .windows(2)
                .filter(|window| *window == [0x89, 0xFF])
                .count()
                >= 8,
            "each FS addr32 lane must zero-extend EDI after {level:?}: {fs_addr32:02X?}"
        );
        assert!(
            fs_addr32
                .windows(3)
                .any(|window| window == [0x83, 0xC7, 0x07]),
            "FS addr32 lane 7 must wrap EDI before segmentation after {level:?}: {fs_addr32:02X?}"
        );
        assert!(
            fs_addr32
                .windows(3)
                .filter(|window| *window == [0x48, 0x01, 0xFE])
                .count()
                >= 8,
            "each FS addr32 lane must add its wrapped offset to FS base after {level:?}: {fs_addr32:02X?}"
        );
    }
}
