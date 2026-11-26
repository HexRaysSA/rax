use super::*;
use crate::{RAX_MODE_ARM, RAX_MODE_BIG_ENDIAN, RAX_MODE_LITTLE_ENDIAN, RAX_MODE_THUMB};

fn arm(arch: i32, mode: u32, pc: u64, word: u32) -> (RaxSmirInstruction, Vec<RaxSmirOp>) {
    let bytes = word.to_le_bytes();
    let mut header = RaxSmirInstruction::default();
    assert_eq!(
        rax_smir_lift_arm(
            arch,
            mode,
            pc,
            bytes.as_ptr().cast(),
            4,
            &mut header,
            std::ptr::null_mut(),
            0
        ),
        RaxStatus::Ok
    );
    assert_eq!(header.flags, RAX_SMIR_COMPLETE);
    assert_eq!(header.op_count, 0);
    let mut operations = vec![RaxSmirOp::default(); header.required_op_count as usize + 1];
    assert_eq!(
        rax_smir_lift_arm(
            arch,
            mode,
            pc,
            bytes.as_ptr().cast(),
            4,
            &mut header,
            operations.as_mut_ptr(),
            operations.len()
        ),
        RaxStatus::Ok
    );
    operations.truncate(header.op_count as usize);
    assert!(
        operations
            .iter()
            .all(|op| op.struct_size as usize == size_of::<RaxSmirOp>()
                && op.abi_version == RAX_SMIR_ABI_VERSION
                && op.guest_pc == pc)
    );
    (header, operations)
}

#[test]
fn arm_register_bank_and_pc_origin_are_explicit() {
    let (_, adrp) = arm(2, RAX_MODE_LITTLE_ENDIAN, 0x1200, 0x90000000);
    let op = adrp.iter().find(|op| op.opcode == RAX_SMIR_MOV).unwrap();
    assert_eq!(
        (op.dst.kind, op.dst.id, op.a.value),
        (RAX_SMIR_OPERAND_ARM, 0, 0x1000)
    );
    assert_ne!(op.auxiliary & RAX_SMIR_ARM_PC_RELATIVE, 0);
    let (_, movz) = arm(2, 0, 0x1200, 0xd2820000); // mov x0,#0x1000
    assert_eq!(movz[0].a.value, 0x1000);
    assert_eq!(movz[0].auxiliary & RAX_SMIR_ARM_PC_RELATIVE, 0);
    let (_, literal) = arm(2, 0, 0x1000, 0x58000080);
    let load = literal
        .iter()
        .find(|op| op.opcode == RAX_SMIR_LOAD)
        .unwrap();
    assert_eq!(load.address.displacement, 0x1010);
    assert_ne!(load.auxiliary & RAX_SMIR_ARM_PC_RELATIVE, 0);
    let (_, a32) = arm(3, RAX_MODE_ARM, 0, 0xe3a0d001); // mov r13,#1
    assert!(
        a32.iter()
            .any(|op| op.dst.kind == RAX_SMIR_OPERAND_ARM && op.dst.id == 13)
    );
}

#[test]
fn arm_pairs_preserve_width_destinations_and_writeback_order() {
    for (word, width) in [(0xa8c11003, 64), (0x28c11003, 32)] {
        let (_, ops) = arm(2, 0, 0x14, word);
        let pair = ops
            .iter()
            .position(|op| op.opcode == RAX_SMIR_LOAD_PAIR)
            .unwrap();
        assert_eq!(
            (ops[pair].dst.id, ops[pair].dst2.id, ops[pair].width_bits),
            (3, 4, width)
        );
        assert_eq!(
            (ops[pair].address.base.kind, ops[pair].address.base.id),
            (RAX_SMIR_OPERAND_ARM, 0)
        );
        assert!(ops[pair + 1..].iter().any(|op| op.opcode == RAX_SMIR_ADD
            && op.dst.id == 0
            && op.b.value == u64::from(width / 4)));
    }
    let (_, store) = arm(2, 0, 24, 0xa8811023);
    assert_eq!(store[0].opcode, RAX_SMIR_STORE_PAIR);
    assert_eq!(
        (store[0].a.id, store[0].b.id, store[0].address.base.id),
        (3, 4, 1)
    );
}

#[test]
fn arm_compound_sources_and_conditions_have_no_hidden_encoding() {
    let (header, ops) = arm(2, 0, 0, 0x8b080c20); // add x0,x1,x8,lsl #3
    let shift = ops.iter().find(|op| op.opcode == RAX_SMIR_SHL).unwrap();
    assert_eq!(
        (shift.a.kind, shift.a.id, shift.b.kind, shift.b.value),
        (5, 8, 3, 3)
    );
    assert!(shift.dst.id < header.temporary_count);
    let add = ops.iter().find(|op| op.opcode == RAX_SMIR_ADD).unwrap();
    assert_eq!((add.b.kind, add.b.id), (1, shift.dst.id));
    let (branch, _) = arm(2, 0, 0x20, 0x54ffffa1); // b.ne backward
    assert_eq!(
        (
            branch.flow,
            branch.condition,
            branch.target,
            branch.fallthrough
        ),
        (2, 1, 0x14, 0x24)
    );
    let (a32, _) = arm(3, RAX_MODE_ARM, 0, 0xea00000a);
    assert_eq!((a32.flow, a32.target), (1, 0x30));
    let (wrapped, literal) = arm(3, RAX_MODE_ARM, 0xfffffffc, 0xe59f0004);
    assert_eq!(wrapped.fallthrough, 0);
    assert_eq!(literal[0].address.displacement, 8);
}

#[test]
fn arm_rejection_and_capacity_failure_publish_no_prefix() {
    let bytes = 0xa8c11003u32.to_le_bytes();
    let mut header = RaxSmirInstruction::default();
    let sentinel = RaxSmirOp {
        guest_pc: 0xdeadbeef,
        ..Default::default()
    };
    let mut operation = sentinel;
    assert_eq!(
        rax_smir_lift_arm(
            2,
            0,
            0,
            bytes.as_ptr().cast(),
            4,
            &mut header,
            &mut operation,
            1
        ),
        RaxStatus::Bounds
    );
    assert_eq!((header.flags, header.op_count), (RAX_SMIR_TRUNCATED, 0));
    assert_eq!(operation, sentinel);
    for (arch, mode, pc, length, status) in [
        (1, 0, 0, 4, RaxStatus::Arch),
        (2, RAX_MODE_ARM, 0, 4, RaxStatus::Mode),
        (3, RAX_MODE_ARM | RAX_MODE_THUMB, 0, 4, RaxStatus::Mode),
        (2, RAX_MODE_BIG_ENDIAN, 0, 4, RaxStatus::Mode),
        (2, 0, 1, 4, RaxStatus::Arg),
        (2, 0, 0, 3, RaxStatus::Arg),
        (3, 0, 0x100000000, 4, RaxStatus::Arg),
    ] {
        assert_eq!(
            rax_smir_lift_arm(
                arch,
                mode,
                pc,
                bytes.as_ptr().cast(),
                length,
                &mut header,
                &mut operation,
                1
            ),
            status
        );
        assert_eq!(header.op_count, 0);
        assert_eq!(operation, sentinel);
    }
    let unsupported = 0xd518c002u32.to_le_bytes();
    assert_eq!(
        rax_smir_lift_arm(
            2,
            0,
            0,
            unsupported.as_ptr().cast(),
            4,
            &mut header,
            &mut operation,
            1
        ),
        RaxStatus::Unsupported
    );
    assert_eq!((header.flags, header.op_count), (RAX_SMIR_UNSUPPORTED, 0));
    assert_eq!(operation, sentinel);
}

#[test]
fn system_frontier_query_never_claims_executable_smir() {
    let bytes = 0xd538f502u32.to_le_bytes(); // unsupported privileged MRS x2
    let mut info = RaxArmSystemInfo::default();
    assert_eq!(
        rax_arm_system_info(2, 0, 0, bytes.as_ptr().cast(), 4, &mut info),
        RaxStatus::Ok
    );
    assert_eq!((info.kind, info.flags, info.gpr_written), (1, 1, 1 << 2));
    let zero = 0u32.to_le_bytes();
    assert_eq!(
        rax_arm_system_info(2, 0, 0, zero.as_ptr().cast(), 4, &mut info),
        RaxStatus::Unsupported
    );
    assert_eq!(info.gpr_written, 0);
    let (header, ops) = arm(2, 0, 0, 0);
    assert_eq!(header.flow, 10); // undefined is a represented trap, not an opaque system op
    assert!(ops.is_empty());
    for word in [0xd50040bfu32, 0xd50041bf] {
        // MSR SPSel,#0/#1
        assert_eq!(
            rax_arm_system_info(2, 0, 0, word.to_le_bytes().as_ptr().cast(), 4, &mut info),
            RaxStatus::Ok
        );
        assert_eq!((info.kind, info.flags, info.gpr_written), (2, 1, 0));
    }
    let sysl = 0xd5280002u32.to_le_bytes();
    assert_eq!(
        rax_arm_system_info(2, 0, 0, sysl.as_ptr().cast(), 4, &mut info),
        RaxStatus::Ok
    );
    assert_eq!((info.kind, info.gpr_written), (1, 4));
    let vmsr = 0xeee80a10u32.to_le_bytes();
    assert_eq!(
        rax_arm_system_info(3, RAX_MODE_ARM, 0, vmsr.as_ptr().cast(), 4, &mut info),
        RaxStatus::Ok
    );
    assert_eq!((info.kind, info.gpr_read, info.gpr_written), (2, 1, 0));
}

#[test]
fn arm_accumulate_expansion_and_thumb_length() {
    let (header, ops) = arm(2, 0, 0x40b8, 0x9b150421); // madd x1,x1,x21,x1
    assert_eq!(ops.len(), 2);
    assert_eq!(
        (ops[0].opcode, ops[0].a.id, ops[0].b.id),
        (RAX_SMIR_MUL_U, 1, 21)
    );
    assert_eq!(
        (ops[1].opcode, ops[1].dst.id, ops[1].a.id, ops[1].b.id),
        (RAX_SMIR_ADD, 1, 1, ops[0].dst.id)
    );
    assert!(ops[0].dst.id < header.temporary_count);
    let bytes = [0x70u8, 0x47]; // bx lr, T16
    let mut h = RaxSmirInstruction::default();
    assert_eq!(
        rax_smir_lift_arm(
            3,
            RAX_MODE_THUMB,
            0,
            bytes.as_ptr().cast(),
            2,
            &mut h,
            std::ptr::null_mut(),
            0
        ),
        RaxStatus::Ok
    );
    assert_eq!(h.bytes_consumed, 2);
    assert!(matches!(h.flow, 4 | 9));
}

#[test]
fn a32_predication_guards_all_effects_and_never_publishes_a_rejected_body() {
    let canonical = [0, 1, 5, 2, 10, 11, 12, 13, 4, 3, 9, 6, 8, 7];
    for (cc, condition) in canonical.into_iter().enumerate() {
        let (h, ops) = arm(3, RAX_MODE_ARM, 0x1054, ((cc as u32) << 28) | 0x059f0038);
        assert_eq!((h.flow, h.fallthrough), (0, 0x1058));
        assert_eq!(
            (ops[0].opcode, ops[0].condition, ops[0].width_bits),
            (RAX_SMIR_GUARD_CC, condition, 0)
        );
        assert_eq!(ops[1].opcode, RAX_SMIR_LOAD);
        assert_eq!(ops[1].address.displacement, 0x1094);
        assert_ne!(ops[1].auxiliary & RAX_SMIR_ARM_PC_RELATIVE, 0);
    }
    let (h, ops) = arm(3, RAX_MODE_ARM, 0x1058, 0x012fff30); // blxeq r0
    assert_eq!(
        (h.flow, ops[0].opcode, ops[0].condition),
        (13, RAX_SMIR_GUARD_CC, 0)
    );
    let (direct, _) = arm(3, RAX_MODE_ARM, 0, 0xfa000000); // blx immediate -> Thumb at PC+8
    assert_eq!((direct.flow, direct.target, direct.fallthrough), (12, 9, 4));
    let (alias, body) = arm(3, RAX_MODE_ARM, 0x20, 0x012fff3e); // blxeq lr snapshots old LR
    assert_eq!((alias.flow, alias.predicate.kind), (13, 1));
    let snapshot = body
        .iter()
        .find(|op| op.dst.kind == 1 && op.dst.id == alias.predicate.id)
        .unwrap();
    assert_eq!(
        (snapshot.opcode, snapshot.a.kind, snapshot.a.id),
        (RAX_SMIR_MOV, 5, 14)
    );
    let link = body
        .iter()
        .find(|op| op.dst.kind == 5 && op.dst.id == 14)
        .unwrap();
    assert_eq!((link.opcode, link.a.value), (RAX_SMIR_MOV, 0x24));
    let (_, branch) = arm(3, RAX_MODE_ARM, 0, 0x0a000000); // beq retains its two-edge terminator
    assert!(branch.iter().all(|op| op.opcode != RAX_SMIR_GUARD_CC));
    let bytes = 0x1590f000u32.to_le_bytes(); // LDRNE pc,[r0]: PC transfer is not in this strict body subset
    let mut h = RaxSmirInstruction::default();
    let mut sentinel = RaxSmirOp {
        guest_pc: 0xfeed,
        ..Default::default()
    };
    assert_eq!(
        rax_smir_lift_arm(
            3,
            RAX_MODE_ARM,
            0,
            bytes.as_ptr().cast(),
            4,
            &mut h,
            &mut sentinel,
            1
        ),
        RaxStatus::Unsupported
    );
    assert_eq!(
        (h.op_count, h.flags, sentinel.guest_pc),
        (0, RAX_SMIR_UNSUPPORTED, 0xfeed)
    );
}

#[test]
fn a32_logical_export_preserves_selective_flags_and_atomic_guard_capacity() {
    let (h, ops) = arm(3, RAX_MODE_ARM, 0x10, 0x03120102); // tsteq r2,#0x80000000
    assert_eq!(h.op_count, 3);
    assert_eq!((ops[0].opcode, ops[0].condition), (RAX_SMIR_GUARD_CC, 0));
    assert_eq!(
        (
            ops[1].opcode,
            ops[1].width_bits,
            ops[1].flags_mask,
            ops[1].b.value
        ),
        (RAX_SMIR_AND, 32, 6, 0x80000000)
    );
    assert_eq!((ops[2].opcode, ops[2].auxiliary), (RAX_SMIR_SET_CF, 0)); // ARM C=1, SMIR CF=0
    let bytes = 0x03120102u32.to_le_bytes();
    let mut header = RaxSmirInstruction::default();
    let sentinel = RaxSmirOp {
        guest_pc: 0xfeed,
        ..Default::default()
    };
    let mut storage = [sentinel; 2];
    assert_eq!(
        rax_smir_lift_arm(
            3,
            RAX_MODE_ARM,
            0x10,
            bytes.as_ptr().cast(),
            4,
            &mut header,
            storage.as_mut_ptr(),
            storage.len()
        ),
        RaxStatus::Bounds
    );
    assert_eq!((header.op_count, header.required_op_count), (0, 3));
    assert_eq!(storage, [sentinel; 2]);
    for word in [0xe190f001u32, 0xe1100081, 0xe1b01001] {
        // PC destination, shifter carry, MOVS outside the added subset
        assert_eq!(
            rax_smir_lift_arm(
                3,
                RAX_MODE_ARM,
                0x10,
                word.to_le_bytes().as_ptr().cast(),
                4,
                &mut header,
                storage.as_mut_ptr(),
                storage.len()
            ),
            RaxStatus::Unsupported
        );
        assert_eq!(header.op_count, 0);
        assert_eq!(storage, [sentinel; 2]);
    }
}
