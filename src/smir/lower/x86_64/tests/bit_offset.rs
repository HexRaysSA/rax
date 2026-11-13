//! Fused native lowering for `BT` with a register bit offset into memory.

use super::*;
use crate::smir::lower::SmirLowerer;
use crate::smir::lower::x86_64::test_support::host_c_call_opcode;

fn x86(reg: X86Reg) -> VReg {
    VReg::Arch(ArchReg::X86(reg))
}

fn virt(id: u32) -> VReg {
    VReg::Virtual(crate::smir::ir::types::VirtualId(id))
}

const PC: u64 = 0x1000;

fn base_addr() -> Address {
    Address::BaseOffset {
        base: x86(X86Reg::Rbx),
        offset: 512,
        disp_size: DispSize::Disp32,
    }
}

/// The eight operations the lifter emits for `bt [mem],reg`.
fn bit_test(width: OpWidth, mem_width: MemWidth, index: X86Reg) -> Vec<OpKind> {
    let (right, left, bits) = match width {
        OpWidth::W16 => (4i64, 1i64, 16i64),
        OpWidth::W32 => (5, 2, 32),
        OpWidth::W64 => (6, 3, 64),
        _ => unreachable!(),
    };
    vec![
        OpKind::SignExtend {
            dst: virt(0),
            src: x86(index),
            from_width: width,
            to_width: OpWidth::W64,
        },
        OpKind::Sar {
            dst: virt(1),
            src: virt(0),
            amount: SrcOperand::Imm(right),
            width: OpWidth::W64,
            flags: FlagUpdate::None,
        },
        OpKind::Shl {
            dst: virt(2),
            src: virt(1),
            amount: SrcOperand::Imm(left),
            width: OpWidth::W64,
            flags: FlagUpdate::None,
        },
        OpKind::Lea {
            dst: virt(3),
            addr: base_addr(),
        },
        OpKind::Add {
            dst: virt(4),
            src1: virt(3),
            src2: SrcOperand::Reg(virt(2)),
            width: OpWidth::W64,
            flags: FlagUpdate::None,
        },
        OpKind::And {
            dst: virt(5),
            src1: x86(index),
            src2: SrcOperand::Imm(bits - 1),
            width: OpWidth::W64,
            flags: FlagUpdate::None,
        },
        OpKind::Load {
            dst: virt(6),
            addr: Address::Direct(virt(4)),
            width: mem_width,
            sign: SignExtend::Zero,
        },
        OpKind::Bt {
            src: virt(6),
            index: SrcOperand::Reg(virt(5)),
            width,
        },
    ]
}

fn lower(ops: Vec<OpKind>) -> (Vec<u8>, usize) {
    let mut builder = FunctionBuilder::new(FunctionId(0), PC);
    for op in ops {
        builder.push_op(PC, op);
    }
    builder.set_terminator(Terminator::Return { values: vec![] });

    let mut lowerer = X86_64Lowerer::new();
    lowerer.set_mem_helpers(true);
    let result = lowerer
        .lower_function(&builder.finish())
        .expect("lower fused memory BT");
    (lowerer.finalize().expect("finalize"), result.entry_offset)
}

#[test]
fn memory_bit_test_folds_the_scaled_offset_into_the_helper_address() {
    let (bytes, _) = lower(bit_test(OpWidth::W64, MemWidth::B8, X86Reg::Rcx));
    assert!(
        bytes
            .windows(5)
            .any(|b| b == [0x48, 0x8D, 0x64, 0x24, 0xE0]),
        "must reserve the flag-neutral caller frame: {bytes:02X?}"
    );
    // `sar rdi,6` then `shl rdi,3` then `add rsi,rdi` scale the offset into the
    // effective address the helper is about to use.
    assert!(
        bytes.windows(4).any(|b| b == [0x48, 0xC1, 0xFF, 0x06]),
        "must arithmetic-shift the bit offset by log2(bits): {bytes:02X?}"
    );
    assert!(
        bytes.windows(4).any(|b| b == [0x48, 0xC1, 0xE7, 0x03]),
        "must scale by log2(bytes): {bytes:02X?}"
    );
    assert!(
        bytes.windows(3).any(|b| b == [0x48, 0x01, 0xFE]),
        "must add the scaled term to the base address: {bytes:02X?}"
    );
    // The architectural CF comes from a native BT on the staged element.
    assert!(
        bytes.windows(4).any(|b| b == [0x48, 0x0F, 0xA3, 0xD0]),
        "must test the staged element: {bytes:02X?}"
    );
}

#[test]
fn narrower_operand_widths_sign_extend_the_offset_before_scaling() {
    let (dword, _) = lower(bit_test(OpWidth::W32, MemWidth::B4, X86Reg::Rcx));
    assert!(
        dword.windows(3).any(|b| b == [0x48, 0x63, 0xFF]),
        "32-bit form must sign-extend EDI: {dword:02X?}"
    );
    assert!(
        dword.windows(4).any(|b| b == [0x48, 0xC1, 0xFF, 0x05]),
        "32-bit form must shift by 5: {dword:02X?}"
    );

    let (word, _) = lower(bit_test(OpWidth::W16, MemWidth::B2, X86Reg::Rcx));
    assert!(
        word.windows(4).any(|b| b == [0x48, 0x0F, 0xBF, 0xFF]),
        "16-bit form must sign-extend DI: {word:02X?}"
    );
    assert!(
        word.windows(4).any(|b| b == [0x48, 0xC1, 0xFF, 0x04]),
        "16-bit form must shift by 4: {word:02X?}"
    );
}

/// The lifted expansion for `bts`/`btr`/`btc [mem],reg`.
fn bit_update(
    width: OpWidth,
    mem_width: MemWidth,
    index: X86Reg,
    update: u8,
    publish_cf: bool,
) -> Vec<OpKind> {
    let bits = match width {
        OpWidth::W16 => 16i64,
        OpWidth::W32 => 32,
        OpWidth::W64 => 64,
        _ => unreachable!(),
    };
    let mut ops = bit_test(width, mem_width, index);
    ops.pop(); // the trailing Bt is re-appended last
    ops.push(OpKind::Mov {
        dst: virt(7),
        src: SrcOperand::Imm(1),
        width,
    });
    ops.push(OpKind::Shl {
        dst: virt(7),
        src: virt(7),
        amount: SrcOperand::Reg(virt(5)),
        width,
        flags: FlagUpdate::None,
    });
    if update == 6 {
        ops.push(OpKind::Not {
            dst: virt(7),
            src: virt(7),
            width,
        });
    }
    ops.push(match update {
        5 => OpKind::Or {
            dst: virt(8),
            src1: virt(6),
            src2: SrcOperand::Reg(virt(7)),
            width,
            flags: FlagUpdate::None,
        },
        6 => OpKind::And {
            dst: virt(8),
            src1: virt(6),
            src2: SrcOperand::Reg(virt(7)),
            width,
            flags: FlagUpdate::None,
        },
        _ => OpKind::Xor {
            dst: virt(8),
            src1: virt(6),
            src2: SrcOperand::Reg(virt(7)),
            width,
            flags: FlagUpdate::None,
        },
    });
    ops.push(OpKind::Store {
        src: virt(8),
        addr: Address::Direct(virt(4)),
        width: mem_width,
    });
    let _ = bits;
    if publish_cf {
        ops.push(OpKind::Bt {
            src: virt(6),
            index: SrcOperand::Reg(virt(5)),
            width,
        });
    }
    ops
}

#[test]
fn memory_bit_updates_compute_the_mask_and_store_before_publishing_cf() {
    let (bytes, _) = lower(bit_update(OpWidth::W64, MemWidth::B8, X86Reg::Rcx, 5, true));
    assert!(
        bytes
            .windows(5)
            .any(|b| b == [0x48, 0x8D, 0x64, 0x24, 0xD0]),
        "must reserve the six-slot caller frame: {bytes:02X?}"
    );
    // `and rcx,63` then `shl rax,cl` builds the architectural mask.
    assert!(
        bytes.windows(4).any(|b| b == [0x48, 0x83, 0xE1, 0x3F]),
        "must mask the shift count to the operand width: {bytes:02X?}"
    );
    assert!(
        bytes.windows(3).any(|b| b == [0x48, 0xD3, 0xE0]),
        "must build the mask with a variable shift: {bytes:02X?}"
    );
    assert!(
        bytes.windows(3).any(|b| b == [0x48, 0x09, 0xC2]),
        "BTS must OR the mask into the element: {bytes:02X?}"
    );
    // The CF publication comes last, after the store helper.
    let bt = bytes
        .windows(4)
        .position(|b| b == [0x48, 0x0F, 0xA3, 0xD0])
        .expect("must publish CF");
    let store_calls = bytes
        .windows(host_c_call_opcode().len())
        .enumerate()
        .filter(|(_, b)| *b == host_c_call_opcode())
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    assert_eq!(store_calls.len(), 2, "one load and one store callback");
    assert!(
        store_calls.iter().all(|call| *call < bt),
        "CF must be published after both helper calls: {bytes:02X?}"
    );

    let (reset, _) = lower(bit_update(OpWidth::W64, MemWidth::B8, X86Reg::Rcx, 6, true));
    assert!(
        reset.windows(3).any(|b| b == [0x48, 0xF7, 0xD0]),
        "BTR must complement the mask: {reset:02X?}"
    );
    assert!(
        reset.windows(3).any(|b| b == [0x48, 0x21, 0xC2]),
        "BTR must AND the complemented mask: {reset:02X?}"
    );

    let (complement, _) = lower(bit_update(
        OpWidth::W64,
        MemWidth::B8,
        X86Reg::Rcx,
        7,
        false,
    ));
    assert!(
        complement.windows(3).any(|b| b == [0x48, 0x31, 0xC2]),
        "BTC must XOR the mask: {complement:02X?}"
    );
    assert!(
        !complement.windows(4).any(|b| b == [0x48, 0x0F, 0xA3, 0xD0]),
        "a dead CF must not be published: {complement:02X?}"
    );
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[derive(Default)]
struct MemoryContext {
    loads: u64,
    load_addr: u64,
    load_size: u64,
    stores: u64,
    store_addr: u64,
    stored: u64,
    stored_size: u64,
    value: u64,
    load_ok: u64,
    store_ok: u64,
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
extern "C" fn load_helper(context: *mut MemoryContext, addr: u64, size: u64) -> (u64, u64) {
    let context = unsafe { &mut *context };
    context.loads += 1;
    context.load_addr = addr;
    context.load_size = size;
    let mask = if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (size * 8)) - 1
    };
    (context.value & mask, context.load_ok)
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_memory_bit_test_addresses_the_bit_string_and_publishes_only_cf() {
    use crate::smir::lower::runtime::{ExecMem, GuestRegs};

    const CF: u64 = 1 << 0;
    const OTHER_STATUS: u64 = 0x8D4; // PF, AF, ZF, SF, OF, DF
    const SENTINEL_PC: u64 = 0xAAAA_BBBB_CCCC_DDDD;
    const VALUE: u64 = 0x8000_0000_0000_0001;

    let mut initial = [0u64; 32];
    initial[3] = 0x1_0000; // RBX base

    let run = |ops: Vec<OpKind>, offset: u64, load_ok: u64| {
        let (code, entry) = lower(ops);
        let exec = ExecMem::new(&code).expect("map fused memory BT");
        let mut context = MemoryContext {
            value: VALUE,
            load_ok,
            ..MemoryContext::default()
        };
        let mut regs = GuestRegs::default();
        regs.gpr = initial;
        regs.gpr[1] = offset; // RCX
        regs.rflags = 0x2 | OTHER_STATUS;
        regs.exit_pc = SENTINEL_PC;
        regs.ctx = (&mut context as *mut MemoryContext) as u64;
        regs.load_fn = load_helper as usize as u64;
        exec.run(entry, &mut regs);
        (context, regs)
    };

    // 64-bit form, including negative offsets whose sign extension moves the
    // accessed element *below* the base address.
    for offset in [0i64, 1, 63, 64, 127, 128, -1, -64, -65, -129] {
        let (context, regs) = run(
            bit_test(OpWidth::W64, MemWidth::B8, X86Reg::Rcx),
            offset as u64,
            1,
        );
        let expected_addr = (0x1_0000u64 + 512).wrapping_add(((offset >> 6) << 3) as u64);
        assert_eq!(context.loads, 1, "offset {offset}");
        assert_eq!(context.load_addr, expected_addr, "offset {offset} address");
        assert_eq!(context.load_size, 8);
        let bit = (VALUE >> ((offset as u64) & 63)) & 1;
        assert_eq!(regs.rflags & CF, bit, "offset {offset} CF");
        assert_eq!(
            regs.rflags & OTHER_STATUS,
            OTHER_STATUS,
            "offset {offset} must preserve the architecturally undefined flags"
        );
        let mut expected = initial;
        expected[1] = offset as u64;
        assert_eq!(regs.gpr, expected, "offset {offset} GPR file");
        assert_eq!(regs.exit_pc, SENTINEL_PC);
    }

    // 32-bit form scales by four bytes and masks the index modulo 32.
    for offset in [0i64, 31, 32, -1, -32, -33] {
        let (context, regs) = run(
            bit_test(OpWidth::W32, MemWidth::B4, X86Reg::Rcx),
            offset as u64,
            1,
        );
        let expected_addr = (0x1_0000u64 + 512).wrapping_add(((offset >> 5) << 2) as u64);
        assert_eq!(context.load_addr, expected_addr, "32-bit offset {offset}");
        assert_eq!(context.load_size, 4);
        let element = VALUE as u32;
        let bit = u64::from((element >> ((offset as u32) & 31)) & 1);
        assert_eq!(regs.rflags & CF, bit, "32-bit offset {offset} CF");
    }

    // A faulting element read commits nothing and resumes at the guest PC.
    let (context, regs) = run(bit_test(OpWidth::W64, MemWidth::B8, X86Reg::Rcx), 0, 0);
    assert_eq!(context.loads, 1);
    let mut expected = initial;
    expected[1] = 0;
    assert_eq!(regs.gpr, expected);
    assert_eq!(regs.exit_pc, PC);
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
extern "C" fn store_helper(context: *mut MemoryContext, addr: u64, value: u64, size: u64) -> u64 {
    let context = unsafe { &mut *context };
    context.stores += 1;
    context.store_addr = addr;
    let mask = if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (size * 8)) - 1
    };
    context.stored = value & mask;
    context.stored_size = size;
    context.store_ok
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_memory_bit_update_writes_the_masked_element_and_orders_cf_last() {
    use crate::smir::lower::runtime::{ExecMem, GuestRegs};

    const CF: u64 = 1 << 0;
    const OTHER_STATUS: u64 = 0x8D4;
    const SENTINEL_PC: u64 = 0xAAAA_BBBB_CCCC_DDDD;
    const VALUE: u64 = 0x8000_0000_0000_0001;

    let mut initial = [0u64; 32];
    initial[3] = 0x2_0000; // RBX base

    let run = |ops: Vec<OpKind>, offset: u64, store_ok: u64| {
        let (code, entry) = lower(ops);
        let exec = ExecMem::new(&code).expect("map fused memory bit update");
        let mut context = MemoryContext {
            value: VALUE,
            load_ok: 1,
            store_ok,
            ..MemoryContext::default()
        };
        let mut regs = GuestRegs::default();
        regs.gpr = initial;
        regs.gpr[1] = offset;
        regs.rflags = 0x2 | OTHER_STATUS;
        regs.exit_pc = SENTINEL_PC;
        regs.ctx = (&mut context as *mut MemoryContext) as u64;
        regs.load_fn = load_helper as usize as u64;
        regs.store_fn = store_helper as usize as u64;
        exec.run(entry, &mut regs);
        (context, regs)
    };

    for (update, name) in [(5u8, "bts"), (6, "btr"), (7, "btc")] {
        for (width, mem_width, bytes) in [
            (OpWidth::W64, MemWidth::B8, 8u64),
            (OpWidth::W32, MemWidth::B4, 4),
            (OpWidth::W16, MemWidth::B2, 2),
        ] {
            let element_mask = if bytes >= 8 {
                u64::MAX
            } else {
                (1u64 << (bytes * 8)) - 1
            };
            let bits = bytes * 8;
            for offset in [
                0i64,
                1,
                (bits as i64) - 1,
                bits as i64,
                -1,
                -(bits as i64) - 1,
            ] {
                let (context, regs) = run(
                    bit_update(width, mem_width, X86Reg::Rcx, update, true),
                    offset as u64,
                    1,
                );
                let element = VALUE & element_mask;
                let bit = (offset as u64) & (bits - 1);
                let mask = 1u64 << bit;
                let expected_element = match update {
                    5 => element | mask,
                    6 => element & !mask,
                    _ => element ^ mask,
                } & element_mask;
                let shift = match bytes {
                    8 => 3,
                    4 => 2,
                    _ => 1,
                };
                let element_shift = match bits {
                    64 => 6,
                    32 => 5,
                    _ => 4,
                };
                let expected_addr =
                    (0x2_0000u64 + 512).wrapping_add(((offset >> element_shift) << shift) as u64);

                assert_eq!(context.loads, 1, "{name} {width:?} offset {offset}");
                assert_eq!(context.load_addr, expected_addr, "{name} address");
                assert_eq!(context.stores, 1, "{name} must store");
                assert_eq!(context.store_addr, expected_addr, "{name} store address");
                assert_eq!(context.stored, expected_element, "{name} stored element");
                assert_eq!(context.stored_size, bytes);
                assert_eq!(
                    regs.rflags & CF,
                    (element >> bit) & 1,
                    "{name} {width:?} offset {offset} CF"
                );
                assert_eq!(
                    regs.rflags & OTHER_STATUS,
                    OTHER_STATUS,
                    "{name} must preserve the architecturally undefined flags"
                );
                let mut expected = initial;
                expected[1] = offset as u64;
                assert_eq!(regs.gpr, expected, "{name} GPR file");
                assert_eq!(regs.exit_pc, SENTINEL_PC);
            }
        }
    }

    // A faulting store publishes no CF and resumes at the guest PC.
    let (context, regs) = run(
        bit_update(OpWidth::W64, MemWidth::B8, X86Reg::Rcx, 5, true),
        0,
        0,
    );
    assert_eq!(context.stores, 1);
    let mut expected = initial;
    expected[1] = 0;
    assert_eq!(regs.gpr, expected);
    assert_eq!(regs.rflags & CF, 0, "a faulting store must not commit CF");
    assert_eq!(regs.exit_pc, PC);
}
