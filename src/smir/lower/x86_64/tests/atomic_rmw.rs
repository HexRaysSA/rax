//! Fused native lowering for LOCK-prefixed x86 memory read-modify-write.

use super::*;
use crate::smir::ir::types::{AtomicOp, MemoryOrder};
use crate::smir::lower::SmirLowerer;

fn x86(reg: X86Reg) -> VReg {
    VReg::Arch(ArchReg::X86(reg))
}

fn virt(id: u32) -> VReg {
    VReg::Virtual(crate::smir::ir::types::VirtualId(id))
}

const PC: u64 = 0x1000;

fn addr() -> Address {
    Address::BaseOffset {
        base: x86(X86Reg::Rdi),
        offset: 8,
        disp_size: DispSize::Disp8,
    }
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
        .expect("lower fused locked RMW");
    (lowerer.finalize().expect("finalize"), result.entry_offset)
}

fn count(bytes: &[u8], needle: &[u8]) -> usize {
    bytes.windows(needle.len()).filter(|w| *w == needle).count()
}

fn assert_one_atomic_call(bytes: &[u8]) {
    let mut slot = vec![0x4C, 0x8B, 0x98]; // mov r11,[rax+atomic_rmw_fn]
    slot.extend_from_slice(&crate::smir::lower::X86_GUEST_ATOMIC_RMW_FN_OFFSET.to_le_bytes());
    assert_eq!(count(bytes, &slot), 1, "one atomic callback selection");
    assert_eq!(count(bytes, &[0x41, 0xFF, 0xD3]), 1, "one call r11");
    for offset in [
        crate::smir::lower::X86_GUEST_LOAD_FN_OFFSET,
        crate::smir::lower::X86_GUEST_STORE_FN_OFFSET,
    ] {
        let mut ordinary_call = vec![0xFF, 0x90];
        ordinary_call.extend_from_slice(&offset.to_le_bytes());
        assert_eq!(
            count(bytes, &ordinary_call),
            0,
            "no ordinary helper substitution"
        );
    }
}

#[test]
fn locked_or_fuses_into_the_helper_backed_frame() {
    // `lock or byte [rdi+8],1` with dead flags: one transaction, no replay.
    let (flag_dead, _) = lower(vec![
        OpKind::Mov {
            dst: virt(0),
            src: SrcOperand::Imm(1),
            width: OpWidth::W8,
        },
        OpKind::AtomicRmw {
            dst: virt(1),
            addr: addr(),
            src: virt(0),
            op: AtomicOp::Or,
            width: MemWidth::B1,
            order: MemoryOrder::SeqCst,
        },
    ]);
    assert!(
        flag_dead
            .windows(5)
            .any(|b| b == [0x48, 0x8D, 0x64, 0x24, 0xE0]),
        "must reserve the 32-byte caller frame: {flag_dead:02X?}"
    );
    assert_one_atomic_call(&flag_dead);
    // All memory computation is inside the transaction callback.
    assert_eq!(
        count(&flag_dead, &[0x80, 0xC8, 0x01]),
        0,
        "flag-dead form must not compute or replay natively: {flag_dead:02X?}"
    );

    // With flags live, replay once against the retained source stack slot.
    let (flag_live, _) = lower(vec![
        OpKind::Mov {
            dst: virt(0),
            src: SrcOperand::Imm(1),
            width: OpWidth::W8,
        },
        OpKind::AtomicRmw {
            dst: virt(1),
            addr: addr(),
            src: virt(0),
            op: AtomicOp::Or,
            width: MemWidth::B1,
            order: MemoryOrder::SeqCst,
        },
        OpKind::Or {
            dst: virt(2),
            src1: virt(1),
            src2: SrcOperand::Reg(virt(0)),
            width: OpWidth::W8,
            flags: FlagUpdate::All,
        },
    ]);
    assert_one_atomic_call(&flag_live);
    assert_eq!(
        count(&flag_live, &[0x0A, 0x44, 0x24, 0x10]),
        1,
        "or al,[rsp+16] publishes flags only after transaction success"
    );
}

#[test]
fn locked_xadd_writes_the_pre_operation_value_back_after_the_transaction() {
    let (bytes, _) = lower(vec![
        OpKind::Mov {
            dst: virt(0),
            src: SrcOperand::Imm(1),
            width: OpWidth::W32,
        },
        OpKind::AtomicRmw {
            dst: virt(1),
            addr: addr(),
            src: virt(0),
            op: AtomicOp::Add,
            width: MemWidth::B4,
            order: MemoryOrder::SeqCst,
        },
        OpKind::Mov {
            dst: x86(X86Reg::Rcx),
            src: SrcOperand::Reg(virt(1)),
            width: OpWidth::W32,
        },
    ]);
    assert_one_atomic_call(&bytes);
    // `mov ecx, [rsp]` delivers the pre-operation memory value, zero-extended.
    assert!(
        bytes.windows(4).any(|b| b == [0x8B, 0x0C, 0x24, 0x48]),
        "must write the loaded value back into ECX before releasing the frame: {bytes:02X?}"
    );
    // The write-back is flag neutral: no PUSHFQ/POPFQ pair is added for it.
    assert_eq!(
        count(&bytes, &[0x83, 0xC0, 0x01]),
        0,
        "a flag-dead XADD must not replay: {bytes:02X?}"
    );
}

#[test]
fn locked_dec_replays_the_unary_flag_contract() {
    let (bytes, _) = lower(vec![
        OpKind::Mov {
            dst: virt(0),
            src: SrcOperand::Imm(1),
            width: OpWidth::W32,
        },
        OpKind::AtomicRmw {
            dst: virt(1),
            addr: addr(),
            src: virt(0),
            op: AtomicOp::Sub,
            width: MemWidth::B4,
            order: MemoryOrder::SeqCst,
        },
        OpKind::Dec {
            dst: virt(2),
            src: virt(1),
            width: OpWidth::W32,
            flags: FlagUpdate::All,
        },
    ]);
    assert_one_atomic_call(&bytes);
    // Published flags come from `dec eax` (FF /1), which leaves
    // CF unchanged exactly as the architecture requires.
    assert!(
        bytes.windows(2).any(|b| b == [0xFF, 0xC8]),
        "must replay the unary DEC flag contract: {bytes:02X?}"
    );
    assert_eq!(
        count(&bytes, &[0x83, 0xE8, 0x01]),
        0,
        "the Group-1 form must not also replay: {bytes:02X?}"
    );
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[derive(Default)]
struct MemoryContext {
    transactions: u64,
    loads: u64,
    stores: u64,
    last_addr: u64,
    value: u64,
    load_ok: u64,
    store_ok: u64,
    stored: u64,
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
extern "C" fn atomic_transaction(
    context: *mut MemoryContext,
    addr: u64,
    operand: u64,
    size: u32,
    operation: u32,
) -> crate::smir::lower::runtime::X86AtomicRmwRet {
    // SAFETY: the test keeps this exclusive, initialized context live and
    // unmoved throughout synchronous native execution.
    let context = unsafe { &mut *context };
    context.transactions += 1;
    context.last_addr = addr;
    if context.load_ok == 0 || context.store_ok == 0 {
        return crate::smir::lower::runtime::X86AtomicRmwRet::default();
    }
    let mask = ((1u128 << (size * 8)) - 1) as u64;
    let old_value = context.value & mask;
    let result = match operation {
        0 => old_value.wrapping_add(operand),
        1 => old_value | operand,
        2 => old_value & operand,
        3 => old_value.wrapping_sub(operand),
        4 => old_value ^ operand,
        5 => operand,
        _ => return crate::smir::lower::runtime::X86AtomicRmwRet::default(),
    };
    context.stored = result & mask;
    context.value = (context.value & !mask) | context.stored;
    crate::smir::lower::runtime::X86AtomicRmwRet { old_value, ok: 1 }
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
extern "C" fn load(context: *mut MemoryContext, addr: u64, size: u64) -> (u64, u64) {
    let context = unsafe { &mut *context };
    context.loads += 1;
    context.last_addr = addr;
    // Mirror `rax_jit_mem_load`, which yields exactly `size` zero-extended bytes.
    let mask = if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (size * 8)) - 1
    };
    (context.value & mask, context.load_ok)
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
extern "C" fn store(context: *mut MemoryContext, addr: u64, value: u64, size: u64) -> u64 {
    let context = unsafe { &mut *context };
    context.stores += 1;
    context.last_addr = addr;
    // Mirror `rax_jit_mem_store`, which commits exactly `size` bytes.
    let mask = if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (size * 8)) - 1
    };
    context.stored = value & mask;
    context.store_ok
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_locked_rmw_updates_memory_publishes_flags_and_writes_back() {
    use crate::smir::lower::runtime::{ExecMem, GuestRegs};

    const FLAGS: u64 = 0x2;
    const ZF: u64 = 1 << 6;
    const SENTINEL_PC: u64 = 0xAAAA_BBBB_CCCC_DDDD;

    let mut initial = [0u64; 32];
    initial[7] = 0x3000; // RDI base

    // `lock add dword [rdi+8], 1` with a live flag result and an XADD-style
    // write-back into ECX.
    let (code, entry) = lower(vec![
        OpKind::Mov {
            dst: virt(0),
            src: SrcOperand::Imm(1),
            width: OpWidth::W32,
        },
        OpKind::AtomicRmw {
            dst: virt(1),
            addr: addr(),
            src: virt(0),
            op: AtomicOp::Add,
            width: MemWidth::B4,
            order: MemoryOrder::SeqCst,
        },
        OpKind::Add {
            dst: virt(2),
            src1: virt(1),
            src2: SrcOperand::Reg(virt(0)),
            width: OpWidth::W32,
            flags: FlagUpdate::All,
        },
        OpKind::Mov {
            dst: x86(X86Reg::Rcx),
            src: SrcOperand::Reg(virt(1)),
            width: OpWidth::W32,
        },
    ]);
    let exec = ExecMem::new(&code).expect("map fused locked RMW");

    for (value, expect_zf) in [(0x1000_0000u64, false), (0xFFFF_FFFFu64, true)] {
        let mut context = MemoryContext {
            value,
            load_ok: 1,
            store_ok: 1,
            ..MemoryContext::default()
        };
        let mut regs = GuestRegs::default();
        regs.gpr = initial;
        regs.rflags = FLAGS;
        regs.exit_pc = SENTINEL_PC;
        regs.ctx = (&mut context as *mut MemoryContext) as u64;
        regs.load_fn = load as usize as u64;
        regs.store_fn = store as usize as u64;
        regs.atomic_rmw_fn = atomic_transaction as usize as u64;
        exec.run(entry, &mut regs);

        assert_eq!(context.transactions, 1);
        assert_eq!(context.loads, 0);
        assert_eq!(context.stores, 0);
        assert_eq!(context.last_addr, 0x3008);
        assert_eq!(context.stored, u64::from((value as u32).wrapping_add(1)));
        assert_eq!(regs.gpr[1], value, "pre-operation value written back");
        assert_eq!(regs.rflags & ZF != 0, expect_zf, "architectural ZF");
        assert_eq!(regs.exit_pc, SENTINEL_PC);
    }

    // A faulting store must leave every architectural register untouched and
    // resume at the locked instruction.
    let mut context = MemoryContext {
        value: 7,
        load_ok: 1,
        store_ok: 0,
        ..MemoryContext::default()
    };
    let mut regs = GuestRegs::default();
    regs.gpr = initial;
    regs.rflags = FLAGS;
    regs.exit_pc = SENTINEL_PC;
    regs.ctx = (&mut context as *mut MemoryContext) as u64;
    regs.load_fn = load as usize as u64;
    regs.store_fn = store as usize as u64;
    regs.atomic_rmw_fn = atomic_transaction as usize as u64;
    exec.run(entry, &mut regs);
    assert_eq!(regs.gpr, initial, "faulting store must not commit");
    assert_eq!(
        (context.transactions, context.loads, context.stores),
        (1, 0, 0)
    );
    assert_eq!(context.value, 7, "failed transaction must not write");
    assert_eq!(
        regs.rflags, FLAGS,
        "failed transaction must not publish flags"
    );
    assert_eq!(regs.exit_pc, PC);
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_exchange_replaces_the_element_and_leaves_flags_untouched() {
    use crate::smir::ir::types::{AtomicOp, MemoryOrder};
    use crate::smir::lower::runtime::{ExecMem, GuestRegs};

    const FLAGS: u64 = 0x8D5;
    const SENTINEL_PC: u64 = 0xAAAA_BBBB_CCCC_DDDD;
    const MEMORY: u64 = 0x0F1E_2D3C_4B5A_6978;

    let mut initial = [0u64; 32];
    initial[1] = 0x1111_2222_3333_4444; // RCX replacement
    initial[7] = 0x8000; // RDI address base

    let exchange = |width: MemWidth, op_width: OpWidth| {
        vec![
            OpKind::AtomicRmw {
                dst: virt(0),
                addr: addr(),
                src: x86(X86Reg::Rcx),
                op: AtomicOp::Swap,
                width,
                order: MemoryOrder::SeqCst,
            },
            OpKind::Mov {
                dst: x86(X86Reg::Rdx),
                src: SrcOperand::Reg(virt(0)),
                width: op_width,
            },
        ]
    };

    for (mem_width, op_width, bytes) in [
        (MemWidth::B8, OpWidth::W64, 8u64),
        (MemWidth::B4, OpWidth::W32, 4),
        (MemWidth::B2, OpWidth::W16, 2),
    ] {
        let mask = if bytes >= 8 {
            u64::MAX
        } else {
            (1u64 << (bytes * 8)) - 1
        };
        let (code, entry) = lower(exchange(mem_width, op_width));
        let exec = ExecMem::new(&code).expect("map fused exchange");
        let mut context = MemoryContext {
            value: MEMORY,
            load_ok: 1,
            store_ok: 1,
            ..MemoryContext::default()
        };
        let mut regs = GuestRegs::default();
        regs.gpr = initial;
        regs.rflags = 0x2 | FLAGS;
        regs.exit_pc = SENTINEL_PC;
        regs.ctx = (&mut context as *mut MemoryContext) as u64;
        regs.load_fn = load as usize as u64;
        regs.store_fn = store as usize as u64;
        regs.atomic_rmw_fn = atomic_transaction as usize as u64;
        exec.run(entry, &mut regs);

        assert_eq!(context.transactions, 1, "{mem_width:?}");
        assert_eq!(context.loads, 0, "{mem_width:?}");
        assert_eq!(context.stores, 0, "{mem_width:?}");
        assert_eq!(context.last_addr, 0x8008);
        assert_eq!(
            context.stored,
            initial[1] & mask,
            "{mem_width:?} replacement element"
        );
        let mut expected = initial;
        expected[2] = match op_width {
            OpWidth::W16 => (initial[2] & !mask) | (MEMORY & mask),
            _ => MEMORY & mask,
        };
        assert_eq!(regs.gpr, expected, "{mem_width:?} write-back");
        assert_eq!(
            regs.rflags & FLAGS,
            FLAGS,
            "{mem_width:?} XCHG must not change flags"
        );
        assert_eq!(regs.exit_pc, SENTINEL_PC);
    }

    // A faulting store commits nothing.
    let (code, entry) = lower(exchange(MemWidth::B8, OpWidth::W64));
    let exec = ExecMem::new(&code).expect("map fused exchange");
    let mut context = MemoryContext {
        value: MEMORY,
        load_ok: 1,
        store_ok: 0,
        ..MemoryContext::default()
    };
    let mut regs = GuestRegs::default();
    regs.gpr = initial;
    regs.rflags = 0x2 | FLAGS;
    regs.exit_pc = SENTINEL_PC;
    regs.ctx = (&mut context as *mut MemoryContext) as u64;
    regs.load_fn = load as usize as u64;
    regs.store_fn = store as usize as u64;
    regs.atomic_rmw_fn = atomic_transaction as usize as u64;
    exec.run(entry, &mut regs);
    assert_eq!(regs.gpr, initial, "faulting exchange must not write back");
    assert_eq!(
        (context.transactions, context.loads, context.stores),
        (1, 0, 0)
    );
    assert_eq!(context.value, MEMORY, "failed transaction must not write");
    assert_eq!(
        regs.rflags,
        0x2 | FLAGS,
        "failed transaction preserves every flag"
    );
    assert_eq!(regs.exit_pc, PC);
}
