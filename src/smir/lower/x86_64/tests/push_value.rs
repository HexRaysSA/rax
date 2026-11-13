//! Fused native lowering for `PUSH m16/m64`.

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

fn source_addr() -> Address {
    Address::BaseOffset {
        base: x86(X86Reg::Rbx),
        offset: 24,
        disp_size: DispSize::Disp8,
    }
}

fn push_memory(source_width: MemWidth, delta: i64, push_width: MemWidth) -> Vec<OpKind> {
    vec![
        OpKind::Load {
            dst: virt(0),
            addr: source_addr(),
            width: source_width,
            sign: SignExtend::Zero,
        },
        OpKind::Sub {
            dst: x86(X86Reg::Rsp),
            src1: x86(X86Reg::Rsp),
            src2: SrcOperand::Imm(delta),
            width: OpWidth::W64,
            flags: FlagUpdate::None,
        },
        OpKind::Store {
            src: virt(0),
            addr: Address::Direct(x86(X86Reg::Rsp)),
            width: push_width,
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
        .expect("lower fused memory push");
    (lowerer.finalize().expect("finalize"), result.entry_offset)
}

#[test]
fn memory_push_stages_the_source_then_reuses_the_helper_backed_push() {
    let (bytes, _) = lower(push_memory(MemWidth::B8, 8, MemWidth::B8));
    assert!(
        bytes
            .windows(5)
            .any(|b| b == [0x48, 0x8D, 0x64, 0x24, 0xE0]),
        "must reserve the flag-neutral staging frame: {bytes:02X?}"
    );
    assert!(
        bytes
            .windows(5)
            .any(|b| b == [0x48, 0x8D, 0x64, 0x24, 0x20]),
        "must release the staging frame before the RSP commit: {bytes:02X?}"
    );
    // Both helper calls go through the GuestRegs function pointers.
    assert!(
        bytes
            .windows(host_c_call_opcode().len())
            .filter(|b| *b == host_c_call_opcode())
            .count()
            >= 2,
        "must call both the load and store helpers: {bytes:02X?}"
    );
    // The architectural stack pointer is committed with the state-backed
    // subtract, which reads and writes GuestRegs.gpr[4] (+20h).
    assert!(
        bytes.windows(4).any(|b| b == [0x48, 0x8B, 0x50, 0x20]),
        "must read the guest RSP slot: {bytes:02X?}"
    );
    assert!(
        bytes.windows(4).any(|b| b == [0x48, 0x89, 0x50, 0x20]),
        "must commit the guest RSP slot: {bytes:02X?}"
    );
}

#[test]
fn narrower_sources_and_word_pushes_use_the_same_fusion() {
    for (source, delta, push) in [
        (MemWidth::B4, 8, MemWidth::B8),
        (MemWidth::B2, 2, MemWidth::B2),
        (MemWidth::B1, 8, MemWidth::B8),
    ] {
        let (bytes, _) = lower(push_memory(source, delta, push));
        assert!(
            bytes
                .windows(5)
                .any(|b| b == [0x48, 0x8D, 0x64, 0x24, 0xE0]),
            "{source:?} -> {push:?} must stage on the caller frame: {bytes:02X?}"
        );
    }
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[derive(Default)]
struct MemoryContext {
    loads: u64,
    stores: u64,
    load_addr: u64,
    load_size: u64,
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
    // Mirror `rax_jit_mem_load`: an unsigned read yields exactly `size` bytes,
    // zero-extended to 64 bits.
    let mask = if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (size * 8)) - 1
    };
    (context.value & mask, context.load_ok)
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
extern "C" fn store_helper(context: *mut MemoryContext, addr: u64, value: u64, size: u64) -> u64 {
    let context = unsafe { &mut *context };
    context.stores += 1;
    context.store_addr = addr;
    context.stored = value;
    context.stored_size = size;
    context.store_ok
}

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
#[test]
fn native_memory_push_writes_the_source_and_commits_rsp_only_on_success() {
    use crate::smir::lower::runtime::{ExecMem, GuestRegs};

    const FLAGS: u64 = 0xCD7;
    const STATUS_MASK: u64 = 0x8D5;
    const SENTINEL_PC: u64 = 0xAAAA_BBBB_CCCC_DDDD;
    const VALUE: u64 = 0x0123_4567_89AB_CDEF;

    let mut initial = [0u64; 32];
    initial[3] = 0x5000; // RBX source base
    initial[4] = 0x9000; // guest RSP

    let run = |ops: Vec<OpKind>, load_ok: u64, store_ok: u64| {
        let (code, entry) = lower(ops);
        let exec = ExecMem::new(&code).expect("map fused memory push");
        let mut context = MemoryContext {
            value: VALUE,
            load_ok,
            store_ok,
            ..MemoryContext::default()
        };
        let mut regs = GuestRegs::default();
        regs.gpr = initial;
        regs.rflags = FLAGS;
        regs.exit_pc = SENTINEL_PC;
        regs.ctx = (&mut context as *mut MemoryContext) as u64;
        regs.load_fn = load_helper as usize as u64;
        regs.store_fn = store_helper as usize as u64;
        exec.run(entry, &mut regs);
        (context, regs)
    };

    // `push qword [rbx+24]`
    let (context, regs) = run(push_memory(MemWidth::B8, 8, MemWidth::B8), 1, 1);
    assert_eq!(context.loads, 1);
    assert_eq!(context.load_addr, 0x5018);
    assert_eq!(context.stores, 1);
    assert_eq!(context.store_addr, 0x9000 - 8, "writes below the entry RSP");
    assert_eq!(context.stored, VALUE);
    assert_eq!(context.stored_size, 8);
    let mut expected = initial;
    expected[4] = 0x9000 - 8;
    assert_eq!(regs.gpr, expected, "only guest RSP changes");
    assert_eq!(regs.rflags & STATUS_MASK, FLAGS & STATUS_MASK);
    assert_eq!(regs.exit_pc, SENTINEL_PC);

    // A narrower source is zero-extended into the stack slot.
    let (context, regs) = run(push_memory(MemWidth::B4, 8, MemWidth::B8), 1, 1);
    assert_eq!(context.load_size, 4, "the source read keeps its own width");
    assert_eq!(context.stored, u64::from(VALUE as u32));
    assert_eq!(
        context.stored_size, 8,
        "the stack slot keeps the push width"
    );
    assert_eq!(regs.gpr[4], 0x9000 - 8);

    // A 16-bit push writes exactly two bytes at the new stack top.
    let (context, regs) = run(push_memory(MemWidth::B2, 2, MemWidth::B2), 1, 1);
    assert_eq!(context.stored, u64::from(VALUE as u16));
    assert_eq!(context.stored_size, 2);
    assert_eq!(context.store_addr, 0x9000 - 2);
    assert_eq!(regs.gpr[4], 0x9000 - 2);

    // A faulting source read commits nothing and resumes at the guest PC.
    let (context, regs) = run(push_memory(MemWidth::B8, 8, MemWidth::B8), 0, 1);
    assert_eq!(context.stores, 0, "no stack write after a faulting read");
    assert_eq!(regs.gpr, initial, "guest RSP must not move");
    assert_eq!(regs.exit_pc, PC);

    // A faulting stack write leaves RSP unchanged, as the architecture
    // requires for a faulting PUSH.
    let (context, regs) = run(push_memory(MemWidth::B8, 8, MemWidth::B8), 1, 0);
    assert_eq!(context.stores, 1);
    assert_eq!(regs.gpr, initial, "guest RSP must not move");
    assert_eq!(regs.exit_pc, PC);
}
