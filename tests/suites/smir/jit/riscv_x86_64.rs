//! End-to-end RISC-V machine code -> SMIR -> x86-64 native execution tests.
#![cfg(all(feature = "smir-jit", target_arch = "x86_64"))]

use std::collections::HashMap;

use rax::isa::riscv::{
    FlatMemory as RvMemory, Isa as RvIsa, Op as RvOp, RiscVConfig, RiscVCpu, RiscVExit,
    Xlen as RvXlen,
};
use rax::smir::ir::types::{
    ArchReg, BlockId, FunctionId, OpId, OpWidth, RiscVReg, SourceArch, SrcOperand, VReg, VirtualId,
};
use rax::smir::ir::{CallingConv, SmirBlock, SmirFunction, Terminator};
use rax::smir::lift::riscv::RiscVExtensions;
use rax::smir::lift::{ControlFlow, LiftContext, SmirLifter};
use rax::smir::lower::SmirLowerer;
use rax::smir::lower::cross::riscv_guest_to_x86_64_host::RiscVX86_64Lowerer;
use rax::smir::lower::runtime::{
    ExecMem, RISCV_FP_RESULT_INVALID, RiscVAtomicCasResult, RiscVAtomicCasStatus,
    RiscVAtomicOpCode, RiscVAtomicResult, RiscVFpOpCode, RiscVFpResult, RiscVGuestRegs,
    RiscVIntCryptoOpCode, RiscVLoadResult, RiscVMemoryOrderCode,
};
use rax::smir::optimize::{OptLevel, optimize_function};
use rax::smir::{OpKind, RiscVLifter, SmirOp};

const CODE: u64 = 0x1000;
const DATA: u64 = 0x2000;
const MEMORY_LEN: usize = 0x4000;

#[path = "riscv_x86_64/vector_validation.rs"]
mod vector_validation;

#[repr(C)]
struct TestMemory {
    bytes: [u8; MEMORY_LEN],
    reservation_addr: u64,
    reservation_size: u64,
    reservation_valid: u64,
    last_atomic_order: u64,
    last_atomic_failure_order: u64,
}

impl TestMemory {
    fn new(bytes: [u8; MEMORY_LEN]) -> Self {
        Self {
            bytes,
            reservation_addr: 0,
            reservation_size: 0,
            reservation_valid: 0,
            last_atomic_order: u64::MAX,
            last_atomic_failure_order: u64::MAX,
        }
    }

    fn read_value(&self, addr: u64, size: u64) -> u64 {
        let addr = addr as usize;
        let size = size as usize;
        assert!(addr.checked_add(size).is_some_and(|end| end <= MEMORY_LEN));
        let mut value = 0u64;
        for index in 0..size {
            value |= u64::from(self.bytes[addr + index]) << (index * 8);
        }
        value
    }

    fn can_access(&self, addr: u64, size: u64) -> bool {
        usize::try_from(addr)
            .ok()
            .and_then(|start| {
                usize::try_from(size)
                    .ok()
                    .and_then(|len| start.checked_add(len))
            })
            .is_some_and(|end| end <= MEMORY_LEN)
    }

    fn write_value(&mut self, addr: u64, value: u64, size: u64) {
        let host_addr = addr as usize;
        let host_size = size as usize;
        assert!(
            host_addr
                .checked_add(host_size)
                .is_some_and(|host_end| host_end <= MEMORY_LEN)
        );
        for index in 0..host_size {
            self.bytes[host_addr + index] = (value >> (index * 8)) as u8;
        }
    }
}

unsafe extern "sysv64" fn load(ctx: u64, addr: u64, size: u64, signed: u64) -> RiscVLoadResult {
    let memory = unsafe { &*(ctx as *const TestMemory) };
    if !memory.can_access(addr, size) {
        return RiscVLoadResult {
            value: 0,
            success: 0,
        };
    }
    let mut value = memory.read_value(addr, size);
    if signed != 0 && size < 8 {
        let bits = size as usize * 8;
        let sign_bit = 1u64 << (bits - 1);
        if value & sign_bit != 0 {
            value |= u64::MAX << bits;
        }
    }
    RiscVLoadResult { value, success: 1 }
}

unsafe extern "sysv64" fn store(ctx: u64, addr: u64, value: u64, size: u64) -> u64 {
    let memory = unsafe { &mut *(ctx as *mut TestMemory) };
    if !memory.can_access(addr, size) {
        return 0;
    }
    memory.write_value(addr, value, size);
    1
}

unsafe extern "sysv64" fn atomic_rmw(
    ctx: u64,
    addr: u64,
    operand: u64,
    size: u64,
    op: u64,
    order: u64,
) -> RiscVAtomicResult {
    let memory = unsafe { &mut *(ctx as *mut TestMemory) };
    assert!(order <= RiscVMemoryOrderCode::SeqCst as u64);
    memory.last_atomic_order = order;
    if !memory.can_access(addr, size) {
        return RiscVAtomicResult {
            value: 0,
            access_success: 0,
        };
    }
    let bits = size * 8;
    let mask = if bits == 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let old = memory.read_value(addr, size) & mask;
    let operand = operand & mask;
    let signed = |value: u64| -> i64 {
        if bits == 64 {
            value as i64
        } else {
            ((value << (64 - bits)) as i64) >> (64 - bits)
        }
    };
    let new = match op {
        value if value == RiscVAtomicOpCode::Add as u64 => old.wrapping_add(operand),
        value if value == RiscVAtomicOpCode::Sub as u64 => old.wrapping_sub(operand),
        value if value == RiscVAtomicOpCode::Neg as u64 => 0u64.wrapping_sub(old),
        value if value == RiscVAtomicOpCode::And as u64 => old & operand,
        value if value == RiscVAtomicOpCode::Or as u64 => old | operand,
        value if value == RiscVAtomicOpCode::Xor as u64 => old ^ operand,
        value if value == RiscVAtomicOpCode::Nand as u64 => !(old & operand),
        value if value == RiscVAtomicOpCode::Max as u64 => {
            std::cmp::max(signed(old), signed(operand)) as u64
        }
        value if value == RiscVAtomicOpCode::Min as u64 => {
            std::cmp::min(signed(old), signed(operand)) as u64
        }
        value if value == RiscVAtomicOpCode::Umax as u64 => std::cmp::max(old, operand),
        value if value == RiscVAtomicOpCode::Umin as u64 => std::cmp::min(old, operand),
        value if value == RiscVAtomicOpCode::Swap as u64 => operand,
        _ => panic!("invalid atomic RMW operation code {op}"),
    } & mask;
    memory.write_value(addr, new, size);
    RiscVAtomicResult {
        value: old,
        access_success: 1,
    }
}

unsafe extern "sysv64" fn compare_and_swap(
    ctx: u64,
    addr: u64,
    expected: u64,
    new_value: u64,
    size: u64,
    order: u64,
) -> RiscVAtomicCasResult {
    let memory = unsafe { &mut *(ctx as *mut TestMemory) };
    assert!(order <= RiscVMemoryOrderCode::SeqCst as u64);
    memory.last_atomic_order = order;
    if !memory.can_access(addr, size) {
        return RiscVAtomicCasResult {
            old: 0,
            status: RiscVAtomicCasStatus::Fault as u64,
        };
    }
    let bits = size * 8;
    let mask = if bits == 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let old = memory.read_value(addr, size) & mask;
    let success = old == expected & mask;
    if success {
        memory.write_value(addr, new_value & mask, size);
    }
    RiscVAtomicCasResult {
        old,
        status: if success {
            RiscVAtomicCasStatus::Swapped
        } else {
            RiscVAtomicCasStatus::CompareFailed
        } as u64,
    }
}

#[allow(clippy::too_many_arguments)]
unsafe extern "sysv64" fn compare_and_swap_pair(
    ctx: u64,
    addr: u64,
    expected_lo: u64,
    expected_hi: u64,
    new_lo: u64,
    new_hi: u64,
    order: u64,
    failure_order: u64,
    out_old_hi: *mut u64,
) -> RiscVAtomicCasResult {
    let memory = unsafe { &mut *(ctx as *mut TestMemory) };
    assert!(order <= RiscVMemoryOrderCode::SeqCst as u64);
    assert!(failure_order <= RiscVMemoryOrderCode::SeqCst as u64);
    assert_eq!(
        failure_order,
        if matches!(order, 1 | 3 | 4) { 1 } else { 0 }
    );
    memory.last_atomic_order = order;
    memory.last_atomic_failure_order = failure_order;
    if out_old_hi.is_null() || addr % 16 != 0 || !memory.can_access(addr, 16) {
        return RiscVAtomicCasResult {
            old: 0,
            status: RiscVAtomicCasStatus::Fault as u64,
        };
    }
    let old = [memory.read_value(addr, 8), memory.read_value(addr + 8, 8)];
    let success = old == [expected_lo, expected_hi];
    if success {
        memory.write_value(addr, new_lo, 8);
        memory.write_value(addr + 8, new_hi, 8);
    }
    unsafe { out_old_hi.write(old[1]) };
    RiscVAtomicCasResult {
        old: old[0],
        status: if success {
            RiscVAtomicCasStatus::Swapped
        } else {
            RiscVAtomicCasStatus::CompareFailed
        } as u64,
    }
}

unsafe extern "sysv64" fn noncanonical_atomic_rmw_status(
    _ctx: u64,
    _addr: u64,
    _operand: u64,
    _size: u64,
    _op: u64,
    _order: u64,
) -> RiscVAtomicResult {
    RiscVAtomicResult {
        value: 0xfeed_face_feed_face,
        access_success: 2,
    }
}

unsafe extern "sysv64" fn noncanonical_cas_status(
    _ctx: u64,
    _addr: u64,
    _expected: u64,
    _new_value: u64,
    _size: u64,
    _order: u64,
) -> RiscVAtomicCasResult {
    RiscVAtomicCasResult {
        old: 0xfeed_face_feed_face,
        status: 3,
    }
}

#[allow(clippy::too_many_arguments)]
unsafe extern "sysv64" fn noncanonical_cas_pair_status(
    _ctx: u64,
    _addr: u64,
    _expected_lo: u64,
    _expected_hi: u64,
    _new_lo: u64,
    _new_hi: u64,
    _order: u64,
    _failure_order: u64,
    out_old_hi: *mut u64,
) -> RiscVAtomicCasResult {
    if !out_old_hi.is_null() {
        unsafe { out_old_hi.write(0xdead_beef_dead_beef) };
    }
    RiscVAtomicCasResult {
        old: 0xfeed_face_feed_face,
        status: 3,
    }
}

unsafe extern "sysv64" fn load_exclusive(ctx: u64, addr: u64, size: u64) -> RiscVAtomicResult {
    let memory = unsafe { &mut *(ctx as *mut TestMemory) };
    if !memory.can_access(addr, size) {
        return RiscVAtomicResult {
            value: 0,
            access_success: 0,
        };
    }
    let value = memory.read_value(addr, size);
    memory.reservation_addr = addr;
    memory.reservation_size = size;
    memory.reservation_valid = 1;
    RiscVAtomicResult {
        value,
        access_success: 1,
    }
}

unsafe extern "sysv64" fn store_exclusive(
    ctx: u64,
    addr: u64,
    value: u64,
    size: u64,
) -> RiscVAtomicResult {
    let memory = unsafe { &mut *(ctx as *mut TestMemory) };
    if !memory.can_access(addr, size) {
        return RiscVAtomicResult {
            value: 0,
            access_success: 0,
        };
    }
    let success = memory.reservation_valid != 0
        && memory.reservation_addr == addr
        && memory.reservation_size == size;
    if success {
        memory.write_value(addr, value, size);
    }
    memory.reservation_valid = 0;
    RiscVAtomicResult {
        value: u64::from(success),
        access_success: 1,
    }
}

unsafe extern "sysv64" fn clear_exclusive(ctx: u64) {
    let memory = unsafe { &mut *(ctx as *mut TestMemory) };
    memory.reservation_valid = 0;
}

unsafe extern "sysv64" fn int_crypto(
    op_code: u64,
    src1: u64,
    src2: u64,
    imm: u64,
    xlen: u64,
) -> u64 {
    let op = match op_code {
        value if value == RiscVIntCryptoOpCode::Clmul as u64 => RvOp::Clmul,
        value if value == RiscVIntCryptoOpCode::Clmulh as u64 => RvOp::Clmulh,
        value if value == RiscVIntCryptoOpCode::Clmulr as u64 => RvOp::Clmulr,
        value if value == RiscVIntCryptoOpCode::Xperm4 as u64 => RvOp::Xperm4,
        value if value == RiscVIntCryptoOpCode::Xperm8 as u64 => RvOp::Xperm8,
        value if value == RiscVIntCryptoOpCode::Sha512Sig0l as u64 => RvOp::Sha512Sig0l,
        value if value == RiscVIntCryptoOpCode::Sha512Sig0h as u64 => RvOp::Sha512Sig0h,
        value if value == RiscVIntCryptoOpCode::Sha512Sig1l as u64 => RvOp::Sha512Sig1l,
        value if value == RiscVIntCryptoOpCode::Sha512Sig1h as u64 => RvOp::Sha512Sig1h,
        value if value == RiscVIntCryptoOpCode::Sha512Sum0r as u64 => RvOp::Sha512Sum0r,
        value if value == RiscVIntCryptoOpCode::Sha512Sum1r as u64 => RvOp::Sha512Sum1r,
        value if value == RiscVIntCryptoOpCode::Sm4ed as u64 => RvOp::Sm4ed,
        value if value == RiscVIntCryptoOpCode::Sm4ks as u64 => RvOp::Sm4ks,
        value if value == RiscVIntCryptoOpCode::Aes32esi as u64 => RvOp::Aes32esi,
        value if value == RiscVIntCryptoOpCode::Aes32esmi as u64 => RvOp::Aes32esmi,
        value if value == RiscVIntCryptoOpCode::Aes32dsi as u64 => RvOp::Aes32dsi,
        value if value == RiscVIntCryptoOpCode::Aes32dsmi as u64 => RvOp::Aes32dsmi,
        value if value == RiscVIntCryptoOpCode::Aes64es as u64 => RvOp::Aes64es,
        value if value == RiscVIntCryptoOpCode::Aes64esm as u64 => RvOp::Aes64esm,
        value if value == RiscVIntCryptoOpCode::Aes64ds as u64 => RvOp::Aes64ds,
        value if value == RiscVIntCryptoOpCode::Aes64dsm as u64 => RvOp::Aes64dsm,
        value if value == RiscVIntCryptoOpCode::Aes64im as u64 => RvOp::Aes64im,
        value if value == RiscVIntCryptoOpCode::Aes64ks1i as u64 => RvOp::Aes64ks1i,
        value if value == RiscVIntCryptoOpCode::Aes64ks2 as u64 => RvOp::Aes64ks2,
        _ => panic!("invalid integer-crypto operation code {op_code}"),
    };
    assert!(matches!(xlen, 32 | 64));
    rax::isa::riscv::crypto::eval_int_crypto(op, src1, src2, imm as u8, xlen as u32)
        .expect("helper operation must be in eval_int_crypto")
}

unsafe extern "sysv64" fn scalar_fp(
    op_code: u64,
    rm_field: u64,
    fcsr: u64,
    a: u64,
    b: u64,
    c: u64,
) -> RiscVFpResult {
    let Some(op_code) = RiscVFpOpCode::from_code(op_code) else {
        return RiscVFpResult {
            value: 0,
            fcsr_status: RISCV_FP_RESULT_INVALID,
        };
    };
    let Some((value, new_fcsr)) = rax::isa::riscv::float::eval_scalar_fp(
        op_code.into_op(),
        rm_field as u8,
        fcsr as u32,
        a,
        b,
        c,
    ) else {
        return RiscVFpResult {
            value: 0,
            fcsr_status: RISCV_FP_RESULT_INVALID,
        };
    };
    RiscVFpResult {
        value,
        fcsr_status: u64::from(new_fcsr),
    }
}

unsafe extern "sysv64" fn vector(state: *mut RiscVGuestRegs, insn: u64, xlen: u64) -> u64 {
    if state.is_null() || insn > u64::from(u32::MAX) {
        return 0;
    }
    let state = unsafe { &mut *state };
    if state.ctx == 0 {
        return 0;
    }
    let memory = unsafe { &mut *(state.ctx as *mut TestMemory) };
    let (config, decode_xlen) = match xlen {
        32 => (RiscVConfig::rv32(RvIsa::rv64gc()), RvXlen::Rv32),
        64 => (RiscVConfig::rv64gc(), RvXlen::Rv64),
        _ => return 0,
    };

    // Execute against a private memory image. State and guest memory are copied
    // back only after exact success, satisfying the helper ABI's transactional
    // failure contract even for vector stores that fault after earlier lanes.
    let mut private_memory = RvMemory::new(0, MEMORY_LEN);
    rax::isa::riscv::Memory::write(&mut private_memory, 0, &memory.bytes)
        .expect("private vector memory has the fixed test extent");
    let mut cpu = RiscVCpu::new(config, Box::new(private_memory));
    cpu.csr_write(0x300, 0b01 << 13)
        .expect("vector helper FP state must be enabled");
    for register in 1..32u8 {
        cpu.set_x(register, state.x[register as usize]);
    }
    for register in 0..32u8 {
        cpu.set_f(register, state.f[register as usize]);
        cpu.set_vreg(register, &state.v[register as usize]);
    }
    cpu.set_fcsr(state.fcsr as u32);
    cpu.set_vl_vtype(state.vl, state.vtype);
    cpu.set_vstart(state.vstart);
    cpu.set_vcsr(state.vcsr);

    let decoded = rax::isa::riscv::decode(insn as u32, decode_xlen, &RvIsa::rv64gc());
    if decoded.is_illegal()
        || !matches!(
            cpu.execute_insn(&decoded, state.pc),
            Ok(RiscVExit::Continue)
        )
    {
        return 0;
    }

    for register in 0..32u8 {
        state.x[register as usize] = cpu.x(register);
        state.f[register as usize] = cpu.f(register);
        state.v[register as usize] = cpu.vreg(register);
    }
    state.fcsr = u64::from(cpu.fcsr());
    state.vl = cpu.vl();
    state.vtype = cpu.vtype();
    state.vstart = cpu.vstart();
    state.vcsr = cpu.vcsr();
    cpu.read_memory(0, &mut memory.bytes)
        .expect("private vector memory has the fixed test extent");
    1
}

unsafe extern "sysv64" fn noncanonical_vector_status(
    _state: *mut RiscVGuestRegs,
    _insn: u64,
    _xlen: u64,
) -> u64 {
    2
}

fn jit_state(
    memory: &mut TestMemory,
    x: [u64; 32],
    f: [u64; 32],
    fcsr: u32,
    pc: u64,
) -> RiscVGuestRegs {
    RiscVGuestRegs {
        x,
        f,
        fcsr: u64::from(fcsr),
        pc,
        ctx: (memory as *mut TestMemory) as u64,
        load_fn: load as *const () as usize as u64,
        store_fn: store as *const () as usize as u64,
        atomic_rmw_fn: atomic_rmw as *const () as usize as u64,
        cas_fn: compare_and_swap as *const () as usize as u64,
        cas_pair_fn: compare_and_swap_pair as *const () as usize as u64,
        load_exclusive_fn: load_exclusive as *const () as usize as u64,
        store_exclusive_fn: store_exclusive as *const () as usize as u64,
        clear_exclusive_fn: clear_exclusive as *const () as usize as u64,
        int_crypto_fn: int_crypto as *const () as usize as u64,
        fp_fn: scalar_fp as *const () as usize as u64,
        vector_fn: vector as *const () as usize as u64,
        ..Default::default()
    }
}

fn r_type(funct7: u32, rs2: u8, rs1: u8, funct3: u32, rd: u8) -> u32 {
    r_type_opcode(funct7, rs2, rs1, funct3, rd, 0x33)
}

fn r_type_opcode(funct7: u32, rs2: u8, rs1: u8, funct3: u32, rd: u8, opcode: u32) -> u32 {
    (funct7 << 25)
        | (u32::from(rs2) << 20)
        | (u32::from(rs1) << 15)
        | (funct3 << 12)
        | (u32::from(rd) << 7)
        | opcode
}

fn r4_type(fmt: u32, rs3: u8, rs2: u8, rs1: u8, rm: u32, rd: u8, opcode: u32) -> u32 {
    (u32::from(rs3) << 27)
        | (fmt << 25)
        | (u32::from(rs2) << 20)
        | (u32::from(rs1) << 15)
        | (rm << 12)
        | (u32::from(rd) << 7)
        | opcode
}

fn i_type(imm: i32, rs1: u8, funct3: u32, rd: u8, opcode: u32) -> u32 {
    ((imm as u32 & 0xfff) << 20)
        | (u32::from(rs1) << 15)
        | (funct3 << 12)
        | (u32::from(rd) << 7)
        | opcode
}

fn s_type(imm: i32, rs2: u8, rs1: u8, funct3: u32) -> u32 {
    s_type_opcode(imm, rs2, rs1, funct3, 0x23)
}

fn s_type_opcode(imm: i32, rs2: u8, rs1: u8, funct3: u32, opcode: u32) -> u32 {
    let imm = imm as u32 & 0xfff;
    ((imm >> 5) << 25)
        | (u32::from(rs2) << 20)
        | (u32::from(rs1) << 15)
        | (funct3 << 12)
        | ((imm & 0x1f) << 7)
        | opcode
}

fn b_type(offset: i32, rs2: u8, rs1: u8, funct3: u32) -> u32 {
    let imm = offset as u32 & 0x1fff;
    (((imm >> 12) & 1) << 31)
        | (((imm >> 5) & 0x3f) << 25)
        | (u32::from(rs2) << 20)
        | (u32::from(rs1) << 15)
        | (funct3 << 12)
        | (((imm >> 1) & 0xf) << 8)
        | (((imm >> 11) & 1) << 7)
        | 0x63
}

fn j_type(offset: i32, rd: u8) -> u32 {
    let imm = offset as u32 & 0x1f_ffff;
    (((imm >> 20) & 1) << 31)
        | (((imm >> 1) & 0x3ff) << 21)
        | (((imm >> 11) & 1) << 20)
        | (((imm >> 12) & 0xff) << 12)
        | (u32::from(rd) << 7)
        | 0x6f
}

fn amo_type(funct5: u32, aq: bool, rl: bool, rs2: u8, rs1: u8, funct3: u32, rd: u8) -> u32 {
    (funct5 << 27)
        | (u32::from(aq) << 26)
        | (u32::from(rl) << 25)
        | (u32::from(rs2) << 20)
        | (u32::from(rs1) << 15)
        | (funct3 << 12)
        | (u32::from(rd) << 7)
        | 0x2f
}

fn v_type(funct6: u32, vm: u32, vs2: u32, src: u32, funct3: u32, vd: u32) -> u32 {
    (funct6 << 26) | (vm << 25) | (vs2 << 20) | (src << 15) | (funct3 << 12) | (vd << 7) | 0x57
}

fn function_for_lift(
    control: ControlFlow,
    ops: Vec<rax::smir::ir::ops::SmirOp>,
    instruction_len: usize,
) -> (SmirFunction, HashMap<BlockId, u64>) {
    function_for_lift_at(CODE, control, ops, instruction_len)
}

fn function_for_lift_at(
    pc: u64,
    control: ControlFlow,
    mut ops: Vec<rax::smir::ir::ops::SmirOp>,
    instruction_len: usize,
) -> (SmirFunction, HashMap<BlockId, u64>) {
    for (index, op) in ops.iter_mut().enumerate() {
        op.id = OpId(index as u16);
    }
    let entry = BlockId(0);
    let mut return_pcs = HashMap::new();
    let mut blocks = Vec::new();
    let terminator = match control {
        ControlFlow::Fallthrough | ControlFlow::NextInsn => {
            return_pcs.insert(entry, pc + instruction_len as u64);
            Terminator::Return { values: vec![] }
        }
        ControlFlow::Branch { target } | ControlFlow::DirectBranch(target) => {
            return_pcs.insert(entry, target);
            Terminator::Return { values: vec![] }
        }
        ControlFlow::CondBranchReg {
            cond,
            taken,
            not_taken,
        } => {
            let taken_id = BlockId(1);
            let not_taken_id = BlockId(2);
            return_pcs.insert(taken_id, taken);
            return_pcs.insert(not_taken_id, not_taken);
            blocks.push(SmirBlock {
                id: taken_id,
                guest_pc: taken,
                phis: vec![],
                ops: vec![],
                terminator: Terminator::Return { values: vec![] },
                exec_count: 0,
            });
            blocks.push(SmirBlock {
                id: not_taken_id,
                guest_pc: not_taken,
                phis: vec![],
                ops: vec![],
                terminator: Terminator::Return { values: vec![] },
                exec_count: 0,
            });
            Terminator::CondBranch {
                cond,
                true_target: taken_id,
                false_target: not_taken_id,
            }
        }
        ControlFlow::IndirectBranch { target } => Terminator::IndirectBranch {
            target,
            possible_targets: vec![],
        },
        other => panic!("control flow is outside this scalar JIT test: {other:?}"),
    };
    blocks.insert(
        0,
        SmirBlock {
            id: entry,
            guest_pc: pc,
            phis: vec![],
            ops,
            terminator,
            exec_count: 0,
        },
    );

    let mut function = SmirFunction::new(FunctionId(0), entry, pc);
    function.blocks = blocks;
    function.guest_range = (pc, pc + instruction_len as u64);
    function.calling_convention = CallingConv::RiscVStd;
    (function, return_pcs)
}

fn run_case(bytes: &[u8], initial_x: [u64; 32], initial_memory: [u8; MEMORY_LEN]) {
    run_case_with_fp(bytes, initial_x, [0; 32], 0, initial_memory);
}

fn run_case_rv32(bytes: &[u8], initial_x: [u64; 32], initial_memory: [u8; MEMORY_LEN]) {
    run_case_for_xlen(bytes, initial_x, [0; 32], 0, initial_memory, true);
}

fn run_case_rv32_with_fp(
    bytes: &[u8],
    initial_x: [u64; 32],
    initial_f: [u64; 32],
    initial_fcsr: u32,
    initial_memory: [u8; MEMORY_LEN],
) {
    run_case_for_xlen(
        bytes,
        initial_x,
        initial_f,
        initial_fcsr,
        initial_memory,
        true,
    );
}

fn run_case_with_fp(
    bytes: &[u8],
    initial_x: [u64; 32],
    initial_f: [u64; 32],
    initial_fcsr: u32,
    initial_memory: [u8; MEMORY_LEN],
) {
    run_case_for_xlen(
        bytes,
        initial_x,
        initial_f,
        initial_fcsr,
        initial_memory,
        false,
    );
}

fn run_case_for_xlen(
    bytes: &[u8],
    initial_x: [u64; 32],
    initial_f: [u64; 32],
    initial_fcsr: u32,
    initial_memory: [u8; MEMORY_LEN],
    rv32: bool,
) {
    let initial_x = if rv32 {
        std::array::from_fn(|index| initial_x[index] & 0xffff_ffff)
    } else {
        initial_x
    };
    let mut reference_memory = RvMemory::new(0, MEMORY_LEN);
    rax::isa::riscv::Memory::write(&mut reference_memory, 0, &initial_memory)
        .expect("seed reference memory");
    let config = if rv32 {
        RiscVConfig::rv32(RvIsa::rv64gc())
    } else {
        RiscVConfig::rv64gc()
    };
    let mut cpu = RiscVCpu::new(config, Box::new(reference_memory));
    cpu.csr_write(0x300, 0b01 << 13)
        .expect("reference FP state must be enabled");
    for register in 1..32u8 {
        cpu.set_x(register, initial_x[register as usize]);
    }
    for register in 0..32u8 {
        cpu.set_f(register, initial_f[register as usize]);
    }
    cpu.set_fcsr(initial_fcsr);
    cpu.write_memory(CODE, bytes).expect("write reference code");
    cpu.set_pc(CODE);
    assert_eq!(
        cpu.step(),
        RiscVExit::Continue,
        "reference instruction trapped"
    );

    let expected_x: [u64; 32] = std::array::from_fn(|index| cpu.x(index as u8));
    let expected_f: [u64; 32] = std::array::from_fn(|index| cpu.f(index as u8));
    let expected_fcsr = cpu.fcsr();
    let expected_pc = cpu.pc();
    let mut expected_data = [0u8; 64];
    cpu.read_memory(DATA, &mut expected_data)
        .expect("read reference data");

    let mut lifter = if rv32 {
        RiscVLifter::new_rv32(RiscVExtensions::rv64gc())
    } else {
        RiscVLifter::rv64gc()
    };
    let source_arch = if rv32 {
        SourceArch::RiscV32
    } else {
        SourceArch::RiscV64
    };
    let mut context = LiftContext::new(source_arch);
    let lifted = lifter
        .lift_insn(CODE, bytes, &mut context)
        .expect("lift RISC-V instruction");
    let (function, return_pcs) =
        function_for_lift(lifted.control_flow, lifted.ops, lifted.bytes_consumed);
    for level in [OptLevel::O0, OptLevel::O2] {
        let mut optimized = function.clone();
        optimize_function(&mut optimized, level);
        let mut lowerer = RiscVX86_64Lowerer::new();
        lowerer.set_return_pcs(return_pcs.clone());
        let lowered = lowerer
            .lower_function(&optimized)
            .unwrap_or_else(|error| panic!("lower RISC-V SMIR at {level:?}: {error:?}"));
        let code = lowerer.finalize().expect("finalize native code");
        let executable = ExecMem::new(&code).expect("map native code");

        let mut test_memory = TestMemory::new(initial_memory);
        let mut state = jit_state(&mut test_memory, initial_x, initial_f, initial_fcsr, CODE);
        executable.run_riscv(lowered.entry_offset, &mut state);

        assert_eq!(
            state.x, expected_x,
            "integer-register divergence at {level:?} for {bytes:02x?}"
        );
        assert_eq!(
            state.f, expected_f,
            "floating-register divergence at {level:?} for {bytes:02x?}"
        );
        assert_eq!(
            state.fcsr,
            u64::from(expected_fcsr),
            "FCSR divergence at {level:?} for {bytes:02x?}"
        );
        assert_eq!(
            state.pc, expected_pc,
            "PC divergence at {level:?} for {bytes:02x?}"
        );
        assert_eq!(
            state.exit_reason, 0,
            "unexpected JIT exit at {level:?} for {bytes:02x?}"
        );
        assert_eq!(
            &test_memory.bytes[DATA as usize..DATA as usize + 64],
            &expected_data,
            "memory divergence at {level:?} for {bytes:02x?}"
        );
    }
}

fn run_vector_case(
    instruction: u32,
    mut initial_state: RiscVGuestRegs,
    mut initial_memory: [u8; MEMORY_LEN],
    rv32: bool,
) {
    initial_memory[CODE as usize..CODE as usize + 4].copy_from_slice(&instruction.to_le_bytes());
    initial_state.x[0] = 0;
    if rv32 {
        for value in &mut initial_state.x {
            *value &= 0xffff_ffff;
        }
    }

    let mut reference_memory = RvMemory::new(0, MEMORY_LEN);
    rax::isa::riscv::Memory::write(&mut reference_memory, 0, &initial_memory)
        .expect("seed vector reference memory");
    let config = if rv32 {
        RiscVConfig::rv32(RvIsa::rv64gc())
    } else {
        RiscVConfig::rv64gc()
    };
    let mut cpu = RiscVCpu::new(config, Box::new(reference_memory));
    cpu.csr_write(0x300, 0b01 << 13)
        .expect("reference FP state must be enabled");
    for register in 1..32u8 {
        cpu.set_x(register, initial_state.x[register as usize]);
    }
    for register in 0..32u8 {
        cpu.set_f(register, initial_state.f[register as usize]);
        cpu.set_vreg(register, &initial_state.v[register as usize]);
    }
    cpu.set_fcsr(initial_state.fcsr as u32);
    cpu.set_vl_vtype(initial_state.vl, initial_state.vtype);
    cpu.set_vstart(initial_state.vstart);
    cpu.set_vcsr(initial_state.vcsr);
    cpu.set_pc(CODE);
    assert_eq!(
        cpu.step(),
        RiscVExit::Continue,
        "reference vector instruction {instruction:08x} trapped"
    );
    let expected_x: [u64; 32] = std::array::from_fn(|index| cpu.x(index as u8));
    let expected_f: [u64; 32] = std::array::from_fn(|index| cpu.f(index as u8));
    let expected_v: [[u8; 16]; 32] = std::array::from_fn(|index| cpu.vreg(index as u8));
    let mut expected_memory = [0u8; MEMORY_LEN];
    cpu.read_memory(0, &mut expected_memory)
        .expect("read vector reference memory");

    let bytes = instruction.to_le_bytes();
    let mut lifter = if rv32 {
        RiscVLifter::new_rv32(RiscVExtensions::rv64gc())
    } else {
        RiscVLifter::rv64gc()
    };
    let mut context = LiftContext::new(if rv32 {
        SourceArch::RiscV32
    } else {
        SourceArch::RiscV64
    });
    let lifted = lifter
        .lift_insn(CODE, &bytes, &mut context)
        .expect("lift vector instruction");
    let (function, return_pcs) =
        function_for_lift(lifted.control_flow, lifted.ops, lifted.bytes_consumed);

    for level in [OptLevel::O0, OptLevel::O2] {
        let mut optimized = function.clone();
        optimize_function(&mut optimized, level);
        let mut lowerer = RiscVX86_64Lowerer::new();
        lowerer.set_return_pcs(return_pcs.clone());
        let lowered = lowerer
            .lower_function(&optimized)
            .unwrap_or_else(|error| panic!("lower vector instruction at {level:?}: {error:?}"));
        let code = lowerer.finalize().expect("finalize vector native code");
        let executable = ExecMem::new(&code).expect("map vector native code");

        let mut memory = TestMemory::new(initial_memory);
        let mut state = jit_state(
            &mut memory,
            initial_state.x,
            initial_state.f,
            initial_state.fcsr as u32,
            CODE,
        );
        state.v = initial_state.v;
        state.vl = initial_state.vl;
        state.vtype = initial_state.vtype;
        state.vstart = initial_state.vstart;
        state.vcsr = initial_state.vcsr;
        executable.run_riscv(lowered.entry_offset, &mut state);

        assert_eq!(state.x, expected_x, "vector x state at {level:?}");
        assert_eq!(state.f, expected_f, "vector f state at {level:?}");
        assert_eq!(
            state.fcsr,
            u64::from(cpu.fcsr()),
            "vector FCSR at {level:?}"
        );
        assert_eq!(state.v, expected_v, "vector register state at {level:?}");
        assert_eq!(state.vl, cpu.vl(), "vector vl at {level:?}");
        assert_eq!(state.vtype, cpu.vtype(), "vector vtype at {level:?}");
        assert_eq!(state.vstart, cpu.vstart(), "vector vstart at {level:?}");
        assert_eq!(state.vcsr, cpu.vcsr(), "vector vcsr at {level:?}");
        assert_eq!(state.pc, CODE + 4, "vector resume PC at {level:?}");
        assert_eq!(state.exit_reason, 0, "vector exit status at {level:?}");
        assert_eq!(memory.bytes, expected_memory, "vector memory at {level:?}");
    }
}

fn run_opaque_fp_case(op: RvOp) {
    use rax::isa::riscv::float::{fp_uses_int_src1, fp_writes_int_dst};

    let writes_int = fp_writes_int_dst(op);
    let dst = if writes_int {
        VReg::Arch(ArchReg::RiscV(RiscVReg::X(5)))
    } else {
        VReg::Arch(ArchReg::RiscV(RiscVReg::F(5)))
    };
    let src1 = if fp_uses_int_src1(op) {
        VReg::Arch(ArchReg::RiscV(RiscVReg::X(1)))
    } else {
        VReg::Arch(ArchReg::RiscV(RiscVReg::F(1)))
    };
    let fcsr_reg = VReg::Arch(ArchReg::RiscV(RiscVReg::Csr(0x003)));
    let opaque = SmirOp::new(
        OpId(0),
        CODE,
        OpKind::RvFp {
            dst,
            fcsr_dst: fcsr_reg,
            src1,
            src2: VReg::Arch(ArchReg::RiscV(RiscVReg::F(2))),
            src3: VReg::Arch(ArchReg::RiscV(RiscVReg::F(3))),
            fcsr_src: fcsr_reg,
            op,
            rm_field: 0,
            xlen: 64,
        },
    );
    let (function, return_pcs) = function_for_lift(ControlFlow::NextInsn, vec![opaque], 4);

    let mut x = [0u64; 32];
    x[1] = 0x8000_0001_0000_0003;
    x[5] = 0x5555_5555_5555_5555;
    let mut f = [0u64; 32];
    f[1] = 0xffff_ffff_3fc0_0000;
    f[2] = 0xffff_ffff_4020_0000;
    f[3] = 0xffff_ffff_bf00_0000;
    f[5] = 0x5555_5555_5555_5555;
    let fcsr = 0x10;
    let a = if fp_uses_int_src1(op) { x[1] } else { f[1] };
    let (expected_value, expected_fcsr) =
        rax::isa::riscv::float::eval_scalar_fp(op, 0, fcsr, a, f[2], f[3])
            .expect("ABI-listed FP operation must evaluate with RNE");

    for level in [OptLevel::O0, OptLevel::O2] {
        let mut optimized = function.clone();
        optimize_function(&mut optimized, level);
        let mut lowerer = RiscVX86_64Lowerer::new();
        lowerer.set_return_pcs(return_pcs.clone());
        let lowered = lowerer
            .lower_function(&optimized)
            .unwrap_or_else(|error| panic!("lower opaque {op:?} at {level:?}: {error:?}"));
        let code = lowerer.finalize().expect("finalize opaque FP code");
        let executable = ExecMem::new(&code).expect("map opaque FP code");
        let mut memory = TestMemory::new([0; MEMORY_LEN]);
        let mut state = jit_state(&mut memory, x, f, fcsr, CODE);
        executable.run_riscv(lowered.entry_offset, &mut state);

        if writes_int {
            assert_eq!(state.x[5], expected_value, "{op:?} result at {level:?}");
            assert_eq!(state.f[5], f[5], "{op:?} wrote the wrong register file");
        } else {
            assert_eq!(state.f[5], expected_value, "{op:?} result at {level:?}");
            assert_eq!(state.x[5], x[5], "{op:?} wrote the wrong register file");
        }
        assert_eq!(state.fcsr, u64::from(expected_fcsr), "{op:?} FCSR");
        assert_eq!(state.pc, CODE + 4, "{op:?} resume PC");
        assert_eq!(state.exit_reason, 0, "{op:?} exit classification");
    }
}

fn run_atomic_sequence(
    instructions: &[u32],
    initial_x: [u64; 32],
    initial_memory: [u8; MEMORY_LEN],
    expected_order: Option<RiscVMemoryOrderCode>,
) {
    let mut reference_memory = RvMemory::new(0, MEMORY_LEN);
    rax::isa::riscv::Memory::write(&mut reference_memory, 0, &initial_memory)
        .expect("seed reference memory");
    let mut cpu = RiscVCpu::new(RiscVConfig::rv64gc(), Box::new(reference_memory));
    for register in 1..32u8 {
        cpu.set_x(register, initial_x[register as usize]);
    }
    let code = instructions
        .iter()
        .flat_map(|instruction| instruction.to_le_bytes())
        .collect::<Vec<_>>();
    cpu.write_memory(CODE, &code).expect("write reference code");
    cpu.set_pc(CODE);
    for instruction in instructions {
        assert_eq!(
            cpu.step(),
            RiscVExit::Continue,
            "reference atomic instruction {instruction:08x} trapped"
        );
    }

    let expected_x: [u64; 32] = std::array::from_fn(|index| cpu.x(index as u8));
    let expected_pc = cpu.pc();
    let mut expected_data = [0u8; 64];
    cpu.read_memory(DATA, &mut expected_data)
        .expect("read reference atomic data");

    for level in [OptLevel::O0, OptLevel::O2] {
        let mut test_memory = TestMemory::new(initial_memory);
        let mut state = jit_state(&mut test_memory, initial_x, [0; 32], 0, CODE);
        let mut lifter = RiscVLifter::rv64gc();

        for (index, instruction) in instructions.iter().enumerate() {
            let pc = CODE + index as u64 * 4;
            assert_eq!(state.pc, pc, "unexpected dispatcher PC before atomic lift");
            let mut context = LiftContext::new(SourceArch::RiscV64);
            let lifted = lifter
                .lift_insn(pc, &instruction.to_le_bytes(), &mut context)
                .unwrap_or_else(|error| panic!("lift atomic {instruction:08x}: {error:?}"));
            let (mut function, return_pcs) =
                function_for_lift_at(pc, lifted.control_flow, lifted.ops, lifted.bytes_consumed);
            optimize_function(&mut function, level);
            let mut lowerer = RiscVX86_64Lowerer::new();
            lowerer.set_return_pcs(return_pcs);
            let lowered = lowerer.lower_function(&function).unwrap_or_else(|error| {
                panic!("lower atomic {instruction:08x} at {level:?}: {error:?}")
            });
            let code = lowerer.finalize().expect("finalize atomic native code");
            let executable = ExecMem::new(&code).expect("map atomic native code");
            executable.run_riscv(lowered.entry_offset, &mut state);
        }

        assert_eq!(
            state.x, expected_x,
            "atomic register divergence at {level:?} for {instructions:08x?}"
        );
        assert_eq!(
            state.pc, expected_pc,
            "atomic PC divergence at {level:?} for {instructions:08x?}"
        );
        assert_eq!(state.exit_reason, 0, "unexpected atomic JIT exit");
        assert_eq!(
            &test_memory.bytes[DATA as usize..DATA as usize + 64],
            &expected_data,
            "atomic memory divergence at {level:?} for {instructions:08x?}"
        );
        if let Some(order) = expected_order {
            assert_eq!(
                test_memory.last_atomic_order, order as u64,
                "atomic ordering code divergence at {level:?}"
            );
        }
        if let Some(instruction) = instructions.iter().rev().find(|instruction| {
            (*instruction >> 27) & 0x1f == 0b00101 && (*instruction >> 12) & 0x7 == 0b100
        }) {
            let expected_failure_order = if instruction & (1 << 26) != 0 {
                RiscVMemoryOrderCode::Acquire
            } else {
                RiscVMemoryOrderCode::Relaxed
            };
            assert_eq!(
                test_memory.last_atomic_failure_order, expected_failure_order as u64,
                "pair CAS failure ordering code divergence at {level:?}"
            );
        }
        assert_eq!(
            test_memory.reservation_valid, 0,
            "reservation leaked after atomic sequence at {level:?}"
        );
    }
}

fn fp_type(funct7: u32, rs2: u8, rs1: u8, funct3: u32, rd: u8) -> u32 {
    (funct7 << 25)
        | (u32::from(rs2) << 20)
        | (u32::from(rs1) << 15)
        | (funct3 << 12)
        | (u32::from(rd) << 7)
        | 0x53
}

#[test]
fn lifted_rv64_integer_alu_and_m_extension_execute_natively() {
    let mut x = [0u64; 32];
    x[1] = 0x8123_4567_89ab_cdef;
    x[2] = 0xfedc_ba98_7654_3211;
    x[3] = 17;
    let memory = [0u8; MEMORY_LEN];

    let instructions = [
        i_type(-37, 1, 0, 5, 0x13),
        r_type(0x00, 2, 1, 0, 6),
        r_type(0x20, 2, 1, 0, 7),
        r_type(0x00, 3, 1, 1, 8),
        r_type(0x00, 3, 1, 5, 9),
        r_type(0x20, 3, 1, 5, 9),
        r_type(0x00, 2, 1, 2, 10),
        r_type(0x00, 2, 1, 3, 11),
        r_type(0x00, 2, 1, 4, 16),
        r_type(0x00, 2, 1, 6, 17),
        r_type(0x00, 2, 1, 7, 18),
        r_type(0x01, 2, 1, 0, 12),
        r_type(0x01, 2, 1, 1, 13),
        r_type(0x01, 2, 1, 2, 19),
        r_type(0x01, 2, 1, 3, 20),
        r_type(0x01, 3, 1, 4, 14),
        r_type(0x01, 3, 1, 5, 21),
        r_type(0x01, 3, 1, 6, 15),
        r_type(0x01, 3, 1, 7, 22),
        r_type(0x30, 3, 1, 1, 23),     // rol
        r_type(0x30, 3, 1, 5, 24),     // ror
        i_type(0x600, 1, 1, 25, 0x13), // clz
        i_type(0x601, 1, 1, 26, 0x13), // ctz
        i_type(0x602, 1, 1, 27, 0x13), // cpop
        r_type_opcode(0x00, 2, 1, 0, 28, 0x3b),
        r_type_opcode(0x01, 3, 1, 4, 29, 0x3b),
    ];
    for instruction in instructions {
        run_case(&instruction.to_le_bytes(), x, memory);
    }

    for value in [0, u64::MAX, 0x0102_0408_1020_4080] {
        let mut counts = x;
        counts[0] = 0xfeed_face_dead_beef;
        counts[1] = value;
        for instruction in [
            i_type(0x600, 1, 1, 25, 0x13),          // clz
            i_type(0x601, 1, 1, 26, 0x13),          // ctz
            i_type(0x602, 1, 1, 27, 0x13),          // cpop
            i_type(0x602, 1, 1, 27, 0x1b),          // cpopw
            r_type_opcode(0x34, 7, 1, 5, 28, 0x13), // brev8
        ] {
            run_case(&instruction.to_le_bytes(), counts, memory);
        }
    }

    // Division edge cases exercise the lifter's RISC-V totalization sequences
    // and prove the native lowerer never exposes host #DE.
    let mut edge = x;
    edge[1] = i64::MIN as u64;
    edge[3] = u64::MAX;
    for instruction in [
        r_type(0x01, 0, 1, 4, 5),
        r_type(0x01, 0, 1, 6, 6),
        r_type(0x01, 3, 1, 4, 7),
        r_type(0x01, 3, 1, 6, 8),
    ] {
        run_case(&instruction.to_le_bytes(), edge, memory);
    }
}

#[test]
fn lifted_rv64_load_store_and_control_flow_execute_natively() {
    let mut x = [0u64; 32];
    x[1] = DATA;
    x[2] = 0x8877_6655_4433_2211;
    x[3] = x[2];
    let mut memory = [0u8; MEMORY_LEN];
    memory[DATA as usize..DATA as usize + 8]
        .copy_from_slice(&0x8000_0001_7654_3210u64.to_le_bytes());

    for instruction in [
        i_type(0, 1, 0, 5, 0x03),
        i_type(0, 1, 1, 5, 0x03),
        i_type(0, 1, 2, 5, 0x03),
        i_type(0, 1, 3, 5, 0x03),
        i_type(0, 1, 4, 5, 0x03),
        i_type(0, 1, 5, 5, 0x03),
        i_type(0, 1, 6, 5, 0x03),
        s_type(16, 2, 1, 0),
        s_type(16, 2, 1, 1),
        s_type(16, 2, 1, 2),
        s_type(16, 2, 1, 3),
        b_type(8, 3, 2, 0),
        b_type(8, 1, 2, 0),
        b_type(8, 1, 2, 1),
        b_type(8, 3, 2, 1),
        j_type(12, 5),
        i_type(4, 2, 0, 5, 0x67),
    ] {
        run_case(&instruction.to_le_bytes(), x, memory);
    }
}

#[test]
fn scalar_load_store_faults_exit_without_committing_destinations() {
    let mut initial_x = [0u64; 32];
    initial_x[1] = MEMORY_LEN as u64 - 4;
    initial_x[2] = 0x1122_3344_5566_7788;
    initial_x[5] = 0x5555_5555_5555_5555;
    let initial_memory = [0xa5; MEMORY_LEN];

    for instruction in [
        i_type(0, 1, 3, 5, 0x03),        // ld x5,0(x1)
        s_type_opcode(0, 2, 1, 3, 0x23), // sd x2,0(x1)
    ] {
        let bytes = instruction.to_le_bytes();
        let mut lifter = RiscVLifter::rv64gc();
        let mut context = LiftContext::new(SourceArch::RiscV64);
        let lifted = lifter
            .lift_insn(CODE, &bytes, &mut context)
            .expect("lift faulting scalar memory instruction");
        let (function, return_pcs) =
            function_for_lift(lifted.control_flow, lifted.ops, lifted.bytes_consumed);

        for level in [OptLevel::O0, OptLevel::O2] {
            let mut optimized = function.clone();
            optimize_function(&mut optimized, level);
            let mut lowerer = RiscVX86_64Lowerer::new();
            lowerer.set_return_pcs(return_pcs.clone());
            let lowered = lowerer
                .lower_function(&optimized)
                .expect("lower faulting scalar memory instruction");
            let code = lowerer.finalize().expect("finalize faulting memory path");
            let executable = ExecMem::new(&code).expect("map faulting memory path");
            let mut memory = TestMemory::new(initial_memory);
            let mut state = jit_state(&mut memory, initial_x, [0; 32], 0, CODE);
            executable.run_riscv(lowered.entry_offset, &mut state);

            assert_eq!(state.x[5], initial_x[5], "destination write at {level:?}");
            assert_eq!(state.pc, CODE, "fault PC at {level:?}");
            assert_eq!(state.exit_reason, 1, "fault classification at {level:?}");
            assert_eq!(memory.bytes, initial_memory, "partial store at {level:?}");
        }
    }
}

#[test]
fn compressed_fallthrough_uses_exact_two_byte_resume_pc() {
    // c.addi x5,1: quadrant 1, funct3=000, rd=x5, imm=1.
    let instruction = ((5u16) << 7) | (1 << 2) | 0b01;
    let mut x = [0u64; 32];
    x[5] = u64::MAX;
    run_case(&instruction.to_le_bytes(), x, [0u8; MEMORY_LEN]);
}

#[test]
fn lifted_fp_bit_operations_and_fcsr_access_execute_natively() {
    let mut x = [0u64; 32];
    x[1] = 0x0123_4567_89ab_cdef;
    x[5] = 0xa5;
    let mut f = [0u64; 32];
    f[1] = 0x8000_0000_0000_0001;
    f[2] = 0x7ff8_1234_5678_9abc;
    let memory = [0u8; MEMORY_LEN];

    for instruction in [
        fp_type(0x71, 0, 1, 0, 5),    // fmv.x.d x5,f1
        fp_type(0x79, 0, 1, 0, 5),    // fmv.d.x f5,x1
        fp_type(0x11, 2, 1, 0, 5),    // fsgnj.d f5,f1,f2
        fp_type(0x11, 2, 1, 1, 5),    // fsgnjn.d f5,f1,f2
        fp_type(0x11, 2, 1, 2, 5),    // fsgnjx.d f5,f1,f2
        fp_type(0x71, 0, 1, 1, 5),    // fclass.d x5,f1
        fp_type(0x10, 2, 1, 0, 5),    // fsgnj.s f5,f1,f2
        fp_type(0x70, 0, 1, 1, 5),    // fclass.s x5,f1
        i_type(0x003, 1, 1, 5, 0x73), // csrrw x5,fcsr,x1
        i_type(0x003, 5, 1, 5, 0x73), // csrrw x5,fcsr,x5 (rd/rs1 alias)
        i_type(0x003, 5, 3, 5, 0x73), // csrrc x5,fcsr,x5 (rd/rs1 alias)
        i_type(0xc22, 0, 2, 5, 0x73), // csrrs x5,vlenb,x0
    ] {
        run_case_with_fp(&instruction.to_le_bytes(), x, f, 0x61, memory);
    }

    let mut memory_x = x;
    memory_x[1] = DATA;
    let mut fp_memory = memory;
    fp_memory[DATA as usize..DATA as usize + 8]
        .copy_from_slice(&0x8000_0001_7654_3210u64.to_le_bytes());
    for instruction in [
        i_type(0, 1, 2, 5, 0x07),         // flw f5,0(x1)
        i_type(0, 1, 3, 5, 0x07),         // fld f5,0(x1)
        s_type_opcode(16, 2, 1, 2, 0x27), // fsw f2,16(x1)
        s_type_opcode(16, 2, 1, 3, 0x27), // fsd f2,16(x1)
    ] {
        run_case_with_fp(&instruction.to_le_bytes(), memory_x, f, 0x61, fp_memory);
    }
}

#[test]
fn lifted_rv64_scalar_fp_executes_through_helper_abi() {
    let memory = [0u8; MEMORY_LEN];

    let mut f32_regs = [0u64; 32];
    f32_regs[1] = 0xffff_ffff_3fc0_0000; // 1.5
    f32_regs[2] = 0xffff_ffff_4020_0000; // 2.5
    for instruction in [
        fp_type(0x00, 2, 1, 0, 5), // fadd.s f5,f1,f2
        fp_type(0x00, 2, 1, 0, 1), // fadd.s f1,f1,f2 (source/destination alias)
        fp_type(0x50, 2, 1, 2, 5), // feq.s x5,f1,f2
    ] {
        run_case_with_fp(&instruction.to_le_bytes(), [0; 32], f32_regs, 0, memory);
    }

    let mut f64_regs = [0u64; 32];
    f64_regs[1] = 1.0f64.to_bits();
    f64_regs[2] = 10.0f64.to_bits();
    f64_regs[3] = (-0.5f64).to_bits();
    for (instruction, fcsr) in [
        (fp_type(0x0d, 2, 1, 7, 5), 2 << 5),  // fdiv.d f5,f1,f2,dyn (RDN)
        (fp_type(0x15, 2, 1, 0, 5), 0),       // fmin.d f5,f1,f2
        (r4_type(1, 3, 2, 1, 0, 5, 0x43), 0), // fmadd.d f5,f1,f2,f3
        (fp_type(0x61, 0, 1, 1, 5), 0),       // fcvt.w.d x5,f1,rtz
    ] {
        run_case_with_fp(&instruction.to_le_bytes(), [0; 32], f64_regs, fcsr, memory);
    }

    let mut x = [0u64; 32];
    x[1] = 0x0020_0000_0000_0001;
    run_case_with_fp(
        &fp_type(0x69, 2, 1, 0, 5).to_le_bytes(), // fcvt.d.l f5,x1
        x,
        [0; 32],
        0,
        memory,
    );

    let mut discard_f = [0u64; 32];
    discard_f[1] = 1.5f64.to_bits();
    run_case_with_fp(
        &fp_type(0x61, 0, 1, 1, 0).to_le_bytes(), // fcvt.w.d x0,f1,rtz
        [0; 32],
        discard_f,
        0,
        memory,
    );

    let mut rv32_f = [0u64; 32];
    rv32_f[1] = 0xffff_ffff_bfc0_0000; // -1.5f
    run_case_rv32_with_fp(
        &fp_type(0x60, 0, 1, 1, 5).to_le_bytes(), // fcvt.w.s x5,f1,rtz
        [0; 32],
        rv32_f,
        0,
        memory,
    );
    rv32_f[1] = 0xffff_ffff_7fc0_0000; // canonical qNaN
    run_case_rv32_with_fp(
        &fp_type(0x60, 1, 1, 0, 5).to_le_bytes(), // fcvt.wu.s x5,f1,rne
        [0; 32],
        rv32_f,
        0,
        memory,
    );
}

#[test]
fn scalar_fp_helper_abi_covers_every_operation_code() {
    for code in 0..=90u64 {
        let abi_op = RiscVFpOpCode::from_code(code).expect("dense FP ABI code");
        let op = abi_op.into_op();
        assert_eq!(RiscVFpOpCode::from_op(op), Some(abi_op));
        assert_eq!(abi_op as u64, code);
        run_opaque_fp_case(op);
    }
    assert_eq!(RiscVFpOpCode::from_code(91), None);
    assert_eq!(RiscVFpOpCode::from_code(u64::MAX), None);
    assert_eq!(RiscVFpOpCode::from_op(RvOp::Add), None);
}

#[test]
fn scalar_fp_invalid_rounding_traps_without_architectural_writes() {
    for (rm_field, fcsr) in [(5, 0), (6, 0), (7, 5 << 5), (7, 6 << 5), (7, 7 << 5)] {
        let fcsr_reg = VReg::Arch(ArchReg::RiscV(RiscVReg::Csr(0x003)));
        let opaque = SmirOp::new(
            OpId(0),
            CODE,
            OpKind::RvFp {
                dst: VReg::Arch(ArchReg::RiscV(RiscVReg::F(5))),
                fcsr_dst: fcsr_reg,
                src1: VReg::Arch(ArchReg::RiscV(RiscVReg::F(1))),
                src2: VReg::Arch(ArchReg::RiscV(RiscVReg::F(2))),
                src3: VReg::Arch(ArchReg::RiscV(RiscVReg::F(3))),
                fcsr_src: fcsr_reg,
                op: RvOp::FaddS,
                rm_field,
                xlen: 64,
            },
        );
        let (function, return_pcs) = function_for_lift(ControlFlow::NextInsn, vec![opaque], 4);
        for level in [OptLevel::O0, OptLevel::O2] {
            let mut optimized = function.clone();
            optimize_function(&mut optimized, level);
            let mut lowerer = RiscVX86_64Lowerer::new();
            lowerer.set_return_pcs(return_pcs.clone());
            let lowered = lowerer
                .lower_function(&optimized)
                .expect("lower invalid-rounding trap path");
            let code = lowerer.finalize().expect("finalize invalid-rounding path");
            let executable = ExecMem::new(&code).expect("map invalid-rounding path");
            let mut memory = TestMemory::new([0; MEMORY_LEN]);
            let mut f = [0u64; 32];
            f[1] = 0xffff_ffff_3f80_0000;
            f[2] = 0xffff_ffff_4000_0000;
            f[5] = 0x5555_5555_5555_5555;
            let mut state = jit_state(&mut memory, [0; 32], f, fcsr, CODE);
            executable.run_riscv(lowered.entry_offset, &mut state);

            assert_eq!(state.f[5], f[5], "rm={rm_field}, fcsr={fcsr:#x}");
            assert_eq!(state.fcsr, u64::from(fcsr));
            assert_eq!(state.pc, CODE);
            assert_eq!(state.exit_reason, 1);
        }
    }
}

#[test]
fn scalar_fp_lowering_rejects_malformed_opaque_operations() {
    let fcsr = VReg::Arch(ArchReg::RiscV(RiscVReg::Csr(0x003)));
    for (op, rm_field, xlen, expected) in [
        (RvOp::Add, 0, 64, "scalar-FP helper operation Add"),
        (RvOp::FaddS, 0, 16, "scalar-FP XLEN 16"),
        (RvOp::FaddS, 8, 64, "scalar-FP rounding field 8"),
        (
            RvOp::FcvtLD,
            0,
            32,
            "RV64-only operation FcvtLD with XLEN 32",
        ),
    ] {
        let opaque = SmirOp::new(
            OpId(0),
            CODE,
            OpKind::RvFp {
                dst: VReg::Arch(ArchReg::RiscV(RiscVReg::F(5))),
                fcsr_dst: fcsr,
                src1: VReg::Imm(1),
                src2: VReg::Imm(2),
                src3: VReg::Imm(3),
                fcsr_src: fcsr,
                op,
                rm_field,
                xlen,
            },
        );
        let (function, return_pcs) = function_for_lift(ControlFlow::NextInsn, vec![opaque], 4);
        let mut lowerer = RiscVX86_64Lowerer::new();
        lowerer.set_return_pcs(return_pcs);
        let error = lowerer
            .lower_function(&function)
            .expect_err("malformed RvFp operation must fail closed");
        assert!(
            format!("{error:?}").contains(expected),
            "unexpected malformed-op error: {error:?}"
        );
    }
}

#[test]
fn lifted_rv64_atomics_execute_through_helper_abi() {
    let mut x = [0u64; 32];
    x[1] = DATA;
    x[2] = 0x7000_0003_7fff_fffd;
    x[3] = 0x1122_3344_5566_7788;
    x[4] = DATA + 8;
    let mut memory = [0u8; MEMORY_LEN];
    memory[DATA as usize..DATA as usize + 8]
        .copy_from_slice(&0x8000_0005_8000_0005u64.to_le_bytes());
    memory[DATA as usize + 8..DATA as usize + 16]
        .copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());

    let operations = [
        0b00001, // amoswap
        0b00000, // amoadd
        0b00100, // amoxor
        0b01100, // amoand
        0b01000, // amoor
        0b10000, // amomin
        0b10100, // amomax
        0b11000, // amominu
        0b11100, // amomaxu
    ];
    let orders = [
        (false, false, RiscVMemoryOrderCode::Relaxed),
        (true, false, RiscVMemoryOrderCode::Acquire),
        (false, true, RiscVMemoryOrderCode::Release),
        (true, true, RiscVMemoryOrderCode::SeqCst),
    ];
    for (index, funct5) in operations.into_iter().enumerate() {
        let (aq, rl, order) = orders[index % orders.len()];
        for funct3 in [0b010, 0b011] {
            let instruction = amo_type(funct5, aq, rl, 2, 1, funct3, 5);
            run_atomic_sequence(&[instruction], x, memory, Some(order));
        }
    }

    // AMOCAS.D success and AMOCAS.W failure exercise both SysV return
    // registers (`old`, three-state status) and word-result sign extension.
    let mut cas_success = x;
    cas_success[5] = 0x8000_0005_8000_0005;
    run_atomic_sequence(
        &[amo_type(0b00101, true, true, 2, 1, 0b011, 5)],
        cas_success,
        memory,
        Some(RiscVMemoryOrderCode::SeqCst),
    );
    let mut cas_failure = x;
    cas_failure[5] = 0x1234;
    run_atomic_sequence(
        &[amo_type(0b00101, true, false, 2, 1, 0b010, 5)],
        cas_failure,
        memory,
        Some(RiscVMemoryOrderCode::Acquire),
    );

    // AMOCAS.Q success/failure covers the stack-passed order/result-pointer
    // arguments and both returned old words at every RISC-V aq/rl setting.
    for (index, (aq, rl, order)) in orders.into_iter().enumerate() {
        let mut q = x;
        q[6] = 0x8000_0005_8000_0005;
        q[7] = if index % 2 == 0 {
            0x0102_0304_0506_0708
        } else {
            0xfefe_fefe_fefe_fefe
        };
        q[8] = 0x1111_2222_3333_4444;
        q[9] = 0x5555_6666_7777_8888;
        run_atomic_sequence(
            &[amo_type(0b00101, aq, rl, 8, 1, 0b100, 6)],
            q,
            memory,
            Some(order),
        );
    }

    // A pair beginning at rd=x0 compares against 128 zero bits and discards
    // both returned words.
    let mut q_x0 = x;
    q_x0[10] = DATA;
    q_x0[1] = 0x0102_0304_0506_0708;
    q_x0[8] = 0x9999_aaaa_bbbb_cccc;
    q_x0[9] = 0xdddd_eeee_ffff_0001;
    let mut q_x0_memory = memory;
    q_x0_memory[DATA as usize..DATA as usize + 16].fill(0);
    run_atomic_sequence(
        &[amo_type(0b00101, false, false, 8, 10, 0b100, 0)],
        q_x0,
        q_x0_memory,
        Some(RiscVMemoryOrderCode::Relaxed),
    );

    // A replacement pair beginning at rs2=x0 supplies 128 zero bits.
    let mut q_zero_new = x;
    q_zero_new[6] = 0x8000_0005_8000_0005;
    q_zero_new[7] = 0x0102_0304_0506_0708;
    run_atomic_sequence(
        &[amo_type(0b00101, false, true, 0, 1, 0b100, 6)],
        q_zero_new,
        memory,
        Some(RiscVMemoryOrderCode::Release),
    );

    // LR/SC success for both widths, missing/different reservations, and the
    // reference CPU's same-hart ordinary-store reservation behavior.
    for funct3 in [0b010, 0b011] {
        run_atomic_sequence(
            &[
                amo_type(0b00010, true, false, 0, 1, funct3, 5),
                amo_type(0b00011, false, true, 2, 1, funct3, 6),
            ],
            x,
            memory,
            None,
        );
    }
    run_atomic_sequence(
        &[amo_type(0b00011, false, false, 2, 1, 0b011, 6)],
        x,
        memory,
        None,
    );
    run_atomic_sequence(
        &[
            amo_type(0b00010, false, false, 0, 1, 0b011, 5),
            s_type(0, 3, 1, 0b011),
            amo_type(0b00011, false, false, 2, 1, 0b011, 6),
        ],
        x,
        memory,
        None,
    );
    run_atomic_sequence(
        &[
            amo_type(0b00010, false, false, 0, 1, 0b011, 5),
            amo_type(0b00011, false, false, 2, 4, 0b011, 6),
        ],
        x,
        memory,
        None,
    );
    run_atomic_sequence(
        &[
            amo_type(0b00010, false, false, 0, 1, 0b011, 5),
            amo_type(0b00010, false, false, 0, 4, 0b011, 7),
            amo_type(0b00011, false, false, 2, 1, 0b011, 6),
        ],
        x,
        memory,
        None,
    );
}

#[test]
fn atomic_memory_faults_exit_without_committing_results() {
    let mut initial_x = [0u64; 32];
    initial_x[1] = MEMORY_LEN as u64 - 4;
    initial_x[2] = 0x1122_3344_5566_7788;
    initial_x[5] = 0x5555_5555_5555_5555;
    initial_x[6] = 0x6666_6666_6666_6666;
    let initial_memory = [0xa5; MEMORY_LEN];

    for instruction in [
        amo_type(0b00000, false, false, 2, 1, 0b011, 5), // amoadd.d
        amo_type(0b00101, false, false, 2, 1, 0b011, 5), // amocas.d
        amo_type(0b00101, false, false, 2, 1, 0b100, 6), // amocas.q
        amo_type(0b00010, false, false, 0, 1, 0b011, 5), // lr.d
        amo_type(0b00011, false, false, 2, 1, 0b011, 6), // sc.d
    ] {
        let bytes = instruction.to_le_bytes();
        let mut lifter = RiscVLifter::rv64gc();
        let mut context = LiftContext::new(SourceArch::RiscV64);
        let lifted = lifter
            .lift_insn(CODE, &bytes, &mut context)
            .expect("lift faulting atomic instruction");
        let (function, return_pcs) =
            function_for_lift(lifted.control_flow, lifted.ops, lifted.bytes_consumed);

        for level in [OptLevel::O0, OptLevel::O2] {
            let mut optimized = function.clone();
            optimize_function(&mut optimized, level);
            let mut lowerer = RiscVX86_64Lowerer::new();
            lowerer.set_return_pcs(return_pcs.clone());
            let lowered = lowerer
                .lower_function(&optimized)
                .expect("lower faulting atomic instruction");
            let code = lowerer.finalize().expect("finalize faulting atomic path");
            let executable = ExecMem::new(&code).expect("map faulting atomic path");
            let mut memory = TestMemory::new(initial_memory);
            let mut state = jit_state(&mut memory, initial_x, [0; 32], 0, CODE);
            executable.run_riscv(lowered.entry_offset, &mut state);

            assert_eq!(state.x, initial_x, "atomic result write at {level:?}");
            assert_eq!(state.pc, CODE, "atomic fault PC at {level:?}");
            assert_eq!(state.exit_reason, 1, "atomic fault class at {level:?}");
            assert_eq!(memory.bytes, initial_memory, "partial atomic at {level:?}");
        }
    }
}

#[test]
fn noncanonical_atomic_helper_statuses_fail_closed() {
    let mut initial_x = [0u64; 32];
    initial_x[1] = DATA;
    initial_x[2] = 0x1122_3344_5566_7788;
    initial_x[5] = 0x5555_5555_5555_5555;
    initial_x[6] = 0x6666_6666_6666_6666;
    initial_x[7] = 0x7777_7777_7777_7777;
    initial_x[8] = 0x8888_8888_8888_8888;
    initial_x[9] = 0x9999_9999_9999_9999;
    let initial_memory = [0xa5; MEMORY_LEN];

    for (instruction, helper) in [
        (amo_type(0b00000, false, false, 2, 1, 0b011, 5), 0),
        (amo_type(0b00101, false, false, 2, 1, 0b011, 5), 1),
        (amo_type(0b00101, false, false, 8, 1, 0b100, 6), 2),
    ] {
        let bytes = instruction.to_le_bytes();
        let mut lifter = RiscVLifter::rv64gc();
        let mut context = LiftContext::new(SourceArch::RiscV64);
        let lifted = lifter
            .lift_insn(CODE, &bytes, &mut context)
            .expect("lift atomic instruction for malformed helper status");
        let (function, return_pcs) =
            function_for_lift(lifted.control_flow, lifted.ops, lifted.bytes_consumed);

        for level in [OptLevel::O0, OptLevel::O2] {
            let mut optimized = function.clone();
            optimize_function(&mut optimized, level);
            let mut lowerer = RiscVX86_64Lowerer::new();
            lowerer.set_return_pcs(return_pcs.clone());
            let lowered = lowerer
                .lower_function(&optimized)
                .expect("lower malformed atomic-helper status path");
            let code = lowerer.finalize().expect("finalize malformed status path");
            let executable = ExecMem::new(&code).expect("map malformed status path");
            let mut memory = TestMemory::new(initial_memory);
            let mut state = jit_state(&mut memory, initial_x, [0; 32], 0, CODE);
            match helper {
                0 => {
                    state.atomic_rmw_fn =
                        noncanonical_atomic_rmw_status as *const () as usize as u64;
                }
                1 => state.cas_fn = noncanonical_cas_status as *const () as usize as u64,
                2 => {
                    state.cas_pair_fn = noncanonical_cas_pair_status as *const () as usize as u64;
                }
                _ => unreachable!(),
            }
            executable.run_riscv(lowered.entry_offset, &mut state);

            assert_eq!(state.x, initial_x, "noncanonical result at {level:?}");
            assert_eq!(state.pc, CODE);
            assert_eq!(state.exit_reason, 1);
            assert_eq!(memory.bytes, initial_memory);
        }
    }
}

#[test]
fn lifted_rv_vector_executes_through_complete_state_helper_abi() {
    const E32_M1: u64 = 0x10;
    let mut initial = RiscVGuestRegs {
        fcsr: 0x10,
        vl: 4,
        vtype: E32_M1,
        vcsr: 5,
        ..Default::default()
    };
    initial.x[10] = DATA;
    initial.x[12] = 3;
    initial.x[13] = 7;
    initial.f[13] = 0xffff_ffff_3f80_0000;
    for lane in 0..4usize {
        initial.v[1][lane * 4..lane * 4 + 4]
            .copy_from_slice(&(0x1020_3040u32 + lane as u32).to_le_bytes());
        initial.v[2][lane * 4..lane * 4 + 4].copy_from_slice(&(lane as u32 + 1).to_le_bytes());
        initial.v[3][lane * 4..lane * 4 + 4]
            .copy_from_slice(&((lane as u32 + 1) * 10).to_le_bytes());
    }
    let mut memory = [0u8; MEMORY_LEN];
    for lane in 0..4usize {
        memory[DATA as usize + lane * 4..DATA as usize + lane * 4 + 4]
            .copy_from_slice(&(0xa0b0_c000u32 + lane as u32).to_le_bytes());
    }

    let instructions = [
        // Configuration writes x11, vl, and vtype.
        (E32_M1 as u32) << 20 | (12 << 15) | (7 << 12) | (11 << 7) | 0x57,
        // Vector-register result.
        v_type(0b000000, 1, 2, 3, 0, 1), // vadd.vv v1,v2,v3
        // Integer and floating scalar outputs.
        v_type(0b010000, 1, 2, 0, 2, 11), // vmv.x.s x11,v2
        v_type(0b010000, 1, 2, 0, 1, 11), // vfmv.f.s f11,v2
        // Memory read and write effects.
        (1 << 25) | (10 << 15) | (6 << 12) | (1 << 7) | 0x07, // vle32.v
        (1 << 25) | (10 << 15) | (6 << 12) | (1 << 7) | 0x27, // vse32.v
    ];
    for rv32 in [false, true] {
        for instruction in instructions {
            run_vector_case(instruction, initial, memory, rv32);
        }
    }
}

#[test]
fn rv_vector_flushes_current_virtual_scalar_sources() {
    const E32_M1: u64 = 0x10;
    let instruction: u32 = (1 << 25) | (10 << 15) | (6 << 12) | (1 << 7) | 0x07;
    let bytes = instruction.to_le_bytes();
    let mut lifter = RiscVLifter::rv64gc();
    let mut context = LiftContext::new(SourceArch::RiscV64);
    let mut lifted = lifter
        .lift_insn(CODE, &bytes, &mut context)
        .expect("lift vector load");
    let current_x10 = VReg::Virtual(VirtualId(0xfeed));
    let OpKind::RvVector { rs1, state, .. } = &mut lifted.ops[0].kind else {
        panic!("vector load did not lift to RvVector");
    };
    *rs1 = current_x10;
    state.x_srcs[10] = current_x10;
    lifted.ops.insert(
        0,
        SmirOp::new(
            OpId(0),
            CODE,
            OpKind::Mov {
                dst: current_x10,
                src: SrcOperand::Imm64(DATA as i64),
                width: OpWidth::W64,
            },
        ),
    );
    let (function, return_pcs) =
        function_for_lift(lifted.control_flow, lifted.ops, lifted.bytes_consumed);

    let stale_address = DATA + 0x40;
    let current_lane = 0xaabb_ccddu32.to_le_bytes();
    let stale_lane = 0x1122_3344u32.to_le_bytes();
    let mut initial_memory = [0u8; MEMORY_LEN];
    initial_memory[DATA as usize..DATA as usize + 4].copy_from_slice(&current_lane);
    initial_memory[stale_address as usize..stale_address as usize + 4].copy_from_slice(&stale_lane);
    let mut initial_x = [0u64; 32];
    initial_x[10] = stale_address;

    for level in [OptLevel::O0, OptLevel::O2] {
        let mut optimized = function.clone();
        optimize_function(&mut optimized, level);
        let mut lowerer = RiscVX86_64Lowerer::new();
        lowerer.set_return_pcs(return_pcs.clone());
        let lowered = lowerer
            .lower_function(&optimized)
            .expect("lower vector load with virtual base");
        let code = lowerer
            .finalize()
            .expect("finalize vector virtual-source code");
        let executable = ExecMem::new(&code).expect("map vector virtual-source code");
        let mut memory = TestMemory::new(initial_memory);
        let mut state = jit_state(&mut memory, initial_x, [0; 32], 0, CODE);
        state.vl = 1;
        state.vtype = E32_M1;
        executable.run_riscv(lowered.entry_offset, &mut state);

        assert_eq!(&state.v[1][0..4], &current_lane, "fresh base at {level:?}");
        assert_ne!(&state.v[1][0..4], &stale_lane, "stale base at {level:?}");
        assert_eq!(state.x[10], DATA, "scalar state forwarding at {level:?}");
        assert_eq!(state.pc, CODE + 4);
        assert_eq!(state.exit_reason, 0);
    }
}

#[test]
fn vector_faults_and_noncanonical_statuses_fail_transactionally() {
    const E32_M1: u64 = 0x10;
    let instruction: u32 = (1 << 25) | (10 << 15) | (6 << 12) | (1 << 7) | 0x07;
    let bytes = instruction.to_le_bytes();
    let mut lifter = RiscVLifter::rv64gc();
    let mut context = LiftContext::new(SourceArch::RiscV64);
    let lifted = lifter
        .lift_insn(CODE, &bytes, &mut context)
        .expect("lift faulting vector load");
    let (function, return_pcs) =
        function_for_lift(lifted.control_flow, lifted.ops, lifted.bytes_consumed);

    let mut initial_x = [0u64; 32];
    initial_x[10] = MEMORY_LEN as u64 - 2;
    let initial_v = [[0x5au8; 16]; 32];
    let initial_memory = [0xa5u8; MEMORY_LEN];
    for (malformed, expected_reason) in [(false, 1), (true, 1)] {
        for level in [OptLevel::O0, OptLevel::O2] {
            let mut optimized = function.clone();
            optimize_function(&mut optimized, level);
            let mut lowerer = RiscVX86_64Lowerer::new();
            lowerer.set_return_pcs(return_pcs.clone());
            let lowered = lowerer
                .lower_function(&optimized)
                .expect("lower vector failure path");
            let code = lowerer.finalize().expect("finalize vector failure path");
            let executable = ExecMem::new(&code).expect("map vector failure path");
            let mut memory = TestMemory::new(initial_memory);
            let mut state = jit_state(&mut memory, initial_x, [0; 32], 0x11, CODE);
            state.v = initial_v;
            state.vl = 1;
            state.vtype = E32_M1;
            state.vstart = 0;
            state.vcsr = 6;
            if malformed {
                state.vector_fn = noncanonical_vector_status as *const () as usize as u64;
            }
            executable.run_riscv(lowered.entry_offset, &mut state);

            assert_eq!(state.x, initial_x, "vector failure x state at {level:?}");
            assert_eq!(state.f, [0; 32], "vector failure f state at {level:?}");
            assert_eq!(state.fcsr, 0x11, "vector failure FCSR at {level:?}");
            assert_eq!(state.v, initial_v, "vector failure v state at {level:?}");
            assert_eq!(state.vl, 1);
            assert_eq!(state.vtype, E32_M1);
            assert_eq!(state.vstart, 0);
            assert_eq!(state.vcsr, 6);
            assert_eq!(state.pc, CODE, "vector failure PC at {level:?}");
            assert_eq!(state.exit_reason, expected_reason);
            assert_eq!(
                memory.bytes, initial_memory,
                "vector partial memory at {level:?}"
            );
        }
    }
}

#[test]
fn lifted_rv64_integer_crypto_executes_through_helper_abi() {
    let mut x = [0u64; 32];
    x[1] = 0x0123_4567_89ab_cdef;
    x[2] = 0xfedc_ba98_7654_3210;
    let memory = [0u8; MEMORY_LEN];

    for instruction in [
        r_type(0x05, 2, 1, 1, 5),         // clmul
        r_type(0x05, 2, 1, 2, 5),         // clmulr
        r_type(0x05, 2, 1, 3, 5),         // clmulh
        r_type(0x14, 2, 1, 2, 5),         // xperm4
        r_type(0x14, 2, 1, 4, 5),         // xperm8
        r_type(0x19, 2, 1, 0, 5),         // aes64es
        r_type(0x1b, 2, 1, 0, 5),         // aes64esm
        r_type(0x1d, 2, 1, 0, 5),         // aes64ds
        r_type(0x1f, 2, 1, 0, 5),         // aes64dsm
        r_type(0x3f, 2, 1, 0, 5),         // aes64ks2
        i_type(0x18 << 5, 1, 1, 5, 0x13), // aes64im
    ] {
        run_case(&instruction.to_le_bytes(), x, memory);
    }

    for bs in 0..4u32 {
        for instruction in [
            r_type((bs << 5) | 0x18, 2, 1, 0, 5), // sm4ed
            r_type((bs << 5) | 0x1a, 2, 1, 0, 5), // sm4ks
        ] {
            run_case(&instruction.to_le_bytes(), x, memory);
        }
    }
    for round in 0..=0xau32 {
        let instruction = i_type((0x18 << 5) | 0x10 | round as i32, 1, 1, 5, 0x13);
        run_case(&instruction.to_le_bytes(), x, memory);
    }
}

#[test]
fn lifted_rv32_integer_crypto_executes_through_helper_abi() {
    let mut x = [0u64; 32];
    x[1] = 0x89ab_cdef;
    x[2] = 0x7654_3210;
    let memory = [0u8; MEMORY_LEN];

    for instruction in [
        r_type(0x05, 2, 1, 1, 5), // clmul
        r_type(0x05, 2, 1, 2, 5), // clmulr
        r_type(0x05, 2, 1, 3, 5), // clmulh
        r_type(0x14, 2, 1, 2, 5), // xperm4
        r_type(0x14, 2, 1, 4, 5), // xperm8
        r_type(0x28, 2, 1, 0, 5), // sha512sum0r
        r_type(0x29, 2, 1, 0, 5), // sha512sum1r
        r_type(0x2a, 2, 1, 0, 5), // sha512sig0l
        r_type(0x2b, 2, 1, 0, 5), // sha512sig1l
        r_type(0x2e, 2, 1, 0, 5), // sha512sig0h
        r_type(0x2f, 2, 1, 0, 5), // sha512sig1h
    ] {
        run_case_rv32(&instruction.to_le_bytes(), x, memory);
    }

    for bs in 0..4u32 {
        for low_funct7 in [0x11, 0x13, 0x15, 0x17] {
            let instruction = r_type((bs << 5) | low_funct7, 2, 1, 0, 5);
            run_case_rv32(&instruction.to_le_bytes(), x, memory);
        }
        for instruction in [
            r_type((bs << 5) | 0x18, 2, 1, 0, 5), // sm4ed
            r_type((bs << 5) | 0x1a, 2, 1, 0, 5), // sm4ks
        ] {
            run_case_rv32(&instruction.to_le_bytes(), x, memory);
        }
    }
}

#[test]
fn integer_crypto_lowering_rejects_malformed_opaque_ops() {
    for (op, xlen, expected) in [
        (RvOp::Add, 64, "helper operation Add"),
        (RvOp::Clmul, 16, "XLEN 16"),
    ] {
        let opaque = SmirOp::new(
            OpId(0),
            CODE,
            OpKind::RvIntCrypto {
                dst: VReg::Arch(ArchReg::RiscV(RiscVReg::X(5))),
                src1: VReg::Imm(1),
                src2: VReg::Imm(2),
                op,
                imm: 0,
                xlen,
            },
        );
        let (function, return_pcs) = function_for_lift(ControlFlow::NextInsn, vec![opaque], 4);
        let mut lowerer = RiscVX86_64Lowerer::new();
        lowerer.set_return_pcs(return_pcs);
        let error = lowerer
            .lower_function(&function)
            .expect_err("malformed opaque crypto op must fail closed");
        assert!(
            format!("{error:?}").contains(expected),
            "unexpected malformed-op error: {error:?}"
        );
    }
}

fn assert_production_cpu_equivalent(actual: &RiscVCpu, expected: &RiscVCpu) {
    for register in 0..32u8 {
        assert_eq!(actual.x(register), expected.x(register), "x{register}");
        assert_eq!(actual.f(register), expected.f(register), "f{register}");
        assert_eq!(
            actual.vreg(register),
            expected.vreg(register),
            "v{register}"
        );
    }
    assert_eq!(actual.pc(), expected.pc(), "PC");
    assert_eq!(actual.fcsr(), expected.fcsr(), "FCSR");
    assert_eq!(actual.vl(), expected.vl(), "vl");
    assert_eq!(actual.vtype(), expected.vtype(), "vtype");
    assert_eq!(actual.vstart(), expected.vstart(), "vstart");
    assert_eq!(actual.vcsr(), expected.vcsr(), "vcsr");
    assert_eq!(actual.privilege(), expected.privilege(), "privilege");
    assert_eq!(actual.instret(), expected.instret(), "instret");
    for csr in [0x017, 0xc00, 0x341, 0x342, 0x343] {
        assert_eq!(
            actual.csr_read(csr),
            expected.csr_read(csr),
            "CSR {csr:#05x}"
        );
    }
    let mut actual_memory = vec![0u8; MEMORY_LEN];
    let mut expected_memory = vec![0u8; MEMORY_LEN];
    actual
        .read_memory(0, &mut actual_memory)
        .expect("read JIT memory");
    expected
        .read_memory(0, &mut expected_memory)
        .expect("read interpreter memory");
    assert_eq!(actual_memory, expected_memory, "guest memory");
}

fn write_production_code(cpu: &mut RiscVCpu, instructions: &[u32]) {
    let code = instructions
        .iter()
        .flat_map(|instruction| instruction.to_le_bytes())
        .collect::<Vec<_>>();
    cpu.write_memory(CODE, &code)
        .expect("write production code");
    cpu.set_pc(CODE);
}

#[test]
fn production_run_jit_regions_match_interpreter_x86_64() {
    let instructions = vec![i_type(1, 5, 0, 5, 0x13); 20]; // addi x5,x5,1
    for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
        let make_cpu = || {
            RiscVCpu::new(
                RiscVConfig::rv64gc(),
                Box::new(RvMemory::new(0, MEMORY_LEN)),
            )
        };
        let mut expected = make_cpu();
        let mut actual = make_cpu();
        write_production_code(&mut expected, &instructions);
        write_production_code(&mut actual, &instructions);

        assert_eq!(expected.run(instructions.len() as u64), RiscVExit::Continue);
        assert_eq!(
            actual.run_jit(instructions.len() as u64, level),
            RiscVExit::Continue
        );
        assert_production_cpu_equivalent(&actual, &expected);
        assert_eq!(actual.x(5), 20);
        assert_eq!(actual.pc(), CODE + 80);
        let stats = actual.jit_stats();
        assert_eq!(stats.cache_entries, 2, "{level:?}");
        assert_eq!(stats.native_executions, 2, "{level:?}");
        assert_eq!(stats.interpreter_fallbacks, 0, "{level:?}");
    }
}

#[test]
fn production_run_jit_region_fault_is_precise_x86_64() {
    let instructions = [
        i_type(7, 5, 0, 5, 0x13),     // addi x5,x5,7
        i_type(0, 1, 0b011, 5, 0x03), // ld x5,0(x1)
    ];
    let make_cpu = || {
        RiscVCpu::new(
            RiscVConfig::rv64gc(),
            Box::new(RvMemory::new(0, MEMORY_LEN)),
        )
    };
    let mut expected = make_cpu();
    let mut actual = make_cpu();
    for cpu in [&mut expected, &mut actual] {
        write_production_code(cpu, &instructions);
        cpu.set_x(1, MEMORY_LEN as u64 - 4);
        cpu.set_x(5, 10);
    }

    let expected_exit = expected.run(2);
    let actual_exit = actual.run_jit(2, OptLevel::O2);
    assert_eq!(
        actual_exit,
        RiscVExit::Trap(rax::isa::riscv::Trap {
            cause: 5,
            tval: MEMORY_LEN as u64 - 4,
        })
    );
    assert_eq!(actual_exit, expected_exit);
    assert_production_cpu_equivalent(&actual, &expected);
    assert_eq!(actual.x(5), 17);
    assert_eq!(actual.instret(), 1);
    assert_eq!(actual.csr_read(0xc00), Ok(2));
    assert_eq!(actual.jit_stats().native_executions, 1);
    assert_eq!(actual.jit_stats().interpreter_fallbacks, 0);
}

#[test]
fn production_jit_cache_keys_code_identity_and_optimization_level() {
    let mut cpu = RiscVCpu::new(
        RiscVConfig::rv64gc(),
        Box::new(RvMemory::new(0, MEMORY_LEN)),
    );
    let add_five = i_type(5, 5, 0, 5, 0x13);
    cpu.write_memory(CODE, &add_five.to_le_bytes())
        .expect("write addi");
    cpu.set_x(5, 10);

    for expected in [15, 20] {
        cpu.set_pc(CODE);
        assert_eq!(cpu.step_jit(OptLevel::O2), RiscVExit::Continue);
        assert_eq!(cpu.x(5), expected);
    }
    let stats = cpu.jit_stats();
    assert_eq!(stats.cache_entries, 1);
    assert_eq!(stats.cache_misses, 1);
    assert_eq!(stats.cache_hits, 1);
    assert_eq!(stats.native_executions, 2);
    assert_eq!(stats.interpreter_fallbacks, 0);

    let add_seven = i_type(7, 5, 0, 5, 0x13);
    cpu.write_memory(CODE, &add_seven.to_le_bytes())
        .expect("replace addi");
    cpu.set_pc(CODE);
    assert_eq!(cpu.step_jit(OptLevel::O2), RiscVExit::Continue);
    assert_eq!(cpu.x(5), 27);
    cpu.set_pc(CODE);
    assert_eq!(cpu.step_jit(OptLevel::O0), RiscVExit::Continue);
    assert_eq!(cpu.x(5), 34);
    let stats = cpu.jit_stats();
    assert_eq!(stats.cache_entries, 3);
    assert_eq!(stats.cache_misses, 3);
    assert_eq!(stats.cache_hits, 1);
    assert_eq!(stats.native_executions, 4);

    cpu.clear_jit_cache();
    assert_eq!(cpu.jit_stats(), Default::default());
    cpu.set_pc(CODE);
    assert_eq!(cpu.run_jit(1, OptLevel::O1), RiscVExit::Continue);
    assert_eq!(cpu.x(5), 41);
    let stats = cpu.jit_stats();
    assert_eq!(stats.cache_entries, 1);
    assert_eq!(stats.cache_misses, 1);
    assert_eq!(stats.native_executions, 1);
}

#[test]
fn production_jit_matches_interpreter_for_helpers_and_native_op_v() {
    const E32_M1: u64 = 0x10;
    let instructions = [
        amo_type(0b00010, true, false, 0, 1, 0b010, 3), // lr.w x3,(x1)
        amo_type(0b00011, false, true, 2, 1, 0b010, 4), // sc.w x4,x2,(x1)
        amo_type(0b00000, true, true, 2, 1, 0b010, 5),  // amoadd.w x5,x2,(x1)
        r_type_opcode(0, 2, 1, 0, 3, 0x53),             // fadd.s f3,f1,f2
        v_type(0b000000, 1, 2, 3, 0, 1),                // vadd.vv v1,v2,v3
    ];
    let make_cpu = || {
        RiscVCpu::new(
            RiscVConfig::rv64gc(),
            Box::new(RvMemory::new(0, MEMORY_LEN)),
        )
    };
    let mut expected = make_cpu();
    let mut actual = make_cpu();
    for cpu in [&mut expected, &mut actual] {
        cpu.csr_write(0x300, 0b01 << 13)
            .expect("production FP state must be enabled");
        write_production_code(cpu, &instructions);
        cpu.set_x(1, DATA);
        cpu.set_x(2, 7);
        cpu.write_memory(DATA, &5u32.to_le_bytes())
            .expect("seed atomic word");
        cpu.set_f(1, 0xffff_ffff_3fc0_0000); // 1.5f32, NaN-boxed
        cpu.set_f(2, 0xffff_ffff_4010_0000); // 2.25f32, NaN-boxed
        cpu.set_vl_vtype(2, E32_M1);
        let mut v2 = [0u8; 16];
        v2[0..4].copy_from_slice(&1u32.to_le_bytes());
        v2[4..8].copy_from_slice(&2u32.to_le_bytes());
        let mut v3 = [0u8; 16];
        v3[0..4].copy_from_slice(&10u32.to_le_bytes());
        v3[4..8].copy_from_slice(&20u32.to_le_bytes());
        cpu.set_vreg(2, &v2);
        cpu.set_vreg(3, &v3);
    }

    for instruction in instructions {
        assert_eq!(expected.step(), RiscVExit::Continue, "{instruction:08x}");
        assert_eq!(
            actual.step_jit(OptLevel::O2),
            RiscVExit::Continue,
            "{instruction:08x}"
        );
        assert_production_cpu_equivalent(&actual, &expected);
    }
    let stats = actual.jit_stats();
    assert_eq!(stats.cache_entries, instructions.len());
    assert_eq!(stats.cache_misses, instructions.len() as u64);
    assert_eq!(stats.native_executions, 4);
    assert_eq!(stats.interpreter_fallbacks, 1);
}

#[test]
fn production_jit_keeps_vector_memory_on_the_interpreter_boundary() {
    const E32_M1: u64 = 0x10;
    let instruction = (1 << 25) | (10 << 15) | (6 << 12) | (1 << 7) | 0x07; // vle32.v
    let make_cpu = || {
        RiscVCpu::new(
            RiscVConfig::rv64gc(),
            Box::new(RvMemory::new(0, MEMORY_LEN)),
        )
    };
    let mut expected = make_cpu();
    let mut actual = make_cpu();
    for cpu in [&mut expected, &mut actual] {
        write_production_code(cpu, &[instruction]);
        cpu.set_x(10, DATA);
        cpu.set_vl_vtype(2, E32_M1);
        cpu.write_memory(DATA, &0x1122_3344u32.to_le_bytes())
            .expect("seed vector lane zero");
        cpu.write_memory(DATA + 4, &0x5566_7788u32.to_le_bytes())
            .expect("seed vector lane one");
    }

    assert_eq!(expected.step(), RiscVExit::Continue);
    assert_eq!(actual.step_jit(OptLevel::O2), RiscVExit::Continue);
    assert_production_cpu_equivalent(&actual, &expected);
    let stats = actual.jit_stats();
    assert_eq!(stats.native_executions, 0);
    assert_eq!(stats.interpreter_fallbacks, 1);
}

#[test]
fn production_jit_matches_interpreter_for_amocas_q() {
    let instruction = amo_type(0b00101, true, true, 8, 10, 0b100, 6);
    let old = [0x0123_4567_89ab_cdefu64, 0xfedc_ba98_7654_3210u64];
    let new = [0x1111_2222_3333_4444u64, 0x5555_6666_7777_8888u64];

    for (level, success) in [
        (OptLevel::O0, false),
        (OptLevel::O0, true),
        (OptLevel::O2, false),
        (OptLevel::O2, true),
    ] {
        let make_cpu = || {
            RiscVCpu::new(
                RiscVConfig::rv64gc(),
                Box::new(RvMemory::new(0, MEMORY_LEN)),
            )
        };
        let mut expected = make_cpu();
        let mut actual = make_cpu();
        for cpu in [&mut expected, &mut actual] {
            write_production_code(cpu, &[instruction]);
            cpu.set_x(10, DATA);
            cpu.set_x(6, if success { old[0] } else { !old[0] });
            cpu.set_x(7, old[1]);
            cpu.set_x(8, new[0]);
            cpu.set_x(9, new[1]);
            cpu.write_memory(DATA, &old[0].to_le_bytes())
                .expect("seed AMOCAS.Q low word");
            cpu.write_memory(DATA + 8, &old[1].to_le_bytes())
                .expect("seed AMOCAS.Q high word");
        }

        assert_eq!(expected.step(), RiscVExit::Continue);
        assert_eq!(actual.step_jit(level), RiscVExit::Continue);
        assert_production_cpu_equivalent(&actual, &expected);
        let stats = actual.jit_stats();
        assert_eq!(stats.native_executions, 1, "{level:?}, success={success}");
        assert_eq!(
            stats.interpreter_fallbacks, 0,
            "{level:?}, success={success}"
        );
    }
}

#[test]
fn production_jit_delivers_precise_native_memory_faults_without_replay() {
    let load = i_type(0, 1, 0b010, 5, 0x03); // lw x5,0(x1)
    let make_cpu = || {
        RiscVCpu::new(
            RiscVConfig::rv64gc(),
            Box::new(RvMemory::new(0, MEMORY_LEN)),
        )
    };
    let mut expected = make_cpu();
    let mut actual = make_cpu();
    for cpu in [&mut expected, &mut actual] {
        write_production_code(cpu, &[load]);
        cpu.set_x(1, MEMORY_LEN as u64 - 2);
        cpu.set_x(5, 0xfeed_face_cafe_beef);
    }

    let expected_exit = expected.step();
    let actual_exit = actual.step_jit(OptLevel::O2);
    assert_eq!(
        actual_exit,
        RiscVExit::Trap(rax::isa::riscv::Trap {
            cause: 5,
            tval: MEMORY_LEN as u64 - 2,
        })
    );
    assert_eq!(actual_exit, expected_exit);
    assert_production_cpu_equivalent(&actual, &expected);
    let stats = actual.jit_stats();
    assert_eq!(stats.native_executions, 1);
    assert_eq!(stats.interpreter_fallbacks, 0);
}

#[test]
fn production_jit_wraps_rv32_effective_addresses() {
    let load = i_type(1, 1, 0b100, 5, 0x03); // lbu x5,1(x1)
    let make_cpu = || {
        RiscVCpu::new(
            RiscVConfig::rv32(RvIsa::rv64gc()),
            Box::new(RvMemory::new(0, MEMORY_LEN)),
        )
    };
    let mut expected = make_cpu();
    let mut actual = make_cpu();
    for cpu in [&mut expected, &mut actual] {
        write_production_code(cpu, &[load]);
        cpu.set_x(1, 0xffff_ffff);
        cpu.write_memory(0, &[0xab]).expect("seed wrapped byte");
    }

    assert_eq!(expected.step(), RiscVExit::Continue);
    assert_eq!(actual.step_jit(OptLevel::O2), RiscVExit::Continue);
    assert_production_cpu_equivalent(&actual, &expected);
    assert_eq!(actual.x(5), 0xab);
    assert_eq!(actual.jit_stats().native_executions, 1);
}

#[test]
fn production_jit_executes_zilsd_pairs_natively() {
    let mut isa = RvIsa::rv64gc();
    isa.zilsd = true;
    let load_pair = (8u32 << 20) | (10 << 15) | (3 << 12) | (6 << 7) | 0x03;
    let store_pair = s_type(16, 6, 10, 3);
    let discard_pair = (8u32 << 20) | (10 << 15) | (3 << 12) | 0x03;
    let store_zero_pair = s_type(24, 0, 10, 3);
    for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
        let make_cpu = || {
            RiscVCpu::new(
                RiscVConfig::rv32(isa),
                Box::new(RvMemory::new(0, MEMORY_LEN)),
            )
        };
        let mut expected = make_cpu();
        let mut actual = make_cpu();
        for cpu in [&mut expected, &mut actual] {
            write_production_code(cpu, &[load_pair, store_pair, discard_pair, store_zero_pair]);
            cpu.set_x(1, 0xfeed_face);
            cpu.set_x(10, DATA);
            cpu.write_memory(DATA + 8, &0xaabb_ccdd_1122_3344u64.to_le_bytes())
                .expect("seed Zilsd pair");
            cpu.write_memory(DATA + 24, &u64::MAX.to_le_bytes())
                .expect("seed zero-store destination");
        }

        assert_eq!(expected.run(4), RiscVExit::Continue);
        assert_eq!(actual.run_jit(4, level), RiscVExit::Continue);
        assert_production_cpu_equivalent(&actual, &expected);
        assert_eq!(actual.x(1), 0xfeed_face, "{level:?}");
        assert_eq!(actual.x(6), 0x1122_3344, "{level:?}");
        assert_eq!(actual.x(7), 0xaabb_ccdd, "{level:?}");
        let mut stored = [0; 8];
        actual
            .read_memory(DATA + 16, &mut stored)
            .expect("read stored Zilsd pair");
        assert_eq!(u64::from_le_bytes(stored), 0xaabb_ccdd_1122_3344);
        actual
            .read_memory(DATA + 24, &mut stored)
            .expect("read x0 pair store");
        assert_eq!(u64::from_le_bytes(stored), 0);
        let stats = actual.jit_stats();
        assert_eq!(stats.native_executions, 4, "{level:?}");
        assert_eq!(stats.interpreter_fallbacks, 0, "{level:?}");
    }
}

#[test]
fn production_jit_executes_zcmp_double_moves_natively() {
    let mut isa = RvIsa::rv64gc();
    isa.zcmp = true;
    let cm_move =
        |funct2: u16| (0b101 << 13) | (0b011 << 10) | (0 << 7) | (funct2 << 5) | (2 << 2) | 0b10;
    let instructions = [cm_move(0b01), cm_move(0b11)]; // x10/x11 <-> x8/x18
    let bytes = instructions
        .into_iter()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();

    for config in [
        RiscVConfig::rv32(isa),
        RiscVConfig {
            xlen: RvXlen::Rv64,
            isa,
        },
    ] {
        for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
            let make_cpu = || RiscVCpu::new(config, Box::new(RvMemory::new(0, MEMORY_LEN)));
            let mut expected = make_cpu();
            let mut actual = make_cpu();
            for cpu in [&mut expected, &mut actual] {
                cpu.write_memory(CODE, &bytes).expect("write Zcmp code");
                cpu.set_pc(CODE);
                cpu.set_x(8, 0x1111_2222_3333_4444);
                cpu.set_x(18, 0x5555_6666_7777_8888);
                cpu.set_x(10, 0x0123_4567_89ab_cdef);
                cpu.set_x(11, 0xfedc_ba98_7654_3210);
            }

            assert_eq!(expected.run(2), RiscVExit::Continue);
            assert_eq!(actual.run_jit(2, level), RiscVExit::Continue);
            assert_production_cpu_equivalent(&actual, &expected);
            assert_eq!(actual.x(8), actual.x(10), "{:?} {level:?}", config.xlen);
            assert_eq!(actual.x(18), actual.x(11), "{:?} {level:?}", config.xlen);
            assert_eq!(actual.pc(), CODE + 4);
            let stats = actual.jit_stats();
            assert_eq!(stats.native_executions, 1, "{:?} {level:?}", config.xlen);
            assert_eq!(
                stats.interpreter_fallbacks, 0,
                "{:?} {level:?}",
                config.xlen
            );
        }
    }
}

#[test]
fn production_jit_executes_zcmp_stack_macros_natively() {
    let mut isa = RvIsa::rv64gc();
    isa.zcmp = true;
    let stack = |funct5: u16| (0b101 << 13) | (funct5 << 8) | (5 << 4) | (0 << 2) | 0b10;
    let push = stack(0x18); // cm.push {ra,s0},-16
    let popretz = stack(0x1c);

    for config in [
        RiscVConfig::rv32(isa),
        RiscVConfig {
            xlen: RvXlen::Rv64,
            isa,
        },
    ] {
        for level in [OptLevel::O0, OptLevel::O1, OptLevel::O2] {
            let make_cpu = || RiscVCpu::new(config, Box::new(RvMemory::new(0, MEMORY_LEN)));
            let mut expected = make_cpu();
            let mut actual = make_cpu();
            for cpu in [&mut expected, &mut actual] {
                cpu.write_memory(CODE, &push.to_le_bytes())
                    .expect("write Zcmp push");
                cpu.set_pc(CODE);
                cpu.set_x(1, CODE + 0x101);
                cpu.set_x(2, DATA + 0x200);
                cpu.set_x(8, 0x1111_2222_3333_4444);
                cpu.set_x(9, 0x5555_6666_7777_8888);
                cpu.set_x(10, 0xfeed_face);
            }
            assert_eq!(expected.step(), RiscVExit::Continue);
            assert_eq!(actual.step_jit(level), RiscVExit::Continue);
            assert_production_cpu_equivalent(&actual, &expected);

            for cpu in [&mut expected, &mut actual] {
                cpu.write_memory(CODE, &popretz.to_le_bytes())
                    .expect("write Zcmp popretz");
                cpu.set_pc(CODE);
                cpu.set_x(1, 1);
                cpu.set_x(8, 2);
                cpu.set_x(9, 3);
            }
            assert_eq!(expected.step(), RiscVExit::Continue);
            assert_eq!(actual.step_jit(level), RiscVExit::Continue);
            assert_production_cpu_equivalent(&actual, &expected);
            assert_eq!(actual.pc(), CODE + 0x100);
            assert_eq!(actual.x(10), 0);
            let mask = if config.xlen == RvXlen::Rv32 {
                u64::from(u32::MAX)
            } else {
                u64::MAX
            };
            assert_eq!(actual.x(8), 0x1111_2222_3333_4444 & mask);
            assert_eq!(actual.x(9), 3, "{:?} {level:?}", config.xlen);
            let stats = actual.jit_stats();
            assert_eq!(stats.native_executions, 2, "{:?} {level:?}", config.xlen);
            assert_eq!(
                stats.interpreter_fallbacks, 0,
                "{:?} {level:?}",
                config.xlen
            );
        }
    }
}

#[test]
fn production_jit_executes_zcmt_table_jumps_natively() {
    let mut isa = RvIsa::rv64gc();
    isa.zcmt = true;
    let cm_jt = ((0b101 << 13) | (17 << 2) | 0b10) as u16;
    let cm_jalt = ((0b101 << 13) | (32 << 2) | 0b10) as u16;

    for config in [
        RiscVConfig::rv32(isa),
        RiscVConfig {
            xlen: RvXlen::Rv64,
            isa,
        },
    ] {
        let make_cpu = || RiscVCpu::new(config, Box::new(RvMemory::new(0, MEMORY_LEN)));
        let mut expected = make_cpu();
        let mut actual = make_cpu();
        let entry_size = if config.xlen == RvXlen::Rv32 { 4 } else { 8 };
        for cpu in [&mut expected, &mut actual] {
            cpu.write_memory(CODE, &cm_jt.to_le_bytes())
                .expect("write cm.jt");
            cpu.set_pc(CODE);
            cpu.csr_write(0x017, DATA | 0x3f).expect("write WARL jvt");
            cpu.set_x(1, 0xfeed_face);
            let target = CODE + 0x201;
            cpu.write_memory(
                DATA + 17 * entry_size,
                &target.to_le_bytes()[..entry_size as usize],
            )
            .expect("write cm.jt target");
        }
        assert_eq!(expected.step(), RiscVExit::Continue);
        assert_eq!(actual.step_jit(OptLevel::O2), RiscVExit::Continue);
        assert_production_cpu_equivalent(&actual, &expected);
        assert_eq!(actual.pc(), CODE + 0x200);
        assert_eq!(actual.x(1), 0xfeed_face);

        for cpu in [&mut expected, &mut actual] {
            cpu.write_memory(CODE, &cm_jalt.to_le_bytes())
                .expect("write cm.jalt");
            cpu.set_pc(CODE);
            let target = CODE + 0x301;
            cpu.write_memory(
                DATA + 32 * entry_size,
                &target.to_le_bytes()[..entry_size as usize],
            )
            .expect("write cm.jalt target");
        }
        assert_eq!(expected.step(), RiscVExit::Continue);
        assert_eq!(actual.step_jit(OptLevel::O2), RiscVExit::Continue);
        assert_production_cpu_equivalent(&actual, &expected);
        assert_eq!(actual.pc(), CODE + 0x300);
        assert_eq!(actual.x(1), CODE + 2);
        let stats = actual.jit_stats();
        assert_eq!(stats.native_executions, 2, "{:?}", config.xlen);
        assert_eq!(stats.interpreter_fallbacks, 0, "{:?}", config.xlen);
    }

    let config = RiscVConfig {
        xlen: RvXlen::Rv64,
        isa,
    };
    let csrrw_jvt = i_type(0x017, 5, 0b001, 6, 0x73);
    let mut code = csrrw_jvt.to_le_bytes().to_vec();
    code.extend_from_slice(&cm_jt.to_le_bytes());
    let make_cpu = || RiscVCpu::new(config, Box::new(RvMemory::new(0, MEMORY_LEN)));
    let mut expected = make_cpu();
    let mut actual = make_cpu();
    for cpu in [&mut expected, &mut actual] {
        cpu.write_memory(CODE, &code)
            .expect("write jvt CSR plus cm.jt");
        cpu.set_pc(CODE);
        cpu.set_x(5, DATA | 0x3f);
        cpu.set_x(6, 0xfeed_face);
        cpu.write_memory(DATA + 17 * 8, &(CODE + 0x400).to_le_bytes())
            .expect("write CSR-configured cm.jt target");
    }
    assert_eq!(expected.run(2), RiscVExit::Continue);
    assert_eq!(actual.run_jit(2, OptLevel::O2), RiscVExit::Continue);
    assert_production_cpu_equivalent(&actual, &expected);
    assert_eq!(actual.x(6), 0);
    assert_eq!(actual.csr_read(0x017), Ok(DATA));
    assert_eq!(actual.pc(), CODE + 0x400);
    assert_eq!(actual.jit_stats().native_executions, 2);
    assert_eq!(actual.jit_stats().interpreter_fallbacks, 0);

    let make_cpu = || RiscVCpu::new(config, Box::new(RvMemory::new(0, MEMORY_LEN)));
    let mut expected = make_cpu();
    let mut actual = make_cpu();
    for cpu in [&mut expected, &mut actual] {
        cpu.write_memory(CODE, &cm_jalt.to_le_bytes())
            .expect("write faulting cm.jalt");
        cpu.set_pc(CODE);
        cpu.csr_write(0x017, MEMORY_LEN as u64 - 64)
            .expect("write out-of-range jvt base");
        cpu.set_x(1, 0xfeed_face);
    }
    let expected_exit = expected.step();
    let actual_exit = actual.step_jit(OptLevel::O2);
    assert_eq!(actual_exit, expected_exit);
    assert_production_cpu_equivalent(&actual, &expected);
    assert_eq!(actual.csr_read(0x342), Ok(1));
    assert_eq!(actual.csr_read(0x343), Ok(MEMORY_LEN as u64 - 64 + 32 * 8));
    assert_eq!(actual.x(1), 0xfeed_face);
    assert_eq!(actual.jit_stats().native_executions, 1);
    assert_eq!(actual.jit_stats().interpreter_fallbacks, 0);
}

#[test]
fn production_jit_falls_back_for_unmodeled_control_alignment_traps() {
    let mut isa = RvIsa::rv64gc();
    isa.c = false;
    let make_cpu = || {
        RiscVCpu::new(
            RiscVConfig {
                xlen: RvXlen::Rv64,
                isa,
            },
            Box::new(RvMemory::new(0, MEMORY_LEN)),
        )
    };
    for instruction in [
        j_type(2, 1),           // jal x1,+2
        b_type(2, 0, 0, 0b000), // beq x0,x0,+2
    ] {
        let mut expected = make_cpu();
        let mut actual = make_cpu();
        write_production_code(&mut expected, &[instruction]);
        write_production_code(&mut actual, &[instruction]);

        let expected_exit = expected.step();
        let actual_exit = actual.step_jit(OptLevel::O2);
        assert_eq!(
            actual_exit,
            RiscVExit::Trap(rax::isa::riscv::Trap {
                cause: 0,
                tval: CODE + 2,
            })
        );
        assert_eq!(actual_exit, expected_exit);
        assert_production_cpu_equivalent(&actual, &expected);
        let stats = actual.jit_stats();
        assert_eq!(stats.cache_entries, 1);
        assert_eq!(stats.native_executions, 0);
        assert_eq!(stats.interpreter_fallbacks, 1);
    }
}

#[test]
fn runtime_layout_matches_codegen_offsets() {
    assert_eq!(RiscVGuestRegs::X_OFFSET, 0);
    assert_eq!(RiscVGuestRegs::F_OFFSET, 32 * 8);
    assert_eq!(RiscVGuestRegs::PC_OFFSET, 64 * 8);
    assert_eq!(RiscVGuestRegs::FCSR_OFFSET, 65 * 8);
    assert_eq!(RiscVGuestRegs::EXIT_REASON_OFFSET, 66 * 8);
    assert_eq!(RiscVGuestRegs::CTX_OFFSET, 67 * 8);
    assert_eq!(RiscVGuestRegs::LOAD_FN_OFFSET, 68 * 8);
    assert_eq!(RiscVGuestRegs::STORE_FN_OFFSET, 69 * 8);
    assert_eq!(RiscVGuestRegs::ATOMIC_RMW_FN_OFFSET, 70 * 8);
    assert_eq!(RiscVGuestRegs::CAS_FN_OFFSET, 71 * 8);
    assert_eq!(RiscVGuestRegs::CAS_PAIR_FN_OFFSET, 72 * 8);
    assert_eq!(RiscVGuestRegs::LOAD_EXCLUSIVE_FN_OFFSET, 73 * 8);
    assert_eq!(RiscVGuestRegs::STORE_EXCLUSIVE_FN_OFFSET, 74 * 8);
    assert_eq!(RiscVGuestRegs::CLEAR_EXCLUSIVE_FN_OFFSET, 75 * 8);
    assert_eq!(RiscVGuestRegs::INT_CRYPTO_FN_OFFSET, 76 * 8);
    assert_eq!(RiscVGuestRegs::FP_FN_OFFSET, 77 * 8);
    assert_eq!(RiscVGuestRegs::V_OFFSET, 78 * 8);
    assert_eq!(RiscVGuestRegs::VL_OFFSET, 142 * 8);
    assert_eq!(RiscVGuestRegs::VTYPE_OFFSET, 143 * 8);
    assert_eq!(RiscVGuestRegs::VSTART_OFFSET, 144 * 8);
    assert_eq!(RiscVGuestRegs::VCSR_OFFSET, 145 * 8);
    assert_eq!(RiscVGuestRegs::VECTOR_FN_OFFSET, 146 * 8);
    assert_eq!(RiscVGuestRegs::JVT_OFFSET, 147 * 8);
    assert_eq!(std::mem::size_of::<RiscVGuestRegs>(), 148 * 8);
    assert_eq!(std::mem::size_of::<RiscVAtomicCasResult>(), 2 * 8);
    assert_eq!(std::mem::size_of::<RiscVAtomicResult>(), 2 * 8);
    assert_eq!(std::mem::size_of::<RiscVLoadResult>(), 2 * 8);
    assert_eq!(std::mem::size_of::<RiscVFpResult>(), 2 * 8);
}
