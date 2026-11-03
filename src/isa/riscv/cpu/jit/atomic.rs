//! Native RISC-V atomic helpers; ABI entry wrappers remain in the parent.
use super::{JitContext, RiscVAtomicCasResult, RiscVAtomicCasStatus, RiscVAtomicResult, cause};
use crate::isa::riscv::memory::AtomicOp;

fn decode_order(order: u64) -> Option<u64> {
    (order <= 4).then_some(order)
}

fn fence_before(order: u64) {
    use std::sync::atomic::{Ordering, fence};
    match order {
        2 | 3 => fence(Ordering::Release),
        4 => fence(Ordering::SeqCst),
        _ => {}
    }
}

fn fence_after(order: u64) {
    use std::sync::atomic::{Ordering, fence};
    match order {
        1 | 3 => fence(Ordering::Acquire),
        4 => fence(Ordering::SeqCst),
        _ => {}
    }
}

pub(super) unsafe fn jit_atomic_rmw_impl(
    ctx: u64,
    addr: u64,
    operand: u64,
    size: u64,
    op: u64,
    order: u64,
) -> RiscVAtomicResult {
    let Some(context) = (unsafe { JitContext::from_abi(ctx) }) else {
        return RiscVAtomicResult::default();
    };
    let addr = context.normalize_addr(addr);
    if !matches!(size, 4 | 8) || addr % size != 0 || decode_order(order).is_none() || op > 11 {
        context.record_fault(cause::STORE_MISALIGNED, addr);
        return RiscVAtomicResult::default();
    }
    let operation = match op {
        0 => AtomicOp::Add(operand),
        1 => AtomicOp::Subtract(operand),
        2 => AtomicOp::Negate,
        3 => AtomicOp::And(operand),
        4 => AtomicOp::Or(operand),
        5 => AtomicOp::Xor(operand),
        6 => AtomicOp::Nand(operand),
        7 => AtomicOp::SignedMax(operand),
        8 => AtomicOp::SignedMin(operand),
        9 => AtomicOp::UnsignedMax(operand),
        10 => AtomicOp::UnsignedMin(operand),
        11 => AtomicOp::Exchange(operand),
        _ => unreachable!(),
    };
    fence_before(order);
    // SAFETY: this synchronous helper retains the stack-owned memory borrow.
    let old = match unsafe { context.memory() }.atomic(addr, size as u8, operation) {
        Ok(old) => old,
        Err(_) => {
            context.record_fault(cause::STORE_ACCESS_FAULT, addr);
            return RiscVAtomicResult::default();
        }
    };
    fence_after(order);
    RiscVAtomicResult {
        value: old as u64,
        access_success: 1,
    }
}

pub(super) unsafe fn jit_compare_and_swap_impl(
    ctx: u64,
    addr: u64,
    expected: u64,
    new_value: u64,
    size: u64,
    order: u64,
) -> RiscVAtomicCasResult {
    let Some(context) = (unsafe { JitContext::from_abi(ctx) }) else {
        return RiscVAtomicCasResult::default();
    };
    let addr = context.normalize_addr(addr);
    if !matches!(size, 4 | 8) || addr % size != 0 || decode_order(order).is_none() {
        context.record_fault(cause::STORE_MISALIGNED, addr);
        return RiscVAtomicCasResult::default();
    }
    let mask = if size == 8 {
        u64::MAX
    } else {
        u64::from(u32::MAX)
    };
    let operation = AtomicOp::CompareExchange {
        expected: u128::from(expected & mask),
        replacement: u128::from(new_value & mask),
    };
    fence_before(order);
    // SAFETY: the native region exclusively borrows its context's memory.
    let old = match unsafe { context.memory() }.atomic(addr, size as u8, operation) {
        Ok(old) => old as u64,
        Err(_) => {
            context.record_fault(cause::STORE_ACCESS_FAULT, addr);
            return RiscVAtomicCasResult::default();
        }
    };
    fence_after(order);
    RiscVAtomicCasResult {
        old,
        status: if old == expected & mask {
            RiscVAtomicCasStatus::Swapped
        } else {
            RiscVAtomicCasStatus::CompareFailed
        } as u64,
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) unsafe fn jit_compare_and_swap_pair_impl(
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
    let Some(context) = (unsafe { JitContext::from_abi(ctx) }) else {
        return RiscVAtomicCasResult::default();
    };
    let addr = context.normalize_addr(addr);
    let required_failure_order = if matches!(order, 1 | 3 | 4) { 1 } else { 0 };
    if addr % 16 != 0 {
        context.record_fault(cause::STORE_MISALIGNED, addr);
        return RiscVAtomicCasResult::default();
    }
    if decode_order(order).is_none()
        || failure_order != required_failure_order
        || out_old_hi.is_null()
    {
        context.record_fault(cause::STORE_ACCESS_FAULT, addr);
        return RiscVAtomicCasResult::default();
    }
    let expected = u128::from(expected_lo) | (u128::from(expected_hi) << 64);
    let replacement = u128::from(new_lo) | (u128::from(new_hi) << 64);
    fence_before(order);
    // SAFETY: the native region retains the context until this helper returns.
    let old = match unsafe { context.memory() }.atomic(
        addr,
        16,
        AtomicOp::CompareExchange {
            expected,
            replacement,
        },
    ) {
        Ok(old) => old,
        Err(_) => {
            context.record_fault(cause::STORE_ACCESS_FAULT, addr);
            return RiscVAtomicCasResult::default();
        }
    };
    let swapped = old == expected;
    fence_after(if swapped { order } else { failure_order });
    // SAFETY: the lowered ABI supplies a live high-word result slot; null was
    // rejected before accessing guest RAM. No result is published on a fault.
    unsafe { out_old_hi.write((old >> 64) as u64) };
    RiscVAtomicCasResult {
        old: old as u64,
        status: if swapped {
            RiscVAtomicCasStatus::Swapped
        } else {
            RiscVAtomicCasStatus::CompareFailed
        } as u64,
    }
}

pub(super) unsafe fn jit_load_exclusive_impl(ctx: u64, addr: u64, size: u64) -> RiscVAtomicResult {
    let Some(context) = (unsafe { JitContext::from_abi(ctx) }) else {
        return RiscVAtomicResult::default();
    };
    let addr = context.normalize_addr(addr);
    if !matches!(size, 4 | 8) || addr % size != 0 {
        context.record_fault(cause::LOAD_MISALIGNED, addr);
        return RiscVAtomicResult::default();
    }
    let mut bytes = [0u8; 8];
    if unsafe { context.memory() }
        .load_reserved(addr, &mut bytes[..size as usize])
        .is_err()
    {
        context.record_fault(cause::LOAD_ACCESS_FAULT, addr);
        return RiscVAtomicResult::default();
    }
    unsafe { *context.reservation() = Some(addr) };
    RiscVAtomicResult {
        value: u64::from_le_bytes(bytes),
        access_success: 1,
    }
}

pub(super) unsafe fn jit_store_exclusive_impl(
    ctx: u64,
    addr: u64,
    value: u64,
    size: u64,
) -> RiscVAtomicResult {
    let Some(context) = (unsafe { JitContext::from_abi(ctx) }) else {
        return RiscVAtomicResult::default();
    };
    let addr = context.normalize_addr(addr);
    if !matches!(size, 4 | 8) || addr % size != 0 {
        context.record_fault(cause::STORE_MISALIGNED, addr);
        return RiscVAtomicResult::default();
    }
    let eligible = unsafe { context.reservation().take() == Some(addr) };
    // SAFETY: the stack-owned JIT context retains the CPU's exclusive memory
    // borrow until this synchronous native region returns.
    let access = unsafe { context.memory() }.store_conditional(
        addr,
        &value.to_le_bytes()[..size as usize],
        eligible,
    );
    let succeeds = match access {
        Ok(succeeds) => succeeds,
        Err(_) => {
            context.record_fault(cause::STORE_ACCESS_FAULT, addr);
            return RiscVAtomicResult::default();
        }
    };
    RiscVAtomicResult {
        value: u64::from(succeeds),
        access_success: 1,
    }
}

pub(super) unsafe fn jit_clear_exclusive_impl(ctx: u64) {
    if let Some(context) = unsafe { JitContext::from_abi(ctx) } {
        unsafe { *context.reservation() = None };
        // SAFETY: this synchronous helper owns the context's memory borrow.
        unsafe { context.memory() }.clear_reservation();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::riscv::{FlatMemory, Memory};

    #[test]
    fn all_twelve_rmw_helper_opcodes_preserve_width_and_signedness() {
        for size in [4u64, 8] {
            let sign = 1u64 << (size * 8 - 1);
            let mask = if size == 4 {
                u64::from(u32::MAX)
            } else {
                u64::MAX
            };
            let old = sign + 1;
            let operand = sign - 1;
            let expected = [
                0,
                2,
                sign - 1,
                1,
                mask,
                mask ^ 1,
                mask ^ 1,
                sign - 1,
                sign + 1,
                sign + 1,
                sign - 1,
                sign - 1,
            ];
            for (opcode, new) in expected.into_iter().enumerate() {
                for order in 0..=4 {
                    let mut memory = FlatMemory::new(0, 4096);
                    memory
                        .write(0x800, &old.to_le_bytes()[..size as usize])
                        .unwrap();
                    let mut reservation = None;
                    let mut context = JitContext {
                        memory: &mut memory as &mut dyn Memory,
                        reservation: &mut reservation,
                        address_mask: u64::MAX,
                        fault: None,
                    };
                    // SAFETY: the context and its two exclusive stack borrows
                    // stay live throughout this synchronous helper call.
                    let result = unsafe {
                        jit_atomic_rmw_impl(
                            (&mut context as *mut JitContext) as usize as u64,
                            0x800,
                            operand,
                            size,
                            opcode as u64,
                            order,
                        )
                    };
                    assert!(context.fault.is_none());
                    assert_eq!((result.value, result.access_success), (old, 1));
                    let mut bytes = [0; 8];
                    memory.read(0x800, &mut bytes[..size as usize]).unwrap();
                    assert_eq!(
                        u64::from_le_bytes(bytes),
                        new,
                        "size={size}, op={opcode}, order={order}"
                    );
                }
            }
        }
    }
}
