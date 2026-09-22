//! Complete native scalar RMW boundary for the canonical serial guest MMU.

use super::X86_64Vcpu;
use crate::smir::lower::runtime::{X86AtomicRmwOp, X86AtomicRmwRet};

/// Execute one complete ordinary-RAM read-modify-write transaction, returning
/// the zero-extended original element. Sizes are bytes; arithmetic is modulo
/// 2^(8 * size). A failed transaction requests direct replay without a data,
/// register, flag, undo-log, or access-record commit.
///
/// This callback relies on the existing canonical MMU's serial execution
/// contract: mappings, permissions, and overlapping guest accesses cannot
/// change between the preflight and store. It does not add synchronization for
/// concurrent guest-memory users. A concurrent backend must instead supply a
/// callback that synchronizes the complete transaction with those users.
/// Preflight and arithmetic inspect at most two 4 KiB pages and use O(1) time
/// and auxiliary space. Existing verifier buffers use amortized O(1) appends.
///
/// # Safety
/// `ctx` must be null or point to a live, exclusively borrowed vCPU. No other
/// thread or callback may access that vCPU or its guest memory concurrently.
pub(super) unsafe extern "C" fn rax_jit_mem_atomic_rmw(
    ctx: *mut X86_64Vcpu,
    addr: u64,
    operand: u64,
    size: u32,
    operation: u32,
) -> X86AtomicRmwRet {
    let Some(operation) = X86AtomicRmwOp::from_raw(operation) else {
        return X86AtomicRmwRet::default();
    };
    let Some(last) = (match size {
        1 | 2 | 4 | 8 => addr.checked_add(u64::from(size) - 1),
        _ => None,
    }) else {
        return X86AtomicRmwRet::default();
    };
    // SAFETY: the native bridge supplies the live exclusive vCPU borrow;
    // null is explicitly treated as a failed transaction.
    let Some(vcpu) = (unsafe { ctx.as_mut() }) else {
        return X86AtomicRmwRet::default();
    };
    if vcpu.mmu.is_code_page(addr)
        || vcpu.mmu.is_code_page(last)
        || !vcpu
            .mmu
            .read_range_is_plain_ram(addr, size as usize, &vcpu.sregs)
        || !vcpu
            .mmu
            .write_range_is_plain_ram(addr, size as usize, &vcpu.sregs)
    {
        return X86AtomicRmwRet::default();
    }

    // Stage the JIT trace until the complete transaction succeeds. The MMU's
    // embedder-visible records are similarly rolled back on an unexpected
    // post-preflight failure, so direct replay cannot report a duplicate read.
    let staged_trace = vcpu.jit_mem_trace.take();
    let record_checkpoint = vcpu.mmu.mem_record_checkpoint();
    let result = (|| {
        let old = vcpu.read_mem(addr, size as u8).ok()?;
        let new = operation.apply(old, operand, size)?;
        // Do not use the ordinary native store helper: it would read the old
        // value again for verification. This read already supplies the undo.
        vcpu.write_mem(addr, new, size as u8).ok()?;
        Some((old, new))
    })();
    vcpu.jit_mem_trace = staged_trace;
    let Some((old, new)) = result else {
        vcpu.mmu.restore_mem_record_checkpoint(record_checkpoint);
        return X86AtomicRmwRet::default();
    };
    vcpu.push_jit_mem_trace((0, addr, size as u8, old));
    vcpu.push_jit_mem_trace((1, addr, size as u8, new));
    if vcpu.jit_mem_log_active() {
        vcpu.push_jit_mem_log((addr, size as u8, old));
    }
    X86AtomicRmwRet {
        old_value: old,
        ok: 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::pci::PciStub;
    use crate::isa::x86_64::cpu::{LazyFlagOp, LazyFlags};
    use crate::vm::vcpu::{MemAccess, VCpu};
    use std::sync::{Arc, Mutex};
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    const RAM_BYTES: usize = 0x10000;
    const ADDRESS: u64 = 0x2000;
    const PREFIX: u64 = 0x1800;
    const PREFIX_LOG: (u64, u8, u64) = (0x1810, 1, 0x5A);
    const PREFIX_TRACE: (u8, u64, u8, u64) = (0, PREFIX, 1, 0xA5);

    fn fixture() -> (X86_64Vcpu, Arc<GuestMemoryMmap>) {
        let memory =
            Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), RAM_BYTES)]).unwrap());
        memory
            .write_slice(&vec![0xA5; RAM_BYTES], GuestAddress(0))
            .unwrap();
        let mut cpu = X86_64Vcpu::new(0, memory.clone());
        cpu.sregs.cr0 = 1;
        cpu.sregs.cr2 = 0xCAFE_BABE;
        cpu.regs.rax = 0x0123_4567_89AB_CDEF;
        cpu.regs.rbx = 0xFEDC_BA98_7654_3210;
        cpu.regs.rip = 0x1000;
        cpu.regs.rflags = 0xCD7;
        cpu.regs.xmm[0] = [u64::MAX, 0xA5A5_5A5A_F0F0_0F0F];
        cpu.mxcsr = 0x0041;
        cpu.lazy_flags = LazyFlags {
            op: LazyFlagOp::Add,
            result: 0x80,
            src: 1,
            dst: 0x7F,
            size: 1,
        };
        cpu.jit_mem_log = Some(vec![PREFIX_LOG]);
        cpu.jit_mem_trace = Some(vec![PREFIX_TRACE]);
        cpu.mmu.set_mem_recording(true);
        assert_eq!(cpu.mmu.read_u8(PREFIX, &cpu.sregs).unwrap(), 0xA5);
        (cpu, memory)
    }

    fn architectural_state(cpu: &X86_64Vcpu) -> Vec<u8> {
        bincode::serialize(&(&cpu.regs, &cpu.sregs, cpu.get_emulator_state())).unwrap()
    }

    fn memory_bytes(memory: &GuestMemoryMmap) -> Vec<u8> {
        let mut bytes = vec![0; RAM_BYTES];
        memory.read_slice(&mut bytes, GuestAddress(0)).unwrap();
        bytes
    }

    fn records(cpu: &mut X86_64Vcpu) -> Vec<(MemAccess, u64, u8, u64)> {
        let mut records = Vec::new();
        cpu.mmu.drain_mem_records(&mut records);
        records
            .into_iter()
            .map(|record| (record.access, record.addr, record.size, record.value))
            .collect()
    }

    fn call(cpu: &mut X86_64Vcpu, addr: u64, operand: u64, size: u32, op: u32) -> X86AtomicRmwRet {
        // SAFETY: the fixture is exclusively borrowed throughout the callback.
        unsafe { rax_jit_mem_atomic_rmw(cpu, addr, operand, size, op) }
    }

    fn assert_rejected(
        cpu: &mut X86_64Vcpu,
        memory: &GuestMemoryMmap,
        addr: u64,
        size: u32,
        op: u32,
    ) {
        let before_state = architectural_state(cpu);
        let before_memory = memory_bytes(memory);
        let before_trace = cpu.jit_mem_trace.clone();
        let before_log = cpu.jit_mem_log.clone();
        let before_records = cpu.mmu.mem_record_checkpoint();
        let before_smc = cpu.mmu.has_smc_dirty();
        assert_eq!(
            call(cpu, addr, u64::MAX, size, op),
            X86AtomicRmwRet::default()
        );
        assert_eq!(
            architectural_state(cpu),
            before_state,
            "addr={addr:#x}, size={size}, op={op}"
        );
        assert_eq!(memory_bytes(memory), before_memory);
        assert_eq!(cpu.jit_mem_trace, before_trace);
        assert_eq!(cpu.jit_mem_log, before_log);
        assert_eq!(cpu.mmu.mem_record_checkpoint(), before_records);
        assert_eq!(cpu.mmu.has_smc_dirty(), before_smc);
    }

    // Independent widened-integer arithmetic, not X86AtomicRmwOp::apply.
    // The largest intermediate is below 2^65, so u128 cannot overflow.
    fn expected(old: u64, operand: u64, size: u32, op: u32) -> (u64, u64) {
        let modulus = 1u128 << (8 * size);
        let old = u128::from(old) % modulus;
        let operand = u128::from(operand) % modulus;
        let new = match op {
            0 => (old + operand) % modulus,
            1 => old | operand,
            2 => old & operand,
            3 => (old + modulus - operand) % modulus,
            4 => old ^ operand,
            5 => operand,
            _ => panic!("test operation outside explicit callback ABI"),
        };
        (old as u64, new as u64)
    }

    fn assert_completed_trace(cpu: &mut X86_64Vcpu, addr: u64, size: u32, old: u64, new: u64) {
        assert_eq!(
            cpu.jit_mem_log,
            Some(vec![PREFIX_LOG, (addr, size as u8, old)])
        );
        assert_eq!(
            cpu.jit_mem_trace,
            Some(vec![
                PREFIX_TRACE,
                (0, addr, size as u8, old),
                (1, addr, size as u8, new)
            ])
        );
        assert_eq!(
            records(cpu),
            vec![
                (MemAccess::Read, PREFIX, 1, 0xA5),
                (MemAccess::Read, addr, size as u8, old),
                (MemAccess::Write, addr, size as u8, new),
            ]
        );
        assert!(!cpu.mmu.has_smc_dirty());
    }

    #[test]
    fn atomic_callback_all_operations_widths_and_boundaries_commit_one_transaction() {
        for op in 0..6 {
            for size in [1, 2, 4, 8] {
                let mask = (u128::MAX >> (128 - 8 * size)) as u64;
                let sign = 1u64 << (8 * size - 1);
                for (old, operand) in [
                    (0, 0),
                    (0, 1),
                    (mask, 1),
                    (0, mask),
                    (mask, mask),
                    (sign, 1),
                    (sign - 1, 1),
                    (0xA5A5_5A5A_F0F0_0F0F, 0x5555_AAAA_00FF_FF00),
                    (0xFEDC_BA98_7654_3210, u64::MAX),
                ] {
                    let (mut cpu, memory) = fixture();
                    // One-byte misalignment also exercises the ordinary unaligned path.
                    let addr = ADDRESS + 1;
                    memory
                        .write_slice(&old.to_le_bytes()[..size as usize], GuestAddress(addr))
                        .unwrap();
                    let state = architectural_state(&cpu);
                    let mut bytes = memory_bytes(&memory);
                    let (old, new) = expected(old, operand, size, op);
                    bytes[addr as usize..addr as usize + size as usize]
                        .copy_from_slice(&new.to_le_bytes()[..size as usize]);
                    assert_eq!(
                        call(&mut cpu, addr, operand, size, op),
                        X86AtomicRmwRet {
                            old_value: old,
                            ok: 1
                        }
                    );
                    assert_eq!(architectural_state(&cpu), state);
                    assert_eq!(memory_bytes(&memory), bytes, "op={op}, size={size}");
                    assert_completed_trace(&mut cpu, addr, size, old, new);
                }
            }
        }
    }

    #[test]
    fn atomic_callback_rejects_invalid_shape_null_context_overflow_and_unmapped_ranges() {
        // SAFETY: a null context is explicitly supported as a failed callback.
        assert_eq!(
            unsafe { rax_jit_mem_atomic_rmw(core::ptr::null_mut(), ADDRESS, 1, 8, 0) },
            X86AtomicRmwRet::default()
        );
        for size in [0, 3, 5, 7, 9, 16, 32, 64, u32::MAX] {
            let (mut cpu, memory) = fixture();
            assert_rejected(&mut cpu, &memory, ADDRESS, size, 0);
        }
        for op in [6, 7, u32::MAX] {
            let (mut cpu, memory) = fixture();
            assert_rejected(&mut cpu, &memory, ADDRESS, 8, op);
        }
        for size in [1, 2, 4, 8] {
            for addr in [RAM_BYTES as u64, u64::MAX] {
                let (mut cpu, memory) = fixture();
                assert_rejected(&mut cpu, &memory, addr, size, 0);
            }
            if size > 1 {
                let (mut cpu, memory) = fixture();
                assert_rejected(&mut cpu, &memory, RAM_BYTES as u64 - 1, size, 5);
            }
        }
    }

    #[test]
    fn atomic_callback_defers_first_or_last_code_page_without_read_or_smc_journal() {
        for size in [1, 2, 4, 8] {
            let (mut cpu, memory) = fixture();
            cpu.mmu.mark_code_page(ADDRESS);
            assert_rejected(&mut cpu, &memory, ADDRESS, size, 0);
            if size > 1 {
                for code_page in [ADDRESS - 0x1000, ADDRESS] {
                    let (mut cpu, memory) = fixture();
                    cpu.mmu.mark_code_page(code_page);
                    assert_rejected(&mut cpu, &memory, ADDRESS - 1, size, 0);
                }
            }
        }
    }

    #[test]
    fn atomic_callback_rejects_mmio_including_partial_pci_aperture_overlap() {
        for size in [1, 2, 4, 8] {
            let (mut cpu, memory) = fixture();
            assert_rejected(&mut cpu, &memory, 0xFEE0_0080, size, 0);
            for addr in [ADDRESS, ADDRESS + 0x100 - 1] {
                let (mut cpu, memory) = fixture();
                cpu.mmu.set_pci_bridge(
                    Arc::new(Mutex::new(PciStub::new())),
                    ADDRESS,
                    ADDRESS + 0x100,
                );
                assert_rejected(&mut cpu, &memory, addr, size, 0);
            }
            if size > 1 {
                let (mut cpu, memory) = fixture();
                cpu.mmu.set_pci_bridge(
                    Arc::new(Mutex::new(PciStub::new())),
                    ADDRESS,
                    ADDRESS + 0x100,
                );
                assert_rejected(&mut cpu, &memory, ADDRESS - 1, size, 0);
            }
        }
    }

    fn put64(memory: &GuestMemoryMmap, addr: u64, value: u64) {
        memory
            .write_slice(&value.to_le_bytes(), GuestAddress(addr))
            .unwrap();
    }

    fn paged_cpu(first: u64, second: u64, cpl: u16) -> (X86_64Vcpu, Arc<GuestMemoryMmap>) {
        let (mut cpu, memory) = fixture();
        memory
            .write_slice(&vec![0; 0x4000], GuestAddress(0x8000))
            .unwrap();
        for (addr, entry) in [(0x8000, 0x9007), (0x9000, 0xA007), (0xA000, 0xB007)] {
            put64(&memory, addr, entry);
        }
        put64(&memory, 0xB000 + 2 * 8, first);
        put64(&memory, 0xB000 + 3 * 8, second);
        cpu.sregs.cr0 = (1 << 31) | (1 << 16) | 1;
        cpu.sregs.cr3 = 0x8000;
        cpu.sregs.cr4 = 1 << 5;
        cpu.sregs.efer = (1 << 8) | (1 << 10);
        cpu.sregs.cs.l = true;
        cpu.sregs.cs.selector = cpl;
        (cpu, memory)
    }

    #[test]
    fn atomic_callback_preflights_permissions_and_both_pages_before_any_data_read() {
        for size in [2, 4, 8] {
            for (first, second, cpl) in [
                (0x2005, 0x3007, 0), // First page read-only.
                (0x2007, 0x3005, 0), // Last page read-only.
                (0, 0x3007, 0),
                (0x2007, 0, 0),
                (0x2003, 0x3007, 3),  // First page supervisor-only.
                (0x2007, 0x3003, 3),  // Last page supervisor-only.
                (0x2007, 0x10007, 0), // Last physical page outside RAM.
            ] {
                let (mut cpu, memory) = paged_cpu(first, second, cpl);
                assert_rejected(&mut cpu, &memory, 0x2FFF, size, 0);
            }
        }
        for (table_addr, entry) in [(0x8000, 0x9005), (0x9000, 0xA005), (0xA000, 0xB005)] {
            let (mut cpu, memory) = paged_cpu(0x2007, 0x3007, 0);
            put64(&memory, table_addr, entry);
            assert_rejected(&mut cpu, &memory, ADDRESS, 8, 0);
        }
        let (mut cpu, memory) = paged_cpu(0x2007, 0x3007, 0);
        assert_rejected(&mut cpu, &memory, 0x0000_8000_0000_0000, 8, 0);
    }

    #[test]
    fn atomic_callback_cross_page_transaction_uses_both_noncontiguous_translations() {
        for op in 0..6 {
            for size in [2, 4, 8] {
                let (mut cpu, memory) = paged_cpu(0x2007, 0x4007, 0);
                let addr = 0x2FFF;
                let raw_old = 0xF1E2_D3C4_B5A6_9788u64;
                let operand = 0x1234_5678_90AB_CDEF;
                let old_bytes = raw_old.to_le_bytes();
                memory
                    .write_slice(&old_bytes[..1], GuestAddress(addr))
                    .unwrap();
                memory
                    .write_slice(&old_bytes[1..size as usize], GuestAddress(0x4000))
                    .unwrap();
                let state = architectural_state(&cpu);
                let mut bytes = memory_bytes(&memory);
                let (old, new) = expected(raw_old, operand, size, op);
                let new_bytes = new.to_le_bytes();
                bytes[addr as usize] = new_bytes[0];
                bytes[0x4000..0x4000 + size as usize - 1]
                    .copy_from_slice(&new_bytes[1..size as usize]);
                assert_eq!(
                    call(&mut cpu, addr, operand, size, op),
                    X86AtomicRmwRet {
                        old_value: old,
                        ok: 1
                    }
                );
                assert_eq!(architectural_state(&cpu), state);
                assert_eq!(memory_bytes(&memory), bytes);
                assert_completed_trace(&mut cpu, addr, size, old, new);
            }
        }
    }

    #[test]
    fn atomic_callback_instrumentation_off_or_at_capacity_does_not_repeat_the_read() {
        let (mut cpu, memory) = fixture();
        cpu.jit_mem_trace = None;
        cpu.jit_mem_log = None;
        cpu.mmu.set_mem_recording(false);
        put64(&memory, ADDRESS, 0xFFFF_FFFF_FFFF_FFFF);
        assert_eq!(
            call(&mut cpu, ADDRESS, 1, 8, 0),
            X86AtomicRmwRet {
                old_value: u64::MAX,
                ok: 1
            }
        );
        assert!(cpu.jit_mem_trace.is_none());
        assert!(cpu.jit_mem_log.is_none());
        assert!(records(&mut cpu).is_empty());
        assert_eq!(memory.read_obj::<u64>(GuestAddress(ADDRESS)).unwrap(), 0);

        let (mut cpu, memory) = fixture();
        cpu.jit_mem_trace = Some(vec![PREFIX_TRACE; super::super::JIT_VERIFY_MEM_TRACE_LIMIT]);
        cpu.jit_mem_log = Some(vec![PREFIX_LOG; super::super::JIT_VERIFY_MEM_LOG_LIMIT]);
        assert_rejected(&mut cpu, &memory, RAM_BYTES as u64, 8, 0);
        assert_eq!(
            call(&mut cpu, ADDRESS, 0x5A, 1, 5),
            X86AtomicRmwRet {
                old_value: 0xA5,
                ok: 1
            }
        );
        assert!(
            cpu.jit_mem_trace.is_none(),
            "existing trace overflow policy"
        );
        assert!(cpu.jit_mem_log.is_none(), "existing undo overflow policy");
        assert_eq!(
            records(&mut cpu),
            vec![
                (MemAccess::Read, PREFIX, 1, 0xA5),
                (MemAccess::Read, ADDRESS, 1, 0xA5),
                (MemAccess::Write, ADDRESS, 1, 0x5A)
            ]
        );
    }

    fn native_fixture(
        code: &[u8],
        old: u64,
        source: u64,
        carry: bool,
    ) -> (X86_64Vcpu, Arc<GuestMemoryMmap>) {
        let memory =
            Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), RAM_BYTES)]).unwrap());
        memory
            .write_slice(&vec![0xA5; RAM_BYTES], GuestAddress(0))
            .unwrap();
        memory.write_slice(code, GuestAddress(0x1000)).unwrap();
        memory.write_obj(old, GuestAddress(ADDRESS + 8)).unwrap();
        let mut cpu = X86_64Vcpu::new(0, memory.clone());
        cpu.sregs.cr0 = 1;
        cpu.sregs.efer = 1 << 10;
        cpu.sregs.cs.l = true;
        cpu.sregs.cr2 = 0xCAFE_BABE;
        for register in 0..32 {
            cpu.set_reg(
                register,
                0x0123_4567_89AB_CDEFu64.wrapping_add(u64::from(register) * 0x0101_1111_2222_3333),
                8,
            );
        }
        cpu.regs.rbx = ADDRESS;
        cpu.regs.rcx = source;
        cpu.regs.rsp = 0x8000;
        cpu.regs.rip = 0x1000;
        cpu.regs.rflags = 0xED6 | u64::from(carry); // Defined status, IF, and DF.
        cpu.regs.xmm[0] = [u64::MAX, 0xA5A5_5A5A_F0F0_0F0F];
        cpu.mxcsr = 0x0041;
        cpu.set_jit_mem(true);
        cpu.set_jit_call(false);
        // These diagnostic buffers do not enable embedder memory recording or
        // alter admission. Compilation fetches are not guest data accesses.
        cpu.jit_mem_trace = Some(vec![PREFIX_TRACE]);
        cpu.jit_mem_log = Some(vec![PREFIX_LOG]);
        (cpu, memory)
    }

    fn native_instruction(kind: u32, size: u32) -> Vec<u8> {
        // Intel encodings, [RBX+8] with CL/CX/ECX/RCX where applicable.
        // XCHG is implicitly locked; the other eight forms use F0 explicitly.
        let mut bytes = Vec::new();
        if kind != 5 {
            bytes.push(0xF0);
        }
        if size == 2 {
            bytes.push(0x66);
        } else if size == 8 {
            bytes.push(0x48);
        }
        match kind {
            0..=4 => {
                let opcode = [0x00, 0x08, 0x20, 0x28, 0x30][kind as usize];
                bytes.extend_from_slice(&[opcode + u8::from(size != 1), 0x4B, 8]);
            }
            5 => bytes.extend_from_slice(&[if size == 1 { 0x86 } else { 0x87 }, 0x4B, 8]),
            6 | 7 => bytes.extend_from_slice(&[
                if size == 1 { 0xFE } else { 0xFF },
                if kind == 6 { 0x43 } else { 0x4B },
                8,
            ]),
            8 => bytes.extend_from_slice(&[0x0F, 0xC1, 0x4B, 8]),
            _ => panic!("native test operation"),
        }
        bytes
    }

    #[test]
    fn atomic_callback_native_cpu_entry_matches_direct_and_commits_exactly_once() {
        let mut native_cases = 0;
        let mut refused_cases = 0;
        for kind in 0..9 {
            for size in [1, 2, 4, 8] {
                // Live byte XADD writeback is outside the existing matcher.
                if kind == 8 && size == 1 {
                    continue;
                }
                let mask = ((1u128 << (size * 8)) - 1) as u64;
                let sign = 1u64 << (size * 8 - 1);
                for sample in [mask, sign - 1, sign, 0] {
                    let old = match kind {
                        1 if sample == mask => mask ^ 1,
                        2 if sample == 0 => mask ^ 1,
                        _ => sample,
                    };
                    let operand = if kind == 1 { !old & mask } else { 1 };
                    let source = if kind == 8 {
                        (0xDEAD_0000 & !mask) | operand
                    } else {
                        (0xA5A5_5A5A_DEAD_BEEF & !mask) | operand
                    };
                    let operation = match kind {
                        6 | 8 => 0,
                        7 => 3,
                        _ => kind,
                    };
                    let (_, new) = expected(old, operand, size, operation);
                    // Every sample changes memory: a missing callback cannot
                    // pass merely because jit_try_block reports a native run.
                    assert_ne!(new, old, "kind={kind}, size={size}, sample={sample:#x}");
                    for carry in [false, true] {
                        let label = format!(
                            "kind={kind}, size={size}, old={old:#x}, source={source:#x}, CF={carry}"
                        );
                        let mut code = native_instruction(kind, size);
                        if matches!(kind, 5 | 6 | 7) && size == 1 {
                            let overwrite_modes: &[bool] =
                                if kind == 5 { &[false, true] } else { &[false] };
                            for &overwrite in overwrite_modes {
                                let mut byte_code = code.clone();
                                if overwrite {
                                    byte_code.extend_from_slice(&[0xB9, 0x44, 0x33, 0x22, 0x11]);
                                }
                                byte_code.extend_from_slice(&[0xEB, 0, 0xF4]);
                                let (mut refused, memory) =
                                    native_fixture(&byte_code, old, source, carry);
                                let before = architectural_state(&refused);
                                let before_memory = memory_bytes(&memory);
                                // Existing byte XCHG writeback is unsupported,
                                // including before an overwrite retained by
                                // conservative DCE. Byte INC/DEC instead reuse
                                // the old virtual as the flag-result dst, so
                                // their two definitions fail the exact matcher.
                                assert!(
                                    !refused.jit_try_block().unwrap(),
                                    "byte refusal overwrite={overwrite}: {label}"
                                );
                                assert_eq!(architectural_state(&refused), before, "{label}");
                                assert_eq!(memory_bytes(&memory), before_memory, "{label}");
                                assert_eq!(
                                    refused.jit_mem_trace,
                                    Some(vec![PREFIX_TRACE]),
                                    "{label}"
                                );
                                assert_eq!(refused.jit_mem_log, Some(vec![PREFIX_LOG]), "{label}");
                                assert_eq!(
                                    refused.insn_count, 0,
                                    "refusal does not execute: {label}"
                                );
                                refused_cases += 1;
                            }
                            continue;
                        }
                        if kind == 8 {
                            // The current lifter saves XADD's register source
                            // into a virtual which copy propagation does not
                            // rewrite through AtomicRmw. MOV ECX,imm32 supplies
                            // a tracked constant (unlike MOVABS's Imm64), so O2
                            // reaches the existing immediate materializer. W16
                            // still verifies preservation of source[31:16].
                            let mut setup = vec![0xB9]; // MOV ECX,source.
                            setup.extend_from_slice(&(source as u32).to_le_bytes());
                            setup.extend_from_slice(&code);
                            code = setup;
                        }
                        code.extend_from_slice(&[0xEB, 0, 0xF4]); // JMP next; HLT frontier.
                        let frontier = 0x1000 + code.len() as u64 - 1;
                        // Separate RAM images are essential: the direct oracle
                        // must not change the native transaction's input.
                        let (mut direct, direct_memory) = native_fixture(&code, old, source, carry);
                        let (mut native, native_memory) = native_fixture(&code, old, source, carry);
                        let mut expected_memory = memory_bytes(&native_memory);
                        expected_memory[ADDRESS as usize + 8..ADDRESS as usize + 8 + size as usize]
                            .copy_from_slice(&new.to_le_bytes()[..size as usize]);
                        for _ in 0..if kind == 8 { 3 } else { 2 } {
                            assert!(direct.step().unwrap().is_none(), "direct {label}");
                        }
                        direct.materialize_flags();
                        assert_eq!(direct.regs.rip, frontier, "direct frontier {label}");
                        assert_eq!(
                            memory_bytes(&direct_memory),
                            expected_memory,
                            "direct {label}"
                        );
                        assert!(
                            native.jit_try_block().unwrap(),
                            "native admission {label}; bytes={code:02X?}\n{}",
                            native.jit_dump_region(0x1000)
                        );
                        assert_eq!(
                            memory_bytes(&native_memory),
                            expected_memory,
                            "native {label}"
                        );
                        assert_eq!(native.regs.rip, frontier, "native frontier {label}");
                        assert_eq!(
                            native.insn_count, 0,
                            "no direct replay inside native run: {label}"
                        );
                        if kind == 5 || kind == 8 {
                            let writeback = match size {
                                2 => (source & !mask) | old,
                                _ => old, // W32 zero-extends; W64 replaces all bits.
                            };
                            assert_eq!(direct.regs.rcx, writeback, "direct writeback {label}");
                            assert_eq!(native.regs.rcx, writeback, "native writeback {label}");
                        }
                        if kind == 6 || kind == 7 {
                            assert_eq!(
                                native.regs.rflags & 1,
                                u64::from(carry),
                                "unary CF {label}"
                            );
                        }
                        // Logical AF is undefined; every other register/flag
                        // bit is compared with the direct architectural image.
                        if matches!(kind, 1 | 2 | 4) {
                            direct.regs.rflags =
                                (direct.regs.rflags & !0x10) | (native.regs.rflags & 0x10);
                        }
                        assert_eq!(
                            bincode::serialize(&native.regs).unwrap(),
                            bincode::serialize(&direct.regs).unwrap(),
                            "full registers {label}"
                        );
                        assert_eq!(native.mxcsr, direct.mxcsr, "MXCSR {label}");
                        assert_eq!(
                            native.jit_mem_trace,
                            Some(vec![
                                PREFIX_TRACE,
                                (0, ADDRESS + 8, size as u8, old),
                                (1, ADDRESS + 8, size as u8, new)
                            ]),
                            "one read and one write {label}"
                        );
                        assert_eq!(
                            native.jit_mem_log,
                            Some(vec![PREFIX_LOG, (ADDRESS + 8, size as u8, old)]),
                            "one undo {label}"
                        );
                        assert!(
                            records(&mut native).is_empty(),
                            "recording stays off: {label}"
                        );
                        native_cases += 1;
                    }
                }
            }
        }
        assert_eq!((native_cases, refused_cases), (256, 32));
        eprintln!(
            "executed {native_cases} native CPU atomic transactions and {refused_cases} byte-form refusals"
        );
    }
}
