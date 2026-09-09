//! Native scalar store boundary and verification undo logging.

use super::X86_64Vcpu;

/// JIT memory-store helper: translate + write `size` bytes of `value` at guest
/// `addr` via the vcpu MMU. Returns 1 on success, 0 on fault/MMIO/unmapped.
pub(super) unsafe extern "C" fn rax_jit_mem_store(
    ctx: *mut X86_64Vcpu,
    addr: u64,
    value: u64,
    size: u32,
) -> u64 {
    // SAFETY: the native bridge supplies its live, exclusively borrowed vCPU;
    // no Rust reference to it is used concurrently across this callback.
    let vcpu = unsafe { &mut *ctx };
    let Some(last) = (match size {
        1 | 2 | 4 | 8 => addr.checked_add(u64::from(size) - 1),
        _ => None,
    }) else {
        return 0;
    };
    // A store to a code page is self-modifying code (e.g. the kernel's
    // text_poke / alternatives patching). Bail to the interpreter so the full
    // SMC + instruction-patching semantics (decode/JIT invalidation ordering,
    // int3 batching) are handled there rather than mid-native-region.
    if vcpu.mmu.is_code_page(addr) || vcpu.mmu.is_code_page(last) {
        return 0;
    }
    // Verify mode: record the pre-store value so the region's writes can be
    // undone and the interpreter re-run for a store-sound differential. The
    // old-value read must NOT pollute the access trace (it is bookkeeping, not
    // a guest access), so the trace is suspended around it.
    if vcpu.jit_mem_log.is_some() {
        let saved_trace = vcpu.jit_mem_trace.take();
        let old = vcpu.read_mem(addr, size as u8);
        vcpu.jit_mem_trace = saved_trace;
        match old {
            Ok(old) => vcpu.push_jit_mem_log((addr, size as u8, old)),
            // No write has happened at this lane. Retain the completed-prefix
            // undo log and defer this store at its exact guest frontier; this
            // also covers write targets unavailable to the snapshot read.
            Err(_) => return 0,
        }
    }
    match vcpu.write_mem(addr, value, size as u8) {
        Ok(()) => 1,
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    fn cpu() -> (X86_64Vcpu, Arc<GuestMemoryMmap>) {
        let memory = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x2000)]).unwrap());
        let mut cpu = X86_64Vcpu::new(0, memory.clone());
        cpu.sregs.cr0 = 1;
        (cpu, memory)
    }

    #[test]
    fn deferred_unmapped_store_retains_completed_prefix_undo_log_and_trace() {
        let (mut cpu, memory) = cpu();
        memory
            .write_obj(0xAABB_CCDDu32, GuestAddress(0x1000))
            .unwrap();
        let log = vec![(0x1000, 4, 0x1122_3344)];
        let trace = vec![(1, 0x1000, 4, 0xAABB_CCDD)];
        cpu.jit_mem_log = Some(log.clone());
        cpu.jit_mem_trace = Some(trace.clone());
        // SAFETY: the callback receives the live, exclusively borrowed CPU.
        assert_eq!(unsafe { rax_jit_mem_store(&mut cpu, 0x2000, 0x55, 4) }, 0);
        assert_eq!(cpu.jit_mem_log, Some(log));
        assert_eq!(cpu.jit_mem_trace, Some(trace));
        assert_eq!(
            memory.read_obj::<u32>(GuestAddress(0x1000)).unwrap(),
            0xAABB_CCDD
        );
    }

    #[test]
    fn successful_store_logs_old_value_without_a_synthetic_read_access() {
        let (mut cpu, memory) = cpu();
        memory
            .write_obj(0x1122_3344u32, GuestAddress(0x1000))
            .unwrap();
        cpu.jit_mem_log = Some(Vec::new());
        cpu.jit_mem_trace = Some(Vec::new());
        // SAFETY: the callback receives the live, exclusively borrowed CPU.
        assert_eq!(
            unsafe { rax_jit_mem_store(&mut cpu, 0x1000, u64::MAX, 4) },
            1
        );
        assert_eq!(cpu.jit_mem_log, Some(vec![(0x1000, 4, 0x1122_3344)]));
        assert_eq!(cpu.jit_mem_trace, Some(vec![(1, 0x1000, 4, 0xFFFF_FFFF)]));
        assert_eq!(
            memory.read_obj::<u32>(GuestAddress(0x1000)).unwrap(),
            u32::MAX
        );
    }
}
