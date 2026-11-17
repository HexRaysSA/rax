//! One `brk` operation owns both mapping changes and MM bookkeeping. The
//! native syscall adapter and process-family broker use this same operation.

use serde::{Deserialize, Serialize};

use super::super::{MmState, ProcState};
use crate::user::linux::abi::{LinuxAbi, PAGE_SIZE, READ_IMPLIES_EXEC, STACK_GUARD_GAP, vma_flags};
use crate::user::linux::syscall::{SysResult, mem, mlock, mseal};
use crate::user::mm::{AddressSpace, Mapping, Perms};

/// Process-owned inputs for `brk`; the break and counters are never imported
/// from the caller. Limits are bytes, as in `ProcState::rlimits`.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BrkPolicy {
    pub(crate) abi: LinuxAbi,
    pub(crate) persona: u32,
    pub(crate) privileged: bool,
    pub(crate) memlock_limit: u64,
}

impl From<&ProcState> for BrkPolicy {
    fn from(process: &ProcState) -> Self {
        Self {
            abi: process.abi,
            persona: process.persona,
            privileged: process.creds.1 == 0,
            memlock_limit: process.rlimits[8].0, // RLIMIT_MEMLOCK.
        }
    }
}

impl MmState {
    /// Preserve the syscall's existing success/refusal rules. The caller
    /// exclusively owns the MM for this entire operation. Broker dispatch
    /// keeps that ownership through accounting and optional population; a
    /// lost reply must not trigger a retry. This is serialization, not a
    /// rollback guarantee for errors from the underlying address space.
    pub(crate) fn change_brk(
        &mut self,
        space: &AddressSpace,
        policy: BrkPolicy,
        addr: u64,
    ) -> SysResult {
        let (start_brk, cur) = (self.start_brk, self.brk);
        if addr < start_brk {
            return Ok(cur);
        }
        let (Some(new_end), Some(old_end)) = (mem::page_align(addr), mem::page_align(cur)) else {
            return Ok(cur);
        };
        if new_end == old_end {
            self.brk = addr;
            return Ok(addr);
        }
        if addr <= cur {
            if mseal::sealed_in_space(space, new_end, old_end - new_end) {
                return Ok(cur);
            }
            mlock::unmapped_mm(space, self, new_end, old_end - new_end);
            space
                .unmap(new_end, old_end - new_end)
                .map_err(mem::map_err)?;
            self.brk = addr;
            return Ok(addr);
        }
        // vm_start_gap(): leave a page before any mapping, and the stack
        // guard gap before a VM_GROWSDOWN mapping.
        let probe_end = new_end.saturating_add(PAGE_SIZE);
        if probe_end > policy.abi.task_size() || !space.is_free(old_end, probe_end - old_end) {
            return Ok(cur);
        }
        if let Some(next) = space.vmas_in(probe_end, policy.abi.task_size()).first()
            && next.flags & vma_flags::GROWSDOWN != 0
            && next.start < probe_end + STACK_GUARD_GAP
        {
            return Ok(cur);
        }
        let lock = self.def_lock;
        if !mlock::future_ok_mm(
            self,
            lock,
            new_end - old_end,
            policy.privileged,
            policy.memlock_limit >> 12,
        ) {
            return Ok(cur);
        }
        let mut perms = Perms::READ | Perms::WRITE;
        if policy.persona & READ_IMPLIES_EXEC != 0 && policy.abi.data_exec_follows_persona() {
            perms |= Perms::EXEC;
        }
        let mut heap = Mapping::anonymous(perms).named("[heap]");
        heap.flags = lock;
        if space.map(old_end, new_end - old_end, heap).is_err() {
            return Ok(cur);
        }
        self.brk = addr;
        mlock::mapped_mm(self, lock, new_end - old_end);
        if lock & vma_flags::LOCKED != 0 {
            let _ = mlock::populate_space(space, old_end, new_end, true);
        }
        Ok(addr)
    }
}

#[cfg(test)]
mod tests;
