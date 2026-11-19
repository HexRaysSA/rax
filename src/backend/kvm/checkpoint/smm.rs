//! Temporary SMRAM for a stopped VMX root transition on a fresh KVM graph.
use crate::error::{Error, Result};
use kvm_bindings::{
    KVM_CAP_MULTI_ADDRESS_SPACE, KVM_CAP_NR_MEMSLOTS, KVM_MP_STATE_RUNNABLE,
    KVM_VCPUEVENT_VALID_SMM, Msrs, kvm_mp_state, kvm_msr_entry, kvm_userspace_memory_region,
    kvm_vcpu_events,
};
use kvm_ioctls::{VcpuFd, VmFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};
use vm_memory::MmapRegion;

pub(super) const IA32_SMBASE: u32 = 0x9e;
// The high PC hole is outside the managed RAM ranges. The SMM save state
// ends just before SMBASE + 0x10000 and fits in the final 4 KiB page.
const SMBASE: u64 = 0xeff0_0000;
const SAVE_PAGE: u64 = SMBASE + 0xf000;
const PAGE_BYTES: usize = 4096;
const SMM_ADDRESS_SPACE: u32 = 1 << 16;

fn invalid(message: impl std::fmt::Display) -> Error {
    Error::InvalidConfig(format!("native KVM SMM restore: {message}"))
}

pub(super) struct Scratch<'a> {
    vm: &'a VmFd,
    fence: &'a AtomicBool,
    retained: MutexGuard<'a, Option<MmapRegion<()>>>,
    slot: u32,
    published: bool,
}

impl<'a> Scratch<'a> {
    pub(super) fn install(
        vm: &'a VmFd,
        backing: &'a Mutex<Option<MmapRegion<()>>>,
        fence: &'a AtomicBool,
    ) -> Result<Self> {
        if vm.check_extension_raw(KVM_CAP_MULTI_ADDRESS_SPACE.into()) < 2 {
            return Err(invalid("host has no managed SMM address space"));
        }
        // The last slot is reserved in the SMM address space. Managed PC
        // RAM registration uses only address space zero. External VM-FD
        // access disqualifies the graph before its caller can reserve a slot.
        let slot_count = vm.check_extension_raw(KVM_CAP_NR_MEMSLOTS.into());
        let last = slot_count
            .checked_sub(1)
            .and_then(|index| u16::try_from(index).ok())
            .filter(|index| *index > 0)
            .ok_or_else(|| invalid("host has no reserved SMM slot"))?;
        let slot = SMM_ADDRESS_SPACE | u32::from(last);
        let mut retained = backing
            .lock()
            .map_err(|_| invalid("scratch lock poisoned"))?;
        if retained.is_some() {
            return Err(invalid("a native SMM scratch mapping is already retained"));
        }
        let mapping = MmapRegion::new(PAGE_BYTES).map_err(invalid)?;
        let userspace_addr = mapping.as_ptr() as u64;
        let descriptor = kvm_userspace_memory_region {
            slot,
            guest_phys_addr: SAVE_PAGE,
            memory_size: PAGE_BYTES as u64,
            userspace_addr,
            flags: 0,
        };
        // SAFETY: the page-sized mapping is aligned and retained across
        // this synchronous registration. The caller holds VM exclusion.
        unsafe { vm.set_user_memory_region(descriptor)? };
        *retained = Some(mapping);
        Ok(Self {
            vm,
            fence,
            retained,
            slot,
            published: false,
        })
    }

    pub(super) fn finish(mut self) -> Result<()> {
        self.remove()?;
        self.published = true;
        Ok(())
    }

    pub(super) fn remove(&mut self) -> Result<()> {
        if self.retained.is_some() {
            // SAFETY: size zero removes the reserved slot under VM
            // exclusion. The backing remains live until the kernel agrees.
            let result = unsafe {
                self.vm.set_user_memory_region(kvm_userspace_memory_region {
                    slot: self.slot,
                    ..Default::default()
                })
            };
            if let Err(error) = result {
                self.fence.store(true, Ordering::Release);
                return Err(error.into());
            }
            *self.retained = None;
        }
        Ok(())
    }
}

impl Drop for Scratch<'_> {
    fn drop(&mut self) {
        if !self.published {
            self.fence.store(true, Ordering::Release);
        }
        let _ = self.remove();
    }
}

/// Prepare a native CPU for a temporary SMI. The saved banks are installed
/// after the transition and the scratch slot is gone before publication.
pub(super) fn prepare(cpu: &VcpuFd) -> Result<()> {
    let events = cpu.get_vcpu_events()?;
    let reset = kvm_vcpu_events {
        flags: events.flags,
        ..Default::default()
    };
    cpu.set_vcpu_events(&reset)?;
    let msrs = Msrs::from_entries(&[kvm_msr_entry {
        index: IA32_SMBASE,
        data: SMBASE,
        ..Default::default()
    }])
    .map_err(invalid)?;
    if cpu.set_msrs(&msrs)? != 1 {
        return Err(invalid("could not set the temporary SMBASE"));
    }
    cpu.set_mp_state(kvm_mp_state {
        mp_state: KVM_MP_STATE_RUNNABLE,
    })?;
    Ok(())
}

pub(super) fn enter(cpu: &mut VcpuFd) -> Result<()> {
    let mut events = cpu.get_vcpu_events()?;
    events.flags |= KVM_VCPUEVENT_VALID_SMM;
    events.smi.pending = 1;
    cpu.set_vcpu_events(&events)?;
    super::super::deadline::service_queued_event(cpu)?;
    let after = cpu.get_vcpu_events()?;
    if after.smi.smm != 1
        || after.smi.pending != 0
        || cpu.get_regs()?.rip != 0x8000
        || cpu.get_sregs()?.cs.base != SMBASE
    {
        return Err(invalid("kernel did not stop at the scratch SMM entry"));
    }
    Ok(())
}
