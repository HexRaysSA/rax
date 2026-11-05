//! Managed native event admission at a settled instruction boundary.
use super::NativeCore;
use crate::error::{Error, Result};
use kvm_bindings::kvm_interrupt;
use std::os::fd::AsRawFd;
use std::sync::atomic::Ordering;

impl NativeCore {
    fn refresh_halted_interrupt_readiness(&mut self) -> Result<()> {
        if self
            .memory_owner
            .vm_fd
            .check_extension_raw(kvm_bindings::KVM_CAP_IMMEDIATE_EXIT.into())
            <= 0
        {
            return Err(Error::InvalidConfig(
                "halted native IRQ admission requires immediate-exit sampling".into(),
            ));
        }
        // A public register overlay can change IF without updating the last
        // run-header sample. Immediate exit refreshes the kernel's complete
        // readiness predicate without executing the instruction after HLT.
        // The caller has excluded native I/O and pending/reinjected events.
        // KVM_RUN first imports run.cr8 even on this stopped path; keep it
        // equal to the current special register rather than an older sample.
        let cr8 = self.vcpu_fd.get_sregs()?.cr8;
        let previous = self.vcpu_fd.get_kvm_run().immediate_exit;
        self.vcpu_fd.get_kvm_run().cr8 = cr8;
        self.vcpu_fd.set_kvm_immediate_exit(1);
        let result = self.vcpu_fd.run().map(|_| ());
        self.vcpu_fd.set_kvm_immediate_exit(previous);
        match result {
            Err(error) if error.errno() == libc::EINTR => Ok(()),
            result => {
                let failure =
                    format!("KVM stopped IRQ sample returned {result:?}; guest entry disabled");
                self.state_failure = Some(failure.clone());
                Err(Error::Emulator(failure))
            }
        }
    }

    fn event_boundary_ready(&self) -> Result<bool> {
        self.state_ready()?;
        Ok(!self.memory_owner.powered_off.load(Ordering::Acquire)
            && !self.servicing_io
            && !self.native_io_unsettled
            && !self.io.has_native_completion()
            && self.deferred_exit.is_none())
    }

    pub(super) fn native_can_inject_interrupt(&mut self) -> Result<bool> {
        if !self.event_boundary_ready()?
            || self.memory_owner.irqchip_created.load(Ordering::Acquire)
        {
            return Ok(false);
        }
        if self.vcpu_fd.get_regs()?.rflags & (1 << 9) == 0 {
            return Ok(false);
        }
        let events = self.vcpu_fd.get_vcpu_events()?;
        if events.interrupt.injected != 0
            || events.interrupt.shadow != 0
            || events.exception.injected != 0
            || events.exception.pending != 0
            || events.nmi.injected != 0
            || events.nmi.pending != 0
        {
            return Ok(false);
        }
        if self.userspace_halted {
            self.refresh_halted_interrupt_readiness()?;
        }
        // The kernel predicate also covers non-public blocking state such as
        // nested execution; do not replace it with the exported IF bit alone.
        Ok(self.vcpu_fd.get_kvm_run().ready_for_interrupt_injection != 0)
    }

    pub(super) fn native_inject_interrupt(&mut self, vector: u8) -> Result<bool> {
        if !self.native_can_inject_interrupt()? {
            return Ok(false);
        }
        let interrupt = kvm_interrupt {
            irq: u32::from(vector),
        };
        // SAFETY: Linux KVM UAPI 4.16 defines this ioctl and initialized
        // integer-only input. VM entry exclusion and the CPU guard retain the
        // live FD and stopped run mapping for the synchronous call. No pointer
        // escapes, no concurrent managed injection can replace the event,
        // and no Rust reference aliases kernel-written run storage.
        let result = unsafe {
            libc::ioctl(
                self.vcpu_fd.as_raw_fd(),
                libc::_IOW::<kvm_interrupt>(kvm_bindings::KVMIO, 0x86),
                &interrupt as *const kvm_interrupt,
            )
        };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EEXIST) {
                return Ok(false);
            }
            return Err(error.into());
        }
        self.userspace_halted = false;
        Ok(true)
    }

    pub(super) fn native_inject_nmi(&mut self) -> Result<bool> {
        if !self.event_boundary_ready()? {
            return Ok(false);
        }
        if self.memory_owner.irqchip_created.load(Ordering::Acquire) {
            // KVM API 4.64 documents external NMI injection with an in-kernel
            // LAPIC as a stopped LINT1 check followed by KVM_NMI. Guest IPI
            // NMIs remain owned by that kernel LAPIC and bypass this method.
            let lapic = self.vcpu_fd.get_lapic()?;
            // The fixed UAPI bank contains 1,024 bytes; LVT1 is at 0x360.
            let lint1 = u32::from_le_bytes([
                lapic.regs[0x360] as u8,
                lapic.regs[0x361] as u8,
                lapic.regs[0x362] as u8,
                lapic.regs[0x363] as u8,
            ]);
            if lint1 & (1 << 16) != 0 || (lint1 >> 8) & 7 != 4 {
                return Ok(false);
            }
        }
        let events = self.vcpu_fd.get_vcpu_events()?;
        if events.nmi.injected != 0 || events.nmi.pending != 0 || events.nmi.masked != 0 {
            return Ok(false);
        }
        // The SDK queues this notification atomically. Replacing a whole
        // GET_VCPU_EVENTS image would overwrite concurrently arriving native
        // events from another CPU's in-kernel controller.
        self.vcpu_fd.nmi()?;
        self.userspace_halted = false;
        Ok(true)
    }

    pub(super) fn native_wake(&mut self) -> Result<()> {
        // GET_MP_STATE can accept INIT/SIPI and reset native I/O storage. A
        // CPU already completing I/O is awake; do not observe startup state
        // while that continuation is owned by the adapter.
        if !self.event_boundary_ready()? {
            return Ok(());
        }
        if self.memory_owner.irqchip_created.load(Ordering::Acquire) {
            let mut state = self.vcpu_fd.get_mp_state()?;
            if state.mp_state == kvm_bindings::KVM_MP_STATE_HALTED {
                state.mp_state = kvm_bindings::KVM_MP_STATE_RUNNABLE;
                self.vcpu_fd.set_mp_state(state)?;
            }
        }
        self.userspace_halted = false;
        Ok(())
    }
}
