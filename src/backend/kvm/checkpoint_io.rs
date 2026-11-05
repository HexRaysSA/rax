//! Close native I/O through real device service, outside CPU/VM entry locks.
use super::{KvmVcpu, NativeCore, deadline, run};
use crate::error::{Error, Result};
use crate::vm::vcpu::{CheckpointIoReply, CheckpointIoState, VcpuExit};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::atomic::Ordering;

enum Step {
    Complete,
    Deferred,
    Device(VcpuExit),
}

struct RestoreImmediate {
    mapping: *mut kvm_bindings::kvm_run,
    previous: u8,
}
impl Drop for RestoreImmediate {
    fn drop(&mut self) {
        // SAFETY: the exclusive core borrow retains the native FD/run mapping
        // until this guard drops. KVM_RUN has returned before any Rust unwind;
        // no native slice or header reference escapes run_native. Only this
        // disjoint u8 entry flag changes, with no concurrent native access.
        unsafe { (*self.mapping).immediate_exit = self.previous };
    }
}

fn fail(core: &mut NativeCore, message: impl std::fmt::Display) -> Error {
    let failure = format!("KVM checkpoint I/O failed: {message}; guest entry disabled");
    core.state_failure = Some(failure.clone());
    Error::Emulator(failure)
}

impl NativeCore {
    fn checkpoint_io_step(&mut self) -> Result<Step> {
        if self.memory_owner.powered_off.load(Ordering::Acquire) {
            return Ok(Step::Deferred);
        }
        self.state_ready()?;
        if self.servicing_io {
            return Err(Error::InvalidConfig(
                "native checkpoint device callback is already in progress".into(),
            ));
        }
        if self.deferred_exit.is_some() {
            return Ok(Step::Deferred);
        }
        if let Some(event) = self.io.event().map_err(Error::Emulator)? {
            self.servicing_io = true;
            return Ok(Step::Device(run::public_event(event)));
        }
        if !self.io.has_native_completion() {
            if self.native_io_unsettled {
                return Err(fail(self, "native completion lost its owned transfer"));
            }
            return Ok(Step::Complete);
        }
        self.io
            .ready_for_native_completion()
            .map_err(Error::Emulator)?;
        if self
            .memory_owner
            .vm_fd
            .check_extension_raw(kvm_bindings::KVM_CAP_IMMEDIATE_EXIT.into())
            <= 0
        {
            return Err(Error::InvalidConfig(
                "native checkpoint requires immediate-exit completion".into(),
            ));
        }
        let mapping = self.vcpu_fd.get_kvm_run() as *mut kvm_bindings::kvm_run;
        // SAFETY: the exclusively borrowed core owns this live initialized
        // mapping. No native entry or other run-buffer reference exists here.
        let previous = unsafe { (*mapping).immediate_exit };
        let restore = RestoreImmediate { mapping, previous };
        self.vcpu_fd.set_kvm_immediate_exit(1);
        // Reuse the private worker's blocked userspace signals and entry-only
        // KVM mask. A caller-thread signal must not interrupt the ioctl before
        // the kernel has reached its native I/O completion path.
        let result = deadline::run(self, std::time::Duration::from_millis(10));
        drop(restore);
        match result {
            Ok(None) => {
                if self.io.has_native_completion() {
                    return Err(fail(self, "interrupted completion retained native work"));
                }
                Ok(Step::Complete)
            }
            Err(error) => Err(error),
            Ok(Some(exit)) if self.io.has_native_completion() => {
                self.servicing_io = true;
                Ok(Step::Device(exit))
            }
            Ok(Some(exit)) => {
                // Conservation of a completion-time fault/terminal exit. It
                // must be returned on resumption and represented by capture;
                // it is never silently consumed as a successful I/O boundary.
                self.deferred_exit = Some(exit);
                Ok(Step::Deferred)
            }
        }
    }
}

impl KvmVcpu {
    pub(super) fn settle_native_checkpoint_io(
        &self,
        service: &mut dyn FnMut(VcpuExit) -> Result<CheckpointIoReply>,
    ) -> Result<CheckpointIoState> {
        loop {
            let event = match self.with_native(|core| core.checkpoint_io_step())? {
                Step::Complete => return Ok(CheckpointIoState::Complete),
                Step::Deferred => return Ok(CheckpointIoState::Deferred),
                Step::Device(event) => event,
            };
            let input = matches!(
                event,
                VcpuExit::IoIn { .. } | VcpuExit::IoInString { .. } | VcpuExit::MmioRead { .. }
            );
            // Both the CPU guard and VM entry lease have dropped. Device
            // callbacks may read CPU state or drive backend IRQ lines without
            // recursively locking this core. Never invent an input value.
            let reply = match catch_unwind(AssertUnwindSafe(|| service(event))) {
                Ok(Ok(reply)) => reply,
                Ok(Err(error)) => {
                    return self.with_native(|core| {
                        core.servicing_io = false;
                        Err(fail(core, error))
                    });
                }
                Err(payload) => {
                    let _ = self.with_native(|core| {
                        core.servicing_io = false;
                        fail(core, "device callback panicked");
                        Ok(())
                    });
                    resume_unwind(payload);
                }
            };
            if matches!(reply, CheckpointIoReply::PowerOff) {
                // The device effect has already powered off the VM. Publish
                // before any fallible acknowledgement or another CPU's entry.
                self.memory_owner.power_off()?;
            }
            self.with_native(|core| {
                core.servicing_io = false;
                match reply {
                    CheckpointIoReply::Input(bytes) if input => core.complete_native_input(&bytes),
                    CheckpointIoReply::Output if !input => core.acknowledge_native_output()?,
                    CheckpointIoReply::PowerOff if !input => {
                        core.acknowledge_native_output()?;
                        core.deferred_exit = Some(VcpuExit::Shutdown);
                        return Ok(());
                    }
                    _ => return Err(fail(core, "device reply kind differs from native request")),
                }
                // An output batch can still have unacknowledged elements;
                // preserve them for the next real service callback. Input
                // length/protocol failures remain terminal in the owned state.
                core.io.event().map_err(Error::Emulator)?;
                Ok(())
            })?;
        }
    }
}
