//! ARM64 native entry with one call-local deadline and explicit host yields.
use super::super::arm64_bindings::{
    EC_DATA_ABORT_CURR, EC_DATA_ABORT_LOWER, EC_HVC64, EC_INST_ABORT_CURR, EC_INST_ABORT_LOWER,
    EC_MSR_MRS, EC_SMC64, EC_SVC64, EC_WFI_WFE, HV_GIC_INT_EL1_VIRTUAL_TIMER,
    HV_GIC_REDISTRIBUTOR_REG_GICR_ISPENDR0, HV_REG_PC, HV_SUCCESS, hv_error_string,
    hv_exit_reason_t, hv_gic_set_redistributor_reg, hv_vcpu_run,
};
use super::{HvfArm64Core, slice};
use crate::backend::intel_hvf_deadline::mach as host_clock;
use crate::error::{Error, Result};
use crate::vm::vcpu::VcpuExit;
use std::sync::atomic::Ordering;
use std::time::Duration;

impl HvfArm64Core {
    pub(super) fn run_host_slice(&mut self, limit: Duration) -> Result<Option<VcpuExit>> {
        slice::validate_interval(limit).map_err(|error| Error::InvalidConfig(error.into()))?;
        let deadline = host_clock::after(limit)?;
        if let Some(exit) = self.power_entry_exit()? {
            return Ok(Some(exit));
        }
        if self.native_shutdown()? {
            return Ok(Some(VcpuExit::Shutdown));
        }
        if let Some(error) = self.io_completion_error.take() {
            return Err(error);
        }
        if self.pending_io_reply.is_some() {
            self.finish_pending_read()?;
        }
        if let Some(pending) = &self.pending_mmio_write {
            return Ok(Some(VcpuExit::MmioWrite {
                addr: pending.address,
                data: pending.data.clone(),
            }));
        }
        if let Some(pending) = self.pending_mmio_read {
            return Ok(Some(VcpuExit::MmioRead {
                addr: pending.addr,
                size: pending.size,
            }));
        }
        loop {
            self._vm.ensure_live()?;
            if let Some(exit) = self.power_entry_exit()? {
                return Ok(Some(exit));
            }
            if host_clock::now() >= deadline {
                return Ok(None);
            }
            self._vm.entered.store(true, Ordering::Release);
            self.ever_entered = true;
            // SAFETY: the permanent creating owner holds this live SDK CPU.
            // The enclosing synchronous request retains VM/RAM and stopped
            // exclusion. The kick thread uses only the retained scalar ID.
            let ret = unsafe { hv_vcpu_run(self.vcpu) };
            if ret != HV_SUCCESS {
                return Err(Error::Emulator(format!(
                    "hv_vcpu_run failed: {}",
                    hv_error_string(ret)
                )));
            }

            // SAFETY: successful creation supplied this SDK-owned exit slot.
            // The creating owner reads it only after successful synchronous run;
            // the slot remains live until this core destroys its CPU.
            let exit_info = unsafe { &*self.exit }.clone();

            match exit_info.reason {
                hv_exit_reason_t::HV_EXIT_REASON_CANCELED => {
                    // A kick can be latched while this CPU is idle. Yielding
                    // immediately could consume every selected turn without
                    // entering the guest. Consume it within the same deadline;
                    // the loop's clock check still bounds the host turn.
                    continue;
                }

                hv_exit_reason_t::HV_EXIT_REASON_EXCEPTION => {
                    let exc = exit_info.exception;
                    let ec = exc.exception_class();

                    match ec {
                        EC_WFI_WFE => {
                            // WFI/WFE is a hint; retire it and yield to the
                            // VMM loop so console/devices get serviced. The
                            // next hv_vcpu_run delivers any due vtimer exit.
                            self.advance_pc(exc.instruction_length() as u64)?;
                            std::thread::sleep(std::time::Duration::from_micros(100));
                            return Ok(Some(VcpuExit::Hlt));
                        }

                        EC_DATA_ABORT_LOWER | EC_DATA_ABORT_CURR => {
                            // Data abort on unmapped memory: MMIO access
                            return self.handle_data_abort(&exit_info).map(Some);
                        }

                        EC_INST_ABORT_LOWER | EC_INST_ABORT_CURR => {
                            let addr = exc.physical_address;
                            return Ok(Some(VcpuExit::Unknown(format!(
                                "Instruction abort at {:#x}",
                                addr
                            ))));
                        }

                        // SMCCC: PSCI calls arrive as HVC (preferred return
                        // address already points past the HVC) or SMC (must
                        // skip the instruction ourselves).
                        EC_HVC64 => {
                            if let Some(exit) = self.handle_psci()? {
                                return Ok(Some(exit));
                            }
                        }
                        EC_SMC64 => {
                            self.advance_pc(4)?;
                            if let Some(exit) = self.handle_psci()? {
                                return Ok(Some(exit));
                            }
                        }

                        EC_MSR_MRS => {
                            self.handle_sysreg_trap(&exc)?;
                        }

                        EC_SVC64 => {
                            // Supervisor call - let the guest handle it
                            return Ok(Some(VcpuExit::Exception(ec as u8)));
                        }

                        _ => {
                            let pc = self.read_gpr(HV_REG_PC).unwrap_or(0);
                            return Ok(Some(VcpuExit::Unknown(format!(
                                "Exception class {:#x} at PC {:#x}, syndrome {:#x}",
                                ec, pc, exc.syndrome
                            ))));
                        }
                    }
                }

                hv_exit_reason_t::HV_EXIT_REASON_VTIMER_ACTIVATED => {
                    // Virtual timer fired: make PPI 27 pending in the guest's
                    // redistributor. HVF masks the vtimer until the guest
                    // deactivates the interrupt, then unmasks it.
                    // SAFETY: this owner holds the live CPU and its VM's
                    // in-kernel GIC; PPI 27 is within the redistributor bank.
                    // The call accepts only retained scalar values.
                    let ret = unsafe {
                        hv_gic_set_redistributor_reg(
                            self.vcpu,
                            HV_GIC_REDISTRIBUTOR_REG_GICR_ISPENDR0,
                            1u64 << HV_GIC_INT_EL1_VIRTUAL_TIMER,
                        )
                    };
                    if ret != HV_SUCCESS {
                        return Err(Error::Emulator(format!(
                            "failed to pend vtimer PPI: {}",
                            hv_error_string(ret)
                        )));
                    }
                }

                hv_exit_reason_t::HV_EXIT_REASON_UNKNOWN => {
                    let pc = self.read_gpr(HV_REG_PC).unwrap_or(0);
                    return Ok(Some(VcpuExit::Unknown(format!(
                        "Unknown exit at PC {:#x}",
                        pc
                    ))));
                }
            }
        }
    }
}
