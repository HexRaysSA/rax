//! Precise instruction attempts and user-mode architectural TF retirement.

use super::*;

impl X86_64Vcpu {
    /// Execute one instruction attempt and consume any STI/MOV-SS interrupt
    /// shadow that protected this boundary. Fetch/decode/execution faults also
    /// consume the shadow because delivery of that event ends inhibition.
    pub fn step(&mut self) -> Result<Option<VcpuExit>> {
        self.interrupt_inhibit = false;
        let single_step = self.user_single_step_enabled();
        if let Some(user) = &mut self.user {
            user.step_suppressed = false;
            // RF suppresses an instruction breakpoint, then clears at the
            // start of execution; it does not suppress a TF trace trap.
            self.regs.rflags &= !flags::bits::RF;
        }
        let result = self.step_inner();
        if result.is_err() {
            if self.user_mode_enabled() && user_fault_frame(&result, self.sregs.dr6) {
                self.regs.rflags |= flags::bits::RF;
            }
            // A failed attempt (including a partially completed REP) did not
            // retire the instruction. Its architectural partial state remains.
            self.insn_count = self.insn_count.wrapping_sub(1);
        }
        let suppressed = self
            .user
            .as_mut()
            .is_some_and(|user| std::mem::take(&mut user.step_suppressed));
        if single_step
            && !suppressed
            && matches!(&result, Ok(None))
            && self.user_trap_pending().is_none()
        {
            // This is a retired instruction. Do not decrement its count when
            // the user-mode exception report returns GuestEvent below.
            self.sregs.dr6 |= 1 << 14; // DR6.BS.
            self.inject_exception(1, None)?;
        }
        result
    }

    /// Execute exactly one guest instruction with the same fault-delivery
    /// semantics as [`run`](Self::run): self-modifying-code caches are drained
    /// first, the instruction is decoded and executed, and any page fault or
    /// #GP it raises is delivered to the guest (returning `Ok(None)` so the
    /// next call resumes in the handler) precisely as the free-running loop
    /// would. The JIT and periodic LAPIC/yield housekeeping are intentionally
    /// bypassed so each call attempts one architectural instruction. A fault
    /// or a TF event between REP elements can return before full retirement.
    /// This is the precise primitive used by the embedding/debugger API.
    pub fn step_with_faults(&mut self) -> Result<Option<VcpuExit>> {
        if self.halted {
            return Ok(Some(VcpuExit::Hlt));
        }

        // Re-decode any code page modified since the previous instruction.
        self.drain_smc();

        match self.step() {
            Ok(exit) => Ok(exit),
            Err(Error::PageFault { vaddr, error_code }) => {
                // Deliver #PF; RIP still points at the faulting instruction so
                // the pushed frame restarts it once the handler returns.
                match self.inject_page_fault(vaddr, error_code) {
                    Ok(()) => Ok(None),
                    Err(Error::PageFault { .. }) => {
                        // Fault during #PF delivery: escalate to #DF (vector 8).
                        self.inject_exception(8, Some(0))
                            .map_err(|e| Error::FaultDelivery {
                                fault: Box::new(Error::PageFault { vaddr, error_code }),
                                diagnosis: format!(
                                    "double fault delivery failed at RIP={:#x}: {e}",
                                    self.regs.rip
                                ),
                            })?;
                        Ok(None)
                    }
                    Err(e @ Error::GuestEvent { .. }) => Err(e),
                    Err(e) => Err(Error::FaultDelivery {
                        fault: Box::new(Error::PageFault { vaddr, error_code }),
                        diagnosis: format!(
                            "#PF delivery failed at vaddr={vaddr:#x} (error_code={error_code:#x}): {e}"
                        ),
                    }),
                }
            }
            Err(Error::GeneralProtection { error_code }) => {
                self.inject_exception(13, Some(error_code))
                    .map_err(|e| match e {
                        // User mode reports the #GP instead of delivering it.
                        e @ Error::GuestEvent { .. } => e,
                        e => Error::FaultDelivery {
                            fault: Box::new(Error::GeneralProtection { error_code }),
                            diagnosis: format!(
                                "#GP (error_code={error_code:#x}) delivery failed: {e}"
                            ),
                        },
                    })?;
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
}

/// Fault frames set RF, unlike software interrupts and trap-class #DB/#BP.
/// A general-detect #DB is fault-class; an instruction breakpoint would keep
/// its incoming RF (that hardware condition is not generated on this path).
fn user_fault_frame(result: &Result<Option<VcpuExit>>, dr6: u64) -> bool {
    match result {
        Err(Error::GuestAccess(_) | Error::PageFault { .. } | Error::GeneralProtection { .. }) => {
            true
        }
        Err(Error::GuestEvent { vector }) => {
            matches!(
                *vector,
                0 | 5 | 6 | 7 | 10 | 11 | 12 | 13 | 14 | 16 | 17 | 19 | 21
            ) || (*vector == 1 && dr6 & (1 << 13) != 0)
        }
        _ => false,
    }
}
