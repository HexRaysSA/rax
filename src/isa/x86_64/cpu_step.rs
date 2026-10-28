//! Direct instruction attempts and retirement-aware fault delivery.
use super::*;

impl X86_64Vcpu {
    /// Execute one instruction attempt and consume any STI/MOV-SS interrupt
    /// shadow that protected this boundary. Fetch/decode/execution faults also
    /// consume the shadow because delivery of that event ends inhibition.
    pub fn step(&mut self) -> Result<Option<VcpuExit>> {
        self.interrupt_inhibit = false;
        let before = self.insn_count;
        self.instruction_faulted = false;
        let result = self.step_inner();
        let faulted = std::mem::take(&mut self.instruction_faulted);
        if result.is_err() || faulted {
            // A failed attempt (including a partially completed REP) did not
            // retire the instruction. Its architectural partial state remains.
            self.insn_count = before;
        }
        result
    }

    /// Execute exactly one guest instruction with the same fault-delivery
    /// semantics as [`run`](Self::run): self-modifying-code caches are drained
    /// first, the instruction is decoded and executed, and any page fault or
    /// #GP it raises is delivered to the guest (returning `Ok(None)` so the
    /// next call resumes in the handler) precisely as the free-running loop
    /// would. The JIT and periodic LAPIC/yield housekeeping are intentionally
    /// bypassed so each call retires exactly one architectural instruction —
    /// this is the precise primitive the embedding/debugger API steps with.
    pub fn step_with_faults(&mut self) -> Result<Option<VcpuExit>> {
        if let Some(exit) = self.jit_callout_exit.take() {
            return Ok(Some(exit));
        }
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
