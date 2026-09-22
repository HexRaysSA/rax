//! Software CPU run loop, including exact native-to-direct handoffs.

#[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
use super::maybe_spawn_mips_reporter;
use super::{Error, LAPIC_POLL_STRIDE, Result, VcpuExit, X86_64Vcpu, publish_instruction_count};

impl X86_64Vcpu {
    pub(super) fn run_loop(&mut self) -> Result<VcpuExit> {
        #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
        maybe_spawn_mips_reporter();
        let start_time = std::time::Instant::now();
        let mut batch: u64 = 0;
        loop {
            // Periodic housekeeping on a stride keeps the per-instruction path
            // free of clock reads, RefCell borrows and 64-bit division.
            batch = batch.wrapping_add(1);
            if batch % LAPIC_POLL_STRIDE == 0 {
                // Yield to the VMM (~1ms wall-clock slices) so timers/IRQs get
                // serviced. Real-time paced: the guest clock (TSC, elapsed_nanos)
                // tracks host wall time, so delays and timers complete in real
                // time rather than being tied to emulator instruction throughput.
                if self.poll_periodic_housekeeping(&start_time) {
                    publish_instruction_count(self.insn_count);
                    return Ok(VcpuExit::Hlt);
                }
            }

            if self.halted {
                publish_instruction_count(self.insn_count);
                // If halted but an interrupt is pending, keep spinning lightly.
                if self.mmu.has_lapic_pending() {
                    std::thread::yield_now();
                    continue;
                }
                return Ok(VcpuExit::Hlt);
            }

            // Self-modifying-code: drain the MMU's write journal and invalidate
            // decode + JIT caches for any code page written since the previous
            // instruction, so a freshly-modified opcode is re-decoded (and any
            // stale native region dropped) before it next executes. Guarded —
            // zero work when no code page has been written. Sits on the
            // run-loop path (where real guest execution and the JIT live); for
            // a JIT'd hot loop it costs one guarded check per native run-loop
            // slice. This is now the SOLE SMC invalidation point on
            // the run path: `note_smc` (in every MMU `write_u*`) journals the
            // page and this drain invalidates it once — deduplicated — before
            // the next fetch, so no per-store immediate scan is needed.
            self.drain_smc();

            #[cfg(feature = "debug")]
            if !self.single_step {
                if let Some(addr) = self.debug_breakpoint_at_current_rip() {
                    publish_instruction_count(self.insn_count);
                    return Ok(VcpuExit::GdbBreakpoint { addr });
                }
            }

            // SMIR hot-block JIT fast path: if the region at RIP has been
            // compiled, run it natively until a frontier/yield exit and continue.
            // Cheap O(1) guard keeps the interpreter path untouched until any
            // region has actually been promoted. `_jit_rip_before` snapshots RIP
            // so the post-step back-edge sampler can spot loop heads.
            #[cfg(all(
                feature = "smir-jit",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            let _jit_rip_before = {
                let rip = self.regs.rip;
                #[cfg(target_arch = "x86_64")]
                let direct_vsib_restart = self.jit_vsib_resume_pc.take() == Some(rip);
                #[cfg(target_arch = "aarch64")]
                let direct_vsib_restart = false;
                if !self.interrupt_inhibit
                    && !direct_vsib_restart
                    && !self.jit_disabled_for_debugger()
                    && !self.jit_cache.is_empty()
                {
                    let key = (rip, self.jit_mode_tag());
                    if let Some(slot) = self.jit_cache.get(&key).cloned() {
                        if let Some(region) = slot {
                            self.jit_run_region(&region);
                            // A lift-through-calls call-out may have bailed with a
                            // VMM-bound exit (I/O, HLT, …) from a callee — propagate it.
                            if let Some(exit) = self.jit_callout_exit.take() {
                                publish_instruction_count(self.insn_count);
                                return Ok(exit);
                            }
                            continue;
                        }
                        // None ⇒ known-ineligible: fall through to the interpreter.
                    }
                }
                rip
            };

            match self.step() {
                Ok(Some(exit)) => {
                    publish_instruction_count(self.insn_count);
                    return Ok(exit);
                }
                Ok(None) => {
                    #[cfg(all(
                        feature = "smir-jit",
                        any(target_arch = "x86_64", target_arch = "aarch64")
                    ))]
                    {
                        if !self.jit_disabled_for_debugger() {
                            self.jit_sample_backedge(_jit_rip_before);
                        }
                        // A region run on promotion may have bailed a call-out exit.
                        if let Some(exit) = self.jit_callout_exit.take() {
                            publish_instruction_count(self.insn_count);
                            return Ok(exit);
                        }
                    }
                    // Check for single-step mode (GDB debugging)
                    #[cfg(feature = "debug")]
                    if self.single_step {
                        publish_instruction_count(self.insn_count);
                        return Ok(VcpuExit::GdbStep);
                    }
                    continue;
                }
                Err(Error::PageFault { vaddr, error_code }) => {
                    // Inject the page fault exception into the guest
                    match self.inject_page_fault(vaddr, error_code) {
                        Ok(()) => continue,
                        Err(Error::PageFault {
                            vaddr: _df_vaddr, ..
                        }) => {
                            // Page fault during page fault delivery = double fault
                            // Try to inject #DF (vector 8)
                            match self.inject_exception(8, Some(0)) {
                                Ok(()) => continue,
                                Err(e) => {
                                    // Triple fault - CPU should reset
                                    return Err(Error::FaultDelivery {
                                        fault: Box::new(Error::PageFault { vaddr, error_code }),
                                        diagnosis: format!(
                                            "Triple fault at RIP={:#x} (double fault delivery failed: {:?}, original #PF at {:#x})",
                                            self.regs.rip, e, vaddr
                                        ),
                                    });
                                }
                            }
                        }
                        Err(e) => {
                            // IDT entry not present or other error during #PF injection
                            return Err(Error::FaultDelivery {
                                fault: Box::new(Error::PageFault { vaddr, error_code }),
                                diagnosis: format!(
                                    "#PF at vaddr={:#x} (error_code={:#x}, RIP={:#x}): {}",
                                    vaddr, error_code, self.regs.rip, e
                                ),
                            });
                        }
                    }
                }
                Err(Error::GeneralProtection { error_code }) => {
                    // Inject #GP (vector 13) into the guest. RIP still points at
                    // the faulting instruction (it is advanced only after an
                    // instruction retires), so the pushed frame restarts it.
                    // Unlike #PF, a #GP does not set CR2.
                    match self.inject_exception(13, Some(error_code)) {
                        Ok(()) => continue,
                        Err(e) => {
                            publish_instruction_count(self.insn_count);
                            return Err(Error::FaultDelivery {
                                fault: Box::new(Error::GeneralProtection { error_code }),
                                diagnosis: format!(
                                    "#GP (error_code={:#x}, RIP={:#x}) delivery failed: {}",
                                    error_code, self.regs.rip, e
                                ),
                            });
                        }
                    }
                }
                Err(e) => {
                    publish_instruction_count(self.insn_count);
                    return Err(e);
                }
            }
        }
    }
}
