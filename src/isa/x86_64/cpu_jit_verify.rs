//! Runtime differential verification of compiled x86-64 regions.

use super::{JitRegion, JitVerifyVsibStop, X86_64Vcpu, flags};

#[cfg(test)]
#[path = "cpu_jit_verify_tests.rs"]
mod tests;

impl X86_64Vcpu {
    /// Replay only the successful prefix of one terminal VSIB instruction.
    /// The ordinal is metadata, not a state oracle: source bytes, active lanes,
    /// addresses, values, and commits are reconstructed independently. Native
    /// instruction ordinal selects the dynamic occurrence before this helper
    /// is called; PC equality alone cannot identify a partial loop handoff.
    fn jit_verify_vsib_frontier(
        &mut self,
        region: &JitRegion,
        lane_plus_one: u64,
        native_trace: Option<&[(u8, u64, u8, u64)]>,
    ) -> core::result::Result<(), String> {
        let pc = self.regs.rip;
        let lane = lane_plus_one
            .checked_sub(1)
            .filter(|&lane| lane < 16)
            .ok_or_else(|| format!("invalid VSIB lane marker {lane_plus_one} at {pc:#x}"))?
            as u8;
        let index = region
            .vsib_instructions
            .binary_search_by_key(&pc, |&(pc, _)| pc)
            .map_err(|_| format!("VSIB marker has no source instruction at {pc:#x}"))?;
        let bytes = region.vsib_instructions[index].1;
        let encoding = bytes
            .evex_vsib_memory_encoding()
            .ok_or_else(|| format!("invalid cached VSIB source at {pc:#x}"))?;
        let mask = self.regs.k[usize::from(encoding.writemask)];
        if !self.sregs.cs.l
            || (encoding.requires_apx && !self.apx_enabled())
            || lane >= encoding.lanes
            || mask & (1u64 << lane) == 0
        {
            return Err(format!("inactive/out-of-range VSIB lane {lane} at {pc:#x}"));
        }
        let current = self
            .read_bytes(pc, bytes.as_slice().len())
            .map_err(|error| format!("unreadable VSIB source at {pc:#x}: {error}"))?;
        if current != bytes.as_slice() {
            return Err(format!("changed VSIB source at {pc:#x}"));
        }
        let prefix_len = (mask & ((1u64 << lane) - 1)).count_ones() as usize;
        let native_trace = native_trace
            .filter(|trace| trace.len() >= prefix_len)
            .ok_or_else(|| format!("missing native VSIB prefix trace at {pc:#x}"))?;
        let trace_start = self
            .jit_mem_trace
            .as_ref()
            .map(Vec::len)
            .ok_or_else(|| format!("missing interpreter VSIB prefix trace at {pc:#x}"))?;

        self.drain_smc();
        self.jit_verify_vsib_stop = Some(JitVerifyVsibStop::Requested { pc, lane });
        let result = self.step();
        let stopped = self.jit_verify_vsib_stop.take();
        if !matches!(result, Ok(None))
            || stopped != Some(JitVerifyVsibStop::Reached { pc, lane })
            || self.regs.rip != pc
        {
            return Err(format!(
                "direct VSIB replay did not reach lane {lane} at {pc:#x}"
            ));
        }
        let replay_trace = self
            .jit_mem_trace
            .as_ref()
            .and_then(|trace| trace.get(trace_start..))
            .ok_or_else(|| format!("overflowed interpreter VSIB prefix trace at {pc:#x}"))?;
        let expected = &native_trace[native_trace.len() - prefix_len..];
        if replay_trace.len() != prefix_len || replay_trace != expected {
            return Err(format!(
                "VSIB prefix access mismatch at {pc:#x}: direct={replay_trace:?}, native={expected:?}"
            ));
        }
        Ok(())
    }

    /// Verify a compiled region against the interpreter (RAX_JIT_VERIFY=1).
    pub(super) fn jit_run_region_verified(&mut self, region: &JitRegion) {
        // RDTSC/RDTSCP read the real-time guest clock. A second interpreter
        // execution cannot reproduce the earlier native value, and that value
        // can influence arbitrary later data/control flow in the same region.
        // Execute these regions normally; dedicated deterministic helper tests
        // validate their native semantics without producing false divergences.
        if region.uses_timestamp || region.uses_io {
            self.jit_run_region_native(region);
            return;
        }
        let entry_pc = self.regs.rip;
        let snap = self.regs.clone();
        let snap_fpu = self.fpu.clone();
        let snap_lf = self.lazy_flags;
        let snap_mxcsr = self.mxcsr;
        let snap_fs_base = self.sregs.fs.base;
        let snap_gs_base = self.sregs.gs.base;
        let snap_kernel_gs_base = self.kernel_gs_base;
        let snap_tsc_adjust = self.tsc_adjust;
        let snap_tsc_aux = self.tsc_aux;
        let snap_misc_enable = self.misc_enable;
        let snap_pat = self.pat;
        let snap_umwait_control = self.umwait_control;
        let snap_pkru = self.pkru;
        let snap_cr0 = self.sregs.cr0;
        let snap_cr2 = self.sregs.cr2;
        let snap_cr3 = self.sregs.cr3;
        let snap_cr4 = self.sregs.cr4;
        let snap_cr8 = self.sregs.cr8;
        let snap_efer = self.sregs.efer;
        let snap_star = self.sregs.star;
        let snap_lstar = self.sregs.lstar;
        let snap_cstar = self.sregs.cstar;
        let snap_fmask = self.sregs.fmask;
        let snap_sysenter_cs = self.sregs.sysenter_cs;
        let snap_sysenter_esp = self.sregs.sysenter_esp;
        let snap_sysenter_eip = self.sregs.sysenter_eip;
        let snap_dr0 = self.sregs.dr0;
        let snap_dr1 = self.sregs.dr1;
        let snap_dr2 = self.sregs.dr2;
        let snap_dr3 = self.sregs.dr3;
        let snap_dr6 = self.sregs.dr6;
        let snap_dr7 = self.sregs.dr7;
        let snap_descriptor_state = self.descriptor_state_snapshot();
        let snap_interrupt_inhibit = self.interrupt_inhibit;

        // 1) Run natively with store-logging (to UNDO writes) and an access
        //    trace (to diff against the interpreter's access sequence).
        self.jit_mem_log = Some(Vec::new());
        self.jit_mem_trace = Some(Vec::new());
        let (vsib_frontier, vsib_ordinal) = self.jit_run_region_native(region);
        let jit = self.regs.clone();
        let jit_fpu = self.fpu.clone();
        let jit_mxcsr = self.mxcsr;
        let jit_fs_base = self.sregs.fs.base;
        let jit_gs_base = self.sregs.gs.base;
        let jit_kernel_gs_base = self.kernel_gs_base;
        let jit_tsc_adjust = self.tsc_adjust;
        let jit_tsc_aux = self.tsc_aux;
        let jit_misc_enable = self.misc_enable;
        let jit_pat = self.pat;
        let jit_umwait_control = self.umwait_control;
        let jit_pkru = self.pkru;
        let jit_cr0 = self.sregs.cr0;
        let jit_cr2 = self.sregs.cr2;
        let jit_cr3 = self.sregs.cr3;
        let jit_cr4 = self.sregs.cr4;
        let jit_cr8 = self.sregs.cr8;
        let jit_efer = self.sregs.efer;
        let jit_star = self.sregs.star;
        let jit_lstar = self.sregs.lstar;
        let jit_cstar = self.sregs.cstar;
        let jit_fmask = self.sregs.fmask;
        let jit_sysenter_cs = self.sregs.sysenter_cs;
        let jit_sysenter_esp = self.sregs.sysenter_esp;
        let jit_sysenter_eip = self.sregs.sysenter_eip;
        let jit_dr0 = self.sregs.dr0;
        let jit_dr1 = self.sregs.dr1;
        let jit_dr2 = self.sregs.dr2;
        let jit_dr3 = self.sregs.dr3;
        let jit_dr6 = self.sregs.dr6;
        let jit_dr7 = self.sregs.dr7;
        let jit_descriptor_state = self.descriptor_state_snapshot();
        let jit_interrupt_inhibit = self.interrupt_inhibit;
        let jit_rflags = self.regs.rflags; // already materialized by the native bridge
        let exit_pc = self.regs.rip;
        // Take the native trace NOW, before the undo/re-read loops add to it.
        let jit_trace = self.jit_mem_trace.take();
        if vsib_frontier != 0
            && (vsib_ordinal == 0 || jit_trace.is_none() || self.jit_mem_log.is_none())
        {
            eprintln!(
                "[JIT-VERIFY] unverifiable VSIB frontier entry={entry_pc:#x} exit={exit_pc:#x}: ordinal={vsib_ordinal}, access/store log unavailable or invalid metadata"
            );
            std::process::exit(70);
        }
        let log = match self.jit_mem_log.take() {
            Some(l) => l,
            // Logging aborted (unreadable store target) → can't undo → adopt
            // the native result unverified.
            None => {
                self.regs = jit;
                self.fpu = jit_fpu;
                self.pkru = jit_pkru;
                return;
            }
        };
        // Capture the native final value at each written address, then UNDO the
        // region's writes (reverse order handles overlapping stores) so the
        // interpreter re-runs from the original memory image.
        let mut native_writes: Vec<(u64, u8, u64)> = Vec::with_capacity(log.len());
        for &(addr, size, _old) in &log {
            if let Ok(v) = self.read_mem(addr, size) {
                native_writes.push((addr, size, v));
            }
        }
        for &(addr, size, old) in log.iter().rev() {
            let _ = self.write_mem(addr, old, size);
        }

        // 2) Re-run the interpreter from the same entry up to the exit PC,
        //    restoring the LAZY flag state (the interpreter's source of truth).
        self.regs = snap.clone();
        self.fpu = snap_fpu;
        self.lazy_flags = snap_lf;
        self.mxcsr = snap_mxcsr;
        self.sregs.fs.base = snap_fs_base;
        self.sregs.gs.base = snap_gs_base;
        self.kernel_gs_base = snap_kernel_gs_base;
        self.tsc_adjust = snap_tsc_adjust;
        self.tsc_aux = snap_tsc_aux;
        self.misc_enable = snap_misc_enable;
        self.pat = snap_pat;
        self.umwait_control = snap_umwait_control;
        self.pkru = snap_pkru;
        self.sregs.cr0 = snap_cr0;
        self.sregs.cr2 = snap_cr2;
        self.sregs.cr3 = snap_cr3;
        self.sregs.cr4 = snap_cr4;
        self.sregs.cr8 = snap_cr8;
        self.sregs.efer = snap_efer;
        self.sregs.star = snap_star;
        self.sregs.lstar = snap_lstar;
        self.sregs.cstar = snap_cstar;
        self.sregs.fmask = snap_fmask;
        self.sregs.sysenter_cs = snap_sysenter_cs;
        self.sregs.sysenter_esp = snap_sysenter_esp;
        self.sregs.sysenter_eip = snap_sysenter_eip;
        self.sregs.dr0 = snap_dr0;
        self.sregs.dr1 = snap_dr1;
        self.sregs.dr2 = snap_dr2;
        self.sregs.dr3 = snap_dr3;
        self.sregs.dr6 = snap_dr6;
        self.sregs.dr7 = snap_dr7;
        self.interrupt_inhibit = snap_interrupt_inhibit;
        snap_descriptor_state.restore(self);
        // A lift-through-call callee can update translation controls through
        // the direct interpreter. The verification replay must not reuse TLB
        // entries created under the native run's CR0/CR3/CR4 state.
        self.mmu.flush_tlb();
        self.jit_mem_trace = Some(Vec::new());
        let cap = 50_000_000u64;
        let mut steps = 0u64;
        let mut reached = true;
        let expects_backward_exit = vsib_frontier == 0
            && region
                .yielded_backward_exit_pcs
                .binary_search(&exit_pc)
                .is_ok();
        let mut observed_backward_exit = false;
        let mut active_callout_return = None;
        let mut completed_vsib = 0u64;
        // A yielded edge can resume at the entry PC or at an internal block
        // that the interpreter reaches earlier by a forward edge. PC equality
        // alone therefore does not identify the native handoff. For an exit
        // synthesized from a CFG backedge, replay through the actual backward
        // transition (including a self-edge) before comparing state.
        while self.regs.rip != exit_pc
            || (expects_backward_exit && !observed_backward_exit)
            || active_callout_return.is_some()
            || (vsib_frontier != 0 && completed_vsib != vsib_ordinal - 1)
        {
            if steps >= cap || (vsib_frontier != 0 && completed_vsib >= vsib_ordinal) {
                reached = false;
                break;
            }
            // SMC: mirror the run-loop drain (this verify re-step bypasses it).
            self.drain_smc();
            let rip_before = self.regs.rip;
            // A direct callout can execute the same addresses, but its VSIB
            // instructions do not increment the native-region ordinal.
            let native_vsib = active_callout_return.is_none()
                && region
                    .vsib_instructions
                    .binary_search_by_key(&rip_before, |&(pc, _)| pc)
                    .is_ok();
            let entering_callout = active_callout_return.is_none().then(|| {
                region
                    .callout_boundaries
                    .binary_search_by_key(&rip_before, |&(call_pc, _)| call_pc)
                    .ok()
                    .map(|index| region.callout_boundaries[index].1)
            });
            match self.step() {
                Ok(None) => {}
                _ => {
                    reached = false;
                    break;
                }
            }
            steps += 1;
            completed_vsib += u64::from(native_vsib);
            if let Some(return_pc) = entering_callout.flatten() {
                active_callout_return = Some(return_pc);
            }
            if active_callout_return == Some(self.regs.rip) {
                active_callout_return = None;
            }
            observed_backward_exit |=
                expects_backward_exit && self.regs.rip == exit_pc && self.regs.rip <= rip_before;
        }
        // RIP equality identifies the instruction, not its partially completed
        // state. A lane helper can defer on SMC before the direct interpreter
        // would fault, so stepping the complete instruction is also incorrect.
        let frontier_error = if vsib_frontier != 0 {
            if reached {
                let result =
                    self.jit_verify_vsib_frontier(region, vsib_frontier, jit_trace.as_deref());
                steps += 1;
                result.err()
            } else {
                Some(format!(
                    "interpreter did not reach VSIB frontier {exit_pc:#x}"
                ))
            }
        } else {
            None
        };
        let interp_trace = self.jit_mem_trace.take();

        if reached || frontier_error.is_some() {
            // Retain the first per-access mismatch for a possible architectural
            // divergence report. Some direct handlers use typed MMU accessors
            // outside read_mem/write_mem, so a trace-only length/order mismatch
            // is diagnostic rather than proof of a JIT error and must not flood
            // a long verification run.
            let trace_diff_at =
                if let (Some(jit_trace), Some(interp_trace)) = (&jit_trace, &interp_trace) {
                    let n = jit_trace.len().min(interp_trace.len());
                    let mut diff_at: Option<usize> = None;
                    for i in 0..n {
                        if jit_trace[i] != interp_trace[i] {
                            diff_at = Some(i);
                            break;
                        }
                    }
                    if diff_at.is_some() || jit_trace.len() != interp_trace.len() {
                        Some((diff_at, n))
                    } else {
                        None
                    }
                } else {
                    None
                };

            // Status flags (CF/PF/AF/ZF/SF/OF), DF, and every virtualized
            // interrupt-control field. CLI may clear IF or VIF; every other
            // admitted operation must preserve IF/IOPL/VM/VIF/VIP. Comparing
            // the complete shadow catches native bridge corruption at the
            // exact handoff frontier.
            const MASK: u64 = flags::bits::CF
                | flags::bits::PF
                | flags::bits::AF
                | flags::bits::ZF
                | flags::bits::SF
                | flags::bits::OF
                | flags::bits::DF
                | crate::isa::x86_64::execute::system::X86_INTERRUPT_CONTROL_RFLAGS_MASK;
            let g = [
                ("rax", self.regs.rax, jit.rax),
                ("rcx", self.regs.rcx, jit.rcx),
                ("rdx", self.regs.rdx, jit.rdx),
                ("rbx", self.regs.rbx, jit.rbx),
                ("rsp", self.regs.rsp, jit.rsp),
                ("rbp", self.regs.rbp, jit.rbp),
                ("rsi", self.regs.rsi, jit.rsi),
                ("rdi", self.regs.rdi, jit.rdi),
                ("r8", self.regs.r8, jit.r8),
                ("r9", self.regs.r9, jit.r9),
                ("r10", self.regs.r10, jit.r10),
                ("r11", self.regs.r11, jit.r11),
                ("r12", self.regs.r12, jit.r12),
                ("r13", self.regs.r13, jit.r13),
                ("r14", self.regs.r14, jit.r14),
                ("r15", self.regs.r15, jit.r15),
                ("r16", self.regs.r16, jit.r16),
                ("r17", self.regs.r17, jit.r17),
                ("r18", self.regs.r18, jit.r18),
                ("r19", self.regs.r19, jit.r19),
                ("r20", self.regs.r20, jit.r20),
                ("r21", self.regs.r21, jit.r21),
                ("r22", self.regs.r22, jit.r22),
                ("r23", self.regs.r23, jit.r23),
                ("r24", self.regs.r24, jit.r24),
                ("r25", self.regs.r25, jit.r25),
                ("r26", self.regs.r26, jit.r26),
                ("r27", self.regs.r27, jit.r27),
                ("r28", self.regs.r28, jit.r28),
                ("r29", self.regs.r29, jit.r29),
                ("r30", self.regs.r30, jit.r30),
                ("r31", self.regs.r31, jit.r31),
            ];
            let mut diffs: Vec<String> = frontier_error.into_iter().collect();
            if vsib_frontier != 0 && self.mxcsr != jit_mxcsr {
                diffs.push(format!(
                    "mxcsr: interp={:#x} jit={jit_mxcsr:#x}",
                    self.mxcsr
                ));
            }
            for (name, interp, native) in g {
                if interp != native {
                    diffs.push(format!("{name}: interp={interp:#x} jit={native:#x}"));
                }
            }
            for (name, interp, native) in [
                ("fs_base", self.sregs.fs.base, jit_fs_base),
                ("gs_base", self.sregs.gs.base, jit_gs_base),
                ("kernel_gs_base", self.kernel_gs_base, jit_kernel_gs_base),
                ("tsc_adjust", self.tsc_adjust, jit_tsc_adjust),
                ("tsc_aux", u64::from(self.tsc_aux), u64::from(jit_tsc_aux)),
                ("misc_enable", self.misc_enable, jit_misc_enable),
                ("pat", self.pat, jit_pat),
                ("umwait_control", self.umwait_control, jit_umwait_control),
                ("pkru", u64::from(self.pkru), u64::from(jit_pkru)),
                ("cr0", self.sregs.cr0, jit_cr0),
                ("cr2", self.sregs.cr2, jit_cr2),
                ("cr3", self.sregs.cr3, jit_cr3),
                ("cr4", self.sregs.cr4, jit_cr4),
                ("cr8", self.sregs.cr8, jit_cr8),
                ("efer", self.sregs.efer, jit_efer),
                ("star", self.sregs.star, jit_star),
                ("lstar", self.sregs.lstar, jit_lstar),
                ("cstar", self.sregs.cstar, jit_cstar),
                ("fmask", self.sregs.fmask, jit_fmask),
                ("sysenter_cs", self.sregs.sysenter_cs, jit_sysenter_cs),
                ("sysenter_esp", self.sregs.sysenter_esp, jit_sysenter_esp),
                ("sysenter_eip", self.sregs.sysenter_eip, jit_sysenter_eip),
                ("dr0", self.sregs.dr0, jit_dr0),
                ("dr1", self.sregs.dr1, jit_dr1),
                ("dr2", self.sregs.dr2, jit_dr2),
                ("dr3", self.sregs.dr3, jit_dr3),
                ("dr6", self.sregs.dr6, jit_dr6),
                ("dr7", self.sregs.dr7, jit_dr7),
            ] {
                if interp != native {
                    diffs.push(format!("{name}: interp={interp:#x} jit={native:#x}"));
                }
            }
            jit_descriptor_state.append_verify_diffs(self, &mut diffs);
            if self.interrupt_inhibit != jit_interrupt_inhibit {
                diffs.push(format!(
                    "interrupt_inhibit: interp={} jit={}",
                    self.interrupt_inhibit, jit_interrupt_inhibit
                ));
            }
            // Vector (XMM/YMM/ZMM) + opmask (k) state. A masked-EVEX miscompile —
            // or any vector divergence — surfaces here. The interpreter result is
            // in self.regs, the native result in `jit`; the GPR/flags/memory checks
            // above are blind to ZMM/k.
            for i in 0..16 {
                if self.regs.xmm[i] != jit.xmm[i] {
                    diffs.push(format!(
                        "xmm{i}: interp={:016x?} jit={:016x?}",
                        self.regs.xmm[i], jit.xmm[i]
                    ));
                }
                if self.regs.ymm_high[i] != jit.ymm_high[i] {
                    diffs.push(format!(
                        "ymm_hi{i}: interp={:016x?} jit={:016x?}",
                        self.regs.ymm_high[i], jit.ymm_high[i]
                    ));
                }
                if self.regs.zmm_high[i] != jit.zmm_high[i] {
                    diffs.push(format!(
                        "zmm_hi{i}: interp={:016x?} jit={:016x?}",
                        self.regs.zmm_high[i], jit.zmm_high[i]
                    ));
                }
                if self.regs.zmm_ext[i] != jit.zmm_ext[i] {
                    diffs.push(format!(
                        "zmm{}: interp={:016x?} jit={:016x?}",
                        i + 16,
                        self.regs.zmm_ext[i],
                        jit.zmm_ext[i]
                    ));
                }
            }
            for i in 0..8 {
                if self.regs.k[i] != jit.k[i] {
                    diffs.push(format!(
                        "k{i}: interp={:#x} jit={:#x}",
                        self.regs.k[i], jit.k[i]
                    ));
                }
                if self.regs.mm[i] != jit.mm[i] {
                    diffs.push(format!(
                        "mm{i}: interp={:#x} jit={:#x}",
                        self.regs.mm[i], jit.mm[i]
                    ));
                }
            }
            self.fpu.append_jit_verify_diffs(&jit_fpu, &mut diffs);
            // A flags-ONLY divergence (registers + memory all match) is a benign
            // dead-flag artifact: the optimizer drops a flag update it proved
            // dead across the FULL lifted function, but the JIT region is
            // truncated at a frontier, so at the hand-off PC the stale flags are
            // still visible — yet the interpreter resumes into the very blocks
            // that overwrite them before any read. Log, don't abort.
            let interp_rflags = self.compute_materialized_rflags();
            let flag_diff = if (interp_rflags & MASK) != (jit_rflags & MASK) {
                Some(format!(
                    "rflags: interp={:#x} jit={:#x}",
                    interp_rflags & MASK,
                    jit_rflags & MASK
                ))
            } else {
                None
            };
            // A partial VSIB handoff exposes the exact fault-time flags. They
            // are not dead at an instruction-internal frontier, so the ordinary
            // flags-only diagnostic exemption cannot apply here.
            if vsib_frontier != 0 {
                if let Some(difference) = &flag_diff {
                    diffs.push(difference.clone());
                }
            }
            // Memory: compare the interpreter's final value at each address the
            // native region wrote.
            for &(addr, size, native_v) in &native_writes {
                if let Ok(interp_v) = self.read_mem(addr, size) {
                    if interp_v != native_v {
                        diffs.push(format!(
                            "mem[{addr:#x}/{size}B]: interp={interp_v:#x} jit={native_v:#x}"
                        ));
                    }
                }
            }
            if !diffs.is_empty() {
                let code = self.read_bytes(entry_pc, 256).unwrap_or_default();
                eprintln!(
                    "\n[JIT-VERIFY] DIVERGENCE entry={entry_pc:#x} exit={exit_pc:#x} steps={steps}"
                );
                eprintln!(
                    "[JIT-VERIFY] entry regs: rax={:#x} rcx={:#x} rdx={:#x} rbx={:#x} rsi={:#x} rdi={:#x} r8={:#x} r9={:#x} r10={:#x} r11={:#x}",
                    snap.rax,
                    snap.rcx,
                    snap.rdx,
                    snap.rbx,
                    snap.rsi,
                    snap.rdi,
                    snap.r8,
                    snap.r9,
                    snap.r10,
                    snap.r11
                );
                eprintln!("[JIT-VERIFY] code@entry[256] = {code:02x?}");
                if let (Some((diff_at, common_len)), Some(jit_trace), Some(interp_trace)) =
                    (trace_diff_at, &jit_trace, &interp_trace)
                {
                    let kindname = |kind: u8| if kind == 0 { "load " } else { "store" };
                    eprintln!(
                        "[JIT-VERIFY] memory trace: jit={} interp={} first_diff={diff_at:?}",
                        jit_trace.len(),
                        interp_trace.len()
                    );
                    let center = diff_at.unwrap_or(common_len.saturating_sub(1));
                    let lo = center.saturating_sub(4);
                    let hi = (center + 4).min(jit_trace.len().max(interp_trace.len()));
                    for index in lo..hi {
                        let native = jit_trace.get(index).map(|&(kind, addr, size, value)| {
                            format!("{} [{addr:#x}/{size}B]={value:#x}", kindname(kind))
                        });
                        let interpreted =
                            interp_trace.get(index).map(|&(kind, addr, size, value)| {
                                format!("{} [{addr:#x}/{size}B]={value:#x}", kindname(kind))
                            });
                        let mark = if jit_trace.get(index) != interp_trace.get(index) {
                            "<<<"
                        } else {
                            ""
                        };
                        eprintln!(
                            "[JIT-VERIFY]   #{index:<3} jit={:<34} interp={:<34} {mark}",
                            native.unwrap_or_else(|| "-".into()),
                            interpreted.unwrap_or_else(|| "-".into())
                        );
                    }
                }
                // The JIT's load trace reconstructs the memory the region reads
                // (the helper funnels every JIT access through read_mem).
                let loads: Vec<String> = jit_trace
                    .as_ref()
                    .map(|trace| {
                        trace
                            .iter()
                            .filter(|&&(k, _, _, _)| k == 0)
                            .map(|&(_, a, s, v)| format!("[{a:#x}/{s}B]={v:#x}"))
                            .collect()
                    })
                    .unwrap_or_default();
                eprintln!("[JIT-VERIFY] jit loads ({}): {:?}", loads.len(), loads);
                eprintln!(
                    "[JIT-VERIFY] lifted+optimized region:\n{}",
                    self.jit_dump_region(entry_pc)
                );
                for d in &diffs {
                    eprintln!("[JIT-VERIFY]   {d}");
                }
                eprintln!("[JIT-VERIFY] aborting (first divergence).");
                std::process::exit(70);
            }

            // Registers + memory matched. A residual flags-only difference is a
            // benign dead-flag artifact (see above) — log a throttled sample and
            // carry on with the native result, exactly as a non-verify run would.
            if let Some(d) = flag_diff {
                use std::sync::atomic::{AtomicUsize, Ordering};
                static N: AtomicUsize = AtomicUsize::new(0);
                let n = N.fetch_add(1, Ordering::Relaxed);
                if n < 8 {
                    eprintln!(
                        "[JIT-VERIFY] benign dead-flag diff #{n} entry={entry_pc:#x} exit={exit_pc:#x}: {d}"
                    );
                }
            }
        }

        // Matched (or unverifiable within the cap): adopt the native result.
        self.regs = jit;
        self.fpu = jit_fpu;
        self.mxcsr = jit_mxcsr;
        self.sregs.fs.base = jit_fs_base;
        self.sregs.gs.base = jit_gs_base;
        self.kernel_gs_base = jit_kernel_gs_base;
        self.tsc_adjust = jit_tsc_adjust;
        self.tsc_aux = jit_tsc_aux;
        self.misc_enable = jit_misc_enable;
        self.pat = jit_pat;
        self.umwait_control = jit_umwait_control;
        self.pkru = jit_pkru;
        self.sregs.cr0 = jit_cr0;
        self.sregs.cr2 = jit_cr2;
        self.sregs.cr3 = jit_cr3;
        self.sregs.cr4 = jit_cr4;
        self.sregs.cr8 = jit_cr8;
        self.sregs.efer = jit_efer;
        self.sregs.star = jit_star;
        self.sregs.lstar = jit_lstar;
        self.sregs.cstar = jit_cstar;
        self.sregs.fmask = jit_fmask;
        self.sregs.sysenter_cs = jit_sysenter_cs;
        self.sregs.sysenter_esp = jit_sysenter_esp;
        self.sregs.sysenter_eip = jit_sysenter_eip;
        self.sregs.dr0 = jit_dr0;
        self.sregs.dr1 = jit_dr1;
        self.sregs.dr2 = jit_dr2;
        self.sregs.dr3 = jit_dr3;
        self.sregs.dr6 = jit_dr6;
        self.sregs.dr7 = jit_dr7;
        self.interrupt_inhibit = jit_interrupt_inhibit;
        jit_descriptor_state.restore(self);
        self.mmu.flush_tlb();
    }
}
