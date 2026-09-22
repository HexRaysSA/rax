//! Emulator-private snapshot capture and validated restoration.

use super::*;

impl X86_64Vcpu {
    pub(super) fn snapshot_emulator_state(&self) -> Option<crate::vm::snapshot::EmulatorState> {
        use crate::vm::snapshot::{EmulatorState, FpuSnapshot, LazyFlagsSnapshot};

        let lf = self.lazy_flags;
        Some(EmulatorState {
            fpu: FpuSnapshot {
                control_word: self.fpu.control_word,
                status_word: self.fpu.status_word,
                tag_word: self.fpu.tag_word,
                data_ptr: self.fpu.data_ptr,
                instr_ptr: self.fpu.instr_ptr,
                last_opcode: self.fpu.last_opcode,
                st: self.fpu.st,
                top: self.fpu.top,
            },
            lazy_flags: LazyFlagsSnapshot {
                op: match lf.op {
                    LazyFlagOp::None => 0,
                    LazyFlagOp::Add => 1,
                    LazyFlagOp::Sub => 2,
                    LazyFlagOp::Logic => 3,
                    LazyFlagOp::Inc => 4,
                    LazyFlagOp::Dec => 5,
                },
                result: lf.result,
                src: lf.src,
                dst: lf.dst,
                size: lf.size,
            },
            kernel_gs_base: self.kernel_gs_base,
            tsc_adjust: self.tsc_adjust,
            tsc_aux: self.tsc_aux,
            misc_enable: self.misc_enable,
            pat: self.pat,
            umwait_control: self.umwait_control,
            pkru: self.pkru,
            mxcsr: self.mxcsr,
            halted: self.halted,
            interrupt_inhibit: self.interrupt_inhibit,
        })
    }

    pub(super) fn restore_emulator_state(
        &mut self,
        state: &crate::vm::snapshot::EmulatorState,
    ) -> Result<()> {
        // Snapshot validation is noncommitting, including emulator-private
        // restart/cache state. Invalid bits must never reach a host LDMXCSR.
        if !crate::isa::x86_64::mxcsr_value_is_valid(state.mxcsr) {
            return Err(Error::InvalidConfig(format!(
                "snapshot MXCSR {:#010x} sets reserved bits (supported mask {:#010x})",
                state.mxcsr,
                crate::isa::x86_64::MXCSR_SUPPORTED_MASK,
            )));
        }
        #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
        {
            self.jit_vsib_resume_pc = None;
        }
        // Restore FPU state
        self.fpu.control_word = state.fpu.control_word;
        self.fpu.status_word = state.fpu.status_word;
        self.fpu.tag_word = state.fpu.tag_word;
        self.fpu.data_ptr = state.fpu.data_ptr;
        self.fpu.instr_ptr = state.fpu.instr_ptr;
        self.fpu.last_opcode = state.fpu.last_opcode;
        self.fpu.st = state.fpu.st;
        self.fpu.top = state.fpu.top;

        // Restore lazy flags
        let op = match state.lazy_flags.op {
            0 => LazyFlagOp::None,
            1 => LazyFlagOp::Add,
            2 => LazyFlagOp::Sub,
            3 => LazyFlagOp::Logic,
            4 => LazyFlagOp::Inc,
            5 => LazyFlagOp::Dec,
            _ => LazyFlagOp::None,
        };
        self.lazy_flags = LazyFlags {
            op,
            result: state.lazy_flags.result,
            src: state.lazy_flags.src,
            dst: state.lazy_flags.dst,
            size: state.lazy_flags.size,
        };

        // Restore other state
        self.kernel_gs_base = state.kernel_gs_base;
        self.tsc_adjust = state.tsc_adjust;
        self.tsc_aux = state.tsc_aux;
        self.misc_enable = state.misc_enable;
        self.pat = state.pat;
        self.umwait_control = state.umwait_control;
        self.pkru = state.pkru;
        self.mxcsr = state.mxcsr;
        self.halted = state.halted;
        self.interrupt_inhibit = state.interrupt_inhibit;

        Ok(())
    }
}
