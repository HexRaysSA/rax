//! Darwin user-entry and syscall-return debug frontiers.

use super::{DarwinCpu, Proc, Thread, Trap};
use crate::isa::x86_64::flags::bits::TF;
use crate::user::darwin::{exception, thread_status, wait::Resume};

pub(super) struct Step {
    arm: bool,
    restart: Option<Resume>,
    pub(super) arm_syndrome: Option<u32>,
}

impl Step {
    pub(super) fn capture(proc: &Proc, thread: &Thread) -> Self {
        let arm = matches!(&thread.cpu, DarwinCpu::Arm64(_))
            && thread_status::arm_step_enabled(&thread.mach.debug_state);
        Self {
            arm,
            restart: thread.resume,
            arm_syndrome: arm
                .then(|| exception::single_step_syndrome(proc, thread))
                .flatten(),
        }
    }

    /// Saved architectural control is authoritative, including a Mach write
    /// that cancels an earlier BSD PT_STEP request.
    pub(super) fn enabled(&self, thread: &Thread) -> bool {
        match &thread.cpu {
            DarwinCpu::Arm64(_) => thread_status::arm_step_enabled(&thread.mach.debug_state),
            DarwinCpu::X86_64(cpu) => cpu.vcpu().user_rflags() & TF != 0,
        }
    }

    pub(super) fn enter_user(&self, thread: &mut Thread) {
        if self.arm
            && let DarwinCpu::Arm64(cpu) = &mut thread.cpu
        {
            // Faults retain SS; a completed Arm step clears it in its handler.
            let psr = cpu.core().el0_spsr();
            cpu.core_mut().set_el0_spsr(psr | (1 << 21));
        }
    }

    pub(super) fn completed(&self, thread: &Thread, trap: Option<&Trap>) -> bool {
        match &thread.cpu {
            DarwinCpu::X86_64(_) => {
                // Ordinary TF traps and MOV/POP SS suppression belong to the
                // CPU. The personality completes SYSRET's debug frontier only
                // after its syscall service has returned.
                self.enabled(thread)
                    && matches!(
                        trap,
                        Some(
                            Trap::Unix { .. }
                                | Trap::Mach { .. }
                                | Trap::Machdep { .. }
                                | Trap::Platform { .. }
                                | Trap::Diag { .. }
                                | Trap::AbsoluteTime
                                | Trap::ContinuousTime
                        )
                    )
            }
            DarwinCpu::Arm64(_) => {
                // A slow Arm kernel return steps the next user instruction,
                // whereas Darwin x86 SYSRET steps at the return PC even after
                // the covered blocking read.
                self.arm
                    && !self.restarted_call(thread, trap)
                    && trap.is_some_and(|trap| {
                        !matches!(
                            trap,
                            Trap::Exception(_) | Trap::Internal(_) | Trap::BadSyscall { .. }
                        )
                    })
            }
        }
    }

    fn restarted_call(&self, thread: &Thread, trap: Option<&Trap>) -> bool {
        self.restart.is_some_and(|resume| {
            resume.pc == thread.cpu.pc()
                && match trap {
                    Some(Trap::Unix { code }) => {
                        let nr = if *code == 0 {
                            thread.cpu.indirect_number()
                        } else {
                            *code
                        };
                        resume.call == i64::from(nr)
                    }
                    Some(Trap::Mach { nr }) => resume.call == -i64::from(*nr),
                    _ => false,
                }
        })
    }
}
