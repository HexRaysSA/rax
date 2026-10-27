//! Bounded execution over the existing one-instruction/one-packet interface.
use super::{VCpu, VcpuExit};
use crate::error::{Error, Result};

/// Planned deterministic scheduler quantum, in retired instructions/packets.
/// This constant does not change existing VMM scheduling by itself.
pub const DEFAULT_RETIREMENT_QUANTUM: u64 = 1_000;

#[derive(Debug)]
pub struct RetirementRun {
    pub retired: u64,
    pub stop: RetirementStop,
}
#[derive(Debug)]
pub enum RetirementStop {
    /// Exactly the requested number retired; no architectural exit occurred.
    BudgetExhausted,
    /// A synchronous exit, including halt/I/O, whether or not that step retired.
    Exit(VcpuExit),
    /// A successful step changed execution state without retiring a unit.
    /// Return control rather than spin through unbounded exception delivery.
    StateChange,
    /// Backend execution failed. `retired` counts earlier completed steps only.
    /// Existing charged instruction meters (eBPF/SBPF) may charge the failing
    /// attempt; that charge remains in the backend meter and is not retirement.
    Fault(Error),
}
pub(super) fn run<T: VCpu + ?Sized>(cpu: &mut T, budget: u64) -> Result<RetirementRun> {
    let mut retired = 0;
    if budget == 0 {
        return Ok(RetirementRun {
            retired,
            stop: RetirementStop::BudgetExhausted,
        });
    }
    if !cpu.supports_stepping() {
        return Err(Error::InvalidConfig(
            "retirement-budget execution requires single-instruction stepping".to_string(),
        ));
    }
    while retired < budget {
        let before = cpu.instruction_count();
        let exit = match cpu.step_insn() {
            Ok(exit) => exit,
            Err(error) => {
                return Ok(RetirementRun {
                    retired,
                    stop: RetirementStop::Fault(error),
                });
            }
        };
        // Successful existing steps commit at most one instruction/packet.
        // Wrapping counters are admitted across their u64 boundary.
        let delta = cpu.instruction_count().wrapping_sub(before);
        if delta > 1 {
            return Ok(RetirementRun {
                retired,
                stop: RetirementStop::Fault(Error::Emulator(format!(
                    "single step reported {delta} retired units; expected at most one"
                ))),
            });
        }
        // Publish before exposing the exit or starting the next instruction, so
        // a clock read inside the next step observes every prior retirement.
        crate::vm::timing::record_retirement(delta);
        retired += delta;
        if let Some(exit) = exit {
            return Ok(RetirementRun {
                retired,
                stop: RetirementStop::Exit(exit),
            });
        }
        if delta == 0 {
            return Ok(RetirementRun {
                retired,
                stop: RetirementStop::StateChange,
            });
        }
    }
    Ok(RetirementRun {
        retired,
        stop: RetirementStop::BudgetExhausted,
    })
}
