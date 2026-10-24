//! Scoped keyed-state helpers for either native host ISA.

use super::Aarch64GuestRegs;
use crate::smir::interpret::arm_pauth::{
    begin_instruction, commit_instruction, execute_pauth, unsupported,
};
use crate::smir::ir::context::{Aarch64RegState, ExitReason};
use crate::smir::ir::memory::SmirMemory;
use crate::smir::ir::ops::ArmPauthOp;

/// Full guest state and exact exits shared by the AArch64 and x86-64 native
/// helper lowerings. PAuth is computed in software using guest keys. A scoped
/// call installs its callback; no global state or host authentication keys are
/// consulted. The memory backend supplies architectural translation/faults.
pub struct Aarch64PauthRuntime<'a> {
    pub registers: Aarch64RegState,
    pub retired: u64,
    pub instruction_limit: u64,
    memory: &'a mut dyn SmirMemory,
    exit: Option<ExitReason>,
    active: Option<(u64, u32)>,
    executed_pauth: bool,
}

impl<'a> Aarch64PauthRuntime<'a> {
    pub fn new(
        registers: Aarch64RegState,
        memory: &'a mut dyn SmirMemory,
    ) -> Result<Self, ExitReason> {
        if registers.pauth_environment().is_none() {
            return Err(unsupported(registers.pc, "AArch64 native PAuth state"));
        }
        Ok(Self {
            registers,
            retired: 0,
            instruction_limit: u64::MAX,
            memory,
            exit: None,
            active: None,
            executed_pauth: false,
        })
    }

    /// Install the callback only while a synchronous native invocation owns
    /// this state. Restore prior bridge fields even if the Rust caller unwinds.
    /// `invoke` must not retain/copy the scoped callback/context for later use.
    pub fn run(
        &mut self,
        registers: &mut Aarch64GuestRegs,
        invoke: impl FnOnce(&mut Aarch64GuestRegs),
    ) -> Result<(), ExitReason> {
        let previous = (registers.pauth_context, registers.pauth_fn);
        self.exit = None;
        self.active = None;
        self.export(registers);
        registers.pauth_context = self as *mut Self as u64;
        registers.pauth_fn = helper as *const () as u64;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| invoke(registers)));
        registers.pauth_context = previous.0;
        registers.pauth_fn = previous.1;
        self.import(registers);
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
        if let Some(exit) = self.exit.take() {
            return Err(exit);
        }
        if self.active.is_some() {
            return Err(unsupported(
                self.registers.pc,
                "AArch64 incomplete native instruction",
            ));
        }
        Ok(())
    }

    fn import(&mut self, registers: &Aarch64GuestRegs) {
        self.registers.x = registers.x;
        self.registers.set_sp_value(registers.sp);
        self.registers.pc = registers.pc;
        self.registers.nzcv = (registers.nzcv & 0xf000_0000) as u32;
        self.registers.fpcr = registers.fpcr as u32;
        self.registers.fpsr = registers.fpsr as u32;
        for (index, value) in self.registers.v.iter_mut().enumerate() {
            *value = [registers.v[index * 2], registers.v[index * 2 + 1]];
        }
    }

    fn export(&self, registers: &mut Aarch64GuestRegs) {
        registers.x = self.registers.x;
        registers.sp = self.registers.sp;
        registers.pc = self.registers.pc;
        registers.nzcv = u64::from(self.registers.nzcv);
        registers.fpcr = u64::from(self.registers.fpcr);
        registers.fpsr = u64::from(self.registers.fpsr);
        for (index, value) in self.registers.v.iter().enumerate() {
            registers.v[index * 2] = value[0];
            registers.v[index * 2 + 1] = value[1];
        }
    }

    fn execute(&mut self, phase: u64, raw: u32, pc: u64, features: u64) -> Result<(), ExitReason> {
        if self.exit.is_some() {
            return Err(unsupported(pc, "AArch64 native execution after exit"));
        }
        match phase {
            0 if self.active.is_none() => {
                self.registers.pc = pc;
                if self.retired >= self.instruction_limit {
                    return Err(ExitReason::InsnLimit);
                }
                begin_instruction(&mut self.registers, self.memory, raw, features, pc)?;
                self.active = Some((pc, raw));
                self.executed_pauth = false;
            }
            1 if self.active == Some((pc, raw)) && !self.executed_pauth => {
                let operation = ArmPauthOp::decode(raw)
                    .ok_or_else(|| unsupported(pc, "AArch64 native PAuth encoding"))?;
                execute_pauth(&mut self.registers, self.memory, operation, pc)?;
                self.executed_pauth = true;
            }
            2 if self.active == Some((pc, raw)) => {
                if ArmPauthOp::decode(raw).is_some() != self.executed_pauth {
                    return Err(unsupported(pc, "AArch64 native PAuth instruction framing"));
                }
                commit_instruction(&mut self.registers, raw, pc);
                self.retired = self.retired.saturating_add(1);
                self.active = None;
            }
            _ => return Err(unsupported(pc, "AArch64 native instruction framing")),
        }
        Ok(())
    }
}

/// # Safety
/// The state pointer and scoped opaque context are valid, uniquely borrowed,
/// and live throughout the synchronous call installed by `run`. The native
/// lowerers reserve the state register and preserve the context fields.
unsafe fn helper_impl(
    registers: *mut Aarch64GuestRegs,
    phase: u64,
    raw: u64,
    pc: u64,
    features: u64,
) -> u64 {
    let Some(registers) = (unsafe { registers.as_mut() }) else {
        return 0;
    };
    if registers.pauth_context == 0 {
        registers.pc = pc;
        registers.exit_flags |= Aarch64GuestRegs::EXIT_VALID;
        return 0;
    }
    // The lifetime is erased only across this synchronous FFI call; `run`
    // retains exclusive ownership of the referenced state and memory backend.
    let runtime = unsafe { &mut *(registers.pauth_context as *mut Aarch64PauthRuntime<'_>) };
    runtime.import(registers);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let raw =
            u32::try_from(raw).map_err(|_| unsupported(pc, "AArch64 native instruction width"))?;
        runtime.execute(phase, raw, pc, features)
    }))
    .unwrap_or_else(|_| {
        Err(ExitReason::Aarch64Fault {
            pc,
            error: crate::isa::arm::common::cpu::ArmError::Internal(
                "AArch64 native PAuth helper panicked".into(),
            ),
        })
    });
    let ok = result.is_ok();
    if let Err(error) = result {
        runtime.registers.pc = pc;
        runtime.exit = Some(error);
        registers.exit_flags |= Aarch64GuestRegs::EXIT_VALID;
    }
    runtime.export(registers);
    u64::from(ok)
}

// The x86-64 lowerer uses SysV even on a Windows host; AArch64 uses AAPCS64.
#[cfg(target_arch = "x86_64")]
unsafe extern "sysv64" fn helper(
    registers: *mut Aarch64GuestRegs,
    phase: u64,
    raw: u64,
    pc: u64,
    features: u64,
) -> u64 {
    unsafe { helper_impl(registers, phase, raw, pc, features) }
}
#[cfg(not(target_arch = "x86_64"))]
unsafe extern "C" fn helper(
    registers: *mut Aarch64GuestRegs,
    phase: u64,
    raw: u64,
    pc: u64,
    features: u64,
) -> u64 {
    unsafe { helper_impl(registers, phase, raw, pc, features) }
}
