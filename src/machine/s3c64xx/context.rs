//! ARM1176 state and the platform models owned by its memory bridge.

use super::{Armv6Vcpu, LastFault, public_state};
use crate::devices::s3c64xx::{Pl192Vic, S3cPwmTimer, S3cSyscon, S3cUart};
use crate::error::{Error, Result};
use crate::isa::arm::Armv7Cpu;
use crate::isa::arm::instructions::ExclusiveMonitor;
use crate::vm::snapshot::{BackendContext, S3C64XX_CONTEXT};
use crate::vm::vcpu::{CpuState, VCpu};
use serde::{Deserialize, Serialize};

const TAG: &[u8; 8] = b"RAXS3C02";
const LEGACY_TAG: &[u8; 8] = b"RAXS3C01";
const MAX_PAYLOAD: usize = 16 * 1024 * 1024 - 8;

#[derive(Serialize, Deserialize)]
struct Context<C = Armv7Cpu> {
    id: u32,
    cpu: C,
    exclusive_address: Option<u32>,
    exclusive_size: u8,
    instruction_count: u64,
    shutdown: bool,
    last_fault: LastFault,
    poweroff: bool,
    vic0: Pl192Vic,
    vic1: Pl192Vic,
    pwm: S3cPwmTimer,
    syscon: S3cSyscon,
    uart: Option<S3cUart>,
}

impl Context<crate::isa::arm::aarch32::checkpoint::legacy::LegacyArmv7Cpu> {
    fn into_current(self) -> Context {
        Context {
            id: self.id,
            cpu: self.cpu.into_current(),
            exclusive_address: self.exclusive_address,
            exclusive_size: self.exclusive_size,
            instruction_count: self.instruction_count,
            shutdown: self.shutdown,
            last_fault: self.last_fault,
            poweroff: self.poweroff,
            vic0: self.vic0,
            vic1: self.vic1,
            pwm: self.pwm,
            syscon: self.syscon,
            uart: self.uart,
        }
    }
}

fn invalid(message: impl std::fmt::Display) -> Error {
    Error::Emulator(format!("S3C64xx context: {message}"))
}

impl Context {
    fn decode(raw: &[u8], id: u32) -> Result<Self> {
        if raw.len() > TAG.len() + MAX_PAYLOAD {
            return Err(invalid("context exceeds budget"));
        }
        let context: Self = if let Some(payload) = raw.strip_prefix(TAG) {
            crate::codec::deserialize_limited::<_, MAX_PAYLOAD>(payload).map_err(invalid)?
        } else if let Some(payload) = raw.strip_prefix(LEGACY_TAG) {
            let old: Context<crate::isa::arm::aarch32::checkpoint::legacy::LegacyArmv7Cpu> =
                crate::codec::deserialize_limited::<_, MAX_PAYLOAD>(payload).map_err(invalid)?;
            old.into_current()
        } else {
            return Err(invalid("invalid context tag"));
        };
        if context.id != id {
            return Err(invalid("vCPU identity differs from target"));
        }
        crate::backend::emulator::aarch32::context::validate_cpu(&context.cpu)?;
        if context.exclusive_address.is_some() && !matches!(context.exclusive_size, 1 | 2 | 4 | 8) {
            return Err(invalid("invalid exclusive reservation width"));
        }
        context.syscon.validate_checkpoint()?;
        Ok(context)
    }
}

impl Armv6Vcpu {
    pub(super) fn capture_context_record(&self) -> Result<BackendContext> {
        let inner = self.bridge.inner.borrow();
        let uart = self
            .uart
            .get()
            .map(|uart| {
                uart.lock()
                    .map(|uart| uart.clone())
                    .map_err(|_| invalid("UART lock poisoned"))
            })
            .transpose()?;
        let context = Context {
            id: self.id,
            cpu: self.cpu.clone(),
            exclusive_address: self.excl.address,
            exclusive_size: self.excl.size,
            instruction_count: self.insn_count,
            shutdown: self.shutdown,
            last_fault: inner.last_fault,
            poweroff: inner.poweroff,
            vic0: inner.vic0.clone(),
            vic1: inner.vic1.clone(),
            pwm: inner.pwm.clone(),
            syscon: inner.syscon.clone(),
            uart,
        };
        let payload = crate::codec::serialize_limited(&context, MAX_PAYLOAD).map_err(invalid)?;
        let mut data = Vec::with_capacity(TAG.len() + payload.len());
        data.extend_from_slice(TAG);
        data.extend_from_slice(&payload);
        // The producer must satisfy the same invariant as an imported record.
        Context::decode(&data, self.id)?;
        Ok(BackendContext {
            kind: S3C64XX_CONTEXT,
            data,
        })
    }

    pub(super) fn validate_context_record(
        &self,
        state: &CpuState,
        context: &BackendContext,
    ) -> Result<()> {
        if context.kind != S3C64XX_CONTEXT {
            return Err(invalid("context producer differs from target backend"));
        }
        let context = Context::decode(&context.data, self.id)?;
        if crate::codec::serialize(&public_state(&context.cpu)).map_err(invalid)?
            != crate::codec::serialize(state).map_err(invalid)?
        {
            return Err(invalid("public registers disagree with backend context"));
        }
        if context.uart.is_some() != self.uart.get().is_some() {
            return Err(invalid("UART attachment differs from target platform"));
        }
        if let Some(uart) = self.uart.get() {
            drop(uart.lock().map_err(|_| invalid("UART lock poisoned"))?);
        }
        Ok(())
    }

    pub(super) fn apply_context_record(
        &mut self,
        state: &CpuState,
        raw: &BackendContext,
    ) -> Result<()> {
        self.validate_context_record(state, raw)?;
        let context = Context::decode(&raw.data, self.id)?;
        let mut uart = self
            .uart
            .get()
            .map(|uart| uart.lock().map_err(|_| invalid("UART lock poisoned")))
            .transpose()?;
        // Acquire every fallible model lock before changing this CPU or bridge.
        let mut inner = self.bridge.inner.borrow_mut();
        self.cpu = context.cpu;
        self.excl = ExclusiveMonitor {
            address: context.exclusive_address,
            size: context.exclusive_size,
        };
        self.insn_count = context.instruction_count;
        self.shutdown = context.shutdown;
        inner.last_fault = context.last_fault;
        inner.poweroff = context.poweroff;
        inner.vic0 = context.vic0;
        inner.vic1 = context.vic1;
        inner.pwm = context.pwm;
        inner.syscon = context.syscon;
        if let (Some(target), Some(source)) = (&mut uart, context.uart) {
            **target = source;
        }
        // Translation/privilege are derived at the next instruction boundary;
        // decoder and host tracing caches do not contain guest-owned state.
        Ok(())
    }
}

#[cfg(test)]
#[path = "context_compat_tests.rs"]
mod compat_tests;
