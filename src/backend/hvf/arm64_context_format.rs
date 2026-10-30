//! Versioned native AArch64 CPU context, separate from shared GIC and RAM.
//! The producer must also match the target profile before native publication.
use crate::error::{Error, Result};
use crate::vm::vcpu::{Aarch64CpuState, CpuState};
use serde::{Deserialize, Serialize};
#[cfg(test)]
#[path = "arm64_context_format_tests.rs"]
mod tests;
const TAG: &[u8; 8] = b"RAXHVA04";
const LIMIT: usize = 128 * 1024;
pub(crate) const MAX_CPU_CONTEXT: u64 = (LIMIT + TAG.len()) as u64;
const VM_TAG: &[u8; 8] = b"RAXHVM02";
pub(crate) const MAX_SHARED_CONTEXT: usize = 64 * 1024 * 1024;
pub(crate) const SYSTEM_IDS: &[u16] = &[
    32772, 32773, 32774, 32775, 32780, 32781, 32782, 32783, 32784, 32786, 32788, 32789, 32790,
    32791, 32796, 32797, 32798, 32799, 32804, 32805, 32806, 32807, 32812, 32813, 32814, 32815,
    32820, 32821, 32822, 32823, 32828, 32829, 32830, 32831, 32836, 32837, 32838, 32839, 32844,
    32845, 32846, 32847, 32852, 32853, 32854, 32855, 32860, 32861, 32862, 32863, 32868, 32869,
    32870, 32871, 32876, 32877, 32878, 32879, 32884, 32885, 32886, 32887, 32892, 32893, 32894,
    32895, 49152, 49157, 49184, 49185, 49186, 49188, 49189, 49192, 49193, 49200, 49201, 49202,
    49208, 49209, 49210, 49211, 49212, 49280, 49281, 49282, 49300, 49302, 49408, 49409, 49410,
    49416, 49417, 49418, 49419, 49424, 49425, 49426, 49427, 49432, 49433, 49664, 49665, 49672,
    49800, 49801, 49808, 49920, 50080, 50448, 50456, 50688, 50817, 50820, 50823, 50952, 53248,
    56962, 56963, 56965, 56967, 57105, 57106, 57113, 57114, 57864,
];
pub(crate) const FEATURE_IDS: &[u16] = &[
    49184, 49185, 49186, 49188, 49189, 49192, 49193, 49200, 49201, 49202, 49208, 49209, 49210,
    49211, 49212,
];
pub(crate) const ICC_IDS: &[u16] = &[
    0xc230, 0xc643, 0xc644, 0xc648, 0xc663, 0xc664, 0xc665, 0xc666, 0xc667,
];
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Register {
    pub id: u16,
    pub value: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Profile {
    pub system_ids: Vec<u16>,
    pub feature_values: Vec<Register>,
    pub maximum_svl: u16,
}
impl Profile {
    fn supports_zt0(&self) -> bool {
        // ID_AA64SMFR0_EL1.SMEver[59:56]: 0 is SME, 1 introduces SME2.
        // Primary metadata: docs/specifications/arm/native-context-feature-registers/.
        self.feature_values
            .iter()
            .find(|register| register.id == 0xc025)
            .is_some_and(|register| (register.value >> 56) & 15 != 0)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Sme {
    pub streaming: bool,
    pub za_enabled: bool,
    pub z: Vec<u8>,
    pub p: Vec<u8>,
    pub za: Vec<u8>,
    pub zt: Option<Vec<u8>>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Controls {
    pub vtimer_masked: bool,
    pub vtimer_offset: u64,
    pub trap_debug_exceptions: bool,
    pub trap_debug_registers: bool,
    pub pending_serror: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PendingRead {
    pub address: u64,
    pub register: u32,
    pub size: u8,
    pub sign_extend: bool,
    pub sixty_four: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PendingWrite {
    pub address: u64,
    pub data: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Context {
    pub id: u32,
    pub profile: Profile,
    pub public: Aarch64CpuState,
    pub system: Vec<Register>,
    pub gic_cpu: Vec<Register>,
    pub running_priority: u64,
    pub controls: Controls,
    pub sme: Sme,
    /// Terminal PSCI exit, distinct from a canceled entry or waiting hint.
    pub shutdown: bool,
    pub pending_read: Option<PendingRead>,
    /// Output handed to the caller but not yet acknowledged after dispatch.
    pub pending_write: Option<PendingWrite>,
    /// Complete device input already obtained before a failed SDK writeback.
    /// Retrying this value must not perform another device read.
    pub pending_reply: Option<Vec<u8>>,
    // The native completion writer produces Error::Emulator; preserve its
    // payload exactly, without adding another display prefix on restoration.
    pub completion_error: Option<String>,
}

/// Shared native device state. CPU-interface registers belong to each CPU
/// record; the SDK blob contains the remaining complete GIC device state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct GlobalContext {
    pub cpus: u8,
    pub power: crate::backend::arm64_hvf_power::Power,
    pub ram_base: u64,
    pub ram_size: u64,
    pub distributor_base: u64,
    pub redistributor_base: u64,
    pub spi_base: u32,
    pub spi_count: u32,
    pub affinities: Vec<u64>,
    pub irq_levels: Vec<(u32, bool)>,
    pub gic: Vec<u8>,
}

impl GlobalContext {
    pub fn validate(&self) -> Result<()> {
        self.power
            .validate(self.cpus, self.ram_base, self.ram_size)?;
        if self.cpus == 0
            || self.affinities.len() != usize::from(self.cpus)
            || self.affinities.iter().copied().ne((0..u32::from(self.cpus))
                .map(crate::isa::arm::aarch64::AArch64Cpu::mpidr_for_cpu_id))
        {
            return Err(invalid("shared CPU affinities differ from native topology"));
        }
        if self.ram_size == 0 || self.ram_base.checked_add(self.ram_size).is_none() {
            return Err(invalid("invalid native RAM window"));
        }
        let spi_end = self
            .spi_base
            .checked_add(self.spi_count)
            .filter(|&end| self.spi_base >= 32 && end > self.spi_base)
            .ok_or_else(|| invalid("invalid native SPI range"))?;
        let mut previous = None;
        for &(irq, _) in &self.irq_levels {
            if irq < self.spi_base || irq >= spi_end || previous.is_some_and(|old| old >= irq) {
                return Err(invalid("invalid native IRQ output levels"));
            }
            previous = Some(irq);
        }
        // Leave a fixed budget for the bounded topology and output-level table.
        if self.irq_levels.len() > 4096
            || self.gic.is_empty()
            || self.gic.len() > MAX_SHARED_CONTEXT - 64 * 1024
        {
            return Err(invalid("native shared device record exceeds its budget"));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut raw = VM_TAG.to_vec();
        raw.extend(crate::codec::serialize_limited(self, MAX_SHARED_CONTEXT).map_err(invalid)?);
        Ok(raw)
    }

    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > MAX_SHARED_CONTEXT + VM_TAG.len() {
            return Err(invalid("native shared record exceeds its byte limit"));
        }
        let data = raw
            .strip_prefix(VM_TAG)
            .ok_or_else(|| invalid("unknown native shared producer/version"))?;
        let context: Self =
            crate::codec::deserialize_limited::<_, MAX_SHARED_CONTEXT>(data).map_err(invalid)?;
        context.validate()?;
        Ok(context)
    }
}
fn invalid(message: impl std::fmt::Display) -> Error {
    Error::Emulator(format!("native AArch64 context: {message}"))
}
fn sorted_unique(ids: impl Iterator<Item = u16>) -> bool {
    let mut previous = None;
    for id in ids {
        if previous.is_some_and(|p| p >= id) {
            return false;
        }
        previous = Some(id);
    }
    true
}
impl Sme {
    fn validate(&self, maximum_svl: u16) -> Result<()> {
        let bytes = usize::from(maximum_svl);
        if bytes == 0 {
            if self.streaming
                || self.za_enabled
                || !self.z.is_empty()
                || !self.p.is_empty()
                || !self.za.is_empty()
                || self.zt.is_some()
            {
                return Err(invalid("SME storage in an absent profile"));
            }
            return Ok(());
        }
        if !(16..=256).contains(&bytes) || bytes % 16 != 0 {
            return Err(invalid("invalid maximum streaming vector length"));
        }
        let (z, p) = if self.streaming {
            (32 * bytes, 2 * bytes)
        } else {
            (0, 0)
        };
        if self.z.len() != z || self.p.len() != p {
            return Err(invalid(
                "streaming register lengths disagree with mode/profile",
            ));
        }
        let za = if self.za_enabled { bytes * bytes } else { 0 };
        if self.za.len() != za
            || self
                .zt
                .as_ref()
                .is_some_and(|zt| !self.za_enabled || zt.len() != 64)
        {
            return Err(invalid("ZA/ZT storage disagrees with mode/profile"));
        }
        Ok(())
    }
}
impl Context {
    pub fn system_value(&self, id: u16) -> Result<u64> {
        self.system
            .binary_search_by_key(&id, |r| r.id)
            .map(|i| self.system[i].value)
            .map_err(|_| invalid(format!("missing system register {id:#x}")))
    }
    pub fn project_system(&mut self) -> Result<()> {
        macro_rules! overlay {($($field:ident=$id:literal),+ $(,)?)=>{$(self.public.sregs.$field=self.system_value($id)?;)+};}
        overlay!(
            sctlr_el1 = 0xc080,
            tcr_el1 = 0xc102,
            ttbr0_el1 = 0xc100,
            ttbr1_el1 = 0xc101,
            mair_el1 = 0xc510,
            vbar_el1 = 0xc600,
            esr_el1 = 0xc290,
            far_el1 = 0xc300,
            elr_el1 = 0xc201,
            spsr_el1 = 0xc200,
            sp_el0 = 0xc208,
            sp_el1 = 0xe208,
            tpidr_el0 = 0xde82,
            tpidr_el1 = 0xc684,
            tpidrro_el0 = 0xde83,
            cntp_ctl_el0 = 0xdf11,
            cntp_cval_el0 = 0xdf12,
            cntv_ctl_el0 = 0xdf19,
            cntv_cval_el0 = 0xdf1a
        );
        self.public.sregs.execution = None;
        self.public.regs.sp = match self.public.regs.pstate & 31 {
            0 | 4 => self.public.sregs.sp_el0,
            5 => self.public.sregs.sp_el1,
            _ => return Err(invalid("unsupported native exception level/mode")),
        };
        Ok(())
    }
    pub fn validate(&self) -> Result<()> {
        let profile = &self.profile;
        if profile.system_ids.is_empty()
            || profile.system_ids.len() > SYSTEM_IDS.len()
            || !sorted_unique(profile.system_ids.iter().copied())
            || profile
                .system_ids
                .iter()
                .any(|id| SYSTEM_IDS.binary_search(id).is_err())
            || self
                .system
                .iter()
                .map(|r| r.id)
                .ne(profile.system_ids.iter().copied())
        {
            return Err(invalid(
                "incomplete, unordered or unknown system register profile",
            ));
        }
        if !sorted_unique(profile.feature_values.iter().map(|r| r.id))
            || profile.feature_values.iter().map(|r| r.id).ne(profile
                .system_ids
                .iter()
                .copied()
                .filter(|id| FEATURE_IDS.binary_search(id).is_ok()))
        {
            return Err(invalid("feature inventory disagrees with register profile"));
        }
        for feature in &profile.feature_values {
            if self.system_value(feature.id)? != feature.value {
                return Err(invalid("feature state differs from admitted profile"));
            }
        }
        if self
            .gic_cpu
            .iter()
            .map(|r| r.id)
            .ne(ICC_IDS.iter().copied())
            || self.running_priority > 255
        {
            return Err(invalid("invalid GIC CPU-interface state"));
        }
        let mut projected = self.clone();
        projected.project_system()?;
        if projected.public != self.public {
            return Err(invalid(
                "public system/stack projection disagrees with native bank",
            ));
        }
        // VM-wide shutdown can coincide with a peer's pending MMIO. Preserve
        // that dormant transaction until the embedder explicitly restarts it.
        if let Some(pending) = &self.pending_read {
            if pending.register > 31 || !matches!(pending.size, 1 | 2 | 4 | 8) {
                return Err(invalid("invalid pending scalar MMIO request"));
            }
        }
        if let Some(pending) = &self.pending_write {
            if self.pending_read.is_some()
                || !matches!(pending.data.len(), 1 | 2 | 4 | 8)
                || pending
                    .address
                    .checked_add((pending.data.len() - 1) as u64)
                    .is_none()
            {
                return Err(invalid("invalid or conflicting pending scalar MMIO output"));
            }
        }
        if self.pending_reply.as_ref().is_some_and(|reply| {
            self.pending_read
                .as_ref()
                .is_none_or(|read| reply.len() != usize::from(read.size))
        }) {
            return Err(invalid("staged reply differs from its pending read"));
        }
        if self.completion_error.as_ref().is_some_and(|e| {
            e.len() > 4096 || self.pending_read.is_none() || self.pending_reply.is_none()
        }) {
            return Err(invalid("invalid deferred native completion failure"));
        }
        self.sme.validate(profile.maximum_svl)?;
        if self.sme.zt.is_some() != (self.sme.za_enabled && profile.supports_zt0()) {
            return Err(invalid(
                "ZT0 storage disagrees with the native SME2 profile",
            ));
        }
        if self.system_value(0xc005)?
            != crate::isa::arm::aarch64::AArch64Cpu::mpidr_for_cpu_id(self.id)
        {
            return Err(invalid("MPIDR differs from the native vCPU identity"));
        }
        if self.sme.streaming {
            for (index, z) in self
                .sme
                .z
                .chunks_exact(usize::from(profile.maximum_svl))
                .enumerate()
            {
                let value = [
                    u64::from_le_bytes(z[..8].try_into().unwrap()),
                    u64::from_le_bytes(z[8..16].try_into().unwrap()),
                ];
                if self.public.regs.v[index] != value {
                    return Err(invalid(
                        "public Q registers disagree with streaming Z aliases",
                    ));
                }
            }
        }
        Ok(())
    }
    pub fn admit(&self, id: u32, profile: &Profile, public: &CpuState) -> Result<()> {
        self.validate()?;
        if self.id != id || &self.profile != profile {
            return Err(invalid("target identity or native profile differs"));
        }
        match public {
            CpuState::Aarch64(state) if state == &self.public => Ok(()),
            _ => Err(invalid("public CPU state disagrees with native context")),
        }
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = TAG.to_vec();
        bytes.extend(crate::codec::serialize_limited(self, LIMIT).map_err(invalid)?);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > TAG.len() + LIMIT {
            return Err(invalid("payload exceeds byte limit"));
        }
        let raw = bytes
            .strip_prefix(TAG)
            .ok_or_else(|| invalid("unknown producer/version tag"))?;
        let context: Self = crate::codec::deserialize_limited::<_, LIMIT>(raw).map_err(invalid)?;
        context.validate()?;
        Ok(context)
    }
}
