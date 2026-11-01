//! Portable, bounded native Intel CPU and VM producer records.
use super::intel_hvf_io::{mmio, port_io};
use super::intel_hvf_projection::{self as projection, Read};
use super::intel_hvf_registers::{hv_vmx_vmcs_field_t as V, hv_x86_reg_t as R};
use super::intel_hvf_xsave::{Layout, MAX_IMAGE};
use crate::error::{Error, Result};
use crate::vm::snapshot::EmulatorState;
use crate::vm::vcpu::{CpuState, VcpuExit, X86_64CpuState};
use serde::{Deserialize, Serialize};

#[cfg(test)]
#[path = "intel_context_tests.rs"]
pub(crate) mod tests;

const CPU_TAG: &[u8; 8] = b"RAXHVI01";
const VM_TAG: &[u8; 8] = b"RAXHVG01";
const CPU_LIMIT: usize = MAX_IMAGE + 128 * 1024;
const VM_LIMIT: usize = 64 * 1024 * 1024;
pub(crate) const MAX_CPU_CONTEXT: u64 = (CPU_LIMIT + 8) as u64;
pub(crate) const STAR: u32 = 0xc000_0081;
pub(crate) const LSTAR: u32 = 0xc000_0082;
pub(crate) const CSTAR: u32 = 0xc000_0083;
pub(crate) const FMASK: u32 = 0xc000_0084;
pub(crate) const KERNEL_GS_BASE: u32 = 0xc000_0102;
pub(crate) const TSC_AUX: u32 = 0xc000_0103;
pub(crate) const MSRS: &[u32] = &[STAR, LSTAR, CSTAR, FMASK, KERNEL_GS_BASE, TSC_AUX];
pub(crate) const MONITOR_TRAP: u64 = 1 << 27;
pub(crate) const DEBUG_EXCEPTIONS: u64 = (1 << 1) | (1 << 3);

fn invalid(message: impl std::fmt::Display) -> Error {
    Error::InvalidConfig(format!("native Intel context: {message}"))
}
fn check_error(value: &Option<String>) -> Result<()> {
    if value.as_ref().is_some_and(|error| error.len() > 16 * 1024) {
        Err(invalid("error payload exceeds its limit"))
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Register {
    pub id: u32,
    pub value: u64,
}

fn bank(registers: &[Register], ids: &[u32]) -> Result<()> {
    if registers
        .iter()
        .map(|register| register.id)
        .ne(ids.iter().copied())
    {
        return Err(invalid("register bank differs from its admitted schema"));
    }
    Ok(())
}
pub(crate) fn value(registers: &[Register], id: u32) -> Result<u64> {
    registers
        .binary_search_by_key(&id, |register| register.id)
        .map(|index| registers[index].value)
        .map_err(|_| invalid(format_args!("missing register {id:#x}")))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Cpuid {
    pub leaf: u32,
    pub subleaf: u32,
    pub words: [u32; 4],
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Identity {
    pub maximum_basic: u32,
    pub maximum_extended: u32,
    pub vendor: [u8; 12],
    pub brand: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Capabilities {
    pub pin: u64,
    pub primary: u64,
    pub secondary: u64,
    pub entry: u64,
    pub misc: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Profile {
    pub identity: Identity,
    pub host: Vec<Cpuid>,
    pub xsave: Layout,
    pub capabilities: Capabilities,
    pub fields: Vec<u32>,
    pub controls: Vec<Register>,
    pub tsc_hz: Option<u64>,
}

fn control(capability: u64, value: u64) -> Result<()> {
    let required = u64::from(capability as u32);
    let allowed = capability >> 32;
    if required & !allowed != 0 || value & required != required || value & !allowed != 0 {
        return Err(invalid("VMX controls violate their capability masks"));
    }
    Ok(())
}

impl Profile {
    pub fn validate(&self) -> Result<()> {
        self.xsave.validate()?;
        if self.identity.brand.len() != 48
            || self.host.len() > 96
            || self.host.is_empty()
            || self.tsc_hz == Some(0)
        {
            return Err(invalid("invalid CPU identity or host profile"));
        }
        if self
            .host
            .windows(2)
            .any(|pair| (pair[0].leaf, pair[0].subleaf) >= (pair[1].leaf, pair[1].subleaf))
        {
            return Err(invalid("host CPUID table is not ordered and unique"));
        }
        let candidates = vmcs_candidates();
        if self.fields.windows(2).any(|pair| pair[0] >= pair[1])
            || self.fields.iter().any(|id| !candidates.contains(id))
            || candidates
                .iter()
                .any(|id| !optional_field(*id) && !self.fields.contains(id))
        {
            return Err(invalid("SDK VMCS field schema is incomplete or unknown"));
        }
        bank(&self.controls, &policy_fields())?;
        self.check_controls(&self.controls, true)?;
        Ok(())
    }

    fn check_controls(&self, fields: &[Register], policy: bool) -> Result<()> {
        for (id, capability) in [
            (V::VMCS_CTRL_PIN_BASED as u32, self.capabilities.pin),
            (V::VMCS_CTRL_CPU_BASED as u32, self.capabilities.primary),
            (V::VMCS_CTRL_CPU_BASED2 as u32, self.capabilities.secondary),
            (
                V::VMCS_CTRL_VMENTRY_CONTROLS as u32,
                self.capabilities.entry,
            ),
        ] {
            let current = value(fields, id)?;
            control(capability, current)?;
            if !policy {
                let dynamic = match id {
                    id if id == V::VMCS_CTRL_CPU_BASED as u32 => MONITOR_TRAP | (1 << 2),
                    id if id == V::VMCS_CTRL_VMENTRY_CONTROLS as u32 => 1 << 9,
                    _ => 0,
                };
                if (current ^ value(&self.controls, id)?) & !dynamic != 0 {
                    return Err(invalid("saved controls differ from the producer policy"));
                }
            }
        }
        if !policy {
            for id in [V::VMCS_CTRL_CR0_MASK as u32, V::VMCS_CTRL_CR4_MASK as u32] {
                if value(fields, id)? != value(&self.controls, id)? {
                    return Err(invalid("saved control-register masks differ from policy"));
                }
            }
            let id = V::VMCS_CTRL_EXC_BITMAP as u32;
            if (value(fields, id)? ^ value(&self.controls, id)?) & !DEBUG_EXCEPTIONS != 0 {
                return Err(invalid("saved exception intercepts differ from policy"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Packet {
    PortRead {
        port: u16,
        size: u8,
    },
    PortWrite {
        port: u16,
        data: Vec<u8>,
    },
    Read {
        address: u64,
        size: u8,
    },
    Write {
        address: u64,
        data: Vec<u8>,
    },
    Rmw {
        address: u64,
        size: u8,
        operation: crate::devices::bus::MmioRmwOp,
    },
}
impl Packet {
    pub fn from_exit(exit: &VcpuExit) -> Result<Self> {
        Ok(match exit {
            VcpuExit::IoIn { port, size } => Self::PortRead {
                port: *port,
                size: *size,
            },
            VcpuExit::IoOut { port, data } => Self::PortWrite {
                port: *port,
                data: data.clone(),
            },
            VcpuExit::MmioRead { addr, size } => Self::Read {
                address: *addr,
                size: *size,
            },
            VcpuExit::MmioWrite { addr, data } => Self::Write {
                address: *addr,
                data: data.clone(),
            },
            VcpuExit::MmioRmw {
                addr,
                size,
                operation,
            } => Self::Rmw {
                address: *addr,
                size: *size,
                operation: *operation,
            },
            _ => return Err(invalid("non-I/O exit in native transaction")),
        })
    }
    pub fn exit(&self) -> VcpuExit {
        match self {
            Self::PortRead { port, size } => VcpuExit::IoIn {
                port: *port,
                size: *size,
            },
            Self::PortWrite { port, data } => VcpuExit::IoOut {
                port: *port,
                data: data.clone(),
            },
            Self::Read { address, size } => VcpuExit::MmioRead {
                addr: *address,
                size: *size,
            },
            Self::Write { address, data } => VcpuExit::MmioWrite {
                addr: *address,
                data: data.clone(),
            },
            Self::Rmw {
                address,
                size,
                operation,
            } => VcpuExit::MmioRmw {
                addr: *address,
                size: *size,
                operation: *operation,
            },
        }
    }
    pub fn validate(&self) -> Result<()> {
        let (address, size, port) = match self {
            Self::PortRead { size, .. } => (None, usize::from(*size), true),
            Self::PortWrite { data, .. } => (None, data.len(), true),
            Self::Read { address, size } => (Some(*address), usize::from(*size), false),
            Self::Write { address, data } => (Some(*address), data.len(), false),
            Self::Rmw {
                address,
                size,
                operation,
            } => {
                operation.validate(*size)?;
                (Some(*address), usize::from(*size), false)
            }
        };
        if !matches!(size, 1 | 2 | 4 | 8)
            || (port && size == 8)
            || address.is_some_and(|address| address.checked_add(size as u64).is_none())
        {
            return Err(invalid("invalid native I/O width or address"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct DebugState {
    pub enabled: bool,
    pub completed: bool,
    pub failure: Option<String>,
}

/// Host binding retained for exact destination rollback. Forward imports use
/// the logical guest time point and establish a new host epoch instead.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ClockBinding {
    pub offset: i64,
    pub pending: Option<(u64, bool)>,
    pub epoch: Option<u64>,
}
impl ClockBinding {
    pub fn at(&self, anchor: u64) -> u64 {
        match self.pending {
            None => anchor.wrapping_add(self.offset as u64),
            Some((point, false)) => point,
            Some((point, true)) => self.epoch.map_or(point, |epoch| {
                point.wrapping_add(anchor.wrapping_sub(epoch))
            }),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Context {
    pub id: u32,
    pub profile: Profile,
    pub public: X86_64CpuState,
    pub emulator: EmulatorState,
    pub registers: Vec<Register>,
    pub vmcs: Vec<Register>,
    pub msrs: Vec<Register>,
    pub fp: Vec<u8>,
    pub tpr: u32,
    pub priority_failure: Option<String>,
    pub apic_base: u64,
    pub halted: bool,
    pub shutdown: bool,
    pub anchor: u64,
    pub guest_tsc: u64,
    pub clock: ClockBinding,
    pub port_input: port_io::InputState,
    pub mmio_input: mmio::InputState,
    pub request: Option<Packet>,
    pub output: Option<(Packet, u64)>,
    pub output_failure: Option<String>,
    pub execution_failure: Option<String>,
    pub restore_failure: Option<String>,
    pub debug: DebugState,
}

impl Read for Context {
    fn register(&self, id: u32) -> Result<u64> {
        if id == R::HV_X86_TPR as u32 {
            Ok(u64::from(self.tpr))
        } else {
            value(&self.registers, id)
        }
    }
    fn vmcs(&self, id: u32) -> Result<u64> {
        value(&self.vmcs, id)
    }
    fn msr(&self, id: u32) -> Result<u64> {
        value(&self.msrs, id)
    }
}

impl Context {
    pub fn projection(&self) -> Result<(X86_64CpuState, EmulatorState)> {
        let mut regs = projection::registers(self)?;
        let sregs = projection::systems(self)?;
        let mut emulator = self.profile.xsave.project(&self.fp, &mut regs)?;
        emulator.kernel_gs_base = self.msr(KERNEL_GS_BASE)?;
        emulator.tsc_aux = self.msr(TSC_AUX)? as u32;
        // The current intercepted PAT profile is fixed. Retain the raw SDK
        // VMCS field separately without claiming mutable PAT execution.
        emulator.pat = crate::isa::x86_64::execute::system::IA32_PAT_RESET;
        emulator.misc_enable = 0x0085_0089;
        emulator.halted = self.halted;
        emulator.interrupt_inhibit =
            self.vmcs(V::VMCS_GUEST_INTERRUPTIBILITY_STATE as u32)? & 3 != 0;
        Ok((X86_64CpuState { regs, sregs }, emulator))
    }
    pub fn validate(&self) -> Result<()> {
        self.profile.validate()?;
        if self.clock.at(self.anchor) != self.guest_tsc {
            return Err(invalid("guest time point differs from its clock binding"));
        }
        bank(&self.registers, &register_ids())?;
        bank(&self.vmcs, &self.profile.fields)?;
        bank(&self.msrs, MSRS)?;
        self.profile.check_controls(&self.vmcs, false)?;
        self.profile.xsave.validate_image(&self.fp)?;
        if self.tpr > 255
            || self.msr(TSC_AUX)? >> 32 != 0
            || !crate::isa::x86_64::identity::valid_apic_base(self.apic_base)
        {
            return Err(invalid(
                "invalid priority, APIC base or TSC auxiliary state",
            ));
        }
        let xcr0 = self.register(R::HV_X86_XCR0 as u32)?;
        if xcr0 & !7 != 0 || xcr0 & 1 == 0 || (xcr0 & 4 != 0 && xcr0 & 2 == 0) {
            return Err(invalid("XCR0 differs from the advertised guest profile"));
        }
        if self.halted && self.vmcs(V::VMCS_GUEST_ACTIVITY_STATE as u32)? != 1 {
            return Err(invalid("halted owner differs from guest HLT activity"));
        }
        if self.debug.completed && !self.debug.enabled {
            return Err(invalid("host step completion without a host step request"));
        }
        if self.debug.failure.is_none()
            && (self.vmcs(V::VMCS_CTRL_CPU_BASED as u32)? & MONITOR_TRAP != 0) != self.debug.enabled
        {
            return Err(invalid(
                "host step owner differs from the VMCS monitor-trap bit",
            ));
        }
        for error in [
            &self.priority_failure,
            &self.output_failure,
            &self.execution_failure,
            &self.restore_failure,
            &self.debug.failure,
        ] {
            check_error(error)?;
        }
        self.port_input.validate_checkpoint().map_err(invalid)?;
        self.mmio_input.validate_checkpoint().map_err(invalid)?;
        let port = self.port_input.descriptor();
        let mmio = self.mmio_input.descriptor();
        if port.is_some() && mmio.is_some() {
            return Err(invalid("two native inputs are pending"));
        }
        match (&self.request, port, mmio) {
            (None, None, None) => (),
            (Some(Packet::PortRead { port, size }), Some(input), None)
                if *port == input.io.port && *size == input.io.size =>
            {
                ()
            }
            (Some(Packet::Read { size, .. }), None, Some((expected, None)))
                if *size == expected =>
            {
                ()
            }
            (
                Some(Packet::Rmw {
                    size, operation, ..
                }),
                None,
                Some((expected, Some(op))),
            ) if *size == expected && *operation == op => (),
            _ => {
                return Err(invalid(
                    "pending input differs from its exported device request",
                ));
            }
        }
        if let Some(request) = &self.request {
            request.validate()?;
        }
        if let Some((packet, length)) = &self.output {
            packet.validate()?;
            if !matches!(packet, Packet::PortWrite { .. } | Packet::Write { .. })
                || !(1..=15).contains(length)
                || self.request.is_some()
            {
                return Err(invalid("invalid native output continuation"));
            }
        }
        let (public, emulator) = self.projection()?;
        if encode_projection(&public, &emulator)?
            != encode_projection(&self.public, &self.emulator)?
        {
            return Err(invalid(
                "architectural projection differs from its native record",
            ));
        }
        Ok(())
    }
    pub fn admit(
        &self,
        id: u32,
        profile: &Profile,
        public: &CpuState,
        emulator: &EmulatorState,
    ) -> Result<()> {
        self.validate()?;
        let CpuState::X86_64(public) = public else {
            return Err(invalid("CPU kind differs from native Intel producer"));
        };
        if self.id != id
            || &self.profile != profile
            || encode_projection(public, emulator)?
                != encode_projection(&self.public, &self.emulator)?
        {
            return Err(invalid("target CPU/profile or public projection differs"));
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut raw = CPU_TAG.to_vec();
        raw.extend(crate::codec::serialize_limited(self, CPU_LIMIT).map_err(invalid)?);
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > CPU_LIMIT + CPU_TAG.len() {
            return Err(invalid("CPU record exceeds its byte limit"));
        }
        let raw = raw
            .strip_prefix(CPU_TAG)
            .ok_or_else(|| invalid("unknown CPU producer/version"))?;
        let context: Self =
            crate::codec::deserialize_limited::<_, CPU_LIMIT>(raw).map_err(invalid)?;
        context.validate()?;
        Ok(context)
    }
}

fn encode_projection(public: &X86_64CpuState, emulator: &EmulatorState) -> Result<Vec<u8>> {
    crate::codec::serialize_limited(&(public, emulator), 16 * 1024).map_err(invalid)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct GlobalContext {
    pub cpus: u8,
    pub ram_size: u64,
    pub regions: Vec<(u64, u64)>,
    pub fixed_holes: Vec<(u64, u64)>,
    pub pending_irqs: Vec<u32>,
    pub resume_clock: Option<u64>,
    pub anchor: u64,
}
impl GlobalContext {
    pub fn validate(&self) -> Result<()> {
        if self.cpus == 0
            || self.ram_size == 0
            || self.regions.is_empty()
            || self.regions.len() > 4096
            || self.fixed_holes.len() > 4096
        {
            return Err(invalid("invalid shared topology or mapping inventory"));
        }
        for spans in [&self.regions, &self.fixed_holes] {
            let mut end = None;
            for &(start, size) in spans {
                let next = start
                    .checked_add(size)
                    .filter(|_| size != 0)
                    .ok_or_else(|| invalid("shared physical span wraps or is empty"))?;
                if end.is_some_and(|end| start < end) {
                    return Err(invalid("shared physical spans overlap or are unordered"));
                }
                end = Some(next);
            }
        }
        let mut unique = std::collections::BTreeSet::new();
        if self.pending_irqs.iter().any(|irq| !unique.insert(*irq)) {
            return Err(invalid("duplicate queued native IRQ source"));
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut raw = VM_TAG.to_vec();
        raw.extend(crate::codec::serialize_limited(self, VM_LIMIT).map_err(invalid)?);
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > VM_LIMIT + VM_TAG.len() {
            return Err(invalid("VM record exceeds its byte limit"));
        }
        let raw = raw
            .strip_prefix(VM_TAG)
            .ok_or_else(|| invalid("unknown VM producer/version"))?;
        let context: Self =
            crate::codec::deserialize_limited::<_, VM_LIMIT>(raw).map_err(invalid)?;
        context.validate()?;
        Ok(context)
    }
}

pub(crate) fn register_ids() -> Vec<u32> {
    use R::*;
    [
        HV_X86_RIP,
        HV_X86_RFLAGS,
        HV_X86_RAX,
        HV_X86_RCX,
        HV_X86_RDX,
        HV_X86_RBX,
        HV_X86_RSI,
        HV_X86_RDI,
        HV_X86_RSP,
        HV_X86_RBP,
        HV_X86_R8,
        HV_X86_R9,
        HV_X86_R10,
        HV_X86_R11,
        HV_X86_R12,
        HV_X86_R13,
        HV_X86_R14,
        HV_X86_R15,
        HV_X86_CR2,
        HV_X86_DR0,
        HV_X86_DR1,
        HV_X86_DR2,
        HV_X86_DR3,
        HV_X86_DR6,
        HV_X86_XCR0,
    ]
    .into_iter()
    .map(|register| register as u32)
    .collect()
}
pub(crate) fn policy_fields() -> Vec<u32> {
    use V::*;
    [
        VMCS_CTRL_PIN_BASED,
        VMCS_CTRL_CPU_BASED,
        VMCS_CTRL_CPU_BASED2,
        VMCS_CTRL_VMENTRY_CONTROLS,
        VMCS_CTRL_EXC_BITMAP,
        VMCS_CTRL_CR0_MASK,
        VMCS_CTRL_CR4_MASK,
    ]
    .into_iter()
    .map(|field| field as u32)
    .collect::<std::collections::BTreeSet<_>>()
    .into_iter()
    .collect()
}
pub(crate) fn optional_field(id: u32) -> bool {
    id == V::VMCS_GUEST_SMBASE as u32 || id == V::VMCS_GUEST_IA32_PERF_GLOBAL_CTRL as u32
}

pub(crate) fn vmcs_candidates() -> Vec<u32> {
    use V::*;
    [
        VMCS_GUEST_ES_SELECTOR,
        VMCS_GUEST_CS_SELECTOR,
        VMCS_GUEST_SS_SELECTOR,
        VMCS_GUEST_DS_SELECTOR,
        VMCS_GUEST_FS_SELECTOR,
        VMCS_GUEST_GS_SELECTOR,
        VMCS_GUEST_LDTR_SELECTOR,
        VMCS_GUEST_TR_SELECTOR,
        VMCS_GUEST_LINK_POINTER,
        VMCS_GUEST_IA32_DEBUGCTL,
        VMCS_GUEST_IA32_PAT,
        VMCS_GUEST_IA32_EFER,
        VMCS_GUEST_IA32_PERF_GLOBAL_CTRL,
        VMCS_GUEST_PDPTE0,
        VMCS_GUEST_PDPTE1,
        VMCS_GUEST_PDPTE2,
        VMCS_GUEST_PDPTE3,
        VMCS_GUEST_ES_LIMIT,
        VMCS_GUEST_CS_LIMIT,
        VMCS_GUEST_SS_LIMIT,
        VMCS_GUEST_DS_LIMIT,
        VMCS_GUEST_FS_LIMIT,
        VMCS_GUEST_GS_LIMIT,
        VMCS_GUEST_LDTR_LIMIT,
        VMCS_GUEST_TR_LIMIT,
        VMCS_GUEST_GDTR_LIMIT,
        VMCS_GUEST_IDTR_LIMIT,
        VMCS_GUEST_ES_ACCESS_RIGHTS,
        VMCS_GUEST_CS_ACCESS_RIGHTS,
        VMCS_GUEST_SS_ACCESS_RIGHTS,
        VMCS_GUEST_DS_ACCESS_RIGHTS,
        VMCS_GUEST_FS_ACCESS_RIGHTS,
        VMCS_GUEST_GS_ACCESS_RIGHTS,
        VMCS_GUEST_LDTR_ACCESS_RIGHTS,
        VMCS_GUEST_TR_ACCESS_RIGHTS,
        VMCS_GUEST_INTERRUPTIBILITY_STATE,
        VMCS_GUEST_ACTIVITY_STATE,
        VMCS_GUEST_SMBASE,
        VMCS_GUEST_IA32_SYSENTER_CS,
        VMCS_GUEST_CR0,
        VMCS_GUEST_CR3,
        VMCS_GUEST_CR4,
        VMCS_GUEST_ES_BASE,
        VMCS_GUEST_CS_BASE,
        VMCS_GUEST_SS_BASE,
        VMCS_GUEST_DS_BASE,
        VMCS_GUEST_FS_BASE,
        VMCS_GUEST_GS_BASE,
        VMCS_GUEST_LDTR_BASE,
        VMCS_GUEST_TR_BASE,
        VMCS_GUEST_GDTR_BASE,
        VMCS_GUEST_IDTR_BASE,
        VMCS_GUEST_DR7,
        VMCS_GUEST_PENDING_DBG_EXCEPTIONS,
        VMCS_GUEST_IA32_SYSENTER_ESP,
        VMCS_GUEST_IA32_SYSENTER_EIP,
        VMCS_CTRL_VMENTRY_CONTROLS,
        VMCS_CTRL_VMENTRY_IRQ_INFO,
        VMCS_CTRL_VMENTRY_EXCEPTION_ERROR,
        VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH,
        VMCS_CTRL_PIN_BASED,
        VMCS_CTRL_CPU_BASED,
        VMCS_CTRL_CPU_BASED2,
        VMCS_CTRL_EXC_BITMAP,
        VMCS_CTRL_CR0_MASK,
        VMCS_CTRL_CR4_MASK,
        VMCS_CTRL_CR0_SHADOW,
        VMCS_CTRL_CR4_SHADOW,
    ]
    .into_iter()
    .map(|field| field as u32)
    .collect::<std::collections::BTreeSet<_>>()
    .into_iter()
    .collect()
}
