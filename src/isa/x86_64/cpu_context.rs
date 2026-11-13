//! Complete represented software-x86 state over admitted external bindings.
use super::*;
use crate::isa::x86_64::memory::checkpoint::MmuContext;
use crate::isa::x86_64::user_mode::UserMode;
use crate::vm::snapshot::{CheckpointResource, PreparedResources, ResourceKey};
use serde::{Deserialize, Serialize};

#[path = "cpu_context/exit.rs"]
mod exit;
use exit::ExitContext;
#[path = "cpu_context/user.rs"]
mod user;
const LEGACY_TAG: &[u8; 8] = b"RAXX8601";
const VERSION2_TAG: &[u8; 8] = b"RAXX8602";
const TAG: &[u8; 8] = b"RAXX8603";
const IOAPIC_TAG: &[u8; 8] = b"RAXX8604";
const SHADOW_TAG: &[u8; 8] = b"RAXX8605";
const IOAPIC_SHADOW_TAG: &[u8; 8] = b"RAXX8606";
const MAX_PAYLOAD: usize = 16 * 1024 * 1024 - TAG.len();

#[derive(Serialize, Deserialize)]
struct Version2<T> {
    base: T,
    user_debug_status: Option<u64>,
}

#[derive(Serialize, Deserialize)]
struct Version3<T> {
    base: Version2<T>,
    apic_base: u64,
}

#[derive(Serialize, Deserialize)]
struct Version5<T> {
    base: Version3<T>,
    instruction_debug_inhibit: bool,
}

#[path = "cpu_context/codec.rs"]
mod codec;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct X86_64Config {
    pub xeon_phi_avx512: bool,
    pub vp2intersect: bool,
    pub sse4a: bool,
    pub tbm: bool,
    pub xop: bool,
    pub avx10_media: bool,
    pub avx10_vminmax: bool,
    pub avx10_sat_convert: bool,
    pub apx: bool,
}
#[derive(Serialize, Deserialize)]
struct DebugContext {
    single_step: bool,
    active: bool,
    breakpoints: Vec<u64>,
}
#[derive(Serialize, Deserialize)]
struct Context {
    // Carried by the version3 envelope, preserving version1/2 base layout.
    #[serde(skip)]
    apic_base: u64,
    id: u32,
    insn_count: u64,
    instruction_faulted: bool,
    regs: Registers,
    sregs: SystemRegisters,
    emulator: crate::vm::snapshot::EmulatorState,
    mmu: MmuContext,
    io_pending: Option<IoPending>,
    xcr0: u64,
    xgetbv1_value: u64,
    profile: X86_64Config,
    debug: Option<DebugContext>,
    bios_cdrom: Option<ResourceKey>,
    bios_mem_bytes: u64,
    jit_mem: bool,
    jit_call: bool,
    pending_exit: Option<ExitContext>,
    vsib_resume_pc: Option<u64>,
    #[serde(with = "user")]
    user: Option<Box<UserMode>>,
    jit_disabled_by_embedder: bool,
}
fn invalid(message: impl std::fmt::Display) -> Error {
    Error::Emulator(format!("x86 context: {message}"))
}

impl Context {
    fn validate(&self, target: &X86_64Vcpu) -> Result<()> {
        if !crate::isa::x86_64::identity::valid_apic_base(self.apic_base) {
            return Err(invalid("unsupported APIC_BASE state"));
        }
        if self.id != target.id || self.user.is_some() != target.user.is_some() {
            return Err(invalid("CPU identity or process binding mode differs"));
        }
        self.mmu.validate(&target.mmu)?;
        self.mmu.validate_priority_projection(self.sregs.cr8)?;
        X86_64Vcpu::validate_emulator_state(&self.emulator)?;
        if !crate::isa::x86_64::user_mode::xcr0_value_is_valid(self.xcr0, self.profile.apx) {
            return Err(invalid(
                "XCR0 is invalid for the selected ISA configuration",
            ));
        }
        if let Some(pending) = &self.io_pending {
            exit::validate_io(pending.size, pending.count)?;
            if matches!(pending.target, IoInTarget::Reg) && pending.count != 1 {
                return Err(invalid("register input cannot be a string batch"));
            }
        }
        if let Some(debug) = &self.debug {
            if debug.breakpoints.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(invalid("debug breakpoints are not ordered and unique"));
            }
            #[cfg(not(feature = "debug"))]
            if debug.single_step || debug.active || !debug.breakpoints.is_empty() {
                return Err(invalid("debugger support is required"));
            }
        }
        if self
            .bios_cdrom
            .is_some_and(|key| key.kind() != crate::vm::snapshot::BOOT_CDROM_RESOURCE)
        {
            return Err(invalid("invalid BIOS resource kind"));
        }
        Ok(())
    }
    fn prepare(self, target: &X86_64Vcpu, resources: &PreparedResources) -> Result<X86_64Vcpu> {
        self.validate(target)?;
        target.validate_checkpoint_quiescence()?;
        let mut cpu = X86_64Vcpu::new(self.id, target.mmu.checkpoint_memory());
        cpu.mmu = self.mmu.prepare(&target.mmu)?;
        cpu.apic_base = self.apic_base;
        cpu.regs = self.regs;
        cpu.sregs = self.sregs;
        cpu.restore_emulator_state(&self.emulator)?;
        cpu.xeon_phi_avx512 = self.profile.xeon_phi_avx512;
        cpu.vp2intersect = self.profile.vp2intersect;
        cpu.sse4a = self.profile.sse4a;
        cpu.tbm = self.profile.tbm;
        cpu.xop = self.profile.xop;
        cpu.avx10_media = self.profile.avx10_media;
        cpu.avx10_vminmax = self.profile.avx10_vminmax;
        cpu.avx10_sat_convert = self.profile.avx10_sat_convert;
        cpu.apx = self.profile.apx;
        cpu.set_xcr0(self.xcr0)?;
        cpu.xgetbv1_value = self.xgetbv1_value;
        cpu.io_pending = self.io_pending;
        cpu.insn_count = self.insn_count;
        cpu.instruction_faulted = self.instruction_faulted;
        cpu.bios_cdrom = self
            .bios_cdrom
            .map(|key| resources.resolve(key))
            .transpose()?;
        cpu.bios_mem_bytes = self.bios_mem_bytes;
        cpu.jit_mem = self.jit_mem;
        cpu.jit_call = self.jit_call;
        cpu.jit_callout_exit = self.pending_exit.map(ExitContext::into_exit).transpose()?;
        cpu.jit_vsib_resume_pc = self.vsib_resume_pc;
        cpu.user = self.user;
        cpu.jit_disabled_by_embedder = self.jit_disabled_by_embedder;
        #[cfg(feature = "debug")]
        if let Some(debug) = self.debug {
            cpu.single_step = debug.single_step;
            cpu.debugger_active = debug.active;
            cpu.debug_breakpoints = debug.breakpoints.into_iter().collect();
        }
        let rflags = cpu.compute_materialized_rflags();
        cpu.mmu.set_data_access_state(rflags, cpu.pkru);
        Ok(cpu)
    }
}

#[cfg(test)]
#[path = "cpu_context/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "cpu_context/identity_tests.rs"]
mod identity_tests;

#[cfg(test)]
#[path = "cpu_context/ioapic_tests.rs"]
mod ioapic_tests;

impl X86_64Vcpu {
    /// Selected optional instruction capabilities, independent of register state.
    pub fn x86_configuration(&self) -> X86_64Config {
        X86_64Config {
            xeon_phi_avx512: self.xeon_phi_avx512,
            vp2intersect: self.vp2intersect,
            sse4a: self.sse4a,
            tbm: self.tbm,
            xop: self.xop,
            avx10_media: self.avx10_media,
            avx10_vminmax: self.avx10_vminmax,
            avx10_sat_convert: self.avx10_sat_convert,
            apx: self.apx,
        }
    }

    fn install_configuration(&mut self, config: X86_64Config) {
        self.xeon_phi_avx512 = config.xeon_phi_avx512;
        self.vp2intersect = config.vp2intersect;
        self.sse4a = config.sse4a;
        self.tbm = config.tbm;
        self.xop = config.xop;
        self.avx10_media = config.avx10_media;
        self.avx10_vminmax = config.avx10_vminmax;
        self.avx10_sat_convert = config.avx10_sat_convert;
        self.apx = config.apx;
    }

    /// Capability changes reject incompatible live XCR0 before publication and
    /// discard code/decode decisions made under the previous configuration.
    pub fn set_x86_configuration(&mut self, config: X86_64Config) -> Result<()> {
        let previous = self.x86_configuration();
        self.install_configuration(config);
        if let Err(error) = self.set_xcr0(self.xcr0) {
            self.install_configuration(previous);
            return Err(error);
        }
        self.invalidate_all_code();
        Ok(())
    }

    fn validate_checkpoint_quiescence(&self) -> Result<()> {
        // Verifier undo/trace buffers and its injected stop are host diagnostic
        // transaction state. Public verified runs take them before returning.
        #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
        if self.jit_mem_log.is_some() || self.jit_mem_trace.is_some() {
            return Err(invalid("native verification transaction is active"));
        }
        #[cfg(any(test, all(feature = "smir-jit", target_arch = "x86_64")))]
        if self.jit_verify_vsib_stop.is_some() {
            return Err(invalid("native verification stop is active"));
        }
        Ok(())
    }

    /// Caller owns matching RAM, device/controller and process translations.
    /// Immutable BIOS bytes are references here; VM bundles carry their content.
    pub fn save_context(&self) -> Result<Vec<u8>> {
        self.validate_checkpoint_quiescence()?;
        // Exhaustive classification: public/base-private state, retained logical
        // state, target bindings, derived native caches, and verifier diagnostics.
        let Self {
            id,
            apic_base,
            insn_count,
            instruction_faulted,
            regs,
            sregs,
            mmu,
            fpu: _,
            halted: _,
            interrupt_inhibit: _,
            io_pending,
            kernel_gs_base: _,
            tsc_adjust: _,
            tsc_aux: _,
            misc_enable: _,
            pat: _,
            umwait_control: _,
            pkru: _,
            mxcsr: _,
            xcr0,
            xgetbv1_value,
            xeon_phi_avx512,
            vp2intersect,
            sse4a,
            tbm,
            xop,
            avx10_media,
            avx10_vminmax,
            avx10_sat_convert,
            apx,
            decode_cache: _,
            lazy_flags: _,
            #[cfg(feature = "debug")]
            single_step,
            #[cfg(feature = "debug")]
            debugger_active,
            #[cfg(feature = "debug")]
            debug_breakpoints,
            bios_cdrom,
            bios_mem_bytes,
            #[cfg(all(
                feature = "smir-jit",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
                jit_cache: _,
            #[cfg(all(
                feature = "smir-jit",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
                jit_hot: _,
            #[cfg(all(
                feature = "smir-jit",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
                jit_ineligible: _,
            #[cfg(all(
                feature = "smir-jit",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
                jit_ineligible_dirty: _,
            #[cfg(all(
                feature = "smir-jit",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
                jit_active_source_range: _,
            #[cfg(all(
                feature = "smir-jit",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
                jit_active_region_stale: _,
            jit_mem,
            jit_call,
            jit_callout_exit,
            #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
                jit_mem_log: _,
            #[cfg(all(feature = "smir-jit", target_arch = "x86_64"))]
                jit_mem_trace: _,
            #[cfg(any(test, all(feature = "smir-jit", target_arch = "x86_64")))]
                jit_verify_vsib_stop: _,
            jit_vsib_resume_pc,
            user,
            jit_disabled_by_embedder,
        } = self;
        #[cfg(feature = "debug")]
        let debug = Some({
            let mut breakpoints: Vec<_> = debug_breakpoints.iter().copied().collect();
            breakpoints.sort_unstable();
            DebugContext {
                single_step: *single_step,
                active: *debugger_active,
                breakpoints,
            }
        });
        #[cfg(not(feature = "debug"))]
        let debug = None;
        let bios_cdrom = bios_cdrom
            .as_ref()
            .map(|bytes| {
                CheckpointResource::boot_cdrom(bytes.clone()).map(|resource| resource.key())
            })
            .transpose()?;
        let context = Context {
            apic_base: *apic_base,
            id: *id,
            insn_count: *insn_count,
            instruction_faulted: *instruction_faulted,
            regs: regs.clone(),
            sregs: {
                let mut value = sregs.clone();
                value.cr8 = u64::from(mmu.task_priority()? >> 4);
                value
            },
            emulator: self
                .snapshot_emulator_state()
                .ok_or_else(|| invalid("missing software emulator state"))?,
            mmu: mmu.checkpoint_state()?,
            io_pending: io_pending.clone(),
            xcr0: *xcr0,
            xgetbv1_value: *xgetbv1_value,
            profile: X86_64Config {
                xeon_phi_avx512: *xeon_phi_avx512,
                vp2intersect: *vp2intersect,
                sse4a: *sse4a,
                tbm: *tbm,
                xop: *xop,
                avx10_media: *avx10_media,
                avx10_vminmax: *avx10_vminmax,
                avx10_sat_convert: *avx10_sat_convert,
                apx: *apx,
            },
            debug,
            bios_cdrom,
            bios_mem_bytes: *bios_mem_bytes,
            jit_mem: *jit_mem,
            jit_call: *jit_call,
            pending_exit: jit_callout_exit.as_ref().map(ExitContext::capture),
            vsib_resume_pc: *jit_vsib_resume_pc,
            user: user.clone(),
            jit_disabled_by_embedder: *jit_disabled_by_embedder,
        };
        context.validate(self)?;
        context.encode()
    }

    pub(super) fn prepare_context(
        &self,
        raw: &[u8],
        resources: &PreparedResources,
    ) -> Result<Self> {
        Context::decode(raw, self)?.prepare(self, resources)
    }

    /// Standalone import uses the target's already-attached immutable media.
    /// Missing/different bindings reject before any live CPU field is changed.
    pub fn restore_context(&mut self, raw: &[u8]) -> Result<()> {
        let context = Context::decode(raw, self)?;
        let prepared = PreparedResources::from_bindings(self.checkpoint_media()?)?;
        let cpu = context.prepare(self, &prepared)?;
        *self = cpu;
        Ok(())
    }

    /// Import from independently verified, complete VM/engine resources.
    pub fn restore_context_with_resources(
        &mut self,
        raw: &[u8],
        resources: &PreparedResources,
    ) -> Result<()> {
        let cpu = self.prepare_context(raw, resources)?;
        *self = cpu;
        Ok(())
    }

    pub(super) fn checkpoint_media(&self) -> Result<Vec<CheckpointResource>> {
        self.bios_cdrom
            .as_ref()
            .map(|bytes| CheckpointResource::boot_cdrom(bytes.clone()))
            .transpose()
            .map(|resource| resource.into_iter().collect())
    }
    pub(super) fn context_resource_references(&self, raw: &[u8]) -> Result<Vec<ResourceKey>> {
        Ok(Context::decode(raw, self)?.bios_cdrom.into_iter().collect())
    }

    pub(super) fn validate_context_projection(
        &self,
        state: &CpuState,
        emulator: &crate::vm::snapshot::EmulatorState,
        raw: &[u8],
    ) -> Result<()> {
        let context = Context::decode(raw, self)?;
        let mut candidate = X86_64Vcpu::new(context.id, self.mmu.checkpoint_memory());
        candidate.regs = context.regs;
        candidate.sregs = context.sregs;
        // This detached projection is validated before shared controller
        // publication. Seed its private inline owner from the saved CPU record.
        candidate
            .mmu
            .set_task_priority((candidate.sregs.cr8 << 4) as u32)?;
        candidate.restore_emulator_state(&context.emulator)?;
        if crate::codec::serialize(&candidate.get_state()?).map_err(invalid)?
            != crate::codec::serialize(state).map_err(invalid)?
            || crate::codec::serialize(&context.emulator).map_err(invalid)?
                != crate::codec::serialize(emulator).map_err(invalid)?
        {
            return Err(invalid(
                "public/emulator projections disagree with backend context",
            ));
        }
        Ok(())
    }
}
