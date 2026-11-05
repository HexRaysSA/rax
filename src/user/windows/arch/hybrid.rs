//! Paired interpreters for the ARM64EC overlay of an AMD64 thread context.
use super::*;
use crate::user::windows::context::{RegContext, x64};
use crate::user::windows::memory::Mem;
use crate::user::windows::process::thread::chpe::{Area, Binding};

#[cfg(test)]
#[path = "hybrid_tests.rs"]
mod tests;

/// An AMD64 thread that can also execute emulation-compatible ARM64 code.
/// The x64 core remains the public CONTEXT representation between run calls.
pub struct Arm64EcCpu {
    pub(super) x64: X86UserCpu,
    pub(super) arm64: A64UserCpu,
    pub(super) active: bool,
    pub(super) context_resume: bool,
    pub(crate) area: Option<crate::user::windows::process::thread::chpe::Binding>,
    entries: Vec<EntryStack>,
}

#[derive(Clone)]
struct EntryStack {
    original: u64,
    aligned: u64,
}

// ARM64EC_NT_CONTEXT in winnt.h: ARM64 register, AMD64 ModR/M register.
const INTEGER: [(u8, usize); 15] = [
    (8, 0),
    (0, 1),
    (1, 2),
    (27, 3),
    (29, 5),
    (25, 6),
    (26, 7),
    (2, 8),
    (3, 9),
    (4, 10),
    (5, 11),
    (19, 12),
    (20, 13),
    (21, 14),
    (22, 15),
];
const X87_LOW: [u8; 8] = [30, 6, 7, 9, 10, 11, 12, 15];

pub(super) fn registers(cpu: &X86UserCpu) -> [u64; 16] {
    let r = cpu.vcpu().user_regs();
    [
        r.rax, r.rcx, r.rdx, r.rbx, r.rsp, r.rbp, r.rsi, r.rdi, r.r8, r.r9, r.r10, r.r11, r.r12,
        r.r13, r.r14, r.r15,
    ]
}

pub(super) fn set_register(cpu: &mut X86UserCpu, n: usize, value: u64) {
    let r = cpu.vcpu_mut().user_regs_mut();
    let slot = match n {
        0 => &mut r.rax,
        1 => &mut r.rcx,
        2 => &mut r.rdx,
        3 => &mut r.rbx,
        4 => &mut r.rsp,
        5 => &mut r.rbp,
        6 => &mut r.rsi,
        7 => &mut r.rdi,
        8 => &mut r.r8,
        9 => &mut r.r9,
        10 => &mut r.r10,
        11 => &mut r.r11,
        12 => &mut r.r12,
        13 => &mut r.r13,
        14 => &mut r.r14,
        15 => &mut r.r15,
        _ => return,
    };
    *slot = value;
}

impl Arm64EcCpu {
    pub(super) fn new(x64: X86UserCpu) -> Self {
        let mut arm64 = A64UserCpu::new(x64.space());
        cycle_counter::bind(&mut arm64);
        Self {
            x64,
            arm64,
            active: false,
            context_resume: false,
            area: None,
            entries: Vec::new(),
        }
    }

    pub(super) fn clone_thread(&self) -> Self {
        let mut arm64 = self.arm64.clone_thread();
        cycle_counter::bind(&mut arm64);
        Self {
            x64: self.x64.clone_thread(),
            arm64,
            active: self.active,
            context_resume: self.context_resume,
            area: self.area.clone(),
            entries: self.entries.clone(),
        }
    }

    pub(crate) fn x64(&self) -> &X86UserCpu {
        &self.x64
    }
    pub(crate) fn x64_mut(&mut self) -> &mut X86UserCpu {
        &mut self.x64
    }

    pub(super) fn from_context(&mut self) {
        let r = registers(&self.x64);
        let fx = self.x64.vcpu().xsave_image(3).bytes;
        let core = self.arm64.core_mut();
        for (arm, x64) in INTEGER {
            core.set_x(arm, r[x64]);
        }
        core.set_current_sp(r[4]);
        core.set_pc(self.x64.pc());
        core.set_x(18, self.x64.vcpu().gs_base());
        let mut high = [0u64; 2];
        for (index, reg) in X87_LOW.into_iter().enumerate() {
            let at = 32 + index * 16;
            core.set_x(reg, u64::from_le_bytes(fx[at..at + 8].try_into().unwrap()));
            let value = u16::from_le_bytes(fx[at + 8..at + 10].try_into().unwrap());
            high[index / 4] |= u64::from(value) << ((index % 4) * 16);
        }
        core.set_x(16, high[0]);
        core.set_x(17, high[1]);
        for index in 0..16 {
            let at = 160 + index * 16;
            core.set_simd(
                index as u8,
                u128::from_le_bytes(fx[at..at + 16].try_into().unwrap()),
            );
        }
        // Call boundaries make condition flags volatile. Context transfers
        // preserve the representable architectural subset; PF/AF/DF remain
        // in the canonical x64 state, with no ARM64 register alias.
        let flags = self.x64.vcpu().user_rflags();
        let nzcv = ((flags >> 7) & 1) << 31
            | ((flags >> 6) & 1) << 30
            | (flags & 1) << 29
            | ((flags >> 11) & 1) << 28;
        core.set_pstate_bits((core.pstate_bits() & !0xf000_0000) | nzcv)
            .expect("only validated EL0 condition flags changed");
        let mxcsr = self.x64.vcpu().mxcsr();
        let rounding = ((mxcsr >> 13) & 1) << 23 | ((mxcsr >> 14) & 1) << 22;
        let enables =
            ((!mxcsr >> 7) & 1) << 8 | ((!mxcsr >> 9) & 0xf) << 9 | ((!mxcsr >> 8) & 1) << 15;
        core.set_fpcr_value(rounding | ((mxcsr >> 15) & 1) << 24 | enables);
        core.set_fpsr_value((mxcsr & 1) | ((mxcsr >> 2) & 0xf) << 1 | ((mxcsr >> 1) & 1) << 7);
    }

    pub(super) fn to_context(&mut self) -> Result<(), String> {
        let core = self.arm64.core();
        for (arm, x64) in INTEGER {
            set_register(&mut self.x64, x64, core.get_x(arm));
        }
        let regs = self.x64.vcpu_mut().user_regs_mut();
        regs.rsp = self.arm64.sp();
        regs.rip = self.arm64.pc();
        self.x64.vcpu_mut().set_gs_base(core.get_x(18));
        let nzcv = core.pstate_bits();
        let bits = ((nzcv >> 31) & 1) << 7
            | ((nzcv >> 30) & 1) << 6
            | ((nzcv >> 29) & 1)
            | ((nzcv >> 28) & 1) << 11;
        let flags = self.x64.vcpu().user_rflags();
        self.x64.vcpu_mut().set_user_rflags((flags & !0x8c1) | bits);
        let mut fx = self.x64.vcpu().xsave_image(3).bytes;
        fx.truncate(512);
        let high = [core.get_x(16), core.get_x(17)];
        for (index, reg) in X87_LOW.into_iter().enumerate() {
            let at = 32 + index * 16;
            fx[at..at + 8].copy_from_slice(&core.get_x(reg).to_le_bytes());
            fx[at + 8..at + 10]
                .copy_from_slice(&((high[index / 4] >> ((index % 4) * 16)) as u16).to_le_bytes());
        }
        for index in 0..16 {
            let at = 160 + index * 16;
            fx[at..at + 16].copy_from_slice(&core.get_simd(index as u8).to_le_bytes());
        }
        let fpcr = core.fpcr_value();
        let fpsr = core.fpsr_value();
        let old = self.x64.vcpu().mxcsr();
        let rounding = ((fpcr >> 23) & 1) << 13 | ((fpcr >> 22) & 1) << 14;
        let masks = ((!fpcr >> 8) & 1) << 7 | ((!fpcr >> 9) & 0xf) << 9 | ((!fpcr >> 15) & 1) << 8;
        let status = fpsr & 1 | ((fpsr >> 1) & 0xf) << 2 | ((fpsr >> 7) & 1) << 1;
        let mxcsr = (old & 0x40) | rounding | masks | status | ((fpcr >> 24) & 1) << 15;
        fx[24..28].copy_from_slice(&mxcsr.to_le_bytes());
        self.x64
            .vcpu_mut()
            .fxrstor_image(&fx)
            .map_err(|error| format!("ARM64EC context transfer: {error:?}"))
    }
}

/// The loader's instruction-boundary decision for a mixed thread.
pub(crate) enum InstructionRoute {
    Stay,
    Enter { target: u64, thunk: u64 },
    ResumeArm64,
    ResumeX64,
}

impl WinCpu {
    pub(crate) fn is_arm64ec(&self) -> bool {
        matches!(self, Self::Arm64Ec(_))
    }

    pub(crate) fn instruction_arch(&self) -> WinArch {
        match self {
            Self::Arm64Ec(cpu) if cpu.active => WinArch::Arm64,
            _ => self.arch(),
        }
    }

    pub(crate) fn call_gpr(&self, n: usize) -> u64 {
        match self {
            Self::Arm64Ec(cpu) if cpu.active => cpu.arm64.core().get_x(n as u8),
            _ => self.gpr(n),
        }
    }

    pub(crate) fn set_call_gpr(&mut self, n: usize, value: u64) {
        match self {
            Self::Arm64Ec(cpu) if cpu.active => {
                cpu.arm64.core_mut().set_x(n as u8, value);
                cpu.to_context()
                    .expect("ARM64EC emits a valid legacy context");
            }
            _ => self.set_gpr(n, value),
        }
    }

    pub(crate) fn context_restored(&mut self) {
        if let Self::Arm64Ec(cpu) = self {
            cpu.context_resume = true;
        }
    }

    pub(crate) fn ec_exit(&mut self, target: u64, stack: u64) -> Result<(), String> {
        let Self::Arm64Ec(cpu) = self else {
            return Err("ARM64EC exit without paired context".into());
        };
        if !cpu.active {
            return Err("ARM64EC exit from AMD64 mode".into());
        }
        // The completed ARM64 instruction run has already synchronized the
        // public context. Only the mode, call target and pushed stack change.
        cpu.active = false;
        let r = cpu.x64.vcpu_mut().user_regs_mut();
        r.rip = target;
        r.rsp = stack;
        Ok(())
    }

    pub(crate) fn ec_return(&mut self) -> Result<(), String> {
        let Self::Arm64Ec(cpu) = self else {
            return Err("ARM64EC return without paired context".into());
        };
        if !cpu.active {
            return Err("ARM64EC return from AMD64 mode".into());
        }
        let frame = cpu
            .entries
            .last()
            .ok_or("ARM64EC return has no entry owner")?;
        if cpu.arm64.sp() != frame.aligned {
            return Err("ARM64EC return stack does not match its entry owner".into());
        }
        let target = cpu.arm64.core().get_x(30);
        let stack = frame.original;
        cpu.entries.pop();
        self.ec_exit(target, stack)
    }

    pub(crate) fn ec_jump(&mut self, target: u64, stack: u64) -> Result<(), String> {
        let Self::Arm64Ec(cpu) = self else {
            return Err("ARM64EC jump without paired context".into());
        };
        let frame = cpu
            .entries
            .last()
            .ok_or("ARM64EC jump has no entry owner")?;
        if frame.original != stack.checked_add(8).ok_or("ARM64EC jump stack overflow")?
            || frame.aligned != cpu.arm64.sp()
        {
            return Err("ARM64EC jump does not match its signature-less entry owner".into());
        }
        cpu.entries.pop();
        self.ec_exit(target, stack)
    }

    pub(crate) fn enable_arm64ec(&mut self) -> Result<(), String> {
        if self.is_arm64ec() {
            return Ok(());
        }
        let Self::X86(core, WinArch::X64) = self else {
            return Err("ARM64EC requires an AMD64 process context".into());
        };
        let replacement = X86UserCpu::new(core.space());
        let x64 = std::mem::replace(core, replacement);
        *self = Self::Arm64Ec(Box::new(Arm64EcCpu::new(x64)));
        Ok(())
    }

    fn route(&mut self, route: InstructionRoute) -> Result<(), String> {
        match route {
            InstructionRoute::Stay => Ok(()),
            InstructionRoute::Enter { target, thunk } => {
                let sp = self.sp();
                let after = sp.checked_add(8).ok_or("ARM64EC entry stack overflow")?;
                let mut bytes = [0; 8];
                let space = self.x86().ok_or("ARM64EC entry has no AMD64 core")?.space();
                space
                    .read(sp, &mut bytes)
                    .map_err(|_| "ARM64EC entry return address is unreadable")?;
                let link = u64::from_le_bytes(bytes);
                self.enable_arm64ec()?;
                let Self::Arm64Ec(cpu) = self else {
                    unreachable!()
                };
                if cpu.entries.len() >= 4096 {
                    return Err("ARM64EC entry nesting exceeds the emulator bound".into());
                }
                cpu.entries
                    .try_reserve(1)
                    .map_err(|_| "ARM64EC entry owner allocation failed")?;
                cpu.from_context();
                let core = cpu.arm64.core_mut();
                core.set_x(30, link);
                core.set_x(9, target);
                core.set_x(4, after);
                core.set_current_sp(after & !15);
                core.set_pc(thunk);
                cpu.entries.push(EntryStack {
                    original: after,
                    aligned: after & !15,
                });
                cpu.active = true;
                Ok(())
            }
            InstructionRoute::ResumeArm64 => {
                self.enable_arm64ec()?;
                let Self::Arm64Ec(cpu) = self else {
                    unreachable!()
                };
                cpu.from_context();
                cpu.active = true;
                Ok(())
            }
            InstructionRoute::ResumeX64 => {
                if let Self::Arm64Ec(cpu) = self {
                    if cpu.active {
                        cpu.to_context()?;
                    }
                    cpu.active = false;
                    let sp = cpu.x64.vcpu().user_regs().rsp;
                    cpu.entries.retain(|frame| frame.original > sp);
                }
                Ok(())
            }
        }
    }

    pub(crate) fn run_routed(
        &mut self,
        budget: u64,
        mut route: impl FnMut(u64, WinArch, bool) -> Result<InstructionRoute, String>,
    ) -> CpuStop {
        if budget == 0 {
            return CpuStop::Yield;
        }
        if let Self::Arm64Ec(cpu) = self {
            if cpu.active {
                cpu.from_context();
            }
        }
        if let Err(error) = self.sync_chpe_area(true) {
            return CpuStop::Internal(error);
        }
        let mut result = CpuStop::Yield;
        for ordinal in 0..budget {
            let (pc, active, context) = match self {
                Self::Arm64Ec(cpu) => (
                    if cpu.active {
                        cpu.arm64.pc()
                    } else {
                        cpu.x64.pc()
                    },
                    if cpu.active {
                        WinArch::Arm64
                    } else {
                        WinArch::X64
                    },
                    std::mem::take(&mut cpu.context_resume),
                ),
                _ => (self.pc(), self.arch(), false),
            };
            let selected = match route(pc, active, context) {
                Ok(selected) => selected,
                Err(error) => {
                    result = CpuStop::Internal(error);
                    break;
                }
            };
            if let Err(error) = self.route(selected) {
                result = CpuStop::Internal(error);
                break;
            }
            if self.instruction_arch() != active {
                if let Err(error) = self.sync_chpe_area(true) {
                    result = CpuStop::Internal(error);
                    break;
                }
            }
            result = match self {
                Self::X86(cpu, _) => step_x64(cpu, ordinal),
                Self::Arm64(cpu) => step_arm64(cpu, ordinal),
                Self::Arm64Ec(cpu) if cpu.active => step_arm64(&mut cpu.arm64, ordinal),
                Self::Arm64Ec(cpu) => step_x64(&mut cpu.x64, ordinal),
            };
            if let Err(error) = self.sync_chpe_area(false) {
                result = CpuStop::Internal(error);
                break;
            }
            if !matches!(result, CpuStop::Yield) {
                break;
            }
        }
        if let Self::Arm64Ec(cpu) = self {
            if cpu.active {
                if let Err(error) = cpu.to_context() {
                    return CpuStop::Internal(error);
                }
            }
        }
        if let Err(error) = self.sync_chpe_area(true) {
            return CpuStop::Internal(error);
        }
        result
    }
}

fn step_x64(cpu: &mut X86UserCpu, ordinal: u64) -> CpuStop {
    if let Err(error) = super::super::system_time::observe(ordinal, cpu.space()) {
        return CpuStop::Internal(error);
    }
    match cpu.step() {
        X86Exit::Syscall { insn, insn_rip } => CpuStop::X86Syscall { insn, insn_rip },
        X86Exit::Event(event) => CpuStop::X86Event(event),
        X86Exit::Fault(fault) => CpuStop::Fault(fault),
        X86Exit::Yield => CpuStop::Yield,
        X86Exit::Internal(error) => CpuStop::Internal(error.to_string()),
    }
}

fn step_arm64(cpu: &mut A64UserCpu, ordinal: u64) -> CpuStop {
    match cpu.run_observed_pc(1, |_, _, space| {
        super::super::system_time::observe(ordinal, space)
    }) {
        A64Exit::Svc { imm, pc } => CpuStop::Svc { imm, pc },
        A64Exit::Brk { imm, pc } => CpuStop::Brk { imm, pc },
        A64Exit::Undefined { pc, reason } => CpuStop::Undefined { pc, reason },
        A64Exit::Exception { pc, ec, iss } => CpuStop::Undefined {
            pc,
            reason: format!("AArch64 exception EC={ec:#x} ISS={iss:#x}"),
        },
        A64Exit::Fault(fault) => CpuStop::Fault(fault),
        A64Exit::Yield => CpuStop::Yield,
        A64Exit::Internal(error) => CpuStop::Internal(error),
    }
}

impl WinCpu {
    pub(crate) fn bind_chpe_area(&mut self, area: Area) -> Result<(), String> {
        self.enable_arm64ec()?;
        let WinCpu::Arm64Ec(cpu) = self else {
            unreachable!()
        };
        cpu.area = Some(Binding {
            area,
            shadow: Vec::new(),
        });
        self.sync_chpe_area(true)
    }

    /// Observe writes to the shared CONTEXT after each guest instruction.
    /// Merge only bytes changed by the guest into the live register image;
    /// untouched snapshot fields cannot roll back intervening ARM64 work.
    /// O(sizeof(CONTEXT)) time and scratch storage, independent of guest input.
    pub(crate) fn sync_chpe_area(&mut self, publish: bool) -> Result<(), String> {
        let binding = match self {
            WinCpu::Arm64Ec(cpu) => cpu.area.take(),
            _ => None,
        };
        let Some(mut binding) = binding else {
            return Ok(());
        };
        let result = (|| {
            let space = self
                .x86()
                .ok_or("CHPE context requires an AMD64 carrier")?
                .space()
                .clone();
            if !binding.area.owns_space(&space) {
                return Err("CHPE context allocation ownership changed".into());
            }
            let mut changed = false;
            if !binding.shadow.is_empty() {
                let mut observed = [0u8; x64::SIZE];
                space
                    .rd(binding.area.context, &mut observed)
                    .map_err(|_| "CHPE context became unreadable")?;
                if observed.as_slice() != binding.shadow {
                    if let WinCpu::Arm64Ec(cpu) = self {
                        if cpu.active {
                            cpu.to_context()?;
                        }
                    }
                    let mut merged = RegContext::capture(self).bytes().to_vec();
                    for (index, byte) in merged.iter_mut().enumerate() {
                        if observed[index] != binding.shadow[index] {
                            *byte = observed[index];
                        }
                    }
                    RegContext::from_bytes(WinArch::X64, merged)
                        .apply(self)
                        .map_err(|status| format!("CHPE context update rejected: {status:#x}"))?;
                    if let WinCpu::Arm64Ec(cpu) = self {
                        if cpu.active {
                            cpu.from_context();
                        }
                    }
                    changed = true;
                }
            }
            if publish || changed {
                if let WinCpu::Arm64Ec(cpu) = self {
                    if cpu.active {
                        cpu.to_context()?;
                    }
                }
                let context = RegContext::capture(self);
                context
                    .write(&space, binding.area.context)
                    .map_err(|_| "CHPE context became unwritable")?;
                space
                    .w8(
                        binding.area.base,
                        u8::from(self.instruction_arch() == WinArch::X64),
                    )
                    .map_err(|_| "CHPE simulation flag became unwritable")?;
                binding.shadow.clear();
                binding.shadow.extend_from_slice(context.bytes());
            }
            Ok(())
        })();
        if let WinCpu::Arm64Ec(cpu) = self {
            cpu.area = Some(binding);
        }
        result
    }
}
