//! Two-byte opcode instruction implementation for x86_64 emulator.

use crate::error::Result;
use crate::vm::vcpu::VcpuExit;

use crate::isa::x86_64::cpu::{InsnContext, X86_64Vcpu};
use crate::isa::x86_64::execute;
use crate::isa::x86_64::execute::crypto::aes;
use crate::isa::x86_64::flags;
use crate::isa::x86_64::mxcsr_value_is_valid;

const CR0_TS: u64 = 1 << 3;
const CR0_EM: u64 = 1 << 2;
const CR4_TSD: u64 = 1 << 2;
const CR4_FSGSBASE: u64 = 1 << 16;
const CR4_OSXSAVE: u64 = 1 << 18;
const CR4_PKE: u64 = 1 << 22;

#[inline(always)]
fn is_canonical_48(addr: u64) -> bool {
    ((addr as i64) << 16 >> 16) as u64 == addr
}

impl X86_64Vcpu {
    #[inline(always)]
    fn monitor_mwait_cpl0(&self) -> bool {
        self.regs.rflags & (1 << 17) == 0
            && (self.sregs.cr0 & 1 == 0 || self.sregs.cs.selector & 3 == 0)
    }

    #[inline(always)]
    fn clac_stac_allowed(&self) -> bool {
        self.regs.rflags & flags::bits::VM == 0
            && (self.sregs.cr0 & 1 == 0 || self.sregs.cs.selector & 3 == 0)
    }

    #[inline(always)]
    fn monitor_mwait_extension(&self) -> u64 {
        if self.sregs.cs.l {
            self.regs.rcx
        } else {
            u64::from(self.regs.rcx as u32)
        }
    }

    #[inline(always)]
    fn monitor_linear_address(&self, ctx: &InsnContext, reg: u8) -> u64 {
        let offset = if self.sregs.cs.l {
            if ctx.address_size_override {
                self.get_reg(reg, 4)
            } else {
                self.get_reg(reg, 8)
            }
        } else {
            let default_16bit = !self.sregs.cs.db;
            if default_16bit ^ ctx.address_size_override {
                self.get_reg(reg, 2)
            } else {
                self.get_reg(reg, 4)
            }
        };
        let segment_base = if self.sregs.cs.l {
            match ctx.segment_override {
                Some(0x64) => self.sregs.fs.base,
                Some(0x65) => self.sregs.gs.base,
                _ => 0,
            }
        } else {
            self.get_segment_base(ctx.segment_override)
        };
        segment_base.wrapping_add(offset)
    }

    #[inline(always)]
    pub(in crate::isa::x86_64) fn require_cr0_ts_clear_for_nm(&mut self) -> Result<bool> {
        if self.sregs.cr0 & CR0_TS != 0 {
            self.inject_exception(7, None)?;
            return Ok(false);
        }
        Ok(true)
    }

    #[inline(always)]
    fn require_cr4_bit_for_ud(&mut self, bit: u64) -> Result<bool> {
        if self.sregs.cr4 & bit == 0 {
            self.inject_undefined_instruction()?;
            return Ok(false);
        }
        Ok(true)
    }

    #[inline(always)]
    pub(in crate::isa::x86_64) fn execute_0f01(
        &mut self,
        ctx: &mut InsnContext,
    ) -> Result<Option<VcpuExit>> {
        // Peek at modrm to determine instruction
        let modrm = ctx.peek_u8()?;

        // Check for special instructions with mod=3
        if modrm >> 6 == 3 {
            match modrm {
                0xC0 | 0xCF | 0xD7 => {
                    // ENCLV, ENCLS, and ENCLU are Intel SGX root instructions.
                    // The fixed profile never enters an active RTM transaction
                    // and does not enumerate SGX or any leaf-12H SGX
                    // capability, so #UD precedes VMX, CPL, CR0.TS, leaf, and
                    // architectural-state checks for all three fixed encodings.
                    ctx.consume_u8()?; // consume modrm
                    self.inject_undefined_instruction()
                }
                0xC1 => {
                    // VMCALL (0x0F 0x01 0xC1) - VMX hypercall
                    ctx.consume_u8()?; // consume modrm
                    // In a real hypervisor, this would cause a VM exit.
                    // When running without VMX, this should generate #UD.
                    // For our emulator, treat as NOP - kernel uses this for
                    // paravirtualized hints in delay loops.
                    self.regs.rip += ctx.cursor as u64;
                    Ok(None)
                }
                0xC6 => {
                    // NP/F2/F3 forms select WRMSRNS/RDMSRLIST/WRMSRLIST.
                    // The fixed CPUID profile exposes neither WRMSRNS nor
                    // MSRLIST, so feature absence raises #UD before mode,
                    // privilege, register, memory, or MSR state is observed.
                    ctx.consume_u8()?; // consume modrm
                    self.inject_undefined_instruction()
                }
                0xC8 => {
                    ctx.consume_u8()?; // consume modrm
                    // MONITOR is available in the fixed guest CPUID profile but
                    // remains privileged. Undefined optional extensions fault
                    // before the architecturally ordered byte read.
                    if !self.monitor_mwait_cpl0() {
                        return self.inject_undefined_instruction();
                    }
                    if self.monitor_mwait_extension() != 0 {
                        self.inject_exception(13, Some(0))?;
                        return Ok(None);
                    }
                    let addr = self.monitor_linear_address(ctx, 0);
                    if self.sregs.cs.l && !is_canonical_48(addr) {
                        let vector = if ctx.segment_override == Some(0x36) {
                            12 // #SS(0)
                        } else {
                            13 // #GP(0)
                        };
                        self.inject_exception(vector, Some(0))?;
                        return Ok(None);
                    }
                    let _ = self.read_mem(addr, 1)?;
                    // Monitor hardware state is intentionally not retained;
                    // the deterministic MWAIT profile returns immediately.
                    self.regs.rip += ctx.cursor as u64;
                    Ok(None)
                }
                0xC9 => {
                    ctx.consume_u8()?; // consume modrm
                    if !self.monitor_mwait_cpl0() {
                        return self.inject_undefined_instruction();
                    }
                    // CPUID.05H:ECX[1]=0, so RCX[0] is not an accepted
                    // interrupt-break extension and every RCX bit is reserved.
                    if self.monitor_mwait_extension() != 0 {
                        self.inject_exception(13, Some(0))?;
                        return Ok(None);
                    }
                    self.regs.rip += ctx.cursor as u64;
                    Ok(None)
                }
                0xD0 => {
                    // XGETBV (0F 01 D0) - read extended control register XCR[ECX].
                    ctx.consume_u8()?; // consume modrm
                    if !self.require_cr4_bit_for_ud(CR4_OSXSAVE)? {
                        return Ok(None);
                    }
                    let value = match self.regs.rcx as u32 {
                        0 => self.xcr0,
                        1 => self.xgetbv1_value,
                        _ => {
                            self.inject_exception(13, Some(0))?;
                            return Ok(None);
                        }
                    };
                    self.regs.rax = value & 0xFFFF_FFFF;
                    self.regs.rdx = (value >> 32) & 0xFFFF_FFFF;
                    self.regs.rip += ctx.cursor as u64;
                    Ok(None)
                }
                0xD1 => {
                    // XSETBV (0F 01 D1) - write XCR[ECX] from EDX:EAX (privileged).
                    ctx.consume_u8()?; // consume modrm
                    if !self.require_cr4_bit_for_ud(CR4_OSXSAVE)? {
                        return Ok(None);
                    }
                    // #GP(0) if CPL != 0.
                    if self.sregs.cr0 & 1 != 0 && (self.sregs.cs.selector & 3) != 0 {
                        self.inject_exception(13, Some(0))?;
                        return Ok(None);
                    }
                    let ecx = self.regs.rcx as u32;
                    let value = (self.regs.rax & 0xFFFF_FFFF) | (self.regs.rdx << 32);
                    // Only XCR0 exists; x87 (bit0) must stay set; AVX (bit2) requires
                    // SSE (bit1); AVX-512 state bits must be enabled as a group;
                    // PKRU (bit9) is independently selectable; APX_F (bit19)
                    // enables APX EGPR state.
                    const XCR0_AVX512: u64 = (1 << 5) | (1 << 6) | (1 << 7);
                    const XCR0_PKRU: u64 = 1 << 9;
                    const XCR0_APX_F: u64 = 1 << 19;
                    let supported = 0x7
                        | XCR0_AVX512
                        | XCR0_PKRU
                        | if self.apx_enabled() { XCR0_APX_F } else { 0 };
                    let avx512_bits = value & XCR0_AVX512;
                    let invalid = ecx != 0
                        || (value & 1) == 0
                        || (value & !supported) != 0
                        || ((value & 0x4) != 0 && (value & 0x2) == 0)
                        || (avx512_bits != 0
                            && (avx512_bits != XCR0_AVX512 || (value & 0x6) != 0x6));
                    if invalid {
                        self.inject_exception(13, Some(0))?;
                        return Ok(None);
                    }
                    self.xcr0 = value;
                    self.regs.rip += ctx.cursor as u64;
                    Ok(None)
                }
                0xD4 => {
                    // VMFUNC (0x0F 0x01 0xD4) requires VMX operation. The
                    // emulator does not expose VMX execution state, so this
                    // form is #UD.
                    ctx.consume_u8()?; // consume modrm
                    self.inject_undefined_instruction()
                }
                0xD5 => {
                    // XEND outside an active transaction raises #GP(0). The
                    // emulator has no transactional state, so every XEND is
                    // outside a transaction.
                    ctx.consume_u8()?; // consume modrm
                    self.inject_exception(13, Some(0))?;
                    Ok(None)
                }
                0xD9 if ctx.rep_prefix.is_some() || ctx.has_rex2() => {
                    // AMD assigns F2/F3 0F 01 D9 to VMGEXIT. This emulator
                    // exposes neither SVM nor SEV-ES, so the aliases are #UD.
                    // REX2 is Intel APX while VMMCALL is AMD-only; the
                    // compressed D9 form is therefore undefined as well.
                    ctx.consume_u8()?; // consume modrm
                    self.inject_undefined_instruction()
                }
                0xD9 => {
                    // VMMCALL (0x0F 0x01 0xD9) - AMD SVM hypercall
                    ctx.consume_u8()?; // consume modrm
                    // The deterministic non-virtualized profile treats the
                    // ordinary encoding as a paravirtualized hint, like VMCALL.
                    self.regs.rip += ctx.cursor as u64;
                    Ok(None)
                }
                0xD6 => {
                    // Outside transactional execution XTEST sets ZF and clears
                    // CF/PF/AF/SF/OF. The emulator has no transactional state,
                    // so every XTEST follows this path.
                    ctx.consume_u8()?; // consume modrm
                    self.clear_lazy_flags();
                    const STATUS_MASK: u64 = flags::bits::CF
                        | flags::bits::PF
                        | flags::bits::AF
                        | flags::bits::ZF
                        | flags::bits::SF
                        | flags::bits::OF;
                    self.regs.rflags = (self.regs.rflags & !STATUS_MASK) | flags::bits::ZF;
                    self.regs.rip += ctx.cursor as u64;
                    Ok(None)
                }
                0xD8 | 0xDA..=0xDF => {
                    // VMRUN, VMLOAD, VMSAVE, STGI, CLGI, SKINIT, and INVLPGA
                    // require AMD SVM or an associated optional facility. The
                    // fixed guest profile advertises none of SVM, SVML, DEV,
                    // or SKINIT and keeps EFER.SVME reserved, so #UD precedes
                    // CPL, operand, and architectural-state checks.
                    ctx.consume_u8()?; // consume modrm
                    self.inject_undefined_instruction()
                }
                0xCA => {
                    // CLAC (0x0F 0x01 0xCA) - Clear AC flag
                    ctx.consume_u8()?; // consume modrm
                    if !self.clac_stac_allowed() {
                        return self.inject_undefined_instruction();
                    }
                    // Materialize (do not discard) pending status flags: CLAC
                    // changes only AC.
                    self.materialize_flags();
                    self.regs.rflags &= !flags::bits::AC;
                    self.regs.rip += ctx.cursor as u64;
                    Ok(None)
                }
                0xCB => {
                    // STAC (0x0F 0x01 0xCB) - Set AC flag
                    ctx.consume_u8()?; // consume modrm
                    if !self.clac_stac_allowed() {
                        return self.inject_undefined_instruction();
                    }
                    // Materialize (do not discard) pending status flags: STAC
                    // changes only AC.
                    self.materialize_flags();
                    self.regs.rflags |= flags::bits::AC;
                    self.regs.rip += ctx.cursor as u64;
                    Ok(None)
                }
                0xE8 | 0xE9 if ctx.rep_prefix == Some(0xF2) => {
                    // XSUSLDTRK/XRESLDTRK require TSXLDTRK, which the emulator
                    // does not expose. Keep the F2 forms distinct from SERIALIZE.
                    ctx.consume_u8()?; // consume modrm
                    self.inject_undefined_instruction()
                }
                0xE8 if ctx.rep_prefix == Some(0xF3) => {
                    // SETSSBSY is a CET shadow-stack instruction. The emulator
                    // does not expose CET shadow stacks, so this form is #UD.
                    ctx.consume_u8()?; // consume modrm
                    self.inject_undefined_instruction()
                }
                0xE8 => {
                    // SERIALIZE (0x0F 0x01 0xE8) - Serialize instruction execution
                    ctx.consume_u8()?; // consume modrm
                    // Serializing instruction - no architectural state changes in emulation.
                    self.regs.rip += ctx.cursor as u64;
                    Ok(None)
                }
                0xEA if ctx.rep_prefix == Some(0xF3) => {
                    // SAVEPREVSSP is a CET shadow-stack instruction. The emulator
                    // does not expose CET shadow stacks, so this form is #UD.
                    ctx.consume_u8()?; // consume modrm
                    self.inject_undefined_instruction()
                }
                0xEC..=0xEF if ctx.rep_prefix == Some(0xF3) => {
                    // UIRET/TESTUI/CLUI/STUI require User Interrupts, which the
                    // emulator does not expose. Without this prefix-sensitive
                    // guard, CLUI/STUI aliases would be decoded as RDPKRU/WRPKRU.
                    ctx.consume_u8()?; // consume modrm
                    self.inject_undefined_instruction()
                }
                0xEE => {
                    // RDPKRU (0x0F 0x01 0xEE) - Read PKRU into EAX, clear EDX
                    ctx.consume_u8()?; // consume modrm
                    if !self.require_cr4_bit_for_ud(CR4_PKE)? {
                        return Ok(None);
                    }
                    if (self.regs.rcx as u32) != 0 {
                        self.inject_exception(13, Some(0))?;
                        return Ok(None);
                    }
                    self.regs.rax = self.pkru as u64;
                    self.regs.rdx = 0;
                    self.regs.rip += ctx.cursor as u64;
                    Ok(None)
                }
                0xEF => {
                    // WRPKRU (0x0F 0x01 0xEF) - Write EAX into PKRU
                    ctx.consume_u8()?; // consume modrm
                    if !self.require_cr4_bit_for_ud(CR4_PKE)? {
                        return Ok(None);
                    }
                    if (self.regs.rcx as u32) != 0 || (self.regs.rdx as u32) != 0 {
                        self.inject_exception(13, Some(0))?;
                        return Ok(None);
                    }
                    self.pkru = self.regs.rax as u32;
                    self.regs.rip += ctx.cursor as u64;
                    Ok(None)
                }
                0xF8 => {
                    // SWAPGS (0x0F 0x01 0xF8): #UD outside 64-bit mode,
                    // then #GP(0) at CPL != 0, before either base is committed.
                    ctx.consume_u8()?; // consume modrm
                    if !self.sregs.cs.l {
                        return self.inject_undefined_instruction();
                    }
                    if (self.sregs.cs.selector & 3) != 0 {
                        self.inject_exception(13, Some(0))?;
                        return Ok(None);
                    }
                    // Exchange GS.base with IA32_KERNEL_GS_BASE MSR (0xC0000102)
                    let gs_base = self.sregs.gs.base;
                    let kernel_gs_base = self.kernel_gs_base;
                    self.sregs.gs.base = kernel_gs_base;
                    self.kernel_gs_base = gs_base;
                    self.regs.rip += ctx.cursor as u64;
                    Ok(None)
                }
                0xF9 => {
                    // RDTSCP (0x0F 0x01 0xF9)
                    ctx.consume_u8()?; // consume modrm
                    execute::system::rdtscp(self, ctx)
                }
                _ => execute::system::group7(self, ctx),
            }
        } else {
            execute::system::group7(self, ctx)
        }
    }

    /// Execute 0x0F 0xAE opcodes (Group 15 - fences, CLFLUSH, etc.)
    #[inline(always)]
    pub(in crate::isa::x86_64) fn execute_0fae(
        &mut self,
        ctx: &mut InsnContext,
    ) -> Result<Option<VcpuExit>> {
        let modrm = ctx.consume_u8()?;
        let reg_op = (modrm >> 3) & 0x07;

        if reg_op == 4 && ctx.rep_prefix == Some(0xF3) {
            // The deterministic CPUID profile returns zero for leaf 14H, so
            // PTWRITE must #UD before observing either register or memory data.
            return self.inject_undefined_instruction();
        }

        // Memory fences and FSGSBASE (mod=3, specific reg values)
        if modrm >> 6 == 3 {
            let rm = (modrm & 0x07) | ctx.any_rex_b();
            if matches!(reg_op, 0..=3) && ctx.rep_prefix == Some(0xF3) {
                // FSGSBASE is defined only in 64-bit mode and has no W16 form.
                if !self.sregs.cs.l || (ctx.operand_size_override && !ctx.any_rex_w()) {
                    return self.inject_undefined_instruction();
                }
            }
            match reg_op {
                // WAITPKG register forms using the 0F AE /6 slot.
                6 if ctx.rep_prefix == Some(0xF3) => {
                    // UMONITOR performs the permission checks and ordered byte
                    // read but does not retain monitor hardware state.
                    let addr = self.monitor_linear_address(ctx, rm);
                    if self.sregs.cs.l && !is_canonical_48(addr) {
                        let vector = if ctx.segment_override == Some(0x36) {
                            12 // #SS(0)
                        } else {
                            13 // #GP(0)
                        };
                        self.inject_exception(vector, Some(0))?;
                        return Ok(None);
                    }
                    let _ = self.read_mem(addr, 1)?;
                    self.regs.rip += ctx.cursor as u64;
                    Ok(None)
                }
                6 if ctx.rep_prefix == Some(0xF2) || ctx.operand_size_override => {
                    // UMWAIT/TPAUSE return immediately on an allowed
                    // implementation-dependent wake event. Validate every
                    // architecturally faulting input before changing flags.
                    let control = self.get_reg(rm, 4) as u32;
                    if control & !1 != 0
                        || (self.sregs.cr0 & 1 != 0
                            && self.sregs.cr4 & CR4_TSD != 0
                            && (self.regs.rflags & flags::bits::VM != 0
                                || self.sregs.cs.selector & 3 != 0))
                    {
                        self.inject_exception(13, Some(0))?;
                        return Ok(None);
                    }
                    self.clear_lazy_flags();
                    self.regs.rflags &= !(flags::bits::CF
                        | flags::bits::PF
                        | flags::bits::AF
                        | flags::bits::ZF
                        | flags::bits::SF
                        | flags::bits::OF);
                    self.regs.rip += ctx.cursor as u64;
                    Ok(None)
                }
                // FSGSBASE instructions (require F3 prefix)
                0 if ctx.rep_prefix == Some(0xF3) => {
                    // RDFSBASE - Read FS base to register
                    if !self.require_cr4_bit_for_ud(CR4_FSGSBASE)? {
                        return Ok(None);
                    }
                    let value = if ctx.any_rex_w() {
                        self.sregs.fs.base
                    } else {
                        self.sregs.fs.base & 0xFFFF_FFFF
                    };
                    self.set_reg(rm, value, if ctx.any_rex_w() { 8 } else { 4 });
                    self.regs.rip += ctx.cursor as u64;
                    Ok(None)
                }
                1 if ctx.rep_prefix == Some(0xF3) => {
                    // RDGSBASE - Read GS base to register
                    if !self.require_cr4_bit_for_ud(CR4_FSGSBASE)? {
                        return Ok(None);
                    }
                    let value = if ctx.any_rex_w() {
                        self.sregs.gs.base
                    } else {
                        self.sregs.gs.base & 0xFFFF_FFFF
                    };
                    self.set_reg(rm, value, if ctx.any_rex_w() { 8 } else { 4 });
                    self.regs.rip += ctx.cursor as u64;
                    Ok(None)
                }
                2 if ctx.rep_prefix == Some(0xF3) => {
                    // WRFSBASE - Write register to FS base
                    if !self.require_cr4_bit_for_ud(CR4_FSGSBASE)? {
                        return Ok(None);
                    }
                    let value = if ctx.any_rex_w() {
                        self.get_reg(rm, 8)
                    } else {
                        self.get_reg(rm, 4)
                    };
                    if !is_canonical_48(value) {
                        self.inject_exception(13, Some(0))?;
                        return Ok(None);
                    }
                    self.sregs.fs.base = value;
                    self.regs.rip += ctx.cursor as u64;
                    Ok(None)
                }
                3 if ctx.rep_prefix == Some(0xF3) => {
                    // WRGSBASE - Write register to GS base
                    if !self.require_cr4_bit_for_ud(CR4_FSGSBASE)? {
                        return Ok(None);
                    }
                    let value = if ctx.any_rex_w() {
                        self.get_reg(rm, 8)
                    } else {
                        self.get_reg(rm, 4)
                    };
                    if !is_canonical_48(value) {
                        self.inject_exception(13, Some(0))?;
                        return Ok(None);
                    }
                    self.sregs.gs.base = value;
                    self.regs.rip += ctx.cursor as u64;
                    Ok(None)
                }
                5 if ctx.rep_prefix == Some(0xF3) => {
                    // INCSSPD/INCSSPQ are CET shadow-stack instructions. The
                    // emulator does not expose CET shadow stacks, so these
                    // F3-prefixed register forms are #UD instead of LFENCE.
                    self.inject_undefined_instruction()
                }
                5 => execute::system::lfence(self, ctx), // LFENCE (E8-EF)
                6 => execute::system::mfence(self, ctx), // MFENCE (F0-F7)
                7 => execute::system::sfence(self, ctx), // SFENCE (F8-FF)
                _ => {
                    self.inject_exception(6, None)?;
                    Ok(None)
                }
            }
        } else {
            if (reg_op == 4 && (ctx.operand_size_override || ctx.rep_prefix == Some(0xF2)))
                || (reg_op == 5 && (ctx.operand_size_override || ctx.rep_prefix.is_some()))
                || (reg_op == 6 && ctx.rep_prefix == Some(0xF2))
                || (reg_op == 7 && ctx.rep_prefix.is_some())
            {
                self.inject_undefined_instruction()?;
                return Ok(None);
            }

            if reg_op == 6 && ctx.rep_prefix == Some(0xF3) {
                // CLRSSBSY is a CET shadow-stack instruction. The emulator does
                // not expose CET shadow stacks, so this F3-prefixed memory form
                // is #UD instead of CLWB.
                self.inject_undefined_instruction()?;
                return Ok(None);
            }

            // Memory operand forms (FXSAVE, FXRSTOR, LDMXCSR, STMXCSR, XSAVE, XRSTOR, CLFLUSH)
            let modrm_start = ctx.cursor - 1;
            let (addr, extra) = self.decode_modrm_addr(ctx, modrm_start)?;
            ctx.cursor = modrm_start + 1 + extra;

            match reg_op {
                0 => {
                    if !self.require_cr0_ts_clear_for_nm()? {
                        return Ok(None);
                    }
                    // FXSAVE - save FPU/SSE state (512 bytes)
                    // Zero the area first
                    for i in 0..64 {
                        self.write_mem(addr + i * 8, 0u64, 8)?;
                    }
                    // FCW at offset 0
                    self.write_mem16(addr, self.fpu.control_word)?;
                    // FSW at offset 2
                    self.write_mem16(addr + 2, self.fpu.status_word)?;
                    // Abridged FTW at offset 4 (1 byte, 1 bit per register)
                    let mut abtw = 0u8;
                    for i in 0..8 {
                        let tag = (self.fpu.tag_word >> (i * 2)) & 3;
                        if tag != 3 {
                            abtw |= 1 << i;
                        }
                    }
                    self.mmu.write_u8(addr + 4, abtw, &self.sregs)?;
                    // FOP at offset 6
                    self.write_mem16(addr + 6, self.fpu.last_opcode)?;
                    // FIP at offset 8 (8 bytes in 64-bit mode)
                    self.write_mem64(addr + 8, self.fpu.instr_ptr)?;
                    // FDP at offset 16 (8 bytes in 64-bit mode)
                    self.write_mem64(addr + 16, self.fpu.data_ptr)?;
                    // MXCSR at offset 24
                    self.write_mem32(addr + 24, self.mxcsr)?;
                    // MXCSR_MASK at offset 28
                    self.write_mem32(addr + 28, 0xFFFF)?;
                    // ST0-ST7 at offset 32 (16 bytes each)
                    for i in 0..8 {
                        let bytes = execute::fpu::f64_to_f80_pub(self.fpu.get_st(i as u8));
                        self.write_bytes(addr + 32 + (i as u64) * 16, &bytes)?;
                    }
                    // XMM0-XMM15 at offset 160 (16 bytes each)
                    for i in 0..16 {
                        let xmm = self.regs.xmm[i];
                        self.write_mem64(addr + 160 + (i as u64) * 16, xmm[0])?;
                        self.write_mem64(addr + 160 + (i as u64) * 16 + 8, xmm[1])?;
                    }
                    self.regs.rip += ctx.cursor as u64;
                    Ok(None)
                }
                1 => {
                    if !self.require_cr0_ts_clear_for_nm()? {
                        return Ok(None);
                    }
                    if self.sregs.cr0 & CR0_EM != 0 {
                        self.inject_exception(7, None)?;
                        return Ok(None);
                    }
                    if addr & 0xF != 0 {
                        self.inject_exception(13, Some(0))?;
                        return Ok(None);
                    }
                    // FXRSTOR - restore FPU/SSE state (512 bytes)
                    // SDM 086 Vol. 1 §10.5.3: reject an illegal MXCSR before
                    // loading x87/SSE state. MXCSR_MASK in the image is ignored.
                    let mxcsr = self.read_mem32(addr + 24)?;
                    if !mxcsr_value_is_valid(mxcsr) {
                        self.inject_exception(13, Some(0))?;
                        return Ok(None);
                    }
                    // FCW at offset 0
                    self.fpu.control_word = self.read_mem16(addr)?;
                    // FSW at offset 2
                    self.fpu.status_word = self.read_mem16(addr + 2)?;
                    self.fpu.top = ((self.fpu.status_word >> 11) & 7) as u8;
                    // Abridged FTW at offset 4
                    let abtw = self.mmu.read_u8(addr + 4, &self.sregs)?;
                    self.fpu.tag_word = 0;
                    for i in 0..8 {
                        if abtw & (1 << i) != 0 {
                            self.fpu.tag_word |= 0 << (i * 2); // Valid
                        } else {
                            self.fpu.tag_word |= 3 << (i * 2); // Empty
                        }
                    }
                    // FOP at offset 6
                    self.fpu.last_opcode = self.read_mem16(addr + 6)?;
                    // FIP at offset 8
                    self.fpu.instr_ptr = self.read_mem64(addr + 8)?;
                    // FDP at offset 16
                    self.fpu.data_ptr = self.read_mem64(addr + 16)?;
                    // MXCSR at offset 24
                    self.mxcsr = mxcsr;
                    // ST0-ST7 at offset 32
                    for i in 0..8 {
                        let bytes = self.read_bytes(addr + 32 + (i as u64) * 16, 10)?;
                        self.fpu
                            .set_st(i as u8, execute::fpu::f80_to_f64_pub(&bytes));
                    }
                    // XMM0-XMM15 at offset 160
                    for i in 0..16 {
                        self.regs.xmm[i][0] = self.read_mem64(addr + 160 + (i as u64) * 16)?;
                        self.regs.xmm[i][1] = self.read_mem64(addr + 160 + (i as u64) * 16 + 8)?;
                    }
                    self.regs.rip += ctx.cursor as u64;
                    Ok(None)
                }
                2 => {
                    if !self.require_cr0_ts_clear_for_nm()? {
                        return Ok(None);
                    }
                    // LDMXCSR - load MXCSR register from memory
                    let value = self.read_mem32(addr)?;
                    if !mxcsr_value_is_valid(value) {
                        self.inject_exception(13, Some(0))?;
                        return Ok(None);
                    }
                    self.mxcsr = value;
                    self.regs.rip += ctx.cursor as u64;
                    Ok(None)
                }
                3 => {
                    if !self.require_cr0_ts_clear_for_nm()? {
                        return Ok(None);
                    }
                    // STMXCSR - store MXCSR register to memory
                    self.write_mem(addr, self.mxcsr as u64, 4)?;
                    self.regs.rip += ctx.cursor as u64;
                    Ok(None)
                }
                4 | 6
                    if reg_op == 4 || (ctx.rep_prefix.is_none() && !ctx.operand_size_override) =>
                {
                    if !self.require_cr4_bit_for_ud(CR4_OSXSAVE)? {
                        return Ok(None);
                    }
                    if !self.require_cr0_ts_clear_for_nm()? {
                        return Ok(None);
                    }
                    // XSAVE/XSAVEOPT - save x87/SSE/AVX/AVX-512 state selected by
                    // (EDX:EAX) & XCR0. XSAVEOPT may omit clean components, but this
                    // conservative save model is architecturally valid for observable state.
                    let rfbm = ((self.regs.rax & 0xFFFF_FFFF) | (self.regs.rdx << 32)) & self.xcr0;
                    let mut xstate_bv = 0u64;
                    // Component 0 (x87): legacy region header + ST0-7.
                    if rfbm & 0x1 != 0 {
                        self.write_mem16(addr, self.fpu.control_word)?;
                        self.write_mem16(addr + 2, self.fpu.status_word)?;
                        let mut abtw = 0u8;
                        for i in 0..8 {
                            if (self.fpu.tag_word >> (i * 2)) & 3 != 3 {
                                abtw |= 1 << i;
                            }
                        }
                        self.mmu.write_u8(addr + 4, abtw, &self.sregs)?;
                        self.write_mem16(addr + 6, self.fpu.last_opcode)?;
                        self.write_mem64(addr + 8, self.fpu.instr_ptr)?;
                        self.write_mem64(addr + 16, self.fpu.data_ptr)?;
                        for i in 0..8 {
                            let bytes = execute::fpu::f64_to_f80_pub(self.fpu.get_st(i as u8));
                            self.write_bytes(addr + 32 + (i as u64) * 16, &bytes)?;
                        }
                        xstate_bv |= 0x1;
                    }
                    // Component 1 (SSE): MXCSR + XMM0-15.
                    if rfbm & 0x2 != 0 {
                        self.write_mem32(addr + 24, self.mxcsr)?;
                        self.write_mem32(addr + 28, 0xFFFF)?;
                        for i in 0..16 {
                            self.write_mem64(addr + 160 + (i as u64) * 16, self.regs.xmm[i][0])?;
                            self.write_mem64(
                                addr + 160 + (i as u64) * 16 + 8,
                                self.regs.xmm[i][1],
                            )?;
                        }
                        xstate_bv |= 0x2;
                    }
                    // Component 2 (AVX): upper 128 bits of YMM0-15 at offset 576.
                    if rfbm & 0x4 != 0 {
                        for i in 0..16 {
                            self.write_mem64(
                                addr + 576 + (i as u64) * 16,
                                self.regs.ymm_high[i][0],
                            )?;
                            self.write_mem64(
                                addr + 576 + (i as u64) * 16 + 8,
                                self.regs.ymm_high[i][1],
                            )?;
                        }
                        xstate_bv |= 0x4;
                    }
                    // Component 5 (opmask): k0-k7 at offset 1088.
                    if rfbm & (1 << 5) != 0 {
                        for i in 0..8 {
                            self.write_mem64(addr + 1088 + (i as u64) * 8, self.regs.k[i])?;
                        }
                        xstate_bv |= 1 << 5;
                    }
                    // Component 6 (ZMM_Hi256): upper 256 bits of ZMM0-15.
                    if rfbm & (1 << 6) != 0 {
                        for i in 0..16 {
                            for lane in 0..4 {
                                self.write_mem64(
                                    addr + 1152 + (i as u64) * 32 + (lane as u64) * 8,
                                    self.regs.zmm_high[i][lane],
                                )?;
                            }
                        }
                        xstate_bv |= 1 << 6;
                    }
                    // Component 7 (Hi16_ZMM): full ZMM16-31.
                    if rfbm & (1 << 7) != 0 {
                        for i in 0..16 {
                            for lane in 0..8 {
                                self.write_mem64(
                                    addr + 1664 + (i as u64) * 64 + (lane as u64) * 8,
                                    self.regs.zmm_ext[i][lane],
                                )?;
                            }
                        }
                        xstate_bv |= 1 << 7;
                    }
                    // Component 19 (APX_F): R16-R31 at offset 960.
                    if rfbm & (1 << 19) != 0 {
                        for i in 0..16 {
                            self.write_mem64(
                                addr + 960 + (i as u64) * 8,
                                self.get_reg(16 + i as u8, 8),
                            )?;
                        }
                        xstate_bv |= 1 << 19;
                    }
                    // XSAVE header (standard, non-compacted): XSTATE_BV + XCOMP_BV.
                    self.write_mem64(addr + 512, xstate_bv)?;
                    self.write_mem64(addr + 520, 0)?;
                    self.regs.rip += ctx.cursor as u64;
                    Ok(None)
                }
                5 => {
                    if !self.require_cr4_bit_for_ud(CR4_OSXSAVE)? {
                        return Ok(None);
                    }
                    if !self.require_cr0_ts_clear_for_nm()? {
                        return Ok(None);
                    }
                    // XRSTOR - restore x87/SSE/AVX/AVX-512 state selected by (EDX:EAX) & XCR0.
                    let Some(restore) = self.prepare_xsave_restore(addr, false)? else {
                        return Ok(None);
                    };
                    if restore.compacted {
                        self.restore_xsave_compacted_area(addr, restore)?;
                        self.regs.rip += ctx.cursor as u64;
                        return Ok(None);
                    }

                    let rfbm = restore.requested;
                    let xstate_bv = restore.present;
                    if rfbm & 0x1 != 0 {
                        if xstate_bv & 0x1 != 0 {
                            self.fpu.control_word = self.read_mem16(addr)?;
                            self.fpu.status_word = self.read_mem16(addr + 2)?;
                            self.fpu.top = ((self.fpu.status_word >> 11) & 7) as u8;
                            let abtw = self.mmu.read_u8(addr + 4, &self.sregs)?;
                            self.fpu.tag_word = 0;
                            for i in 0..8 {
                                if abtw & (1 << i) == 0 {
                                    self.fpu.tag_word |= 3 << (i * 2);
                                }
                            }
                            self.fpu.last_opcode = self.read_mem16(addr + 6)?;
                            self.fpu.instr_ptr = self.read_mem64(addr + 8)?;
                            self.fpu.data_ptr = self.read_mem64(addr + 16)?;
                            for i in 0..8 {
                                let bytes = self.read_bytes(addr + 32 + (i as u64) * 16, 10)?;
                                self.fpu
                                    .set_st(i as u8, execute::fpu::f80_to_f64_pub(&bytes));
                            }
                        } else {
                            self.fpu.init();
                        }
                    }
                    if let Some(mxcsr) = restore.mxcsr {
                        self.mxcsr = mxcsr;
                    }
                    if rfbm & 0x2 != 0 {
                        if xstate_bv & 0x2 != 0 {
                            for i in 0..16 {
                                self.regs.xmm[i][0] =
                                    self.read_mem64(addr + 160 + (i as u64) * 16)?;
                                self.regs.xmm[i][1] =
                                    self.read_mem64(addr + 160 + (i as u64) * 16 + 8)?;
                            }
                        } else {
                            for i in 0..16 {
                                self.regs.xmm[i] = [0, 0];
                            }
                        }
                    }
                    if rfbm & 0x4 != 0 {
                        if xstate_bv & 0x4 != 0 {
                            for i in 0..16 {
                                self.regs.ymm_high[i][0] =
                                    self.read_mem64(addr + 576 + (i as u64) * 16)?;
                                self.regs.ymm_high[i][1] =
                                    self.read_mem64(addr + 576 + (i as u64) * 16 + 8)?;
                            }
                        } else {
                            for i in 0..16 {
                                self.regs.ymm_high[i] = [0, 0];
                            }
                        }
                    }
                    if rfbm & (1 << 5) != 0 {
                        if xstate_bv & (1 << 5) != 0 {
                            for i in 0..8 {
                                self.regs.k[i] = self.read_mem64(addr + 1088 + (i as u64) * 8)?;
                            }
                        } else {
                            self.regs.k = [0; 8];
                        }
                    }
                    if rfbm & (1 << 6) != 0 {
                        if xstate_bv & (1 << 6) != 0 {
                            for i in 0..16 {
                                for lane in 0..4 {
                                    self.regs.zmm_high[i][lane] = self.read_mem64(
                                        addr + 1152 + (i as u64) * 32 + (lane as u64) * 8,
                                    )?;
                                }
                            }
                        } else {
                            self.regs.zmm_high = [[0; 4]; 16];
                        }
                    }
                    if rfbm & (1 << 7) != 0 {
                        if xstate_bv & (1 << 7) != 0 {
                            for i in 0..16 {
                                for lane in 0..8 {
                                    self.regs.zmm_ext[i][lane] = self.read_mem64(
                                        addr + 1664 + (i as u64) * 64 + (lane as u64) * 8,
                                    )?;
                                }
                            }
                        } else {
                            self.regs.zmm_ext = [[0; 8]; 16];
                        }
                    }
                    if rfbm & (1 << 19) != 0 {
                        if xstate_bv & (1 << 19) != 0 {
                            for i in 0..16 {
                                let value = self.read_mem64(addr + 960 + (i as u64) * 8)?;
                                self.set_reg(16 + i as u8, value, 8);
                            }
                        } else {
                            for i in 0..16 {
                                self.set_reg(16 + i as u8, 0, 8);
                            }
                        }
                    }
                    self.regs.rip += ctx.cursor as u64;
                    Ok(None)
                }
                6 => {
                    // CLWB - treat as NOP
                    self.regs.rip += ctx.cursor as u64;
                    Ok(None)
                }
                7 => {
                    // CLFLUSH/CLFLUSHOPT - treat as NOP
                    self.regs.rip += ctx.cursor as u64;
                    Ok(None)
                }
                _ => unreachable!("0F AE reg_op is masked to three bits"),
            }
        }
    }
}
