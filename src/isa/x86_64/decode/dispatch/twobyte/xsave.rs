//! XSAVE-family state-area transfers for the direct x86-64 interpreter.

use crate::error::Result;
use crate::isa::x86_64::cpu::{InsnContext, X86_64Vcpu};
use crate::isa::x86_64::execute;
use crate::isa::x86_64::mxcsr_value_is_valid;
use crate::vm::vcpu::VcpuExit;

const XSAVE_COMPACTED_FORMAT: u64 = 1 << 63;
const XSAVE_EXTENDED_COMPONENTS: [u8; 5] = [2, 5, 6, 7, 19];

/// Header-derived selection and the already-validated MXCSR value. This is
/// private to the direct two-byte dispatcher, not a snapshot representation.
pub(super) struct XsaveRestore {
    pub(super) requested: u64,
    pub(super) present: u64,
    pub(super) compacted: bool,
    format: u64,
    pub(super) mxcsr: Option<u32>,
}

impl X86_64Vcpu {
    fn xsave_requested_feature_bitmap(&self) -> u64 {
        ((self.regs.rax & 0xFFFF_FFFF) | ((self.regs.rdx & 0xFFFF_FFFF) << 32)) & self.xcr0
    }

    /// Check the XSAVE header before reading the selected MXCSR, and validate
    /// that value before restoring any component. Intel SDM 086 Vol. 1
    /// §§13.8.1, 13.8.2, and 13.12 distinguish the two MXCSR selection rules.
    ///
    /// CR4.OSXSAVE and CR0.TS are checked by the owning instruction dispatcher;
    /// XRSTORS additionally checks CPL before calling this helper. IA32_XSS is
    /// fixed to zero in the implemented MSR profile, so XCR0 is the enabled
    /// component bitmap for both XRSTOR and XRSTORS.
    pub(super) fn prepare_xsave_restore(
        &mut self,
        addr: u64,
        supervisor: bool,
    ) -> Result<Option<XsaveRestore>> {
        if addr & 0x3F != 0 {
            // The SDM permits #GP in place of #AC for this alignment check.
            self.inject_exception(13, Some(0))?;
            return Ok(None);
        }
        let xcomp_bv = self.read_mem64(addr + 520)?;
        let present = self.read_mem64(addr + 512)?;
        let compacted = xcomp_bv & XSAVE_COMPACTED_FORMAT != 0;
        let format = xcomp_bv & !XSAVE_COMPACTED_FORMAT;
        let malformed = if compacted {
            // XSTATE_BV is a subset of the full XCOMP_BV, including bit 63.
            // Only the component-enable comparison excludes the format bit.
            format & !self.xcr0 != 0 || present & !xcomp_bv != 0
        } else {
            present & !self.xcr0 != 0 || xcomp_bv != 0
        };
        if malformed || (supervisor && !compacted) {
            self.inject_exception(13, Some(0))?;
            return Ok(None);
        }
        // Standard XRSTOR checks header bytes 23:8, but not bytes 63:24.
        // Compacted XRSTOR(S) requires every header byte 63:16 to be zero.
        let reserved = self.read_bytes(addr + 528, if compacted { 48 } else { 8 })?;
        if reserved.iter().any(|byte| *byte != 0) {
            self.inject_exception(13, Some(0))?;
            return Ok(None);
        }

        let requested = self.xsave_requested_feature_bitmap();
        let mxcsr = if compacted {
            if requested & 2 == 0 {
                None
            } else if present & 2 == 0 {
                Some(0x1F80)
            } else {
                Some(self.read_mem32(addr + 24)?)
            }
        } else if requested & 6 != 0 {
            // Standard XRSTOR loads MXCSR for SSE OR AVX, regardless of
            // XSTATE_BV, including an SSE request that initializes XMM state.
            Some(self.read_mem32(addr + 24)?)
        } else {
            None
        };
        if mxcsr.is_some_and(|value| !mxcsr_value_is_valid(value)) {
            self.inject_exception(13, Some(0))?;
            return Ok(None);
        }
        Ok(Some(XsaveRestore {
            requested,
            present,
            compacted,
            format,
            mxcsr,
        }))
    }

    fn xsave_extended_component_size(component: u8) -> u64 {
        match component {
            2 => 256,
            5 => 64,
            6 => 512,
            7 => 1024,
            19 => 128,
            _ => unreachable!("XSAVE component is filtered by XSAVE_EXTENDED_COMPONENTS"),
        }
    }

    fn save_xsave_x87_component(&mut self, area_addr: u64) -> Result<()> {
        self.write_mem16(area_addr, self.fpu.control_word)?;
        self.write_mem16(area_addr + 2, self.fpu.status_word)?;
        let mut abtw = 0u8;
        for i in 0..8 {
            if (self.fpu.tag_word >> (i * 2)) & 3 != 3 {
                abtw |= 1 << i;
            }
        }
        self.mmu.write_u8(area_addr + 4, abtw, &self.sregs)?;
        self.write_mem16(area_addr + 6, self.fpu.last_opcode)?;
        self.write_mem64(area_addr + 8, self.fpu.instr_ptr)?;
        self.write_mem64(area_addr + 16, self.fpu.data_ptr)?;
        for i in 0..8 {
            let bytes = execute::fpu::f64_to_f80_pub(self.fpu.get_st(i as u8));
            self.write_bytes(area_addr + 32 + (i as u64) * 16, &bytes)?;
        }
        Ok(())
    }

    fn save_xsave_sse_component(&mut self, area_addr: u64) -> Result<()> {
        self.write_mem32(area_addr + 24, self.mxcsr)?;
        self.write_mem32(area_addr + 28, 0xFFFF)?;
        for i in 0..16 {
            self.write_mem64(area_addr + 160 + (i as u64) * 16, self.regs.xmm[i][0])?;
            self.write_mem64(area_addr + 160 + (i as u64) * 16 + 8, self.regs.xmm[i][1])?;
        }
        Ok(())
    }

    fn save_xsave_extended_component(&mut self, component: u8, component_addr: u64) -> Result<()> {
        match component {
            2 => {
                for i in 0..16 {
                    self.write_mem64(component_addr + (i as u64) * 16, self.regs.ymm_high[i][0])?;
                    self.write_mem64(
                        component_addr + (i as u64) * 16 + 8,
                        self.regs.ymm_high[i][1],
                    )?;
                }
            }
            5 => {
                for i in 0..8 {
                    self.write_mem64(component_addr + (i as u64) * 8, self.regs.k[i])?;
                }
            }
            6 => {
                for i in 0..16 {
                    for lane in 0..4 {
                        self.write_mem64(
                            component_addr + (i as u64) * 32 + (lane as u64) * 8,
                            self.regs.zmm_high[i][lane],
                        )?;
                    }
                }
            }
            7 => {
                for i in 0..16 {
                    for lane in 0..8 {
                        self.write_mem64(
                            component_addr + (i as u64) * 64 + (lane as u64) * 8,
                            self.regs.zmm_ext[i][lane],
                        )?;
                    }
                }
            }
            19 => {
                for i in 0..16 {
                    self.write_mem64(
                        component_addr + (i as u64) * 8,
                        self.get_reg(16 + i as u8, 8),
                    )?;
                }
            }
            _ => unreachable!("XSAVE component is filtered by XSAVE_EXTENDED_COMPONENTS"),
        }
        Ok(())
    }

    pub(super) fn execute_xsave_compacted(
        &mut self,
        ctx: &mut InsnContext,
    ) -> Result<Option<VcpuExit>> {
        let (_, _, is_memory, addr, _) = self.decode_modrm(ctx)?;
        if !is_memory {
            return self.inject_undefined_instruction();
        }

        let rfbm = self.xsave_requested_feature_bitmap();
        let mut xstate_bv = 0u64;

        if rfbm & 0x1 != 0 {
            self.save_xsave_x87_component(addr)?;
            xstate_bv |= 0x1;
        }
        if rfbm & 0x2 != 0 {
            self.save_xsave_sse_component(addr)?;
            xstate_bv |= 0x2;
        }

        let mut next_component_addr = addr + 576;
        for component in XSAVE_EXTENDED_COMPONENTS {
            if rfbm & (1u64 << component) != 0 {
                self.save_xsave_extended_component(component, next_component_addr)?;
                xstate_bv |= 1u64 << component;
                next_component_addr += Self::xsave_extended_component_size(component);
            }
        }

        self.write_mem64(addr + 512, xstate_bv)?;
        self.write_mem64(addr + 520, XSAVE_COMPACTED_FORMAT | rfbm)?;
        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }

    fn restore_xsave_x87_component(&mut self, area_addr: u64) -> Result<()> {
        self.fpu.control_word = self.read_mem16(area_addr)?;
        self.fpu.status_word = self.read_mem16(area_addr + 2)?;
        self.fpu.top = ((self.fpu.status_word >> 11) & 7) as u8;
        let abtw = self.mmu.read_u8(area_addr + 4, &self.sregs)?;
        self.fpu.tag_word = 0;
        for i in 0..8 {
            if abtw & (1 << i) == 0 {
                self.fpu.tag_word |= 3 << (i * 2);
            }
        }
        self.fpu.last_opcode = self.read_mem16(area_addr + 6)?;
        self.fpu.instr_ptr = self.read_mem64(area_addr + 8)?;
        self.fpu.data_ptr = self.read_mem64(area_addr + 16)?;
        for i in 0..8 {
            let bytes = self.read_bytes(area_addr + 32 + (i as u64) * 16, 10)?;
            // Stack order; keep the tags the abridged tag word restored.
            let idx = self.fpu.st_index(i as u8);
            self.fpu.st[idx] = execute::fpu::f80_to_f64_pub(&bytes);
        }
        Ok(())
    }

    fn restore_xsave_xmm_component(&mut self, area_addr: u64) -> Result<()> {
        for i in 0..16 {
            self.regs.xmm[i][0] = self.read_mem64(area_addr + 160 + (i as u64) * 16)?;
            self.regs.xmm[i][1] = self.read_mem64(area_addr + 160 + (i as u64) * 16 + 8)?;
        }
        Ok(())
    }

    fn restore_xsave_extended_component(
        &mut self,
        component: u8,
        component_addr: u64,
    ) -> Result<()> {
        match component {
            2 => {
                for i in 0..16 {
                    self.regs.ymm_high[i][0] = self.read_mem64(component_addr + (i as u64) * 16)?;
                    self.regs.ymm_high[i][1] =
                        self.read_mem64(component_addr + (i as u64) * 16 + 8)?;
                }
            }
            5 => {
                for i in 0..8 {
                    self.regs.k[i] = self.read_mem64(component_addr + (i as u64) * 8)?;
                }
            }
            6 => {
                for i in 0..16 {
                    for lane in 0..4 {
                        self.regs.zmm_high[i][lane] =
                            self.read_mem64(component_addr + (i as u64) * 32 + (lane as u64) * 8)?;
                    }
                }
            }
            7 => {
                for i in 0..16 {
                    for lane in 0..8 {
                        self.regs.zmm_ext[i][lane] =
                            self.read_mem64(component_addr + (i as u64) * 64 + (lane as u64) * 8)?;
                    }
                }
            }
            19 => {
                for i in 0..16 {
                    let value = self.read_mem64(component_addr + (i as u64) * 8)?;
                    self.set_reg(16 + i as u8, value, 8);
                }
            }
            _ => unreachable!("XSAVE component is filtered by XSAVE_EXTENDED_COMPONENTS"),
        }
        Ok(())
    }

    fn init_xsave_component(&mut self, component: u8) {
        match component {
            0 => self.fpu.init(),
            1 => {
                self.mxcsr = 0x1F80;
                for i in 0..16 {
                    self.regs.xmm[i] = [0, 0];
                }
            }
            2 => {
                for i in 0..16 {
                    self.regs.ymm_high[i] = [0, 0];
                }
            }
            5 => self.regs.k = [0; 8],
            6 => self.regs.zmm_high = [[0; 4]; 16],
            7 => self.regs.zmm_ext = [[0; 8]; 16],
            19 => {
                for i in 0..16 {
                    self.set_reg(16 + i as u8, 0, 8);
                }
            }
            _ => {}
        }
    }

    pub(super) fn restore_xsave_compacted_area(
        &mut self,
        addr: u64,
        restore: XsaveRestore,
    ) -> Result<()> {
        let rfbm = restore.requested;
        let xstate_bv = restore.present;
        let format = restore.format;

        for component in [0u8, 1] {
            if component == 1 {
                if let Some(mxcsr) = restore.mxcsr {
                    self.mxcsr = mxcsr;
                }
            }
            let bit = 1u64 << component;
            if rfbm & bit == 0 {
                continue;
            }
            if format & bit != 0 && xstate_bv & bit != 0 {
                if component == 0 {
                    self.restore_xsave_x87_component(addr)?;
                } else {
                    self.restore_xsave_xmm_component(addr)?;
                }
            } else {
                self.init_xsave_component(component);
            }
        }

        let mut next_component_addr = addr + 576;
        for component in XSAVE_EXTENDED_COMPONENTS {
            let bit = 1u64 << component;
            if format & bit != 0 {
                if rfbm & bit != 0 && xstate_bv & bit != 0 {
                    self.restore_xsave_extended_component(component, next_component_addr)?;
                }
                next_component_addr += Self::xsave_extended_component_size(component);
            } else if rfbm & bit != 0 {
                self.init_xsave_component(component);
            }
        }

        Ok(())
    }

    pub(super) fn execute_xrstors(&mut self, ctx: &mut InsnContext) -> Result<Option<VcpuExit>> {
        let (_, _, is_memory, addr, _) = self.decode_modrm(ctx)?;
        if !is_memory {
            return self.inject_undefined_instruction();
        }

        // Real mode has effective CPL0; VM86 has effective CPL3 independently
        // of CS.RPL. SDM 086 Vol. 1 §13.12 checks privilege before the header.
        if self.sregs.cr0 & 1 != 0
            && (self.regs.rflags & (1 << 17) != 0 || self.sregs.cs.selector & 3 != 0)
        {
            self.inject_exception(13, Some(0))?;
            return Ok(None);
        }
        let Some(restore) = self.prepare_xsave_restore(addr, true)? else {
            return Ok(None);
        };
        self.restore_xsave_compacted_area(addr, restore)?;
        self.regs.rip += ctx.cursor as u64;
        Ok(None)
    }
}
