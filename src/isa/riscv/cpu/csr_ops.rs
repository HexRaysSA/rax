//! Control and status register behavior.

use super::*;

impl RiscVCpu {
    pub(super) fn exec_csr(&mut self, insn: &Insn) -> Result<(), Trap> {
        let addr = insn.csr;
        let is_imm = matches!(insn.op, Op::Csrrwi | Op::Csrrsi | Op::Csrrci);
        let src = if is_imm {
            insn.rs1 as u64
        } else {
            self.x(insn.rs1)
        };
        let is_write = matches!(insn.op, Op::Csrrw | Op::Csrrwi);
        let writes = is_write || insn.rs1 != 0;

        let minimum_privilege = ((addr >> 8) & 0b11) as u8;
        if (self.priv_ as u8) < minimum_privilege {
            return Err(Trap::illegal(insn.raw));
        }

        if writes && Csr::is_read_only(addr) {
            return Err(Trap::illegal(insn.raw));
        }

        // CSRRW with rd=x0 suppresses the CSR read and any read side effects.
        let old = if is_write && insn.rd == 0 {
            0
        } else {
            self.csr_read(addr)?
        };

        if writes {
            let new = match insn.op {
                Op::Csrrw | Op::Csrrwi => src,
                Op::Csrrs | Op::Csrrsi => old | src,
                Op::Csrrc | Op::Csrrci => old & !src,
                _ => unreachable!(),
            };
            self.csr_write(addr, new)?;
            if matches!(addr, 0x001..=0x003) {
                self.mark_fp_state_dirty();
            }
        }
        self.set_x(insn.rd, old);
        Ok(())
    }

    /// Read a CSR value (XLEN-wide).
    pub fn csr_read(&self, addr: u16) -> Result<u64, Trap> {
        let csr = match Csr::from_addr(addr) {
            Some(c) => c,
            None => {
                if self.cfg.isa.xsoteria {
                    return Ok(self.ext_csr.get(&addr).copied().unwrap_or(0) & self.xmask());
                }
                return Err(Trap::illegal(0));
            }
        };
        if !self.csr_available(csr) {
            return Err(Trap::illegal(0));
        }
        if !self.counter_read_allowed(csr) {
            return Err(Trap::illegal(0));
        }
        let v = match csr {
            Csr::Fflags => (self.fcsr & 0x1f) as u64,
            Csr::Frm => ((self.fcsr >> 5) & 0x7) as u64,
            Csr::Fcsr => (self.fcsr & 0xff) as u64,
            Csr::Jvt => self.jvt,
            Csr::Cycle => self.cycle & self.xmask(),
            Csr::Time => self.time & self.xmask(),
            Csr::Instret => self.instret & self.xmask(),
            Csr::CycleH => (self.cycle >> 32) & 0xffff_ffff,
            Csr::TimeH => (self.time >> 32) & 0xffff_ffff,
            Csr::InstretH => (self.instret >> 32) & 0xffff_ffff,
            Csr::Mstatus => self.mstatus_read_value(),
            Csr::Sstatus => self.mstatus_read_value() & self.sstatus_mask(),
            Csr::Misa => self.misa(),
            Csr::Medeleg => self.medeleg,
            Csr::Mideleg => self.mideleg,
            Csr::Mie => self.mie,
            Csr::Sie => self.mie & self.supervisor_interrupt_mask(),
            Csr::Sepc => self.sepc_read_value(),
            Csr::Mtvec => self.mtvec,
            Csr::Mcounteren => self.mcounteren,
            Csr::Scounteren => self.scounteren,
            Csr::Mscratch => self.mscratch,
            Csr::Mepc => self.mepc_read_value(),
            Csr::Mcause => self.mcause,
            Csr::Mtval => self.mtval,
            Csr::Mip => self.mip,
            Csr::Sip => self.mip & self.supervisor_interrupt_mask(),
            Csr::Mvendorid | Csr::Marchid | Csr::Mimpid => 0,
            Csr::Mhartid => self.mhartid,
            Csr::Vl => self.vl,
            Csr::Vtype => self.vtype,
            Csr::Vlenb => VLEN / 8,
            Csr::Vstart => self.vstart,
            Csr::Vxsat => self.vxsat,
            Csr::Vxrm => self.vxrm,
            Csr::Vcsr => (self.vxrm << 1) | self.vxsat,
        };
        Ok(v & self.xmask())
    }

    /// Write a CSR value (XLEN-wide).
    pub fn csr_write(&mut self, addr: u16, value: u64) -> Result<(), Trap> {
        let csr = match Csr::from_addr(addr) {
            Some(c) => c,
            None => {
                if self.cfg.isa.xsoteria {
                    self.ext_csr.insert(addr, value & self.xmask());
                    return Ok(());
                }
                return Err(Trap::illegal(0));
            }
        };
        if !self.csr_available(csr) {
            return Err(Trap::illegal(0));
        }
        match csr {
            Csr::Fflags => self.fcsr = (self.fcsr & !0x1f) | (value as u32 & 0x1f),
            Csr::Frm => self.fcsr = (self.fcsr & !0xe0) | (((value as u32) & 0x7) << 5),
            Csr::Fcsr => self.fcsr = value as u32 & 0xff,
            // Jump-table mode zero is the only currently defined/implemented
            // WARL mode; BASE is consequently always 64-byte aligned.
            Csr::Jvt => self.jvt = value & !0x3f & self.xmask(),
            Csr::Mstatus => self.mstatus = self.mstatus_warl_value(value),
            Csr::Sstatus => {
                let mask = self.sstatus_write_mask();
                self.mstatus = (self.mstatus & !mask) | (value & mask);
            }
            Csr::Medeleg => self.medeleg = value & DELEGATABLE_EXCEPTION_MASK & self.xmask(),
            Csr::Mideleg => self.mideleg = value & S_INTERRUPT_MASK & self.xmask(),
            Csr::Mie => self.mie = value,
            Csr::Sie => {
                let mask = self.supervisor_interrupt_mask();
                self.mie = (self.mie & !mask) | (value & mask);
            }
            Csr::Sepc => self.sepc = value & self.epc_alignment_mask() & self.xmask(),
            Csr::Mtvec => {
                let base = value & !0b11 & self.xmask();
                let mode = u64::from(value & 0b11 == 1);
                self.mtvec = base | mode;
            }
            Csr::Mcounteren => self.mcounteren = value & 0xffff_ffff,
            Csr::Scounteren => self.scounteren = value & 0xffff_ffff,
            Csr::Mscratch => self.mscratch = value,
            Csr::Mepc => self.mepc = value & self.epc_alignment_mask() & self.xmask(),
            Csr::Mcause => self.mcause = value,
            Csr::Mtval => self.mtval = value,
            Csr::Mip => self.mip = value & IMPLEMENTED_INTERRUPT_MASK & self.xmask(),
            Csr::Sip => {
                let mask = self.supervisor_software_interrupt_mask();
                self.mip = (self.mip & !mask) | (value & mask);
            }
            Csr::Vstart => self.vstart = value,
            Csr::Vxsat => self.vxsat = value & 1,
            Csr::Vxrm => self.vxrm = value & 3,
            Csr::Vcsr => {
                self.vxsat = value & 1;
                self.vxrm = (value >> 1) & 3;
            }
            _ => {}
        }
        Ok(())
    }

    /// Whether a recognized CSR exists in the configured architectural
    /// profile. Zicsr controls the CSR instructions themselves; this gate
    /// covers the XLEN- and extension-dependent register families.
    fn csr_available(&self, csr: Csr) -> bool {
        match csr {
            Csr::Fflags | Csr::Frm | Csr::Fcsr => {
                // priv spec v1.12 norm:mstatus_fs_op: FP CSRs are gated on
                // mstatus.FS != Off in every privilege mode.
                self.cfg.isa.f && (self.mstatus >> 13) & 0b11 != 0
            }
            Csr::Jvt => self.cfg.isa.zcmt,
            Csr::CycleH | Csr::TimeH | Csr::InstretH => self.rv32(),
            Csr::Vstart
            | Csr::Vxsat
            | Csr::Vxrm
            | Csr::Vcsr
            | Csr::Vl
            | Csr::Vtype
            | Csr::Vlenb => self.cfg.isa.v,
            _ => true,
        }
    }

    fn sstatus_mask(&self) -> u64 {
        let sd = 1u64 << (self.xbits() - 1);
        let uxl = if self.rv32() { 0 } else { 0b11 << 32 };
        (SSTATUS_BASE_MASK | uxl | sd) & self.xmask()
    }

    fn sstatus_write_mask(&self) -> u64 {
        let sd = 1u64 << (self.xbits() - 1);
        self.sstatus_mask() & !sd
    }

    fn mstatus_read_value(&self) -> u64 {
        let sd = 1u64 << (self.xbits() - 1);
        let dirty = [9, 13, 15]
            .into_iter()
            .any(|shift| (self.mstatus >> shift) & 0b11 == 0b11);
        (self.mstatus & !sd & self.xmask()) | if dirty { sd } else { 0 }
    }

    fn mstatus_warl_value(&self, value: u64) -> u64 {
        let sd = 1u64 << (self.xbits() - 1);
        let mut canonical = value & !sd & self.xmask();
        if (canonical >> 11) & 0b11 == 0b10 {
            canonical &= !(0b11 << 11);
        }
        canonical
    }

    fn counter_read_allowed(&self, csr: Csr) -> bool {
        let bit = match csr {
            Csr::Cycle | Csr::CycleH => 0,
            Csr::Time | Csr::TimeH => 1,
            Csr::Instret | Csr::InstretH => 2,
            _ => return true,
        };
        match self.priv_ {
            Priv::Machine => true,
            Priv::Supervisor => self.mcounteren & (1 << bit) != 0,
            Priv::User => self.mcounteren & self.scounteren & (1 << bit) != 0,
        }
    }

    fn supervisor_interrupt_mask(&self) -> u64 {
        self.mideleg & S_INTERRUPT_MASK & self.xmask()
    }

    fn supervisor_software_interrupt_mask(&self) -> u64 {
        self.mideleg & (1 << cause::INT_S_SOFTWARE) & self.xmask()
    }

    fn misa(&self) -> u64 {
        let mxl: u64 = if self.rv32() { 1 } else { 2 };
        let shift = self.xbits() as u64 - 2;
        let mut bits: u64 = 1 << 8; // I
        let isa = &self.cfg.isa;
        for (enabled, bit) in [
            (isa.a, 0),
            (isa.c, 2),
            (isa.d, 3),
            (isa.f, 5),
            (isa.h, 7),
            (isa.m, 12),
            (isa.v, 21),
        ] {
            if enabled {
                bits |= 1 << bit;
            }
        }
        (mxl << shift) | bits
    }

    #[inline]
    fn epc_alignment_mask(&self) -> u64 {
        if self.cfg.isa.c { !1 } else { !3 }
    }

    #[inline]
    fn mepc_read_value(&self) -> u64 {
        self.mepc & self.epc_alignment_mask() & self.xmask()
    }

    #[inline]
    fn sepc_read_value(&self) -> u64 {
        self.sepc & self.epc_alignment_mask() & self.xmask()
    }

    pub(super) fn mret(&mut self) {
        // pc <- mepc; MIE <- MPIE; MPIE <- 1; priv <- MPP; MPP <- U.
        self.pc = self.mepc_read_value();
        let mpie = (self.mstatus >> 7) & 1;
        self.mstatus &= !(1 << 3);
        self.mstatus |= mpie << 3;
        self.mstatus |= 1 << 7;
        let mpp = (self.mstatus >> 11) & 0b11;
        self.priv_ = match mpp {
            3 => Priv::Machine,
            1 => Priv::Supervisor,
            _ => Priv::User,
        };
        self.mstatus &= !(0b11 << 11);
    }

    pub(super) fn sret(&mut self, insn: &Insn) -> Result<(), Trap> {
        const MSTATUS_SIE: u64 = 1 << 1;
        const MSTATUS_SPIE: u64 = 1 << 5;
        const MSTATUS_SPP: u64 = 1 << 8;
        const MSTATUS_MPRV: u64 = 1 << 17;
        const MSTATUS_TSR: u64 = 1 << 22;

        if self.priv_ < Priv::Supervisor
            || (self.priv_ == Priv::Supervisor && self.mstatus & MSTATUS_TSR != 0)
        {
            return Err(Trap::illegal(insn.raw));
        }

        self.pc = self.sepc_read_value();
        let spie = self.mstatus & MSTATUS_SPIE != 0;
        self.mstatus &= !MSTATUS_SIE;
        self.mstatus |= u64::from(spie) * MSTATUS_SIE;
        self.mstatus |= MSTATUS_SPIE;
        self.priv_ = if self.mstatus & MSTATUS_SPP != 0 {
            Priv::Supervisor
        } else {
            Priv::User
        };
        self.mstatus &= !(MSTATUS_SPP | MSTATUS_MPRV);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::isa::riscv::{FlatMemory, decode};

    fn cpu_with_xlen(xlen: Xlen, isa: Isa) -> RiscVCpu {
        RiscVCpu::new(
            RiscVConfig { xlen, isa },
            Box::new(FlatMemory::new(0, 0x2000)),
        )
    }

    fn cpu(isa: Isa) -> RiscVCpu {
        cpu_with_xlen(Xlen::Rv64, isa)
    }

    fn csr_insn(csr: u32, funct3: u32, rs1: u32, rd: u32) -> u32 {
        (csr << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | 0x73
    }

    #[test]
    fn csr_instructions_enforce_the_encoded_minimum_privilege() {
        let mut hart = cpu(Isa::rv64gc());
        hart.set_x(1, 0xfeed_face);
        hart.set_x(2, 0x1234_5678);

        for (privilege, csr) in [
            (Priv::User, 0x100),       // sstatus: supervisor-level
            (Priv::User, 0x305),       // mtvec: machine-level
            (Priv::Supervisor, 0x305), // mtvec: machine-level
        ] {
            hart.priv_ = privilege;
            let raw = csr_insn(csr, 0b001, 2, 1); // csrrw x1, csr, x2
            let insn = decode(raw, Xlen::Rv64, &Isa::rv64gc());
            assert_eq!(hart.execute_insn(&insn, 0x1000), Err(Trap::illegal(raw)));
            assert_eq!(hart.x(1), 0xfeed_face);
            assert_eq!(hart.mtvec, 0);
        }

        hart.priv_ = Priv::Supervisor;
        let supervisor_raw = csr_insn(0x100, 0b010, 0, 1); // csrr x1, sstatus
        let supervisor = decode(supervisor_raw, Xlen::Rv64, &Isa::rv64gc());
        assert_eq!(
            hart.execute_insn(&supervisor, 0x1000),
            Ok(RiscVExit::Continue)
        );
    }

    #[test]
    fn counter_enable_csrs_are_32_bit_and_gate_lower_privilege_reads() {
        let mut hart = cpu(Isa::rv64gc());
        hart.csr_write(0x306, (1 << 33) | 0b111).unwrap();
        hart.csr_write(0x106, (1 << 34) | 0b111).unwrap();
        assert_eq!(hart.csr_read(0x306), Ok(0b111));
        assert_eq!(hart.csr_read(0x106), Ok(0b111));

        hart.csr_write(0x306, 0).unwrap();
        hart.csr_write(0x106, 0).unwrap();
        hart.priv_ = Priv::Supervisor;
        assert_eq!(hart.csr_read(0xc00), Err(Trap::illegal(0)));
        hart.priv_ = Priv::User;
        assert_eq!(hart.csr_read(0xc00), Err(Trap::illegal(0)));

        hart.priv_ = Priv::Machine;
        hart.csr_write(0x306, 1).unwrap();
        hart.priv_ = Priv::Supervisor;
        assert!(hart.csr_read(0xc00).is_ok());
        hart.priv_ = Priv::User;
        assert_eq!(hart.csr_read(0xc00), Err(Trap::illegal(0)));

        hart.priv_ = Priv::Machine;
        hart.csr_write(0x106, 1).unwrap();
        hart.priv_ = Priv::User;
        assert!(hart.csr_read(0xc00).is_ok());
    }

    #[test]
    fn status_interrupt_and_delegation_csrs_canonicalize_warl_fields() {
        const MSTATUS_SD: u64 = 1 << 63;
        const MSTATUS_FS_DIRTY: u64 = 0b11 << 13;
        const MSTATUS_MPP_RESERVED: u64 = 0b10 << 11;
        const SUPPORTED_INTERRUPTS: u64 =
            (1 << 1) | (1 << 3) | (1 << 5) | (1 << 7) | (1 << 9) | (1 << 11);

        let mut hart = cpu(Isa::rv64gc());
        hart.csr_write(0x300, MSTATUS_SD | MSTATUS_FS_DIRTY | MSTATUS_MPP_RESERVED)
            .unwrap();
        let status = hart.csr_read(0x300).unwrap();
        assert_eq!(status & (0b11 << 11), 0, "reserved MPP canonicalizes to U");
        assert_ne!(status & MSTATUS_SD, 0, "SD summarizes dirty FS");

        hart.csr_write(0x300, MSTATUS_SD).unwrap();
        assert_eq!(
            hart.csr_read(0x300).unwrap() & MSTATUS_SD,
            0,
            "SD is read-only"
        );

        hart.csr_write(0x344, u64::MAX).unwrap();
        assert_eq!(hart.csr_read(0x344), Ok(SUPPORTED_INTERRUPTS));
        hart.csr_write(0x303, u64::MAX).unwrap();
        assert_eq!(hart.csr_read(0x303), Ok((1 << 1) | (1 << 5) | (1 << 9)));
        hart.csr_write(0x302, (1 << 2) | (1 << 10)).unwrap();
        assert_eq!(hart.csr_read(0x302), Ok(1 << 2));

        let mut rv32 = cpu_with_xlen(Xlen::Rv32, Isa::rv64gc());
        rv32.csr_write(0x300, 1 << 31).unwrap();
        assert_eq!(rv32.csr_read(0x300).unwrap() & (1 << 31), 0);
        rv32.csr_write(0x100, MSTATUS_FS_DIRTY | (1 << 31)).unwrap();
        assert_ne!(rv32.csr_read(0x300).unwrap() & (1 << 31), 0);
        assert_ne!(rv32.csr_read(0x100).unwrap() & (1 << 31), 0);
    }

    #[test]
    fn mepc_masks_the_configured_ialign_on_reads_and_mret() {
        let mut no_c = cpu(Isa::rv_i());
        no_c.csr_write(0x341, 0x1003).unwrap();
        assert_eq!(no_c.csr_read(0x341), Ok(0x1000));
        no_c.mret();
        assert_eq!(no_c.pc(), 0x1000);

        let mut with_c = cpu(Isa {
            c: true,
            ..Isa::rv_i()
        });
        with_c.csr_write(0x341, 0x1003).unwrap();
        assert_eq!(with_c.csr_read(0x341), Ok(0x1002));
        with_c.mret();
        assert_eq!(with_c.pc(), 0x1002);
    }

    #[test]
    fn sepc_masks_ialign_and_sret_restores_only_supervisor_stack() {
        let mut hart = cpu(Isa::rv64gc());
        let sret = decode(0x1020_0073, Xlen::Rv64, &Isa::rv64gc());
        let machine_stack = (0b11 << 11) | (1 << 7) | (1 << 3);
        hart.mstatus = machine_stack | (1 << 17) | (1 << 8) | (1 << 5);
        hart.sepc = 0x2003;
        hart.priv_ = Priv::Supervisor;

        assert_eq!(hart.execute_insn(&sret, 0x1000), Ok(RiscVExit::Continue));
        assert_eq!(hart.pc(), 0x2002);
        assert_eq!(hart.privilege(), Priv::Supervisor);
        assert_eq!(hart.mstatus & machine_stack, machine_stack);
        assert_ne!(hart.mstatus & (1 << 1), 0, "SIE <- SPIE");
        assert_ne!(hart.mstatus & (1 << 5), 0, "SPIE <- 1");
        assert_eq!(hart.mstatus & (1 << 8), 0, "SPP <- U");
        assert_eq!(hart.mstatus & (1 << 17), 0, "MPRV clears below M-mode");

        let mut no_c = cpu(Isa::rv_i());
        no_c.csr_write(0x141, 0x3003).unwrap();
        assert_eq!(no_c.csr_read(0x141), Ok(0x3000));
        no_c.priv_ = Priv::Supervisor;
        assert_eq!(no_c.sret(&sret), Ok(()));
        assert_eq!(no_c.pc(), 0x3000);
        assert_eq!(no_c.privilege(), Priv::User);
        assert_eq!(no_c.mstatus & (1 << 1), 0);
        assert_ne!(no_c.mstatus & (1 << 5), 0);
    }

    #[test]
    fn sret_privilege_and_tsr_failures_do_not_commit_state() {
        let sret = decode(0x1020_0073, Xlen::Rv64, &Isa::rv64gc());
        for (privilege, status) in [(Priv::User, 0), (Priv::Supervisor, 1 << 22)] {
            let mut cpu = cpu(Isa::rv64gc());
            cpu.priv_ = privilege;
            cpu.mstatus = status | (1 << 5) | (1 << 8);
            cpu.sepc = 0x2000;
            cpu.pc = 0x1000;
            let before = (cpu.pc, cpu.priv_, cpu.mstatus, cpu.sepc);
            assert_eq!(cpu.sret(&sret), Err(Trap::illegal(sret.raw)));
            assert_eq!((cpu.pc, cpu.priv_, cpu.mstatus, cpu.sepc), before);
        }
    }

    #[test]
    fn misa_reports_enabled_h_and_v_independently() {
        for (h, v) in [(false, false), (true, false), (false, true), (true, true)] {
            let cpu = cpu(Isa {
                h,
                v,
                ..Isa::rv_i()
            });
            let misa = cpu.csr_read(0x301).unwrap();
            assert_eq!((misa >> 7) & 1, h as u64, "H projection");
            assert_eq!((misa >> 21) & 1, v as u64, "V projection");
        }
    }

    #[test]
    fn mtvec_warl_readback_never_exposes_a_reserved_mode() {
        let mut cpu = cpu(Isa::rv_i());
        for mode in 0..=3 {
            cpu.csr_write(0x305, 0x1000 | mode).unwrap();
            let expected_mode = u64::from(mode == 1);
            assert_eq!(
                cpu.csr_read(0x305),
                Ok(0x1000 | expected_mode),
                "MODE={mode}"
            );
        }
    }

    #[test]
    fn csr_availability_tracks_xlen_and_declaring_extensions() {
        let mut unavailable = cpu(Isa::rv_i());
        for addr in [
            0x001, 0x002, 0x003, // F
            0x017, // Zcmt
            0x008, 0x009, 0x00A, 0x00F, 0xC20, 0xC21, 0xC22, // V
            0xC80, 0xC81, 0xC82, // RV32-only counter high halves
        ] {
            assert_eq!(
                unavailable.csr_read(addr),
                Err(Trap::illegal(0)),
                "read {addr:#05x}"
            );
            assert_eq!(
                unavailable.csr_write(addr, u64::MAX),
                Err(Trap::illegal(0)),
                "write {addr:#05x}"
            );
        }

        let mut available = cpu(Isa {
            f: true,
            v: true,
            zcmt: true,
            ..Isa::rv_i()
        });
        available.csr_write(0x300, 0b01 << 13).unwrap(); // mstatus.FS=Initial
        for addr in [0x001, 0x002, 0x003, 0x017, 0x008, 0x009, 0x00A, 0x00F] {
            assert!(available.csr_write(addr, 0).is_ok(), "write {addr:#05x}");
        }
        for addr in [
            0x001, 0x002, 0x003, 0x017, 0x008, 0x009, 0x00A, 0x00F, 0xC20, 0xC21, 0xC22,
        ] {
            assert!(available.csr_read(addr).is_ok(), "read {addr:#05x}");
        }

        let rv32 = cpu_with_xlen(Xlen::Rv32, Isa::rv_i());
        for addr in [0xC80, 0xC81, 0xC82] {
            assert!(rv32.csr_read(addr).is_ok(), "RV32 read {addr:#05x}");
        }
    }
}
