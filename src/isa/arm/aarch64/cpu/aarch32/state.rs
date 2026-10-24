//! Shared physical register file views used by the AArch32 executor.

use crate::isa::arm::aarch32::cp15::{Cpacr, Sctlr};
use crate::isa::arm::aarch32::cpu::{Armv7Cpu, ProcessorMode, Psr};
use crate::isa::arm::aarch32::vfp::Fpscr;
use crate::isa::arm::aarch64::aarch32_state::{Aarch32Pstate, mode_el, register_index};
use crate::isa::arm::aarch64::cpu::AArch64Cpu;
use crate::isa::arm::common::cpu::ArmError;
use crate::isa::arm::common::sysreg::Aarch64SysRegEncoding;

fn spsr_encoding(index: u8) -> u16 {
    // Clang's SPSR_irq/abt/und/fiq encodings, S3_4_C4_C3_<0..3>.
    Aarch64SysRegEncoding::new(3, 4, 4, 3, index).encode()
}

impl AArch64Cpu {
    pub(super) fn aarch32_register_state(&self) -> Armv7Cpu {
        let psr = self.aarch32.expect("AArch32 execution mode");
        let mut cpu = Armv7Cpu::new();
        cpu.pstate_features = self.config.features;
        for index in 0..15 {
            cpu.regs[index] =
                self.x[usize::from(register_index(index as u8, psr.mode).unwrap())] as u32;
        }
        cpu.regs[15] = self.pc as u32;
        let saved = self.pstate_bits() as u32;
        let cpsr = (saved & !((1 << 24) | (1 << 21))) | (u32::from(self.dit) << 21);
        cpu.cpsr = Psr::from_u32(cpsr);
        cpu.regs_usr = [self.x[13] as u32, self.x[14] as u32];
        cpu.regs_usr_high = std::array::from_fn(|i| self.x[8 + i] as u32);
        cpu.regs_fiq = std::array::from_fn(|i| self.x[24 + i] as u32);
        cpu.regs_irq = [self.x[17] as u32, self.x[16] as u32];
        cpu.regs_svc = [self.x[19] as u32, self.x[18] as u32];
        cpu.regs_abt = [self.x[21] as u32, self.x[20] as u32];
        cpu.regs_und = [self.x[23] as u32, self.x[22] as u32];
        cpu.sp_hyp = self.x[15] as u32;
        let bank = |index| {
            Psr::from_u32(
                self.sysregs
                    .impl_defined
                    .get(&spsr_encoding(index))
                    .copied()
                    .unwrap_or(0) as u32,
            )
        };
        cpu.spsr_irq = bank(0);
        cpu.spsr_abt = bank(1);
        cpu.spsr_und = bank(2);
        cpu.spsr_fiq = bank(3);
        cpu.spsr_svc = Psr::from_u32(self.sysregs.el1.spsr as u32);
        cpu.spsr_hyp = Psr::from_u32(self.sysregs.el2.spsr as u32);
        for index in 0..32 {
            cpu.vfp.dregs[index] = (self.v[index / 2] >> ((index & 1) * 64)) as u64;
        }
        cpu.vfp.fpscr = Fpscr::from_bits((self.fpcr & 0x07c8_0000) | self.fpsr);
        let el1_aarch32 = crate::isa::arm::aarch64::exception_return::uses_aarch32(
            self.pauth_controls(),
            self.sysregs.id_aa64pfr0_el1,
            1,
        ) == Some(true);
        cpu.vfp.fpexc = if self.current_el == 0 && !el1_aarch32 {
            1 << 30
        } else {
            self.sysregs
                .impl_defined
                .get(&Aarch64SysRegEncoding::new(3, 4, 5, 3, 0).encode())
                .copied()
                .unwrap_or(0) as u32
        };
        let controls = self.pauth_controls();
        let regime = controls.regime_el() as u8;
        let system = self.sysregs.bank(regime);
        cpu.cp15.sctlr = Sctlr::from_bits(system.sctlr as u32);
        cpu.cp15.cpacr =
            Cpacr::from_bits((system.cpacr as u32) | (((system.cpacr >> 20) as u32 & 3) << 22));
        cpu.cp15.ttbr0 = system.ttbr0;
        cpu.cp15.ttbr1 = system.ttbr1;
        cpu.cp15.ttbcr = system.tcr as u32;
        cpu.cp15.contextidr = system.contextidr as u32;
        cpu.cp15.tpidrprw = system.tpidr as u32;
        cpu.cp15.tpidrurw = self.sysregs.tpidr_el0 as u32;
        cpu.cp15.tpidruro = self.sysregs.tpidrro_el0 as u32;
        cpu.cp15.cntfrq = self.sysregs.cntfrq_el0 as u32;
        cpu.cp15.cntpct = self.sysregs.cntpct_el0;
        cpu.cp15.cntvoff = self.sysregs.cntvoff_el2;
        cpu.cp15.cntkctl = self.sysregs.cntkctl_el1 as u32;
        cpu
    }

    pub(super) fn commit_aarch32_register_state(
        &mut self,
        cpu: &mut Armv7Cpu,
    ) -> Result<(), ArmError> {
        let mode = ProcessorMode::from_bits(cpu.cpsr.mode)
            .ok_or_else(|| ArmError::Internal("invalid AArch32 executor mode".into()))?;
        if mode == ProcessorMode::Monitor {
            return Err(ArmError::Unimplemented(
                "AArch32 Monitor state on an AArch64-reset EL3".into(),
            ));
        }
        cpu.save_to_banked(mode);
        if mode != ProcessorMode::Fiq {
            cpu.regs_usr_high.copy_from_slice(&cpu.regs[8..13]);
        }
        let mut words = std::array::from_fn::<_, 31, _>(|index| self.x[index] as u32);
        words[..8].copy_from_slice(&cpu.regs[..8]);
        words[8..13].copy_from_slice(&cpu.regs_usr_high);
        words[13..15].copy_from_slice(&cpu.regs_usr);
        words[15] = cpu.sp_hyp;
        words[16] = cpu.regs_irq[1];
        words[17] = cpu.regs_irq[0];
        words[18] = cpu.regs_svc[1];
        words[19] = cpu.regs_svc[0];
        words[20] = cpu.regs_abt[1];
        words[21] = cpu.regs_abt[0];
        words[22] = cpu.regs_und[1];
        words[23] = cpu.regs_und[0];
        words[24..31].copy_from_slice(&cpu.regs_fiq);
        for (register, word) in self.x.iter_mut().zip(words) {
            *register = (*register & 0xffff_ffff_0000_0000) | u64::from(word);
        }
        for index in 0..16 {
            self.v[index] = u128::from(cpu.vfp.dregs[index * 2])
                | (u128::from(cpu.vfp.dregs[index * 2 + 1]) << 64);
        }
        let fpscr = cpu.vfp.fpscr.bits();
        self.fpcr = (self.fpcr & !0x07c8_0000) | (fpscr & 0x07c8_0000);
        self.fpsr = fpscr & 0xf800_009f;
        self.nzcv = ((cpu.cpsr.to_u32() >> 28) & 15) as u8;
        self.daif = (self.daif & 8)
            | (u8::from(cpu.cpsr.a) << 2)
            | (u8::from(cpu.cpsr.i) << 1)
            | u8::from(cpu.cpsr.f);
        self.pan = cpu.cpsr.pan;
        self.dit = cpu.cpsr.dit;
        self.ssbs = cpu.cpsr.ssbs;
        self.il = cpu.cpsr.il;
        self.current_el = mode_el(cpu.cpsr.mode).unwrap();
        self.sp_sel = !matches!(mode, ProcessorMode::User | ProcessorMode::System);
        self.aarch32 = Some(Aarch32Pstate {
            mode: cpu.cpsr.mode,
            q: cpu.cpsr.q,
            it: cpu.cpsr.it_state,
            ge: cpu.cpsr.ge,
            e: cpu.cpsr.e,
            t: cpu.cpsr.t,
        });
        self.pc = u64::from(cpu.regs[15]);
        self.sysregs.tpidr_el0 =
            (self.sysregs.tpidr_el0 & 0xffff_ffff_0000_0000) | u64::from(cpu.cp15.tpidrurw);
        self.sysregs.tpidrro_el0 =
            (self.sysregs.tpidrro_el0 & 0xffff_ffff_0000_0000) | u64::from(cpu.cp15.tpidruro);
        for (index, psr) in [&cpu.spsr_irq, &cpu.spsr_abt, &cpu.spsr_und, &cpu.spsr_fiq]
            .into_iter()
            .enumerate()
        {
            let key = spsr_encoding(index as u8);
            let value = u64::from(psr.to_u32());
            let previous = self.sysregs.impl_defined.get(&key).copied().unwrap_or(0);
            if value != u64::from(Psr::from_u32(previous as u32).to_u32()) {
                self.sysregs.impl_defined.insert(key, value);
            }
        }
        // EL1/EL2 banked SPSRs already share their architectural storage. Only
        // an AArch32 privileged destination can use these 32-bit views.
        if self.current_el >= 1
            && cpu.spsr_svc.to_u32() != Psr::from_u32(self.sysregs.el1.spsr as u32).to_u32()
        {
            self.sysregs.el1.spsr = u64::from(cpu.spsr_svc.to_u32());
        }
        if self.current_el == 2
            && cpu.spsr_hyp.to_u32() != Psr::from_u32(self.sysregs.el2.spsr as u32).to_u32()
        {
            self.sysregs.el2.spsr = u64::from(cpu.spsr_hyp.to_u32());
        }
        let fpexc = Aarch64SysRegEncoding::new(3, 4, 5, 3, 0).encode();
        if self.current_el >= 1
            && (cpu.vfp.fpexc != 0 || self.sysregs.impl_defined.contains_key(&fpexc))
        {
            self.sysregs
                .impl_defined
                .insert(fpexc, u64::from(cpu.vfp.fpexc));
        }
        self.update_mmu_config();
        Ok(())
    }
}
