//! INIT is a control-flow reset, distinct from a power-on reset.
use super::*;
use crate::vm::vcpu::{DescriptorTable, Segment};

impl X86_64Vcpu {
    /// Intel SDM086 Vol.3A 11.1/Table11-1: INIT preserves the FP/vector,
    /// XCR0, PKRU, timestamp and most MSR state. Do not call reset_state().
    pub(super) fn deliver_init_signal(&mut self) -> Result<()> {
        let regs = Registers {
            rip: 0xfff0,
            rflags: 2,
            rdx: u64::from(
                execute::system::evaluate_cpuid(1, 0, execute::system::X86CpuidState::default()).0,
            ),
            xmm: self.regs.xmm,
            ymm_high: self.regs.ymm_high,
            zmm_high: self.regs.zmm_high,
            zmm_ext: self.regs.zmm_ext,
            k: self.regs.k,
            mm: self.regs.mm,
            ..Default::default()
        };
        let data = Segment {
            limit: 0xffff,
            type_: 3,
            present: true,
            s: true,
            ..Default::default()
        };
        let mut sregs = self.sregs.clone();
        sregs.cr0 = 0x6000_0010;
        sregs.cr2 = 0;
        sregs.cr3 = 0;
        sregs.cr4 = 0;
        sregs.cr8 = 0;
        sregs.efer = 0;
        sregs.cs = Segment {
            selector: 0xf000,
            base: 0xffff_0000,
            ..data.clone()
        };
        sregs.ds = data.clone();
        sregs.es = data.clone();
        sregs.ss = data.clone();
        sregs.fs = data.clone();
        sregs.gs = data.clone();
        sregs.tr = Segment {
            s: false,
            ..data.clone()
        };
        sregs.ldt = Segment {
            s: false,
            type_: 2,
            ..data
        };
        sregs.gdt = DescriptorTable {
            base: 0,
            limit: 0xffff,
        };
        sregs.idt = DescriptorTable {
            base: 0,
            limit: 0xffff,
        };
        sregs.dr0 = 0;
        sregs.dr1 = 0;
        sregs.dr2 = 0;
        sregs.dr3 = 0;
        sregs.dr6 = 0xffff_0ff0;
        sregs.dr7 = 0x400;
        self.set_state(&CpuState::X86_64(X86_64CpuState { regs, sregs }))?;
        self.halted = false;
        self.io_pending = None;
        self.mmu.flush_tlb();
        #[cfg(all(
            feature = "smir-jit",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            self.jit_callout_exit = None;
            self.jit_active_source_range = None;
            self.jit_active_region_stale = false;
            self.jit_cache.clear();
            self.jit_hot.clear();
            self.jit_ineligible.clear();
            self.jit_ineligible_dirty.clear();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    #[test]
    fn init_resets_control_flow_and_preserves_vector_fp_msr_and_retirement_state() {
        let memory = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 65536)]).unwrap());
        let mut cpu = X86_64Vcpu::new(3, memory);
        cpu.regs.rax = u64::MAX;
        cpu.regs.r15 = u64::MAX;
        cpu.regs.r31 = u64::MAX;
        cpu.regs.xmm = [[0x1122_3344_5566_7788; 2]; 16];
        cpu.regs.ymm_high = [[0x8877_6655_4433_2211; 2]; 16];
        cpu.regs.zmm_high = [[0x1357_9bdf_2468_ace0; 4]; 16];
        cpu.regs.zmm_ext = [[0xfedc_ba98_7654_3210; 8]; 16];
        cpu.regs.k = [0x0123_4567_89ab_cdef; 8];
        cpu.regs.mm = [0x5555_aaaa_5555_aaaa; 8];
        cpu.fpu.top = 3;
        cpu.fpu.tag_word = 0x55aa;
        cpu.fpu.st = [[0xa5; 10]; 8];
        cpu.mxcsr = 0x3f80;
        cpu.xcr0 = 7;
        cpu.pkru = 0x1234_5678;
        cpu.sregs.star = 0x1122_3344_5566_7788;
        cpu.sregs.lstar = 0x1234_5678;
        cpu.sregs.sysenter_cs = 0x10;
        cpu.sregs.sysenter_eip = 0x7654_3210;
        cpu.sregs.cr3 = 0x1000;
        cpu.sregs.dr7 = 0x555;
        cpu.tsc_adjust = 0x0123_4567_89ab_cdef;
        cpu.tsc_aux = 0x5678;
        cpu.insn_count = 83;
        cpu.halted = true;
        cpu.interrupt_inhibit = true;
        #[cfg(all(
            feature = "smir-jit",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            cpu.jit_callout_exit = Some(VcpuExit::Hlt);
            cpu.jit_active_source_range = Some((0x8000, 0x8100));
            cpu.jit_active_region_stale = true;
        }
        let before = cpu.regs.clone();
        let before_fpu = bincode::serialize(&cpu.get_emulator_state().unwrap().fpu).unwrap();
        cpu.deliver_init().unwrap();
        assert_eq!(cpu.regs.rax, 0);
        assert_eq!(cpu.regs.r15, 0);
        assert_eq!(cpu.regs.r31, 0);
        assert_eq!(cpu.regs.rdx, 0x6f1); // selected guest CPUID signature
        assert_eq!(cpu.regs.rip, 0xfff0);
        assert_eq!(cpu.regs.rflags, 2);
        assert_eq!(cpu.sregs.cr0, 0x6000_0010);
        assert_eq!((cpu.sregs.cr2, cpu.sregs.cr3, cpu.sregs.cr4), (0, 0, 0));
        assert_eq!(
            (cpu.sregs.cs.selector, cpu.sregs.cs.base),
            (0xf000, 0xffff_0000)
        );
        assert_eq!((cpu.sregs.gdt.limit, cpu.sregs.idt.limit), (0xffff, 0xffff));
        assert_eq!((cpu.sregs.dr6, cpu.sregs.dr7), (0xffff_0ff0, 0x400));
        assert_eq!(cpu.regs.xmm, before.xmm);
        assert_eq!(cpu.regs.ymm_high, before.ymm_high);
        assert_eq!(cpu.regs.zmm_high, before.zmm_high);
        assert_eq!(cpu.regs.zmm_ext, before.zmm_ext);
        assert_eq!(cpu.regs.k, before.k);
        assert_eq!(cpu.regs.mm, before.mm);
        assert_eq!(
            bincode::serialize(&cpu.get_emulator_state().unwrap().fpu).unwrap(),
            before_fpu
        );
        assert_eq!((cpu.mxcsr, cpu.xcr0, cpu.pkru), (0x3f80, 7, 0x1234_5678));
        assert_eq!(cpu.sregs.star, 0x1122_3344_5566_7788);
        assert_eq!(cpu.sregs.lstar, 0x1234_5678);
        assert_eq!(
            (cpu.sregs.sysenter_cs, cpu.sregs.sysenter_eip),
            (0x10, 0x7654_3210)
        );
        assert_eq!(
            (cpu.tsc_adjust, cpu.tsc_aux),
            (0x0123_4567_89ab_cdef, 0x5678)
        );
        assert_eq!(cpu.insn_count, 83);
        assert!(!cpu.halted && !cpu.interrupt_inhibit);
        #[cfg(all(
            feature = "smir-jit",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        assert!(
            cpu.jit_callout_exit.is_none()
                && cpu.jit_active_source_range.is_none()
                && !cpu.jit_active_region_stale,
            "INIT must discard the old native callout exit"
        );
    }
}
