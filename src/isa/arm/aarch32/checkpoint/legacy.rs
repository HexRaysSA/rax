//! Frozen pre-FHM CP15/CPU positional layout for RAXA3201/RAXS3C01.
//! Psr and VfpState keep their unchanged v1 layouts; their compatibility
//! fixtures must remain readable if those nested types change in future.
use crate::isa::arm::aarch32::cp15::{Cp15State, Cpacr, Sctlr};
use crate::isa::arm::aarch32::cpu::{Armv7Cpu, Psr};
use crate::isa::arm::aarch32::vfp::VfpState;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct LegacyCp15State {
    // =========================================================================
    // ID Registers (read-only) - CRn=0
    // =========================================================================
    /// Main ID Register (MIDR).
    pub(crate) midr: u32,
    /// Cache Type Register (CTR).
    pub(crate) ctr: u32,
    /// TCM Type Register.
    pub(crate) tcmtr: u32,
    /// TLB Type Register.
    pub(crate) tlbtr: u32,
    /// Multiprocessor Affinity Register (MPIDR).
    pub(crate) mpidr: u32,
    /// Processor Feature Register 0 (ID_PFR0).
    pub(crate) id_pfr0: u32,
    /// Processor Feature Register 1 (ID_PFR1).
    pub(crate) id_pfr1: u32,
    /// Debug Feature Register 0 (ID_DFR0).
    pub(crate) id_dfr0: u32,
    /// Auxiliary Feature Register 0 (ID_AFR0).
    pub(crate) id_afr0: u32,
    /// Memory Model Feature Register 0-3.
    pub(crate) id_mmfr: [u32; 4],
    /// Instruction Set Attribute Register 0-5.
    pub(crate) id_isar: [u32; 6],

    // =========================================================================
    // System Control Registers - CRn=1
    // =========================================================================
    /// System Control Register (SCTLR).
    pub(crate) sctlr: Sctlr,
    /// Auxiliary Control Register (ACTLR).
    pub(crate) actlr: u32,
    /// Coprocessor Access Control Register (CPACR).
    pub(crate) cpacr: Cpacr,
    /// Secure Configuration Register (SCR) - if Security Extensions.
    pub(crate) scr: u32,
    /// Secure Debug Enable Register (SDER).
    pub(crate) sder: u32,
    /// Non-Secure Access Control Register (NSACR).
    pub(crate) nsacr: u32,
    /// Hyp access controls and represented exception-entry state.
    pub(crate) hcptr: u32,
    pub(crate) hcr: u32,
    pub(crate) hsctlr: Sctlr,
    pub(crate) hvbar: u32,
    pub(crate) hsr: u32,
    pub(crate) elr_hyp: u32,

    // =========================================================================
    // Translation Table Registers - CRn=2
    // =========================================================================
    /// Translation Table Base Register 0 (TTBR0).
    pub(crate) ttbr0: u64,
    /// Translation Table Base Register 1 (TTBR1).
    pub(crate) ttbr1: u64,
    /// Translation Table Base Control Register (TTBCR).
    pub(crate) ttbcr: u32,

    // =========================================================================
    // Domain Access Control - CRn=3
    // =========================================================================
    /// Domain Access Control Register (DACR).
    pub(crate) dacr: u32,

    // =========================================================================
    // Fault Status Registers - CRn=5
    // =========================================================================
    /// Data Fault Status Register (DFSR).
    pub(crate) dfsr: u32,
    /// Instruction Fault Status Register (IFSR).
    pub(crate) ifsr: u32,
    /// Auxiliary Data Fault Status Register (ADFSR).
    pub(crate) adfsr: u32,
    /// Auxiliary Instruction Fault Status Register (AIFSR).
    pub(crate) aifsr: u32,

    // =========================================================================
    // Fault Address Registers - CRn=6
    // =========================================================================
    /// Data Fault Address Register (DFAR).
    pub(crate) dfar: u32,
    /// Instruction Fault Address Register (IFAR).
    pub(crate) ifar: u32,

    // =========================================================================
    // Cache Operations - CRn=7
    // =========================================================================
    // Most are write-only operations, no state needed

    // =========================================================================
    // TLB Operations - CRn=8
    // =========================================================================
    // All are write-only operations, no state needed

    // =========================================================================
    // Performance Monitors - CRn=9
    // =========================================================================
    /// Performance Monitor Control Register (PMCR).
    pub(crate) pmcr: u32,
    /// Count Enable Set Register (PMCNTENSET).
    pub(crate) pmcntenset: u32,
    /// Cycle Count Register (PMCCNTR).
    pub(crate) pmccntr: u32,
    /// Performance counter registers.
    pub(crate) pmevcntr: [u32; 6],
    /// Event type selection registers.
    pub(crate) pmevtyper: [u32; 6],
    /// User Enable Register (PMUSERENR).
    pub(crate) pmuserenr: u32,

    // =========================================================================
    // Memory Barrier Operations - CRn=7, various
    // =========================================================================
    // Write-only operations, no state

    // =========================================================================
    // Context ID - CRn=13
    // =========================================================================
    /// FCSE PID Register (deprecated).
    pub(crate) fcseidr: u32,
    /// Context ID Register (CONTEXTIDR).
    pub(crate) contextidr: u32,
    /// User Read/Write Thread ID Register (TPIDRURW).
    pub(crate) tpidrurw: u32,
    /// User Read-Only Thread ID Register (TPIDRURO).
    pub(crate) tpidruro: u32,
    /// PL1 Only Thread ID Register (TPIDRPRW).
    pub(crate) tpidrprw: u32,

    // =========================================================================
    // Generic Timer - CRn=14
    // =========================================================================
    /// Counter Frequency Register (CNTFRQ).
    pub(crate) cntfrq: u32,
    /// Physical Timer Value Register (CNTP_TVAL).
    pub(crate) cntp_tval: u32,
    /// Physical Timer Control Register (CNTP_CTL).
    pub(crate) cntp_ctl: u32,
    /// Virtual Timer Value Register (CNTV_TVAL).
    pub(crate) cntv_tval: u32,
    /// Virtual Timer Control Register (CNTV_CTL).
    pub(crate) cntv_ctl: u32,
    /// Timer PL1 Control Register (CNTKCTL): what PL0 may reach
    /// ([`CNTKCTL_PL0PCTEN`], [`CNTKCTL_PL0VCTEN`], ...).
    pub(crate) cntkctl: u32,
    /// The system counter's count (CNTPCT), which the platform advances.
    pub(crate) cntpct: u64,
    /// Virtual Offset Register (CNTVOFF): CNTVCT is CNTPCT less it.
    pub(crate) cntvoff: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct LegacyArmv7Cpu {
    /// Additional PSTATE fields implemented by an enclosing ARMv8 PE.
    #[serde(with = "crate::isa::arm::aarch32::checkpoint::feature_bits")]
    pub(crate) pstate_features: crate::isa::arm::common::features::ArmFeatures,
    pub(crate) nonsecure: bool,
    pub(crate) fp_access_context: Option<crate::isa::arm::aarch32::fp_controls::FpAccessContext>,
    pub(crate) instruction_size: u8,
    /// Current register values R0-R15 (R15 = PC)
    pub(crate) regs: [u32; 16],
    /// Current Program Status Register
    pub(crate) cpsr: Psr,

    // Banked registers per mode
    /// User mode R13-R14
    pub(crate) regs_usr: [u32; 2], // SP, LR
    /// FIQ mode R8-R14
    pub(crate) regs_fiq: [u32; 7], // R8-R14
    /// User/common R8-R12, saved while executing in FIQ mode (FIQ banks
    /// R8-R12 in addition to SP/LR; every other mode shares the user copies).
    pub(crate) regs_usr_high: [u32; 5],
    /// IRQ mode R13-R14
    pub(crate) regs_irq: [u32; 2],
    /// Supervisor mode R13-R14
    pub(crate) regs_svc: [u32; 2],
    /// Monitor mode R13-R14
    pub(crate) regs_mon: [u32; 2],
    /// Abort mode R13-R14
    pub(crate) regs_abt: [u32; 2],
    /// Undefined mode R13-R14
    pub(crate) regs_und: [u32; 2],

    /// Hyp mode SP; LR remains the User/System LR.
    pub(crate) sp_hyp: u32,

    // Saved Program Status Registers
    pub(crate) spsr_fiq: Psr,
    pub(crate) spsr_irq: Psr,
    pub(crate) spsr_svc: Psr,
    pub(crate) spsr_mon: Psr,
    pub(crate) spsr_abt: Psr,
    pub(crate) spsr_und: Psr,
    pub(crate) spsr_hyp: Psr,

    // Execution state
    /// Pending branch target (None if no branch)
    pub(crate) branch_to: Option<u32>,
    /// Whether CPU is halted (WFI)
    pub(crate) is_halted: bool,

    // Shifter output (set by shift operations)
    pub(crate) carry_out: bool,
    pub(crate) overflow: bool,

    /// VFP/NEON register file and FP system registers.
    pub(crate) vfp: VfpState,

    /// CP15 system-control coprocessor (SCTLR/TTBR/DACR/FSR/FAR/...): the
    /// source of truth for MCR/MRC p15 and the v6 MMU configuration.
    pub(crate) cp15: LegacyCp15State,
}

impl LegacyCp15State {
    fn into_current(self) -> Cp15State {
        Cp15State {
            midr: self.midr,
            ctr: self.ctr,
            tcmtr: self.tcmtr,
            tlbtr: self.tlbtr,
            mpidr: self.mpidr,
            id_pfr0: self.id_pfr0,
            id_pfr1: self.id_pfr1,
            id_dfr0: self.id_dfr0,
            id_afr0: self.id_afr0,
            id_mmfr: self.id_mmfr,
            id_isar: self.id_isar,
            sctlr: self.sctlr,
            actlr: self.actlr,
            cpacr: self.cpacr,
            scr: self.scr,
            sder: self.sder,
            nsacr: self.nsacr,
            hcptr: self.hcptr,
            hcr: self.hcr,
            hsctlr: self.hsctlr,
            hvbar: self.hvbar,
            hsr: self.hsr,
            elr_hyp: self.elr_hyp,
            ttbr0: self.ttbr0,
            ttbr1: self.ttbr1,
            ttbcr: self.ttbcr,
            dacr: self.dacr,
            dfsr: self.dfsr,
            ifsr: self.ifsr,
            adfsr: self.adfsr,
            aifsr: self.aifsr,
            dfar: self.dfar,
            ifar: self.ifar,
            pmcr: self.pmcr,
            pmcntenset: self.pmcntenset,
            pmccntr: self.pmccntr,
            pmevcntr: self.pmevcntr,
            pmevtyper: self.pmevtyper,
            pmuserenr: self.pmuserenr,
            fcseidr: self.fcseidr,
            contextidr: self.contextidr,
            tpidrurw: self.tpidrurw,
            tpidruro: self.tpidruro,
            tpidrprw: self.tpidrprw,
            cntfrq: self.cntfrq,
            cntp_tval: self.cntp_tval,
            cntp_ctl: self.cntp_ctl,
            cntv_tval: self.cntv_tval,
            cntv_ctl: self.cntv_ctl,
            cntkctl: self.cntkctl,
            cntpct: self.cntpct,
            cntvoff: self.cntvoff,
            id_isar6: 1 << 8, // v1 reports the old full FHM profile.
        }
    }
}

impl LegacyArmv7Cpu {
    pub(crate) fn into_current(self) -> Armv7Cpu {
        Armv7Cpu {
            pstate_features: self.pstate_features,
            nonsecure: self.nonsecure,
            fp_access_context: self.fp_access_context,
            instruction_size: self.instruction_size,
            regs: self.regs,
            cpsr: self.cpsr,
            regs_usr: self.regs_usr,
            regs_fiq: self.regs_fiq,
            regs_usr_high: self.regs_usr_high,
            regs_irq: self.regs_irq,
            regs_svc: self.regs_svc,
            regs_mon: self.regs_mon,
            regs_abt: self.regs_abt,
            regs_und: self.regs_und,
            sp_hyp: self.sp_hyp,
            spsr_fiq: self.spsr_fiq,
            spsr_irq: self.spsr_irq,
            spsr_svc: self.spsr_svc,
            spsr_mon: self.spsr_mon,
            spsr_abt: self.spsr_abt,
            spsr_und: self.spsr_und,
            spsr_hyp: self.spsr_hyp,
            branch_to: self.branch_to,
            is_halted: self.is_halted,
            carry_out: self.carry_out,
            overflow: self.overflow,
            vfp: self.vfp,
            cp15: self.cp15.into_current(),
        }
    }
}
