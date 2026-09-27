//! CPU adapter contracts. Instruction bytes were produced with `llvm-mc`
//! (`-triple=aarch64 -mattr=+v8.2a`, `-triple=armv7a -mattr=+vfp3`,
//! `-triple=thumbv7a`, `-triple=riscv64 -mattr=+m,+a,+f,+d,+c,+zicsr,
//! +zicntr`, `-triple=x86_64 -x86-asm-syntax=intel`). Expected exception
//! reporting follows the Arm ARM (preferred return addresses of SVC, BRK,
//! BKPT, and synchronous aborts; PL0 access to CP15 and the FP system
//! registers; ARMv8's AArch32 without SWP and, lacking mixed-endian EL0,
//! SETEND), the RISC-V Privileged ISA (ECALL/EBREAK epc, U-mode CSR
//! privilege, MRET privilege), and Linux's EL0/U-mode register
//! configuration.

use super::aarch64::{A64Exit, A64UserCpu};
use super::arm::{A32Exit, A32UserCpu};
use super::riscv64::{RvExit, RvUserCpu};
use super::x86_64::{RESERVED_PHYS, X86Exit, X86UserCpu};
use super::{AccessFault, AccessFaultKind};
use crate::error::MemoryAccessKind;
use crate::isa::arm::common::cpu::ArmCpu;
use crate::isa::riscv::RiscVConfig;
use crate::user::mm::{AddressSpace, Mapping, PAGE_SIZE, Perms, SpaceConfig};

const CODE: u64 = 0x10000;
const DATA: u64 = 0x20000;
const RODATA: u64 = 0x30000;
const UNMAPPED: u64 = 0x40000;

fn space(code: &[u8]) -> AddressSpace {
    let s = AddressSpace::new(SpaceConfig {
        va_limit: 1 << 47,
        arena_bytes: 64 * PAGE_SIZE,
        reserved_phys: RESERVED_PHYS.to_vec(),
    })
    .unwrap();
    s.map(
        CODE,
        PAGE_SIZE,
        Mapping::anonymous(Perms::READ | Perms::EXEC),
    )
    .unwrap();
    s.map(
        DATA,
        PAGE_SIZE,
        Mapping::anonymous(Perms::READ | Perms::WRITE),
    )
    .unwrap();
    s.map(RODATA, PAGE_SIZE, Mapping::anonymous(Perms::READ))
        .unwrap();
    s.write_raw(CODE, code).unwrap();
    s
}

fn words(ws: &[u32]) -> Vec<u8> {
    ws.iter().flat_map(|w| w.to_le_bytes()).collect()
}

// ------------------------------------------------------------------ AArch64

const A64_MOV_X8_93: u32 = 0xd280_0ba8;
const A64_SVC_0: u32 = 0xd400_0001;
const A64_BRK_1000: u32 = 0xd420_7d00;
const A64_UDF_0: u32 = 0x0000_0000;
const A64_LDR_X0_X1: u32 = 0xf940_0020;
const A64_STR_X0_X1: u32 = 0xf900_0020;
const A64_MSR_TPIDR_X0: u32 = 0xd51b_d040;
const A64_MRS_X1_TPIDR: u32 = 0xd53b_d041;
const A64_MRS_X0_SCTLR_EL1: u32 = 0xd538_1000;
const A64_MRS_X0_CNTVCT: u32 = 0xd53b_e040;
const A64_LDXR_X0_X1: u32 = 0xc85f_7c20;
const A64_STXR_W2_X0_X1: u32 = 0xc802_7c20;
const A64_HVC_0: u32 = 0xd400_0002;
const A64_WFI: u32 = 0xd503_207f;
const A64_FMOV_D0_1: u32 = 0x1e6e_1000;
const A64_FADD_D1_D0_D0: u32 = 0x1e60_2801;
const A64_DC_CVAU_X1: u32 = 0xd50b_7b21;
const A64_IC_IVAU_X1: u32 = 0xd50b_7521;
const A64_DSB_ISH: u32 = 0xd503_3b9f;
const A64_ISB: u32 = 0xd503_3fdf;
const A64_MRS_X0_MIDR: u32 = 0xd538_0000;
const A64_HLT_0: u32 = 0xd440_0000;

fn a64(code: &[u32]) -> A64UserCpu {
    let s = space(&words(code));
    let mut cpu = A64UserCpu::new(&s);
    cpu.core_mut().set_pc(CODE);
    cpu.set_sp(DATA + 0x800);
    cpu
}

#[test]
fn a64_starts_at_el0_with_sp_el0() {
    let cpu = a64(&[A64_SVC_0]);
    assert_eq!(cpu.core().current_el(), 0);
    assert_eq!(cpu.sp(), DATA + 0x800);
}

#[test]
fn a64_svc_reports_immediate_with_pc_past_it() {
    let mut cpu = a64(&[A64_MOV_X8_93, A64_SVC_0]);
    assert_eq!(
        cpu.run(100),
        A64Exit::Svc {
            imm: 0,
            pc: CODE + 4
        }
    );
    assert_eq!(
        cpu.pc(),
        CODE + 8,
        "SVC's preferred return address is the next instruction"
    );
    assert_eq!(cpu.core().get_x(8), 93);
}

#[test]
fn a64_brk_and_undefined_leave_pc_at_the_instruction() {
    let mut cpu = a64(&[A64_BRK_1000]);
    assert_eq!(
        cpu.run(10),
        A64Exit::Brk {
            imm: 1000,
            pc: CODE
        }
    );
    assert_eq!(cpu.pc(), CODE);

    for insn in [A64_UDF_0, A64_HVC_0, A64_HLT_0, A64_MRS_X0_SCTLR_EL1] {
        let mut cpu = a64(&[insn]);
        match cpu.run(10) {
            A64Exit::Undefined { pc, .. } => assert_eq!(pc, CODE, "{insn:#010x}"),
            other => panic!("{insn:#010x}: expected UNDEFINED, got {other:?}"),
        }
        assert_eq!(cpu.pc(), CODE, "{insn:#010x}");
    }
}

#[test]
fn a64_memory_faults_are_precise_and_classified() {
    let cases = [
        (
            A64_LDR_X0_X1,
            UNMAPPED + 8,
            MemoryAccessKind::Read,
            AccessFaultKind::Unmapped,
        ),
        (
            A64_STR_X0_X1,
            RODATA + 8,
            MemoryAccessKind::Write,
            AccessFaultKind::Permission,
        ),
    ];
    for (insn, addr, access, kind) in cases {
        let mut cpu = a64(&[insn]);
        cpu.core_mut().set_x(1, addr);
        assert_eq!(
            cpu.run(10),
            A64Exit::Fault(AccessFault {
                addr,
                access,
                kind,
                pc: CODE
            })
        );
        assert_eq!(cpu.pc(), CODE);
    }
    // Instruction fetch requires execute permission.
    let mut cpu = a64(&[A64_SVC_0]);
    cpu.core_mut().set_pc(DATA);
    assert_eq!(
        cpu.run(10),
        A64Exit::Fault(AccessFault {
            addr: DATA,
            access: MemoryAccessKind::Fetch,
            kind: AccessFaultKind::Permission,
            pc: DATA
        })
    );
}

#[test]
fn a64_el0_thread_pointer_and_id_registers_are_accessible() {
    let mut cpu = a64(&[
        A64_MSR_TPIDR_X0,
        A64_MRS_X1_TPIDR,
        A64_MRS_X0_MIDR,
        A64_SVC_0,
    ]);
    cpu.core_mut().set_x(0, 0x1234_5678_9abc);
    assert!(matches!(cpu.run(10), A64Exit::Svc { .. }));
    assert_eq!(cpu.core().get_x(1), 0x1234_5678_9abc);
    assert_eq!(cpu.core().tpidr_el0(), 0x1234_5678_9abc);
    assert_ne!(
        cpu.core().get_x(0),
        0,
        "MIDR_EL1 is readable at EL0 (HWCAP_CPUID)"
    );
}

#[test]
fn a64_virtual_counter_follows_host_time() {
    let mut cpu = a64(&[A64_MRS_X0_CNTVCT, A64_SVC_0]);
    assert!(matches!(cpu.run(10), A64Exit::Svc { .. }));
    let first = cpu.core().get_x(0);
    std::thread::sleep(std::time::Duration::from_millis(2));
    cpu.core_mut().set_pc(CODE);
    assert!(matches!(cpu.run(10), A64Exit::Svc { .. }));
    let second = cpu.core().get_x(0);
    // 2 ms at 62.5 MHz is 125000 ticks; allow scheduling slack above.
    assert!(second - first >= 125_000, "{first} -> {second}");
}

#[test]
fn a64_exclusive_monitor_is_cleared_between_runs() {
    // ldxr x0,[x1]; stxr w2,x0,[x1]; svc -- in one run the store succeeds.
    let mut cpu = a64(&[A64_LDXR_X0_X1, A64_STXR_W2_X0_X1, A64_SVC_0]);
    cpu.core_mut().set_x(1, DATA);
    assert!(matches!(cpu.run(10), A64Exit::Svc { .. }));
    assert_eq!(
        cpu.core().get_x(2),
        0,
        "STXR succeeds with the monitor held"
    );
    // Split across a run boundary (a context switch), the store fails.
    let mut cpu = a64(&[A64_LDXR_X0_X1, A64_STXR_W2_X0_X1, A64_SVC_0]);
    cpu.core_mut().set_x(1, DATA);
    assert_eq!(cpu.run(1), A64Exit::Yield);
    assert!(matches!(cpu.run(10), A64Exit::Svc { .. }));
    assert_eq!(cpu.core().get_x(2), 1, "STXR fails after exception return");
}

#[test]
fn a64_fp_cache_maintenance_and_wfi_run_at_el0() {
    let mut cpu = a64(&[
        A64_FMOV_D0_1,
        A64_FADD_D1_D0_D0,
        A64_DC_CVAU_X1,
        A64_IC_IVAU_X1,
        A64_DSB_ISH,
        A64_ISB,
        A64_WFI,
        A64_SVC_0,
    ]);
    cpu.core_mut().set_x(1, CODE);
    assert_eq!(cpu.run(100), A64Exit::Yield, "WFI yields the slice");
    assert!(matches!(cpu.run(100), A64Exit::Svc { .. }));
    assert_eq!(
        cpu.core().get_simd(1) as u64,
        2.0f64.to_bits(),
        "FP/SIMD is enabled at EL0"
    );
}

#[test]
fn a64_budget_bounds_a_run() {
    // b . (0x14000000) spins forever.
    let mut cpu = a64(&[0x1400_0000]);
    assert_eq!(cpu.run(1000), A64Exit::Yield);
    assert_eq!(cpu.pc(), CODE);
}

#[test]
fn a64_clone_thread_copies_register_state() {
    let mut cpu = a64(&[A64_FMOV_D0_1, A64_SVC_0]);
    cpu.core_mut().set_x(19, 0xfeed);
    cpu.core_mut().set_tpidr_el0(0x7000);
    assert!(matches!(cpu.run(10), A64Exit::Svc { .. }));
    let child = cpu.clone_thread();
    assert_eq!(child.core().get_x(19), 0xfeed);
    assert_eq!(child.pc(), cpu.pc());
    assert_eq!(child.sp(), cpu.sp());
    assert_eq!(child.core().tpidr_el0(), 0x7000);
    assert_eq!(child.core().get_simd(0), cpu.core().get_simd(0));
    assert_eq!(child.core().current_el(), 0);
    assert!(child.space().same_space(cpu.space()));
}

#[test]
fn a64_el0_spsr_records_and_restores_pstate() {
    // cmp x0, x0 sets Z and C; SPSR[31:28] = NZCV, M[4:0] = EL0t (Arm ARM
    // D1.2 "Saved Program Status Registers").
    let mut cpu = a64(&[0xeb00_001f, A64_SVC_0]);
    assert!(matches!(cpu.run(100), A64Exit::Svc { .. }));
    assert_eq!(cpu.core().el0_spsr(), 0x6000_0000);
    // N and V, BTYPE = 0b10, SSBS: loaded as an ERET to EL0t would.
    let spsr = 0x9000_0000 | (0b10 << 10) | (1 << 12);
    assert!(cpu.core_mut().set_el0_spsr(spsr));
    assert_eq!(cpu.core().nzcv_bits(), 0b1001);
    assert_eq!(cpu.core().el0_spsr(), spsr);
    // EL1h and AArch32 images are not EL0t returns and change nothing.
    assert!(!cpu.core_mut().set_el0_spsr(0x3c5));
    assert!(!cpu.core_mut().set_el0_spsr(0x10));
    assert_eq!(cpu.core().el0_spsr(), spsr);
    assert_eq!(cpu.core().current_el(), 0);
}

// ---------------------------------------------------------------- AArch32

const A32_MOV_R7_1: u32 = 0xe3a0_7001;
const A32_SVC_0: u32 = 0xef00_0000;
const A32_BKPT_1234: u32 = 0xe121_2374;
const A32_UDF_0: u32 = 0xe7f0_00f0;
const A32_SWP_R2_R2_R1: u32 = 0xe101_2092;
const A32_SETEND_BE: u32 = 0xf101_0200;
const A32_LDR_R0_R1: u32 = 0xe591_0000;
const A32_STR_R0_R1: u32 = 0xe581_0000;
const A32_MCR_TPIDRURW_R0: u32 = 0xee0d_0f50;
const A32_MRC_R1_TPIDRURW: u32 = 0xee1d_1f50;
const A32_MRC_R2_TPIDRURO: u32 = 0xee1d_2f70;
const A32_MCR_TPIDRURO_R0: u32 = 0xee0d_0f70;
const A32_MCR_CP15DMB_R0: u32 = 0xee07_0fba;
const A32_VMRS_R0_FPSID: u32 = 0xeef0_0a10;
const A32_VMRS_R1_FPSCR: u32 = 0xeef1_1a10;
const A32_LDREX_R0_R1: u32 = 0xe191_0f9f;
const A32_STREX_R2_R0_R1: u32 = 0xe181_2f90;
const A32_ADR_R0_PLUS_1: u32 = 0xe28f_0001;
const A32_BX_R0: u32 = 0xe12f_ff10;
const A32_WFI: u32 = 0xe320_f003;
const A32_B_SELF: u32 = 0xeaff_fffe;

fn a32(code: &[u8]) -> A32UserCpu {
    let s = space(code);
    let mut cpu = A32UserCpu::new(&s);
    cpu.set_pc(CODE);
    cpu.set_sp(DATA + 0x800);
    cpu
}

fn halves(hs: &[u16]) -> Vec<u8> {
    hs.iter().flat_map(|h| h.to_le_bytes()).collect()
}

fn a32_undefined(exit: A32Exit) -> (u64, u32, bool) {
    match exit {
        A32Exit::Undefined {
            pc, insn, thumb, ..
        } => (pc, insn, thumb),
        other => panic!("expected an undefined instruction, got {other:?}"),
    }
}

#[test]
fn a32_starts_in_user_mode_with_fp_enabled() {
    let cpu = a32(&words(&[A32_SVC_0]));
    let core = cpu.core();
    assert_eq!(core.cpsr.to_u32(), 0x10, "User mode, A32, no masks");
    assert!(!core.is_privileged());
    assert_eq!(core.vfp.fpexc, 1 << 30);
    assert!(!core.cp15.sctlr.cp15ben());
    assert_eq!(core.regs[..13], [0; 13]);
}

#[test]
fn a32_svc_reports_with_pc_past_it() {
    let mut cpu = a32(&words(&[A32_MOV_R7_1, A32_SVC_0]));
    assert_eq!(
        cpu.run(10),
        A32Exit::Svc {
            imm: 0,
            pc: CODE + 4
        }
    );
    assert_eq!((cpu.pc(), cpu.core().regs[7]), (CODE + 8, 1));
}

#[test]
fn a32_bkpt_and_undefined_leave_pc_at_the_instruction() {
    let mut cpu = a32(&words(&[A32_BKPT_1234]));
    assert_eq!(
        cpu.run(10),
        A32Exit::Bkpt {
            imm: 0x1234,
            pc: CODE
        }
    );
    assert_eq!(cpu.pc(), CODE);
    // UDF, and SWP and SETEND, which ARMv8 AArch32 EL0 lacks.
    for insn in [A32_UDF_0, A32_SWP_R2_R2_R1, A32_SETEND_BE] {
        let mut cpu = a32(&words(&[insn]));
        cpu.core_mut().regs[1] = DATA as u32;
        assert_eq!(a32_undefined(cpu.run(10)), (CODE, insn, false));
        assert_eq!(cpu.pc(), CODE);
    }
    // T16 SETEND and BKPT.
    let mut cpu = a32(&halves(&[0xb658]));
    cpu.core_mut().cpsr.t = true;
    assert_eq!(a32_undefined(cpu.run(10)), (CODE, 0xb658, true));
    let mut cpu = a32(&halves(&[0xbe12]));
    cpu.core_mut().cpsr.t = true;
    assert_eq!(
        cpu.run(10),
        A32Exit::Bkpt {
            imm: 0x12,
            pc: CODE
        }
    );
}

#[test]
fn a32_memory_faults_are_precise_and_classified() {
    let fault = |addr, access, kind, pc| {
        A32Exit::Fault(AccessFault {
            addr,
            access,
            kind,
            pc,
        })
    };
    let mut cpu = a32(&words(&[A32_LDR_R0_R1]));
    cpu.core_mut().regs[1] = UNMAPPED as u32;
    let unmapped = AccessFaultKind::Unmapped;
    assert_eq!(
        cpu.run(10),
        fault(UNMAPPED, MemoryAccessKind::Read, unmapped, CODE)
    );
    assert_eq!(cpu.pc(), CODE);
    let mut cpu = a32(&words(&[A32_STR_R0_R1]));
    cpu.core_mut().regs[1] = RODATA as u32 + 2;
    let denied = AccessFaultKind::Permission;
    assert_eq!(
        cpu.run(10),
        fault(RODATA + 2, MemoryAccessKind::Write, denied, CODE)
    );
    // Fetching from a page without execute permission.
    let mut cpu = a32(&words(&[A32_SVC_0]));
    cpu.set_pc(DATA);
    assert_eq!(
        cpu.run(10),
        fault(DATA, MemoryAccessKind::Fetch, denied, DATA)
    );
    // The second halfword of a T32 instruction on the next, unmapped page.
    let mut code = vec![0; PAGE_SIZE as usize - 2];
    code.extend(halves(&[0xf8d1]));
    let mut cpu = a32(&code);
    cpu.core_mut().cpsr.t = true;
    let last = CODE + PAGE_SIZE - 2;
    cpu.set_pc(last);
    assert_eq!(
        cpu.run(10),
        fault(CODE + PAGE_SIZE, MemoryAccessKind::Fetch, unmapped, last)
    );
    // A32 execution at a PC that is not word-aligned.
    let mut cpu = a32(&words(&[A32_SVC_0, A32_SVC_0]));
    cpu.set_pc(CODE + 2);
    let align = AccessFaultKind::Alignment;
    assert_eq!(
        cpu.run(10),
        fault(CODE + 2, MemoryAccessKind::Fetch, align, CODE + 2)
    );
}

#[test]
fn a32_pl0_reaches_the_thread_ids_and_fpscr_only() {
    let mut cpu = a32(&words(&[
        A32_MCR_TPIDRURW_R0,
        A32_MRC_R1_TPIDRURW,
        A32_MRC_R2_TPIDRURO,
        A32_VMRS_R1_FPSCR,
        A32_SVC_0,
    ]));
    cpu.core_mut().regs[0] = 0x1234_5678;
    cpu.core_mut().cp15.tpidruro = 0xbeef_0000;
    cpu.core_mut().vfp.fpscr = crate::isa::arm::vfp::Fpscr::from_bits(0x0300_0000);
    assert!(matches!(cpu.run(10), A32Exit::Svc { .. }));
    assert_eq!(cpu.core().regs[1..3], [0x0300_0000, 0xbeef_0000]);
    assert_eq!(cpu.core().cp15.tpidrurw, 0x1234_5678);
    // TPIDRURO is read-only, the CP15 barriers are disabled, and FPSID is
    // PL1's.
    for insn in [A32_MCR_TPIDRURO_R0, A32_MCR_CP15DMB_R0, A32_VMRS_R0_FPSID] {
        let mut cpu = a32(&words(&[insn]));
        assert_eq!(a32_undefined(cpu.run(10)), (CODE, insn, false));
        assert_eq!(cpu.core().cp15.tpidruro, 0);
    }
}

#[test]
fn a32_exclusive_monitor_is_cleared_between_runs() {
    let code = words(&[A32_LDREX_R0_R1, A32_STREX_R2_R0_R1, A32_SVC_0]);
    let mut cpu = a32(&code);
    cpu.core_mut().regs[1] = DATA as u32;
    assert!(matches!(cpu.run(10), A32Exit::Svc { .. }));
    assert_eq!(cpu.core().regs[2], 0, "STREX succeeds within a run");
    let mut cpu = a32(&code);
    cpu.core_mut().regs[1] = DATA as u32;
    assert_eq!(cpu.run(1), A32Exit::Yield);
    assert!(matches!(cpu.run(10), A32Exit::Svc { .. }));
    assert_eq!(cpu.core().regs[2], 1, "STREX fails after the thread left");
}

#[test]
fn a32_unaligned_exclusives_are_alignment_faults() {
    // ldrex r0, [r1] and strex r2, r0, [r1] at DATA + 2.
    for (insn, access) in [
        (A32_LDREX_R0_R1, MemoryAccessKind::Read),
        (A32_STREX_R2_R0_R1, MemoryAccessKind::Write),
    ] {
        let mut cpu = a32(&words(&[insn]));
        cpu.core_mut().regs[1] = DATA as u32 + 2;
        assert_eq!(
            cpu.run(10),
            A32Exit::Fault(AccessFault {
                addr: DATA + 2,
                access,
                kind: AccessFaultKind::Alignment,
                pc: CODE,
            })
        );
        assert_eq!(cpu.pc(), CODE);
    }
}

#[test]
fn a32_interworks_with_thumb_and_it_blocks() {
    // adr r0, . + 9 ; bx r0 ; then T32 at CODE + 8: movs r1, #5 ;
    // cmp r1, #5 ; ite eq ; moveq r2, #1 ; movne r2, #2 ; svc #0x12.
    let mut code = words(&[A32_ADR_R0_PLUS_1, A32_BX_R0]);
    code.extend(halves(&[0x2105, 0x2905, 0xbf0c, 0x2201, 0x2202, 0xdf12]));
    let mut cpu = a32(&code);
    assert_eq!(
        cpu.run(20),
        A32Exit::Svc {
            imm: 0x12,
            pc: CODE + 18
        }
    );
    assert!(cpu.thumb());
    assert_eq!((cpu.pc(), cpu.core().regs[2]), (CODE + 20, 1));
    assert!(!cpu.core().cpsr.in_it_block());
}

#[test]
fn a32_wfi_completes_and_the_budget_bounds_a_run() {
    let mut cpu = a32(&words(&[A32_WFI, A32_B_SELF]));
    assert_eq!(cpu.run(10), A32Exit::Yield);
    assert_eq!(cpu.pc(), CODE + 4);
    assert_eq!(cpu.run(1000), A32Exit::Yield);
    assert_eq!(cpu.pc(), CODE + 4);
}

#[test]
fn a32_clone_thread_copies_register_state() {
    let mut code = halves(&[0xdf00]);
    code.extend([0; 2]);
    let mut cpu = a32(&code);
    cpu.core_mut().cpsr.t = true;
    cpu.core_mut().regs[5] = 0xfeed;
    cpu.core_mut().cpsr.ge = 0b0101;
    cpu.core_mut().vfp.dregs[31] = 0x4000_0000_0000_0000;
    cpu.core_mut().cp15.tpidrurw = 0x7000;
    cpu.core_mut().cp15.tpidruro = 0x8000;
    assert!(matches!(cpu.run(10), A32Exit::Svc { .. }));
    let child = cpu.clone_thread();
    let (c, p) = (child.core(), cpu.core());
    assert_eq!(c.regs, p.regs);
    assert_eq!(c.cpsr.to_u32(), p.cpsr.to_u32());
    assert!(child.thumb());
    assert_eq!(c.vfp.dregs[31], 0x4000_0000_0000_0000);
    assert_eq!((c.cp15.tpidrurw, c.cp15.tpidruro), (0x7000, 0x8000));
    assert!(!c.is_privileged());
    assert!(child.space().same_space(cpu.space()));
}

// ------------------------------------------------------------------- RV64

fn rv(code: &[u8]) -> RvUserCpu {
    let s = space(code);
    let mut cpu = RvUserCpu::new(&s, RiscVConfig::rv64gc());
    cpu.core_mut().set_pc(CODE);
    cpu.core_mut().set_x(2, DATA + 0x800);
    cpu
}

const RV_LI_A7_93: [u8; 4] = [0x93, 0x08, 0xd0, 0x05];
const RV_ECALL: [u8; 4] = [0x73, 0x00, 0x00, 0x00];
const RV_EBREAK: [u8; 4] = [0x73, 0x00, 0x10, 0x00];
const RV_C_EBREAK: [u8; 2] = [0x02, 0x90];
const RV_UNIMP: [u8; 4] = [0x73, 0x10, 0x00, 0xc0];
const RV_LD_A0_A1: [u8; 4] = [0x03, 0xb5, 0x05, 0x00];
const RV_SD_A0_A1: [u8; 4] = [0x23, 0xb0, 0xa5, 0x00];
const RV_MRET: [u8; 4] = [0x73, 0x00, 0x20, 0x30];
const RV_RDTIME_A0: [u8; 4] = [0x73, 0x25, 0x10, 0xc0];
const RV_RDCYCLE_A0: [u8; 4] = [0x73, 0x25, 0x00, 0xc0];
const RV_CSRR_A0_MSTATUS: [u8; 4] = [0x73, 0x25, 0x00, 0x30];
const RV_LR_D: [u8; 4] = [0x2f, 0xb5, 0x05, 0x10];
const RV_SC_D: [u8; 4] = [0x2f, 0xb6, 0xa5, 0x18];
const RV_FADD_D: [u8; 4] = [0x53, 0xf5, 0xc5, 0x02];
const RV_J_SELF: [u8; 4] = [0x6f, 0x00, 0x00, 0x00];

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

#[test]
fn rv_ecall_reports_pc_of_the_ecall() {
    let mut cpu = rv(&cat(&[&RV_LI_A7_93, &RV_ECALL]));
    assert_eq!(cpu.run(100), RvExit::Ecall { pc: CODE + 4 });
    assert_eq!(cpu.pc(), CODE + 4);
    assert_eq!(cpu.core().x(17), 93);
}

#[test]
fn rv_ebreak_forms_leave_pc_at_the_instruction() {
    let mut cpu = rv(&RV_EBREAK);
    assert_eq!(cpu.run(10), RvExit::Ebreak { pc: CODE });
    let mut cpu = rv(&RV_C_EBREAK);
    assert_eq!(cpu.run(10), RvExit::Ebreak { pc: CODE });
}

#[test]
fn rv_illegal_instructions_restore_user_mode() {
    use crate::isa::riscv::cpu::Priv;
    for code in [&RV_UNIMP, &RV_MRET, &RV_RDCYCLE_A0, &RV_CSRR_A0_MSTATUS] {
        let mut cpu = rv(code);
        match cpu.run(10) {
            RvExit::Illegal { pc, .. } => assert_eq!(pc, CODE, "{code:02x?}"),
            other => panic!("{code:02x?}: expected illegal instruction, got {other:?}"),
        }
        assert_eq!(cpu.pc(), CODE);
        assert_eq!(cpu.core().privilege(), Priv::User, "{code:02x?}");
    }
}

#[test]
fn rv_time_is_readable_and_advances() {
    let mut cpu = rv(&cat(&[&RV_RDTIME_A0, &RV_ECALL]));
    assert!(matches!(cpu.run(10), RvExit::Ecall { .. }));
    let first = cpu.core().x(10);
    std::thread::sleep(std::time::Duration::from_millis(2));
    cpu.core_mut().set_pc(CODE);
    assert!(matches!(cpu.run(10), RvExit::Ecall { .. }));
    // 2 ms at 10 MHz is 20000 ticks.
    assert!(cpu.core().x(10) - first >= 20_000);
}

#[test]
fn rv_memory_faults_are_precise_and_classified() {
    let cases = [
        (
            RV_LD_A0_A1,
            UNMAPPED + 8,
            MemoryAccessKind::Read,
            AccessFaultKind::Unmapped,
        ),
        (
            RV_SD_A0_A1,
            RODATA + 8,
            MemoryAccessKind::Write,
            AccessFaultKind::Permission,
        ),
    ];
    for (insn, addr, access, kind) in cases {
        let mut cpu = rv(&insn);
        cpu.core_mut().set_x(11, addr);
        assert_eq!(
            cpu.run(10),
            RvExit::Fault(AccessFault {
                addr,
                access,
                kind,
                pc: CODE
            })
        );
        assert_eq!(cpu.pc(), CODE);
    }
    // A load straddling into an unmapped page reports the first bad byte.
    let mut cpu = rv(&RV_LD_A0_A1);
    cpu.core_mut().set_x(11, DATA + PAGE_SIZE - 4);
    match cpu.run(10) {
        RvExit::Fault(f) => assert_eq!(f.addr, DATA + PAGE_SIZE),
        other => panic!("expected fault, got {other:?}"),
    }
    // Instruction fetch requires execute permission.
    let mut cpu = rv(&RV_ECALL);
    cpu.core_mut().set_pc(DATA);
    assert_eq!(
        cpu.run(10),
        RvExit::Fault(AccessFault {
            addr: DATA,
            access: MemoryAccessKind::Fetch,
            kind: AccessFaultKind::Permission,
            pc: DATA
        })
    );
}

#[test]
fn rv_reservation_is_cleared_between_runs() {
    let prog = cat(&[&RV_LR_D, &RV_SC_D, &RV_ECALL]);
    let mut cpu = rv(&prog);
    cpu.core_mut().set_x(11, DATA);
    assert!(matches!(cpu.run(10), RvExit::Ecall { .. }));
    assert_eq!(cpu.core().x(12), 0, "SC succeeds with the reservation held");
    let mut cpu = rv(&prog);
    cpu.core_mut().set_x(11, DATA);
    assert_eq!(cpu.run(1), RvExit::Yield);
    assert!(matches!(cpu.run(10), RvExit::Ecall { .. }));
    assert_eq!(cpu.core().x(12), 1, "SC fails after a trap return");
}

#[test]
fn rv_fp_budget_and_clone() {
    let mut cpu = rv(&cat(&[&RV_FADD_D, &RV_J_SELF]));
    cpu.core_mut().set_f(11, 1.5f64.to_bits());
    cpu.core_mut().set_f(12, 2.25f64.to_bits());
    assert_eq!(cpu.run(1000), RvExit::Yield);
    assert_eq!(cpu.pc(), CODE + 4);
    assert_eq!(cpu.core().f(10), 3.75f64.to_bits());
    let child = cpu.clone_thread();
    assert_eq!(child.core().f(10), 3.75f64.to_bits());
    assert_eq!(child.pc(), CODE + 4);
    assert_eq!(child.core().x(2), DATA + 0x800);
}

#[cfg(all(
    feature = "smir-jit",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn rv_jit_and_interpreter_agree_on_exits() {
    let prog = cat(&[&RV_LI_A7_93, &RV_LD_A0_A1, &RV_ECALL]);
    let mut interp = rv(&prog);
    let mut jit = rv(&prog);
    jit.set_jit(true);
    for cpu in [&mut interp, &mut jit] {
        cpu.core_mut().set_x(11, UNMAPPED);
    }
    assert_eq!(interp.run(100), jit.run(100));
    assert_eq!(interp.core().x(17), jit.core().x(17));
}

/// A forked process drops the native code it inherited (see
/// `GuestCpu::discard_native_code`) and runs on, compiling again.
#[cfg(all(
    feature = "smir-jit",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn rv_discarding_native_code_empties_the_jit_cache() {
    let prog = cat(&[&RV_LI_A7_93, &RV_ECALL]);
    let mut cpu = rv(&prog);
    cpu.set_jit(true);
    let first = cpu.run(100);
    assert!(cpu.core().jit_stats().cache_entries > 0);
    cpu.discard_native_code();
    assert_eq!(cpu.core().jit_stats().cache_entries, 0);
    cpu.core_mut().set_pc(CODE);
    assert_eq!(cpu.run(100), first);
    assert!(cpu.core().jit_stats().cache_entries > 0, "compiled again");
}

// ------------------------------------------------------------------- x86-64

fn x86(code: &[u8]) -> X86UserCpu {
    let s = space(code);
    let mut cpu = X86UserCpu::new(&s);
    cpu.vcpu_mut().user_regs_mut().rip = CODE;
    cpu.vcpu_mut().user_regs_mut().rsp = DATA + 0x800;
    cpu
}

#[test]
fn x86_adapter_reports_syscalls_events_and_faults() {
    use crate::isa::x86_64::X86SyscallInsn;
    // mov eax, 60 ; syscall
    let mut cpu = x86(&[0xB8, 0x3C, 0, 0, 0, 0x0F, 0x05]);
    match cpu.run() {
        X86Exit::Syscall { insn, insn_rip } => {
            assert_eq!((insn, insn_rip), (X86SyscallInsn::Syscall, CODE + 5))
        }
        other => panic!("expected syscall, got {other:?}"),
    }
    // int3
    let mut cpu = x86(&[0xCC]);
    match cpu.run() {
        X86Exit::Event(e) => assert_eq!((e.vector, e.return_rip), (3, CODE + 1)),
        other => panic!("expected #BP, got {other:?}"),
    }
    // mov rax, [rbx] with RBX unmapped.
    let mut cpu = x86(&[0x48, 0x8B, 0x03]);
    cpu.vcpu_mut().user_regs_mut().rbx = UNMAPPED + 16;
    match cpu.run() {
        X86Exit::Fault(f) => assert_eq!(
            f,
            AccessFault {
                addr: UNMAPPED + 16,
                access: MemoryAccessKind::Read,
                kind: AccessFaultKind::Unmapped,
                pc: CODE
            }
        ),
        other => panic!("expected fault, got {other:?}"),
    }
}

#[test]
fn x86_adapter_observes_host_code_writes() {
    // mov eax, 1 ; syscall -- then the host patches the immediate.
    let mut cpu = x86(&[0xB8, 0x01, 0, 0, 0, 0x0F, 0x05]);
    assert!(matches!(cpu.run(), X86Exit::Syscall { .. }));
    assert_eq!(cpu.vcpu().user_regs().rax, 1);
    cpu.space().write_raw(CODE + 1, &[0x02]).unwrap();
    cpu.vcpu_mut().user_regs_mut().rip = CODE;
    assert!(matches!(cpu.run(), X86Exit::Syscall { .. }));
    assert_eq!(cpu.vcpu().user_regs().rax, 2);
}

#[test]
fn x86_clone_thread_copies_register_state() {
    let mut cpu = x86(&[0x0F, 0x05]);
    cpu.vcpu_mut().user_regs_mut().r12 = 0xabc;
    cpu.vcpu_mut().user_regs_mut().xmm[3] = [1, 2];
    cpu.vcpu_mut().set_fs_base(0x7000_0000);
    cpu.vcpu_mut().set_mxcsr(0x9FC0).unwrap();
    let child = cpu.clone_thread();
    assert_eq!(child.vcpu().user_regs().r12, 0xabc);
    assert_eq!(child.vcpu().user_regs().xmm[3], [1, 2]);
    assert_eq!(child.vcpu().fs_base(), 0x7000_0000);
    assert_eq!(child.vcpu().mxcsr(), 0x9FC0);
    assert_eq!(child.pc(), CODE);
    assert!(child.space().same_space(cpu.space()));
}
