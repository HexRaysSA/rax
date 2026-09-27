//! The AArch32 and Cortex-M engines, and the engine choice's independence
//! from the process environment. Encodings are from LLVM 23 `llvm-mc`.
use super::*;
use crate::arch::{RAX_MODE_ARM, RAX_MODE_BIG_ENDIAN, RAX_MODE_THUMB};
use crate::engine::rax_engine_supports_stepping;
use crate::fault::{RAX_FAULT_UNMAPPED, RaxFaultInfo, rax_emu_last_fault};
use crate::run::RAX_STOP_HLT;

const ARM_R0: i32 = 0x0100;
const REG_SP: i32 = 0x0010;
const REG_PC: i32 = 0x0011;
const REG_PSTATE: i32 = 0x0012;
const CM_S0: i32 = 0x0200;
const CM_FPSCR: i32 = 0x0022;
const CM_MSP: i32 = 0x0030;
const CM_VTOR: i32 = 0x0036;
const CM_HFSR: i32 = 0x003A;
const CM_SHPR3: i32 = 0x003F;

fn open(arch: RaxArch, mode: u32) -> *mut Engine {
    let mut e = ptr::null_mut();
    assert_eq!(rax_engine_open(arch as i32, mode, &mut e), RaxStatus::Ok);
    e
}

fn last_exit(e: *mut Engine) -> ExitInfo {
    let mut x = ExitInfo::none();
    assert_eq!(rax_emu_last_exit(e, &mut x), RaxStatus::Ok);
    x
}

/// movw r0,#40000 ; subs r0,r0,#1 ; bne -8 ; wfi — 80 002 instructions,
/// past the 65 536-instruction batch at which the machine vCPU yielded.
const A32_LOOP: &[u8] = &[
    0x40, 0x0C, 0x09, 0xE3, 0x01, 0x00, 0x50, 0xE2, 0xFD, 0xFF, 0xFF, 0x1A, 0x03, 0xF0, 0x20, 0xE3,
];
/// The same loop in Thumb.
const T32_LOOP: &[u8] = &[0x49, 0xF6, 0x40, 0x40, 0x40, 0x1E, 0xFD, 0xD1, 0x30, 0xBF];

#[test]
fn arm32_long_runs_stop_at_the_guest_wait() {
    for (mode, code, wfi) in [
        (RAX_MODE_ARM, A32_LOOP, 0x100C),
        (RAX_MODE_THUMB, T32_LOOP, 0x1008),
    ] {
        let e = open(RaxArch::Arm, mode);
        assert_eq!(rax_engine_supports_stepping(e), 1);
        unsafe {
            write(e, 0x1000, code);
            assert_eq!(rax_emu_start(e, 0x1000, RAX_NO_ADDR, 0, 0), RaxStatus::Ok);
            let x = last_exit(e);
            assert_eq!(x.reason, RAX_STOP_HLT, "mode {mode:#x}");
            assert_eq!(x.value, 80_002);
            assert_eq!(rd_u64(e, ARM_R0), 0);
            assert_eq!(
                rd_u64(e, REG_PC),
                wfi + if mode == RAX_MODE_ARM { 4 } else { 2 }
            );
            // Stepping is instruction-granular: `until` inside the loop.
            assert_eq!(rax_emu_start(e, 0x1000, wfi - 4, 0, 0), RaxStatus::Ok);
            assert_eq!(last_exit(e).reason, RAX_STOP_UNTIL);
            let mut executed = 0;
            assert_eq!(rax_emu_step(e, 3, &mut executed), RaxStatus::Ok);
            assert_eq!(executed, 3);
        }
        rax_engine_close(e);
    }
}

#[test]
fn arm32_memory_faults_report_the_first_missing_byte() {
    let e = open(RaxArch::Arm, 0);
    unsafe {
        // ldr r1,[r2] with r2 past the 256 MiB default mapping.
        write(e, 0x1000, &[0x00, 0x10, 0x92, 0xE5]);
        assert_eq!(rax_reg_write_u64(e, ARM_R0 + 2, 0x1000_0000), RaxStatus::Ok);
        assert_eq!(
            rax_emu_start(e, 0x1000, RAX_NO_ADDR, 0, 1),
            RaxStatus::Fault
        );
        let mut fault = RaxFaultInfo::default();
        assert_eq!(rax_emu_last_fault(e, &mut fault), RaxStatus::Ok);
        assert_eq!(
            (fault.kind, fault.address),
            (RAX_FAULT_UNMAPPED, 0x1000_0000)
        );
        assert_eq!(rd_u64(e, REG_PC), 0x1000, "the load does not retire");
    }
    rax_engine_close(e);
}

/// Vector table at `base` whose exceptions 2-15 enter `handler`.
unsafe fn vector_table(e: *mut Engine, base: u64, handler: u32) {
    for exception in 2..16u64 {
        unsafe { write(e, base + 4 * exception, &(handler | 1).to_le_bytes()) };
    }
}

#[test]
fn cortex_m_runs_thumb_code_and_takes_exceptions() {
    for mode in [RAX_MODE_ARM, RAX_MODE_BIG_ENDIAN] {
        let mut e = ptr::null_mut();
        assert_eq!(
            rax_engine_open(RaxArch::CortexM as i32, mode, &mut e),
            RaxStatus::Mode
        );
    }
    let e = open(RaxArch::CortexM, 0);
    assert_eq!(rax_engine_supports_stepping(e), 1);
    unsafe {
        // movs r0,#1 ; svc #0 ; adds r0,#2 ; wfi — the SVCall handler adds
        // 10 to the stacked R0: ldr r1,[sp] ; adds r1,#10 ; str r1,[sp] ; bx lr
        write(e, 0x1000, &[0x01, 0x20, 0x00, 0xDF, 0x02, 0x30, 0x30, 0xBF]);
        write(e, 0x2000, &[0x00, 0x99, 0x0A, 0x31, 0x00, 0x91, 0x70, 0x47]);
        vector_table(e, 0x4000, 0x2000);
        assert_eq!(rax_reg_write_u64(e, CM_VTOR, 0x4000), RaxStatus::Ok);
        assert_eq!(rax_reg_write_u64(e, REG_SP, 0x8000), RaxStatus::Ok);
        assert_eq!(
            rd_u64(e, CM_MSP),
            0x8000,
            "SP is the main stack in Thread mode"
        );
        assert_eq!(rax_emu_start(e, 0x1000, RAX_NO_ADDR, 0, 0), RaxStatus::Ok);
        let x = last_exit(e);
        assert_eq!(x.reason, RAX_STOP_HLT);
        assert_eq!(x.value, 8, "3 + the handler's 4 + WFI");
        assert_eq!(rd_u64(e, ARM_R0), 13);
        assert_eq!(rd_u64(e, REG_SP), 0x8000);
        assert_eq!(rd_u64(e, REG_PSTATE) & 0x1FF, 0, "back in Thread mode");

        // A BKPT escalates to HardFault; HFSR records the debug event.
        write(e, 0x1000, &[0x01, 0xBE]);
        write(e, 0x2000, &[0x30, 0xBF]); // the handler: wfi
        assert_eq!(rax_emu_start(e, 0x1000, RAX_NO_ADDR, 0, 0), RaxStatus::Ok);
        assert_eq!(last_exit(e).reason, RAX_STOP_HLT);
        assert_eq!(rd_u64(e, REG_PSTATE) & 0x1FF, 3);
        assert_eq!(rd_u64(e, CM_HFSR), 1 << 31);
        assert_eq!(rax_reg_size(RaxArch::CortexM as i32, CM_SHPR3), 4);
    }
    // No Floating-point Extension: its registers are not valid ids.
    for id in [CM_S0, CM_FPSCR] {
        assert_eq!(rax_reg_size(RaxArch::CortexM as i32, id), 0);
    }
    rax_engine_close(e);
}

/// Behaviour that the `RAX_MACHINE` board vCPUs change: ARM stepping, and
/// RV64 memory at the system-mode UART window (0x1000_0000).
fn engines_ignore_board_selection() {
    let e = open(RaxArch::Arm, 0);
    assert_eq!(rax_engine_supports_stepping(e), 1);
    rax_engine_close(e);

    let e = open_riscv_with_ext(0);
    unsafe {
        assert_eq!(
            rax_mem_map(e, 0x1000_0000, 0x1000, RAX_PROT_ALL),
            RaxStatus::Ok
        );
        // li t0,0x10000000 ; li t1,0x41 ; sb t1,0(t0) ; lbu t2,0(t0)
        let code: Vec<u8> = [0x1000_02B7u32, 0x0410_0313, 0x0062_8023, 0x0002_C383]
            .iter()
            .flat_map(|i| i.to_le_bytes())
            .collect();
        write(e, 0x1000, &code);
        assert_eq!(rax_emu_start(e, 0x1000, 0x1010, 0, 0), RaxStatus::Ok);
        assert_eq!(rd_u64(e, RISCV_X0 + 7), 0x41, "the store reached memory");
        let mut byte = 0u8;
        assert_eq!(rax_mem_read(e, 0x1000_0000, &mut byte, 1), RaxStatus::Ok);
        assert_eq!(byte, 0x41);
    }
    rax_engine_close(e);
}

#[test]
fn engine_choice_ignores_the_machine_environment() {
    engines_ignore_board_selection();
    if std::env::var_os("RAX_CAPI_MACHINE_CHILD").is_some() {
        return;
    }
    // Re-run this test in a child process with each board selected.
    let name = format!(
        "{}::engine_choice_ignores_the_machine_environment",
        module_path!().split_once("::").unwrap().1
    );
    for machine in ["s5l8900", "gsc"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([name.as_str(), "--exact", "--test-threads=1"])
            .env("RAX_MACHINE", machine)
            .env("RAX_CAPI_MACHINE_CHILD", "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success(), "RAX_MACHINE={machine}:\n{stdout}");
        assert!(
            stdout.contains("1 passed"),
            "RAX_MACHINE={machine} ran nothing:\n{stdout}"
        );
    }
}
