//! Unbounded runs stop only at guest events: a backend's periodic yield (the
//! x86 core's ~1 ms `Hlt`, the AArch64 and RV64 batch ends) is not a stop.
use super::*;
use crate::run::{RAX_STOP_SHUTDOWN, rax_emu_step};

fn last_exit(e: *mut Engine) -> ExitInfo {
    let mut x = ExitInfo::none();
    assert_eq!(rax_emu_last_exit(e, &mut x), RaxStatus::Ok);
    x
}

#[test]
fn x86_long_run_reaches_the_guest_halt() {
    let e = open_x86();
    unsafe {
        // mov ecx,100000 ; dec ecx ; jnz -4 ; hlt
        write(
            e,
            0x1000,
            &[0xB9, 0xA0, 0x86, 0x01, 0x00, 0xFF, 0xC9, 0x75, 0xFC, 0xF4],
        );
        assert_eq!(rax_emu_start(e, 0x1000, RAX_NO_ADDR, 0, 0), RaxStatus::Ok);
        let x = last_exit(e);
        assert_eq!(x.reason, RAX_STOP_HLT);
        assert_eq!(rd_u64(e, RCX), 0);
        assert_eq!(x.value, 1 + 2 * 100_000 + 1);
        assert_eq!(rd_u64(e, RIP), 0x100A);
    }
    rax_engine_close(e);
}

#[test]
fn arm64_long_run_reaches_the_guest_wait() {
    let mut e = ptr::null_mut();
    assert_eq!(
        rax_engine_open(RaxArch::Arm64 as i32, 0, &mut e),
        RaxStatus::Ok
    );
    unsafe {
        // movz x0,#40000 ; sub x0,x0,#1 ; cbnz x0,-4 ; wfi  (80 002 instructions,
        // more than one 65 536-instruction backend batch)
        let code: Vec<u8> = [0xD293_8800u32, 0xD100_0400, 0xB5FF_FFE0, 0xD503_207F]
            .iter()
            .flat_map(|i| i.to_le_bytes())
            .collect();
        write(e, 0x1000, &code);
        assert_eq!(rax_emu_start(e, 0x1000, RAX_NO_ADDR, 0, 0), RaxStatus::Ok);
        assert_eq!(last_exit(e).reason, RAX_STOP_HLT);
        assert_eq!(rd_u64(e, ARM64_X0), 0);
    }
    rax_engine_close(e);
}

#[test]
fn riscv_long_run_reaches_the_environment_call() {
    let e = open_riscv_with_ext(0);
    unsafe {
        // li t0,1000001 ; addi t0,t0,-1 ; bnez t0,-4 ; ecall (2 000 004
        // instructions, more than one 2 000 000-instruction backend batch)
        let code: Vec<u8> = [
            0x000F_42B7u32,
            0x2412_8293,
            0xFFF2_8293,
            0xFE02_9EE3,
            0x0000_0073,
        ]
        .iter()
        .flat_map(|i| i.to_le_bytes())
        .collect();
        write(e, 0x1000, &code);
        assert_eq!(rax_emu_start(e, 0x1000, RAX_NO_ADDR, 0, 0), RaxStatus::Ok);
        // The bare-metal RV64 core treats ECALL as a shutdown request.
        assert_eq!(last_exit(e).reason, RAX_STOP_SHUTDOWN);
        assert_eq!(rd_u64(e, RISCV_X0 + 5), 0);
        assert_eq!(rd_u64(e, RISCV_PC), 0x1010);
    }
    rax_engine_close(e);
}

#[test]
fn start_resumes_a_halted_x86_vcpu_at_begin() {
    let e = open_x86();
    unsafe {
        write(e, 0x1000, &[0xF4]); // hlt
        write(e, 0x2000, &[0xB8, 0x2A, 0x00, 0x00, 0x00, 0xF4]); // mov eax,42 ; hlt
        assert_eq!(rax_emu_start(e, 0x1000, RAX_NO_ADDR, 0, 0), RaxStatus::Ok);
        assert_eq!(last_exit(e).reason, RAX_STOP_HLT);
        // A bare step stays halted; an explicit start resumes at `begin`.
        let mut done = u64::MAX;
        assert_eq!(rax_emu_step(e, 1, &mut done), RaxStatus::Ok);
        assert_eq!(done, 0);
        assert_eq!(rax_emu_start(e, 0x2000, RAX_NO_ADDR, 0, 0), RaxStatus::Ok);
        let x = last_exit(e);
        assert_eq!((x.reason, x.value), (RAX_STOP_HLT, 2));
        assert_eq!(rd_u64(e, RAX), 42);
    }
    rax_engine_close(e);
}

#[test]
fn start_resumes_a_waiting_arm64_vcpu_at_begin() {
    let mut e = ptr::null_mut();
    assert_eq!(
        rax_engine_open(RaxArch::Arm64 as i32, 0, &mut e),
        RaxStatus::Ok
    );
    unsafe {
        write(e, 0x1000, &0xD503_207Fu32.to_le_bytes()); // wfi
        // movz x0,#42 ; wfi
        let code: Vec<u8> = [0xD280_0540u32, 0xD503_207F]
            .iter()
            .flat_map(|i| i.to_le_bytes())
            .collect();
        write(e, 0x2000, &code);
        assert_eq!(rax_emu_start(e, 0x1000, RAX_NO_ADDR, 0, 0), RaxStatus::Ok);
        assert_eq!(last_exit(e).reason, RAX_STOP_HLT);
        assert_eq!(rax_emu_start(e, 0x2000, RAX_NO_ADDR, 0, 0), RaxStatus::Ok);
        assert_eq!(last_exit(e).reason, RAX_STOP_HLT);
        assert_eq!(rd_u64(e, ARM64_X0), 42);
    }
    rax_engine_close(e);
}

/// `{ r0 = ##200000 }` then `{ r0 = add(r0,#-1) }` and
/// `{ p0 = cmp.eq(r0,#0); if (!p0.new) jump:t <add> }` until r0 is zero, then
/// `{ r1 = #42 }` and `{ r2 = #7 }` (assembled by LLVM 23 `llvm-mc -triple=hexagon`).
const HEXAGON_LOOP: [u32; 6] = [
    0x0000_4C35,
    0x7800_C000,
    0xBFE0_FFE0,
    0x1070_E0FE,
    0x7800_C541,
    0x7800_C0E2,
];
const HEX_R0: i32 = 0x0100;
const HEX_PC: i32 = 0x0309;

fn open_hexagon_loop() -> *mut Engine {
    let mut e = ptr::null_mut();
    assert_eq!(
        rax_engine_open(RaxArch::Hexagon as i32, 0, &mut e),
        RaxStatus::Ok
    );
    let code: Vec<u8> = HEXAGON_LOOP.iter().flat_map(|i| i.to_le_bytes()).collect();
    unsafe { write(e, 0x1000, &code) };
    e
}

#[test]
fn hexagon_runs_past_one_batch_and_stops_at_until() {
    let e = open_hexagon_loop();
    unsafe {
        assert_eq!(crate::engine::rax_engine_supports_stepping(e), 1);
        // 400 002 packets: more than the 100 000-packet backend batch.
        assert_eq!(rax_emu_start(e, 0x1000, 0x1014, 0, 0), RaxStatus::Ok);
        let x = last_exit(e);
        assert_eq!((x.reason, x.address), (RAX_STOP_UNTIL, 0x1014));
        assert_eq!(x.value, 1 + 2 * 200_000 + 1);
        assert_eq!(rd_u64(e, HEX_R0), 0);
        assert_eq!(rd_u64(e, HEX_R0 + 1), 42);
        assert_eq!(rax_emu_icount(e), 400_002);
    }
    rax_engine_close(e);
}

#[test]
fn hexagon_steps_one_packet_at_a_time() {
    let e = open_hexagon_loop();
    unsafe {
        assert_eq!(rax_reg_write_u64(e, HEX_PC, 0x1000), RaxStatus::Ok);
        let mut done = 0;
        // The first packet is immext + transfer (8 bytes).
        assert_eq!(rax_emu_step(e, 1, &mut done), RaxStatus::Ok);
        assert_eq!(done, 1);
        assert_eq!(rd_u64(e, HEX_PC), 0x1008);
        assert_eq!(rd_u64(e, HEX_R0), 200_000);
        assert_eq!(rax_emu_step(e, 3, &mut done), RaxStatus::Ok);
        assert_eq!(done, 3);
        assert_eq!(rd_u64(e, HEX_R0), 199_998);
        assert_eq!(rd_u64(e, HEX_PC), 0x100C);
        assert_eq!(last_exit(e).reason, RAX_STOP_COUNT);
    }
    rax_engine_close(e);
}
