//! Integration tests for the PIT (Programmable Interval Timer) via x86 emulation.
//!
//! These tests verify that the PIT correctly handles I/O port operations
//! when accessed through x86 IN/OUT instructions via the emulator.
//!
//! PIT I/O Ports:
//! - 0x40: Channel 0 data
//! - 0x41: Channel 1 data
//! - 0x42: Channel 2 data
//! - 0x43: Mode/Command register (write-only)

use std::sync::Arc;

use crate::common::*;
use rax::devices::bus::IoDevice;
use rax::devices::pit::Pit;
use rax::vm::timing::{ClockMode, PIT_FREQUENCY_HZ, TimingContext};
use rax::vm::vcpu::{Registers, VcpuExit};

/// Helper to run code with PIT device handling
fn run_with_pit(code: &[u8], regs: Registers) -> (Vec<(u16, Vec<u8>)>, Vec<(u16, u8)>, Registers) {
    let (mut vcpu, _) = setup_vm(code, Some(regs));
    let clock = Arc::new(TimingContext::with_mode(ClockMode::Retired));
    let _scope = clock.enter();
    let mut pit = Pit::new();
    let mut io_writes: Vec<(u16, Vec<u8>)> = Vec::new();
    let mut io_reads: Vec<(u16, u8)> = Vec::new();

    for tick in 1u64.. {
        let exit = vcpu.run().unwrap();
        // Sample each exit after another PIT clock, independent of host scheduling.
        clock.set_resume_base((tick * 1_000_000_000).div_ceil(PIT_FREQUENCY_HZ));
        match exit {
            VcpuExit::IoIn { port, size } => {
                let mut data = vec![0u8; size as usize];
                // Route PIT ports to the PIT device
                if port >= 0x40 && port <= 0x43 {
                    for (i, byte) in data.iter_mut().enumerate() {
                        *byte = pit.read(port + i as u16);
                    }
                    io_reads.push((port, data[0]));
                }
                vcpu.complete_io_in(&data);
            }
            VcpuExit::IoOut { port, data } => {
                io_writes.push((port, data.clone()));
                // Route PIT ports to the PIT device
                if port >= 0x40 && port <= 0x43 {
                    for (i, byte) in data.iter().enumerate() {
                        pit.write(port + i as u16, *byte);
                    }
                }
            }
            VcpuExit::Hlt => break,
            _ => continue,
        }
    }

    let final_regs = vcpu.get_regs().unwrap();
    (io_writes, io_reads, final_regs)
}

// ============================================================================
// PIT Command Register Tests (port 0x43)
// ============================================================================

#[test]
fn test_pit_command_register_write() {
    // OUT 0x43, AL - Write command byte
    // Command: 0x36 = channel 0, lobyte/hibyte, mode 3 (square wave)
    let code = [
        0xB0, 0x36, // MOV AL, 0x36
        0xE6, 0x43, // OUT 0x43, AL
        0xF4, // HLT
    ];
    let regs = Registers::default();
    let (writes, _reads, _final_regs) = run_with_pit(&code, regs);

    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0], (0x43, vec![0x36]));
}

#[test]
fn test_pit_command_register_read_returns_ff() {
    // IN AL, 0x43 - Read from command register should return 0xFF (write-only)
    let code = [
        0xE4, 0x43, // IN AL, 0x43
        0xF4, // HLT
    ];
    let regs = Registers::default();
    let (_writes, reads, final_regs) = run_with_pit(&code, regs);

    assert_eq!(reads.len(), 1);
    assert_eq!(reads[0], (0x43, 0xFF));
    assert_eq!(final_regs.rax & 0xFF, 0xFF);
}

// ============================================================================
// PIT Data Register Tests (ports 0x40-0x42)
// ============================================================================

#[test]
fn test_pit_channel0_write_reload_value() {
    // Configure channel 0 and write a reload value
    // Command 0x36: channel 0, lobyte/hibyte, mode 3
    // Reload value: 0x2E9C (11932 for ~100Hz)
    let code = [
        0xB0, 0x36, // MOV AL, 0x36
        0xE6, 0x43, // OUT 0x43, AL (command)
        0xB0, 0x9C, // MOV AL, 0x9C (low byte)
        0xE6, 0x40, // OUT 0x40, AL
        0xB0, 0x2E, // MOV AL, 0x2E (high byte)
        0xE6, 0x40, // OUT 0x40, AL
        0xF4, // HLT
    ];
    let regs = Registers::default();
    let (writes, _reads, _final_regs) = run_with_pit(&code, regs);

    assert_eq!(writes.len(), 3);
    assert_eq!(writes[0], (0x43, vec![0x36])); // Command
    assert_eq!(writes[1], (0x40, vec![0x9C])); // Low byte
    assert_eq!(writes[2], (0x40, vec![0x2E])); // High byte
}

#[test]
fn test_pit_channel0_latch_and_read() {
    // First configure channel 0, then latch and read the count
    // Latch command: 0x00 (channel 0, access mode 00 = latch)
    let code = [
        // Configure channel 0: mode 3, lobyte/hibyte
        0xB0, 0x36, // MOV AL, 0x36
        0xE6, 0x43, // OUT 0x43, AL
        // Write reload value 0x1234
        0xB0, 0x34, // MOV AL, 0x34
        0xE6, 0x40, // OUT 0x40, AL
        0xB0, 0x12, // MOV AL, 0x12
        0xE6, 0x40, // OUT 0x40, AL
        // Latch channel 0
        0xB0, 0x00, // MOV AL, 0x00 (latch command)
        0xE6, 0x43, // OUT 0x43, AL
        // Read latched value (low then high)
        0xE4, 0x40, // IN AL, 0x40 (low byte) -> AL
        0x88, 0xC4, // MOV AH, AL (save low byte)
        0xE4, 0x40, // IN AL, 0x40 (high byte)
        0x86, 0xC4, // XCHG AL, AH (now AX = high:low correctly ordered)
        0xF4, // HLT
    ];
    let regs = Registers::default();
    let (_writes, reads, final_regs) = run_with_pit(&code, regs);

    // We should have read twice from port 0x40
    assert_eq!(reads.len(), 2);
    assert_eq!(reads[0].0, 0x40); // Low byte read
    assert_eq!(reads[1].0, 0x40); // High byte read

    // The latch samples the edge that transfers the initial divisor.
    assert_eq!(final_regs.rax & 0xFFFF, 0x1234);
}

#[test]
fn test_pit_channel2_write() {
    // Configure and write to channel 2 (speaker channel)
    // Command 0xB6: channel 2, lobyte/hibyte, mode 3
    let code = [
        0xB0, 0xB6, // MOV AL, 0xB6
        0xE6, 0x43, // OUT 0x43, AL
        0xB0, 0xEF, // MOV AL, 0xEF
        0xE6, 0x42, // OUT 0x42, AL
        0xB0, 0xBE, // MOV AL, 0xBE
        0xE6, 0x42, // OUT 0x42, AL
        0xF4, // HLT
    ];
    let regs = Registers::default();
    let (writes, _reads, _final_regs) = run_with_pit(&code, regs);

    assert_eq!(writes.len(), 3);
    assert_eq!(writes[0], (0x43, vec![0xB6]));
    assert_eq!(writes[1], (0x42, vec![0xEF]));
    assert_eq!(writes[2], (0x42, vec![0xBE]));
}

// ============================================================================
// Access Mode Tests
// ============================================================================

#[test]
fn test_pit_low_byte_only_mode() {
    // Configure channel 0 for low byte only access (mode bits = 01)
    // Command 0x10: channel 0, low byte only, mode 0
    let code = [
        0xB0, 0x10, // MOV AL, 0x10
        0xE6, 0x43, // OUT 0x43, AL
        0xB0, 0x42, // MOV AL, 0x42
        0xE6, 0x40, // OUT 0x40, AL
        // Latch and read
        0xB0, 0x00, // MOV AL, 0x00 (latch)
        0xE6, 0x43, // OUT 0x43, AL
        0xE4, 0x40, // IN AL, 0x40
        0xF4, // HLT
    ];
    let regs = Registers::default();
    let (_writes, reads, final_regs) = run_with_pit(&code, regs);

    assert_eq!(reads.len(), 1);
    assert_eq!(final_regs.rax & 0xFF, 0x42);
}

#[test]
fn test_pit_high_byte_only_mode() {
    // Configure channel 0 for high byte only access (mode bits = 10)
    // Command 0x20: channel 0, high byte only, mode 0
    let code = [
        0xB0, 0x20, // MOV AL, 0x20
        0xE6, 0x43, // OUT 0x43, AL
        0xB0, 0x42, // MOV AL, 0x42
        0xE6, 0x40, // OUT 0x40, AL
        // Latch and read
        0xB0, 0x00, // MOV AL, 0x00 (latch)
        0xE6, 0x43, // OUT 0x43, AL
        0xE4, 0x40, // IN AL, 0x40
        0xF4, // HLT
    ];
    let regs = Registers::default();
    let (_writes, reads, final_regs) = run_with_pit(&code, regs);

    assert_eq!(reads.len(), 1);
    assert_eq!(final_regs.rax & 0xFF, 0x42);
}

// ============================================================================
// Standard Configurations Used by OS/BIOS
// ============================================================================

#[test]
fn test_pit_bios_default_18hz() {
    // BIOS sets up PIT for ~18.2 Hz: divisor 0 (= 65536)
    // 1193182 / 65536 ≈ 18.2065 Hz
    let code = [
        0xB0, 0x36, // MOV AL, 0x36 (channel 0, lobyte/hibyte, mode 3)
        0xE6, 0x43, // OUT 0x43, AL
        0xB0, 0x00, // MOV AL, 0x00 (low byte)
        0xE6, 0x40, // OUT 0x40, AL
        0xB0, 0x00, // MOV AL, 0x00 (high byte)
        0xE6, 0x40, // OUT 0x40, AL
        0xF4, // HLT
    ];
    let regs = Registers::default();
    let (writes, _reads, _final_regs) = run_with_pit(&code, regs);

    assert_eq!(writes.len(), 3);
    // Reload value 0x0000 represents 65536
}

#[test]
fn test_pit_100hz_configuration() {
    // Common OS configuration for 100 Hz (10ms timer)
    // Divisor: 1193182 / 100 ≈ 11932 = 0x2E9C
    let code = [
        0xB0, 0x36, // MOV AL, 0x36
        0xE6, 0x43, // OUT 0x43, AL
        0xB0, 0x9C, // MOV AL, 0x9C
        0xE6, 0x40, // OUT 0x40, AL
        0xB0, 0x2E, // MOV AL, 0x2E
        0xE6, 0x40, // OUT 0x40, AL
        0xF4, // HLT
    ];
    let regs = Registers::default();
    let (writes, _reads, _final_regs) = run_with_pit(&code, regs);

    assert_eq!(writes.len(), 3);
}

#[test]
fn test_pit_1000hz_configuration() {
    // High-frequency timer at 1000 Hz (1ms period)
    // Divisor: 1193182 / 1000 ≈ 1193 = 0x04A9
    let code = [
        0xB0, 0x36, // MOV AL, 0x36
        0xE6, 0x43, // OUT 0x43, AL
        0xB0, 0xA9, // MOV AL, 0xA9
        0xE6, 0x40, // OUT 0x40, AL
        0xB0, 0x04, // MOV AL, 0x04
        0xE6, 0x40, // OUT 0x40, AL
        0xF4, // HLT
    ];
    let regs = Registers::default();
    let (writes, _reads, _final_regs) = run_with_pit(&code, regs);

    assert_eq!(writes.len(), 3);
}

// ============================================================================
// Multiple Latch Commands (second should be ignored)
// ============================================================================

#[test]
fn test_pit_second_latch_ignored() {
    // The first latch must survive a divisor transfer and a second latch command.
    let code = [
        // Configure channel 0
        0xB0, 0x36, // MOV AL, 0x36
        0xE6, 0x43, // OUT 0x43, AL
        // Write the initial odd divisor 5.
        0xB0, 0x05, // MOV AL, 5
        0xE6, 0x40, // OUT 0x40, AL
        0xB0, 0x00, // MOV AL, 0
        0xE6, 0x40, // OUT 0x40, AL
        // First latch
        0xB0, 0x00, // MOV AL, 0x00
        0xE6, 0x43, // OUT 0x43, AL
        // Write new value 0x2222 (won't affect latched value)
        0xB0, 0x22, // MOV AL, 0x22
        0xE6, 0x40, // OUT 0x40, AL
        0xB0, 0x22, // MOV AL, 0x22
        0xE6, 0x40, // OUT 0x40, AL
        // Second latch (should be ignored)
        0xB0, 0x00, // MOV AL, 0x00
        0xE6, 0x43, // OUT 0x43, AL
        // Read the first latched count.
        0xE4, 0x40, // IN AL, 0x40 (low byte)
        0x88, 0xC4, // MOV AH, AL
        0xE4, 0x40, // IN AL, 0x40 (high byte)
        0x86, 0xC4, // XCHG AL, AH
        0xF4, // HLT
    ];
    let regs = Registers::default();
    let (_writes, _reads, final_regs) = run_with_pit(&code, regs);

    // The first latch sampled 4. The active count has reached 0x2222.
    assert_eq!(final_regs.rax & 0xFFFF, 4);
}

// ============================================================================
// All Operating Modes
// ============================================================================

#[test]
fn test_pit_mode0_interrupt_on_terminal_count() {
    // Command 0x30: channel 0, lobyte/hibyte, mode 0
    let code = [
        0xB0, 0x30, // MOV AL, 0x30
        0xE6, 0x43, // OUT 0x43, AL
        0xF4, // HLT
    ];
    let regs = Registers::default();
    let (writes, _reads, _final_regs) = run_with_pit(&code, regs);
    assert_eq!(writes[0], (0x43, vec![0x30]));
}

#[test]
fn test_pit_mode1_hardware_oneshot() {
    // Command 0x32: channel 0, lobyte/hibyte, mode 1
    let code = [
        0xB0, 0x32, // MOV AL, 0x32
        0xE6, 0x43, // OUT 0x43, AL
        0xF4, // HLT
    ];
    let regs = Registers::default();
    let (writes, _reads, _final_regs) = run_with_pit(&code, regs);
    assert_eq!(writes[0], (0x43, vec![0x32]));
}

#[test]
fn test_pit_mode2_rate_generator() {
    // Command 0x34: channel 0, lobyte/hibyte, mode 2
    let code = [
        0xB0, 0x34, // MOV AL, 0x34
        0xE6, 0x43, // OUT 0x43, AL
        0xF4, // HLT
    ];
    let regs = Registers::default();
    let (writes, _reads, _final_regs) = run_with_pit(&code, regs);
    assert_eq!(writes[0], (0x43, vec![0x34]));
}

#[test]
fn test_pit_mode3_square_wave() {
    // Command 0x36: channel 0, lobyte/hibyte, mode 3
    let code = [
        0xB0, 0x36, // MOV AL, 0x36
        0xE6, 0x43, // OUT 0x43, AL
        0xF4, // HLT
    ];
    let regs = Registers::default();
    let (writes, _reads, _final_regs) = run_with_pit(&code, regs);
    assert_eq!(writes[0], (0x43, vec![0x36]));
}

#[test]
fn test_pit_mode4_software_strobe() {
    // Command 0x38: channel 0, lobyte/hibyte, mode 4
    let code = [
        0xB0, 0x38, // MOV AL, 0x38
        0xE6, 0x43, // OUT 0x43, AL
        0xF4, // HLT
    ];
    let regs = Registers::default();
    let (writes, _reads, _final_regs) = run_with_pit(&code, regs);
    assert_eq!(writes[0], (0x43, vec![0x38]));
}

#[test]
fn test_pit_mode5_hardware_strobe() {
    // Command 0x3A: channel 0, lobyte/hibyte, mode 5
    let code = [
        0xB0, 0x3A, // MOV AL, 0x3A
        0xE6, 0x43, // OUT 0x43, AL
        0xF4, // HLT
    ];
    let regs = Registers::default();
    let (writes, _reads, _final_regs) = run_with_pit(&code, regs);
    assert_eq!(writes[0], (0x43, vec![0x3A]));
}

// ============================================================================
// DX-based I/O (variable port)
// ============================================================================

#[test]
fn test_pit_dx_based_io() {
    // Use OUT DX, AL for PIT access
    let code = [
        0x66, 0xBA, 0x43, 0x00, // MOV DX, 0x43
        0xB0, 0x36, // MOV AL, 0x36
        0xEE, // OUT DX, AL
        0x66, 0xBA, 0x40, 0x00, // MOV DX, 0x40
        0xB0, 0x9C, // MOV AL, 0x9C
        0xEE, // OUT DX, AL
        0xB0, 0x2E, // MOV AL, 0x2E
        0xEE, // OUT DX, AL
        0xF4, // HLT
    ];
    let regs = Registers::default();
    let (writes, _reads, _final_regs) = run_with_pit(&code, regs);

    assert_eq!(writes.len(), 3);
    assert_eq!(writes[0], (0x43, vec![0x36]));
    assert_eq!(writes[1], (0x40, vec![0x9C]));
    assert_eq!(writes[2], (0x40, vec![0x2E]));
}

#[test]
fn test_pit_dx_based_read() {
    // Channel 2 transfers the odd divisor with GATE low and then stays frozen.
    let code = [
        // Configure channel 2 for lobyte/hibyte mode 3.
        0x66, 0xBA, 0x43, 0x00, // MOV DX, 0x43
        0xB0, 0xB6, // MOV AL, 0xB6
        0xEE, // OUT DX, AL
        // Write value 0xABCD
        0x66, 0xBA, 0x42, 0x00, // MOV DX, 0x42
        0xB0, 0xCD, // MOV AL, 0xCD
        0xEE, // OUT DX, AL
        0xB0, 0xAB, // MOV AL, 0xAB
        0xEE, // OUT DX, AL
        // Latch channel 2.
        0x66, 0xBA, 0x43, 0x00, // MOV DX, 0x43
        0xB0, 0x80, // MOV AL, 0x80
        0xEE, // OUT DX, AL
        // Read via DX
        0x66, 0xBA, 0x42, 0x00, // MOV DX, 0x42
        0xEC, // IN AL, DX (low byte)
        0x88, 0xC4, // MOV AH, AL
        0xEC, // IN AL, DX (high byte)
        0x86, 0xC4, // XCHG AL, AH
        0xF4, // HLT
    ];
    let regs = Registers::default();
    let (_writes, _reads, final_regs) = run_with_pit(&code, regs);

    assert_eq!(final_regs.rax & 0xFFFF, 0xABCC);
}
