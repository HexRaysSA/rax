//! Minimal real-mode BIOS for legacy/El-Torito boot (e.g. TempleOS).
//!
//! rax has no firmware: the Linux path enters long mode directly. A CD boot
//! image instead runs in 16-bit real mode and calls BIOS services via `INT`.
//! This module services the small set the TempleOS bootloader needs — INT 10h
//! (video/teletype) and INT 13h (extended LBA disk read from the boot CD) —
//! natively, reading sectors out of the retained ISO image. It is consulted
//! from the `INT imm8` handler only when running in real mode with a boot CD
//! installed via [`install_cd`].
//!
//! The CD image is held in a module-level static because legacy boot is
//! inherently single-vCPU (the bootloader runs before any SMP bring-up).

use std::io::Write;
use std::sync::{Arc, Mutex};

use crate::error::Result;

use super::cpu::X86_64Vcpu;

/// CD-ROM logical sector size used by INT 13h extended reads.
const CD_SECTOR: usize = 2048;

static BIOS_CD: Mutex<Option<Arc<Vec<u8>>>> = Mutex::new(None);

/// Install the boot CD image (the El-Torito ISO) so INT 13h reads can serve it.
/// Passing this enables the real-mode mini-BIOS.
pub fn install_cd(iso: Arc<Vec<u8>>) {
    *BIOS_CD.lock().unwrap() = Some(iso);
}

/// Whether a boot CD (and thus the mini-BIOS) is installed.
pub fn active() -> bool {
    BIOS_CD.lock().unwrap().is_some()
}

fn cd() -> Option<Arc<Vec<u8>>> {
    BIOS_CD.lock().unwrap().clone()
}

#[inline]
fn set_cf(vcpu: &mut X86_64Vcpu, set: bool) {
    if set {
        vcpu.regs.rflags |= 1;
    } else {
        vcpu.regs.rflags &= !1;
    }
}

#[inline]
fn set_ah(vcpu: &mut X86_64Vcpu, ah: u8) {
    vcpu.regs.rax = (vcpu.regs.rax & !0xFF00) | ((ah as u64) << 8);
}

#[inline]
fn ah(vcpu: &X86_64Vcpu) -> u8 {
    (vcpu.regs.rax >> 8) as u8
}

/// Service a real-mode BIOS software interrupt. Returns `Ok(true)` if the vector
/// was handled (the caller has already advanced past the `INT` instruction).
pub fn service(vcpu: &mut X86_64Vcpu, vector: u8) -> Result<bool> {
    match vector {
        0x10 => {
            int10(vcpu);
            Ok(true)
        }
        0x13 => {
            int13(vcpu)?;
            Ok(true)
        }
        0x15 => {
            int15(vcpu);
            Ok(true)
        }
        0x16 => {
            int16(vcpu);
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// INT 10h — video services (the subset bootloaders use).
fn int10(vcpu: &mut X86_64Vcpu) {
    match ah(vcpu) {
        // AH=0Eh: teletype output — write AL to the console.
        0x0E => {
            let ch = vcpu.regs.rax as u8;
            let mut out = std::io::stdout().lock();
            let _ = out.write_all(&[ch]);
            let _ = out.flush();
        }
        // AH=0Fh: get video mode → AL=mode (3 = 80x25 text), AH=columns (80),
        // BH=active page (0).
        0x0F => {
            vcpu.regs.rax = (vcpu.regs.rax & !0xFFFF) | 0x5003; // AH=0x50(80), AL=3
            vcpu.regs.rbx &= !0xFF00; // BH=0
        }
        // AH=00h (set mode), 02h (set cursor), 03h (get cursor), 01h, 05h, 06h,
        // 07h, 09h/0Ah (write char): accept as no-ops so progress output flows.
        0x03 => {
            // get cursor position/size → report (0,0), default shape.
            vcpu.regs.rcx = (vcpu.regs.rcx & !0xFFFF) | 0x0607;
            vcpu.regs.rdx &= !0xFFFF;
        }
        _ => {}
    }
}

/// INT 13h — disk services. Only the El-Torito extended-read path is meaningful;
/// it reads 2048-byte CD sectors out of the boot ISO.
fn int13(vcpu: &mut X86_64Vcpu) -> Result<()> {
    match ah(vcpu) {
        // AH=00h: reset disk system.
        0x00 => {
            set_ah(vcpu, 0);
            set_cf(vcpu, false);
        }
        // AH=41h: check extensions present → CF=0, BX=0xAA55, AH=0x21 (EDD v2.1),
        // CX bit0 = fixed-disk extended access supported.
        0x41 => {
            vcpu.regs.rbx = (vcpu.regs.rbx & !0xFFFF) | 0xAA55;
            vcpu.regs.rcx = (vcpu.regs.rcx & !0xFFFF) | 0x0001;
            set_ah(vcpu, 0x21);
            set_cf(vcpu, false);
        }
        // AH=42h: extended read using a Disk Address Packet at DS:SI.
        0x42 => {
            let dap = vcpu.sregs.ds.base.wrapping_add(vcpu.regs.rsi & 0xFFFF);
            let count = vcpu.mmu.read_u16(dap + 2, &vcpu.sregs)? as usize;
            let buf_off = vcpu.mmu.read_u16(dap + 4, &vcpu.sregs)? as u64;
            let buf_seg = vcpu.mmu.read_u16(dap + 6, &vcpu.sregs)? as u64;
            let lba = vcpu.mmu.read_u64(dap + 8, &vcpu.sregs)?;
            let buf_lin = (buf_seg << 4).wrapping_add(buf_off);

            let cd = match cd() {
                Some(c) => c,
                None => {
                    set_ah(vcpu, 0x01);
                    set_cf(vcpu, true);
                    return Ok(());
                }
            };
            let start = (lba as usize).saturating_mul(CD_SECTOR);
            let len = count * CD_SECTOR;
            if start.saturating_add(len) > cd.len() {
                // Read past end of medium → error (AH=0x04 sector not found).
                set_ah(vcpu, 0x04);
                set_cf(vcpu, true);
                return Ok(());
            }
            vcpu.write_bytes(buf_lin, &cd[start..start + len])?;
            set_ah(vcpu, 0);
            set_cf(vcpu, false);
        }
        // AH=08h: get drive parameters (minimal success).
        0x08 => {
            set_ah(vcpu, 0);
            set_cf(vcpu, false);
        }
        // Unknown function: report failure.
        _ => {
            set_ah(vcpu, 0x01);
            set_cf(vcpu, true);
        }
    }
    Ok(())
}

/// INT 15h — miscellaneous system services. Reported unsupported for now
/// (callers fall back to defaults); a real E820 map can be added when needed.
fn int15(vcpu: &mut X86_64Vcpu) {
    set_ah(vcpu, 0x86); // unsupported function
    set_cf(vcpu, true);
}

/// INT 16h — keyboard services. Report "no key available".
fn int16(vcpu: &mut X86_64Vcpu) {
    match ah(vcpu) {
        // AH=01h: check for keystroke → ZF=1 (none). ZF is bit 6 of RFLAGS.
        0x01 => {
            vcpu.regs.rflags |= 1 << 6;
        }
        // AH=00h: read keystroke → return 0 (no key); avoids blocking the boot.
        _ => {
            vcpu.regs.rax &= !0xFFFF;
        }
    }
}
