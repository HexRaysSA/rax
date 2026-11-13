//! Linux's ptrace comparator objects and requested DR7, separate from the
//! installed hardware bank. Linux v6.19: x86 ptrace.c and hw_breakpoint.c.

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::{EINVAL, EIO};
use super::super::arch::GuestCpu;
use super::super::process::Thread;
use crate::user::cpu::x86_64::X86UserCpu;

const DR6_RESERVED: u64 = 0xffff_0ff0;
const TASK_SIZE_MAX: u64 = (1 << 47) - 4096;

#[derive(Clone, Copy, Debug)]
struct Breakpoint {
    address: u64,
    configuration: u8,
    enabled: bool,
}

/// The tracee's ptrace objects (`ptrace_bps`) and unmasked requested DR7.
#[derive(Clone, Debug, Default)]
pub(crate) struct Registers {
    slots: [Option<Breakpoint>; 4],
    requested_control: u64,
}

impl Registers {
    pub(crate) fn read(&self, cpu: &X86UserCpu, n: usize) -> u64 {
        match n {
            0..=3 => self.slots[n].map_or(0, |b| b.address),
            6 => cpu.vcpu().last_user_debug_status() ^ DR6_RESERVED,
            7 => self.requested_control,
            _ => 0,
        }
    }

    pub(crate) fn write(
        &mut self,
        cpu: &mut X86UserCpu,
        n: usize,
        value: u64,
    ) -> Result<(), Errno> {
        match n {
            0..=3 => {
                let mut b = self.slots[n].unwrap_or(Breakpoint {
                    address: 0,
                    configuration: 1,
                    enabled: false,
                });
                b.address = value;
                validate(b)?;
                self.slots[n] = Some(b);
            }
            6 => {
                cpu.vcpu_mut().set_user_debug_status(value ^ DR6_RESERVED);
                return Ok(());
            }
            7 => {
                let old = self.effective_control();
                if let Err(error) = self.apply_control(value) {
                    // ptrace_write_dr7 restores from the old installed
                    // attributes. Successfully allocated earlier objects
                    // remain allocated, disabled with the restored fields.
                    self.apply_control(old)
                        .expect("previous comparator state is valid");
                    self.install(cpu);
                    return Err(error);
                }
                self.requested_control = value;
            }
            _ => return Err(Errno(EIO)),
        }
        self.install(cpu);
        Ok(())
    }

    fn apply_control(&mut self, control: u64) -> Result<(), Errno> {
        // DR_CONTROL_RESERVED removes the high word and low reserved bits;
        // only enables and the four type/length nibbles describe perf events.
        for (i, slot) in self.slots.iter_mut().enumerate() {
            let enabled = control >> (i * 2) & 3 != 0;
            if slot.is_none() && !enabled {
                continue;
            }
            let b = Breakpoint {
                address: slot.map_or(0, |b| b.address),
                configuration: (control >> (16 + i * 4) & 15) as u8,
                enabled,
            };
            validate(b)?;
            *slot = Some(b);
        }
        Ok(())
    }

    fn effective_control(&self) -> u64 {
        let mut control = 0;
        for (i, b) in self.slots.iter().enumerate() {
            if let Some(b) = b.filter(|b| b.enabled) {
                // encode_dr7 uses global enable plus global slowdown.
                control |= 0x200 | (2 << (i * 2)) | (u64::from(b.configuration) << (16 + i * 4));
            }
        }
        control
    }

    fn install(&self, cpu: &mut X86UserCpu) {
        let mut bank = cpu.vcpu().user_debug_registers();
        for (i, slot) in self.slots.iter().enumerate() {
            bank[i] = slot.map_or(0, |b| b.address);
        }
        bank[5] = self.effective_control() | 0x400;
        cpu.vcpu_mut().set_user_debug_registers(bank);
    }

    /// copy_thread clears breakpoint objects, retaining virtual DR6/DR7.
    pub(crate) fn without_breakpoints(&self) -> Self {
        Self {
            slots: [None; 4],
            requested_control: self.requested_control,
        }
    }

    pub(crate) fn clear_breakpoints(&mut self, cpu: &mut GuestCpu) {
        self.slots = [None; 4];
        if let GuestCpu::X86_64(cpu) = cpu {
            self.install(cpu);
        }
    }
}

fn validate(b: Breakpoint) -> Result<(), Errno> {
    let kind = b.configuration & 3;
    if kind == 2 || (kind == 0 && b.configuration != 0) {
        return Err(Errno(EINVAL));
    }
    let len = if kind == 0 {
        1
    } else {
        [1, 2, 8, 4][(b.configuration >> 2) as usize]
    };
    let end = b.address.checked_add(len - 1).ok_or(Errno(EINVAL))?;
    if b.address & (len - 1) != 0 || end >= TASK_SIZE_MAX {
        return Err(Errno(EINVAL));
    }
    Ok(())
}

/// Resolve debug-area words before the general-register views. The compat
/// getreg32/putreg32 range cases divide by four before their default alignment
/// check; native arch_ptrace checks alignment before dispatching the area.
pub(crate) fn serve(
    t: &mut Thread,
    compat: bool,
    off: u64,
    write: Option<u64>,
) -> Option<Result<Vec<u8>, Errno>> {
    let GuestCpu::X86_64(cpu) = &mut t.cpu else {
        return None;
    };
    let (base, width) = if compat { (252, 4) } else { (848, 8) };
    if !(base..base + width * 8).contains(&off) {
        return None;
    }
    if !compat && off % width != 0 {
        return Some(Err(Errno(EIO)));
    }
    let n = ((off - base) / width) as usize;
    Some(match write {
        Some(value) => t
            .debug
            .write(cpu, n, if compat { value as u32 as u64 } else { value })
            .map(|()| Vec::new()),
        None => Ok(t.debug.read(cpu, n).to_le_bytes()[..width as usize].to_vec()),
    })
}
