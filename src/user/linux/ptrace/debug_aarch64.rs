//! ARM64 Linux ptrace instruction-comparator objects. The UAPI has sixteen
//! logical entries; allocating even a disabled object consumes a native slot.

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::{EINVAL, ENOSPC};
use super::super::arch::GuestCpu;
use super::super::process::Thread;
use super::{regs, req};
use crate::user::cpu::aarch64::A64UserCpu;

const SIZE: usize = 264;

#[derive(Clone, Copy, Debug, Default)]
struct Breakpoint {
    /// perf_event_attr.bp_addr, before hardware alignment/BAS adjustment.
    address: u64,
    enabled: bool,
}

impl Breakpoint {
    fn hardware(self) -> (u64, u32) {
        let bas = 15u32 << (self.address & 3);
        (self.address & !3, (bas << 5) | 4 | u32::from(self.enabled))
    }

    fn validate(self, limit: u64) -> Result<(), Errno> {
        // arch_build_bp_info normalizes every A64 execute length to four;
        // arch_check_bp_in_kernelspace checks both inclusive endpoints.
        if self.address >= limit && self.address.wrapping_add(3) >= limit {
            return Err(Errno(EINVAL));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Registers {
    slots: [Option<Breakpoint>; 16],
}

impl Registers {
    pub(crate) fn get(&self, cpu: &A64UserCpu) -> Vec<u8> {
        let (count, _, version) = cpu.core().user_debug_capabilities();
        let mut out = vec![0; SIZE];
        let info = u32::from(count) | (u32::from(version) << 8);
        out[..4].copy_from_slice(&info.to_le_bytes());
        for (i, slot) in self.slots.iter().enumerate() {
            if let Some(bp) = slot {
                let (address, control) = bp.hardware();
                let at = 8 + 16 * i;
                out[at..at + 8].copy_from_slice(&address.to_le_bytes());
                out[at + 8..at + 12].copy_from_slice(&control.to_le_bytes());
            }
        }
        out
    }

    pub(crate) fn set(&mut self, cpu: &mut A64UserCpu, bytes: &[u8]) -> Result<(), Errno> {
        let (count, _, _) = cpu.core().user_debug_capabilities();
        let result = self.apply(bytes, usize::from(count), cpu.space().va_limit());
        // The kernel retains earlier fields and newly allocated default
        // objects after a later field fails. Install that retained state too.
        self.install(cpu);
        result
    }

    fn initialised(&mut self, i: usize, count: usize) -> Result<&mut Breakpoint, Errno> {
        if self.slots[i].is_none() {
            if self.slots.iter().flatten().count() >= count {
                return Err(Errno(ENOSPC));
            }
            self.slots[i] = Some(Breakpoint::default());
        }
        Ok(self.slots[i].as_mut().expect("initialised above"))
    }

    fn apply(&mut self, bytes: &[u8], count: usize, limit: u64) -> Result<(), Errno> {
        let end = bytes.len().min(SIZE);
        let mut at = 8;
        let mut i = 0;
        while at < end {
            if end - at < 8 {
                return Err(Errno(EINVAL));
            }
            let address = u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
            let bp = self.initialised(i, count)?;
            let proposed = Breakpoint { address, ..*bp };
            proposed.validate(limit)?;
            *bp = proposed;
            at += 8;
            if at == end {
                break;
            }
            if end - at < 4 {
                return Err(Errno(EINVAL));
            }
            let control = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
            let mut proposed = *bp;
            proposed.enabled = control & 1 != 0;
            if proposed.enabled {
                let bas = (control >> 5) & 255;
                if control >> 3 & 3 != 0 || bas == 0 {
                    return Err(Errno(EINVAL));
                }
                let offset = bas.trailing_zeros();
                let run = bas >> offset;
                if run & (run + 1) != 0 {
                    return Err(Errno(EINVAL));
                }
                // ptrace_hbp_fill_attr_ctrl adds BAS's leading offset;
                // A64's arch parser normalizes its contiguous length to 4.
                proposed.address = proposed.address.wrapping_add(u64::from(offset));
                proposed.validate(limit)?;
            }
            *bp = proposed;
            at = (at + 8).min(end); // control plus ignored UAPI padding.
            i += 1;
        }
        Ok(())
    }

    fn install(&self, cpu: &mut A64UserCpu) {
        let mut bank = cpu.core().user_debug_registers();
        bank.breakpoint_control.fill(0);
        bank.breakpoint_value.fill(0);
        for (physical, bp) in self.slots.iter().flatten().enumerate() {
            let (address, control) = bp.hardware();
            bank.breakpoint_control[physical] = u64::from(control);
            bank.breakpoint_value[physical] = address;
        }
        cpu.core_mut().set_user_debug_registers(bank);
    }

    pub(crate) fn clear(&mut self, cpu: &mut GuestCpu) {
        self.slots.fill(None);
        if let GuestCpu::Aarch64(cpu) = cpu {
            self.install(cpu);
        }
    }
}

pub(crate) fn serve(
    t: &mut Thread,
    request: u64,
    note: u64,
    size: u64,
    payload: &[u8],
) -> Option<Result<Vec<u8>, Errno>> {
    if note != regs::NT_ARM_HW_BREAK || !matches!(request, req::GETREGSET | req::SETREGSET) {
        return None;
    }
    let GuestCpu::Aarch64(cpu) = &mut t.cpu else {
        return None;
    };
    Some(if request == req::GETREGSET {
        let mut out = t.arm_debug.get(cpu);
        out.truncate(size.min(SIZE as u64) as usize);
        Ok(out)
    } else {
        t.arm_debug
            .set(cpu, payload)
            .map(|()| size.to_le_bytes().to_vec())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::linux::abi::{LinuxAbi, Sysno};
    use crate::user::linux::tests::harness::{CODE, Harness};

    fn armed(h: &mut Harness) {
        let mut b = vec![0; 24];
        b[8..16].copy_from_slice(&(CODE + 0x1000).to_le_bytes());
        b[16..20].copy_from_slice(&0x1e5u32.to_le_bytes());
        let t = &mut h.proc.threads[0];
        let GuestCpu::Aarch64(cpu) = &mut t.cpu else {
            unreachable!()
        };
        t.arm_debug.set(cpu, &b).unwrap();
    }

    #[test]
    fn metadata_only_writes_and_general_register_updates_preserve_comparators() {
        let mut h = Harness::embedded(LinuxAbi::Aarch64);
        armed(&mut h);
        let t = &mut h.proc.threads[0];
        let GuestCpu::Aarch64(cpu) = &mut t.cpu else {
            unreachable!()
        };
        let before = t.arm_debug.get(cpu);
        t.arm_debug.set(cpu, &[255; 8]).unwrap();
        assert_eq!(t.arm_debug.get(cpu), before);
        let mut general = regs::prstatus(&t.cpu, None);
        general[8..16].copy_from_slice(&42u64.to_le_bytes());
        regs::set_prstatus(&mut t.cpu, &mut t.syscall, &general).unwrap();
        let GuestCpu::Aarch64(cpu) = &t.cpu else {
            unreachable!()
        };
        assert_eq!(cpu.core().get_x(1), 42);
        assert_eq!(t.arm_debug.get(cpu), before);
        assert_eq!(
            cpu.core().user_debug_registers().breakpoint_control[0],
            0x1e5
        );
    }

    #[test]
    fn clone_and_process_fork_clear_objects_and_installed_comparators() {
        use crate::user::linux::syscall::thread::cf::*;
        let mut h = Harness::embedded(LinuxAbi::Aarch64);
        armed(&mut h);
        const THREAD: u64 =
            CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM;
        h.ok(Sysno::Clone, &[THREAD, 0, 0, 0, 0]);
        let child = &h.proc.threads[1];
        let GuestCpu::Aarch64(cpu) = &child.cpu else {
            unreachable!()
        };
        assert!(child.arm_debug.get(cpu)[4..].iter().all(|&v| v == 0));
        assert!(
            cpu.core()
                .user_debug_registers()
                .breakpoint_control
                .iter()
                .all(|&v| v == 0)
        );
        let parent = &mut h.proc.threads[0];
        parent.arm_debug.clear(&mut parent.cpu);
        let GuestCpu::Aarch64(cpu) = &parent.cpu else {
            unreachable!()
        };
        assert!(parent.arm_debug.get(cpu)[4..].iter().all(|&v| v == 0));
        assert!(
            cpu.core()
                .user_debug_registers()
                .breakpoint_control
                .iter()
                .all(|&v| v == 0)
        );
    }

    #[test]
    fn rejected_kernel_address_retains_the_new_default_object() {
        let mut h = Harness::embedded(LinuxAbi::Aarch64);
        let t = &mut h.proc.threads[0];
        let GuestCpu::Aarch64(cpu) = &mut t.cpu else {
            unreachable!()
        };
        let mut b = vec![0; 16];
        b[8..16].copy_from_slice(&(1u64 << 48).to_le_bytes());
        assert_eq!(t.arm_debug.set(cpu, &b), Err(Errno(EINVAL)));
        let state = t.arm_debug.get(cpu);
        assert_eq!(u64::from_le_bytes(state[8..16].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(state[16..20].try_into().unwrap()), 0x1e4);
        assert_eq!(
            cpu.core().user_debug_registers().breakpoint_control[0],
            0x1e4
        );
    }
}
