//! Machine-dependent calls: x86-64 class 3 (`machdep_syscall64`) and arm64
//! platform calls (`platform_syscall`).

use crate::user::darwin::mach::kr;
use crate::user::darwin::process::{Proc, Thread};

/// `USER_CTHREAD`: the selector `thread_fast_set_cthread_self64` returns.
const USER_CTHREAD: u64 = 0x0f;

/// x86-64 machine-dependent call `nr` (`machdep_call_table64`).
pub fn machdep(proc: &mut Proc, thread: &mut Thread, nr: u32) {
    let arg0 = thread.cpu.reg(7); // RDI
    let r = match nr {
        // thread_fast_set_cthread_self64
        3 => {
            thread.cpu.set_tsd_base(arg0);
            USER_CTHREAD
        }
        // i386_set_ldt64 / i386_get_ldt64: no LDT for 64-bit processes.
        5 | 6 => {
            thread.cpu.set_unix_result(
                crate::user::darwin::abi::Ret::Int,
                Err(crate::user::darwin::abi::Errno::EINVAL),
            );
            return;
        }
        // kern_invalid (including the hypervisor traps 0 and 1).
        _ => kr::KERN_INVALID_ARGUMENT as u64,
    };
    if proc.config.strace {
        eprintln!("[{:#x}] machdep({nr}, {arg0:#x}) = {r:#x}", thread.tid);
    }
    thread.cpu.set_reg(0, r);
}

/// arm64 platform call `code` (`X3`).
pub fn platform(proc: &mut Proc, thread: &mut Thread, code: u32) {
    match code {
        // set cthread self
        2 => {
            let base = thread.cpu.reg(0);
            thread.cpu.set_tsd_base(base);
        }
        // get cthread self
        3 => {
            let base = thread.cpu.tsd_base();
            thread.cpu.set_reg(0, base);
        }
        // I-cache and D-cache flushes (removed): no effect.
        _ => {}
    }
    if proc.config.strace {
        eprintln!(
            "[{:#x}] platform_syscall({code}) x0={:#x}",
            thread.tid,
            thread.cpu.reg(0)
        );
    }
}
