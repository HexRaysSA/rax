//! System-call entry (Linux 6.19): the bits of the number register that
//! select the call. x86-64 passes it to `do_syscall_64` as an `int` and
//! arm64 to `el0_svc_common` as one, so their upper 32 bits are ignored;
//! RV64's `do_trap_ecall_u` bounds the whole `long` in `a7`.

use super::harness::{Harness, each_abi};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::syscall::Outcome;

#[test]
fn the_number_register_is_read_at_the_kernel_width() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let pid = h.proc.state.pid as u64;
        let getpid = abi.number(Sysno::Getpid).unwrap();
        let high = getpid | 0x5a5a_0000_0000_0000;
        let got = h.proc.dispatch_to_completion(0, high, [0; 6]);
        let want = if abi == LinuxAbi::Riscv64 {
            Outcome::Return(-(ENOSYS as i64) as u64)
        } else {
            Outcome::Return(pid)
        };
        assert_eq!(got, want, "{abi:?}");
        // A number past the table is ENOSYS on every ABI.
        let none = h.proc.dispatch_to_completion(0, 0x7fff_0000, [0; 6]);
        assert_eq!(none, Outcome::Return(-(ENOSYS as i64) as u64));
    });
}
