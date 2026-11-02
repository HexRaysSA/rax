//! Linux v6.19 arm64 do_fpsimd_exc: ordered syndrome flags,send_sig_fault.
//! Primary: https://github.com/torvalds/linux/blob/v6.19/arch/arm64/kernel/fpsimd.c
use super::CpuEvent;
use crate::user::linux::signal::frame::FaultUpdate;
use crate::user::linux::signal::{SIGFPE, SigInfo, code};
pub(super) fn event(pc: u64, iss: u32) -> CpuEvent {
    let signal_code = if iss & (1 << 23) == 0 {
        code::FPE_FLTUNK
    } else {
        [
            (1, code::FPE_FLTINV),
            (2, code::FPE_FLTDIV),
            (4, code::FPE_FLTOVF),
            (8, code::FPE_FLTUND),
            (16, code::FPE_FLTRES),
        ]
        .into_iter()
        .find_map(|(flag, code)| (iss & flag != 0).then_some(code))
        .unwrap_or(code::FPE_FLTUNK)
    };
    CpuEvent::Signal(SigInfo::fault(SIGFPE, signal_code, pc), FaultUpdate::None)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signal_priority_validity_and_unknown_denormal_match_kernel() {
        for (status, expected) in [
            (0, 14),
            (1, 7),
            (2, 3),
            (4, 4),
            (8, 5),
            (16, 6),
            (128, 14),
            (0x9f, 7),
            (0x1c, 4),
        ] {
            let CpuEvent::Signal(info, FaultUpdate::None) = event(0x1234, (1 << 23) | status)
            else {
                panic!()
            };
            assert_eq!(info.signo, SIGFPE);
            assert_eq!(info.code, expected);
        }
        let CpuEvent::Signal(info, FaultUpdate::None) = event(0x1234, 0x9f) else {
            panic!()
        };
        assert_eq!(info.code, 14);
    }
}

#[cfg(test)]
#[path = "fp_exceptions/tests.rs"]
mod adapter_tests;
