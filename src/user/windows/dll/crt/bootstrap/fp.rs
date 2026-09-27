//! Publisher-body FP reset, including the x86 saved exception-context path.

use crate::user::windows::arch::{WinArch, WinCpu};
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;

use super::{RuntimeKind, runtime, with_ptd};

pub(super) fn reset(c: &mut Ctx) -> ApiResult {
    let kind = runtime(c)?;
    if c.arch() == WinArch::X86 {
        with_ptd(c, kind, Box::new(move |c, cells| snapshot(c, kind, cells)))
    } else {
        reset_cpu(c)?;
        Flow::void()
    }
}

fn snapshot(c: &mut Ctx, kind: RuntimeKind, cells: u64) -> ApiResult {
    match c.mem().u32(cells + 8) {
        Ok(info) => {
            // getptd and the pointer load precede FNINIT in the publisher body.
            reset_cpu(c)?;
            if info == 0 {
                Flow::void()
            } else {
                resume(c, Phase::Context(info))
            }
        }
        Err(fault) => Ok(Flow::RetryFault {
            fault,
            retry: Box::new(move |c, _| snapshot(c, kind, cells)),
        }),
    }
}

fn reset_cpu(c: &mut Ctx) -> Result<(), ApiErr> {
    let mxcsr_error = |error| ApiErr::Internal(format!("CRT _fpreset MXCSR: {error}"));
    match &mut c.t.cpu {
        WinCpu::X86(cpu, WinArch::X86) => {
            let core = cpu.vcpu_mut();
            // FNINIT preserves PHYSICAL binary80 payloads. The publisher's
            // control87 converter then supplies FLDCW operand 0x023F:
            // exception masks 0x003F | PC53 0x0200 | nearest 0x0000.
            // Reserved-bit readback (including bit 6) is not an ISA claim.
            core.init_user_x87(0x023F);
            // The selected user CPU advertises OS-enabled SSE2. This profile
            // admits the publisher's availability>=1 path; mapping arbitrary
            // downlevel CPUs to its private __isa_available is not established.
            if core.cpuid(1, 0).3 & (1 << 26) != 0 {
                core.set_mxcsr(0x1F80).map_err(mxcsr_error)?;
            }
        }
        WinCpu::X86(cpu, WinArch::X64) => cpu.vcpu_mut().set_mxcsr(0x1F80).map_err(mxcsr_error)?,
        WinCpu::X86(_, WinArch::Arm64) => {
            return Err(ApiErr::Internal(
                "CRT _fpreset inconsistent x86 CPU architecture".into(),
            ));
        }
        WinCpu::Arm64(cpu) => {
            cpu.core_mut().set_fpcr_value(0);
            cpu.core_mut().set_fpsr_value(0);
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Phase {
    Context(u32),
    Flags(u32),
    StatusRead(u32),
    StatusWrite(u32),
    TagWrite(u32),
}

/// x86 ModR/M effective addresses wrap modulo 2^32 before checked access.
fn at(base: u32, offset: u32) -> u64 {
    u64::from(base.wrapping_add(offset))
}

fn resume(c: &mut Ctx, mut phase: Phase) -> ApiResult {
    loop {
        let step = match phase {
            Phase::Context(info) => c.mem().u32(at(info, 0x4)).map(Phase::Flags),
            Phase::Flags(context) => {
                let flags = match c.mem().u32(u64::from(context)) {
                    Ok(flags) => flags,
                    Err(fault) => return retry(phase, fault),
                };
                if flags & 0x0001_0008 == 0 {
                    return Flow::void();
                }
                Ok(Phase::StatusRead(context))
            }
            // Publisher AND DWORD PTR [context+0x20],0 reads before writing;
            // do not turn a write-only/read-fault boundary into a blind store.
            Phase::StatusRead(context) => c
                .mem()
                .u32(at(context, 0x20))
                .map(|_| Phase::StatusWrite(context)),
            Phase::StatusWrite(context) => match c.mem().w32(at(context, 0x20), 0) {
                Ok(()) => Ok(Phase::TagWrite(context)),
                // AND is one read-modify-write instruction. A write fault
                // has not retired it: retry its read as well, but none of the
                // preceding pointer loads or FP reset instructions.
                Err(fault) => return retry(Phase::StatusRead(context), fault),
            },
            Phase::TagWrite(context) => match c.mem().w32(at(context, 0x24), 0xFFFF) {
                Ok(()) => return Flow::void(),
                Err(fault) => return retry(phase, fault),
            },
        };
        match step {
            Ok(next) => phase = next,
            Err(fault) => return retry(phase, fault),
        }
    }
}

fn retry(phase: Phase, fault: crate::user::windows::memory::MemFault) -> ApiResult {
    Ok(Flow::RetryFault {
        fault,
        retry: Box::new(move |c, _| resume(c, phase)),
    })
}
