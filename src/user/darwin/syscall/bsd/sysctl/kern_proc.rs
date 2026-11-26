//! The caller's `KERN_PROC_PID` record in the closed process namespace.

use super::{Req, project_kern_proc};
use crate::user::darwin::{abi::Errno, syscall::Ctx};

const SIZE: usize = 648;
const SIZE_QUERY_SLACK: usize = 5 * SIZE;

// The arm64 and x86-64 user64_kinfo_proc layouts have the same offsets.
const FLAGS: usize = 32;
const STATUS: usize = 36;
const PID: usize = 40;
const STACK: usize = 56;
const COMMAND: usize = 243;
const COMMAND_MAX: usize = 16;
const REAL_UID: usize = 392;
const REAL_GID: usize = 400;
const EFFECTIVE_UID: usize = 420;
const GROUP_COUNT: usize = 424;
const FIRST_GROUP: usize = 428;
const GROUP_PID: usize = 564;
const TERMINAL_DEVICE: usize = 572;
const TERMINAL_GROUP: usize = 576;
const EPROC_FLAGS: usize = 612;
const P_LP64: u32 = 0x0000_0004;
const P_EXEC: u32 = 0x0000_4000;
const SRUN: u8 = 2;
const EPROC_SLEADER: u32 = 2;

pub(super) fn self_pid(ctx: &Ctx<'_>, req: &mut Req) -> Result<(), Errno> {
    if req.newptr != 0 {
        return Err(Errno::EPERM);
    }
    if req.oldptr == 0 {
        // XNU sizes a process-query buffer with five extra record slots.
        req.oldidx = (SIZE + SIZE_QUERY_SLACK) as u64;
        return Ok(());
    }

    let proc = &ctx.proc;
    let Some(member) = &proc.family else {
        return Err(Errno::ESRCH);
    };
    let identity = member.identity(0)?;
    let (ruid, euid, rgid, egid) = proc.creds;
    let mut record = [0; SIZE];
    let flags = P_LP64 | if proc.execed { P_EXEC } else { 0 };
    record[FLAGS..FLAGS + 4].copy_from_slice(&flags.to_le_bytes());
    record[STATUS] = SRUN;
    record[PID..PID + 4].copy_from_slice(&proc.pid.to_le_bytes());
    record[STACK..STACK + 8].copy_from_slice(&proc.program.stack.top.to_le_bytes());
    let name = super::super::proc::image_name(ctx);
    let name = &name[..name.len().min(COMMAND_MAX)];
    record[COMMAND..COMMAND + name.len()].copy_from_slice(name);
    record[REAL_UID..REAL_UID + 4].copy_from_slice(&ruid.to_le_bytes());
    record[REAL_GID..REAL_GID + 4].copy_from_slice(&rgid.to_le_bytes());
    record[EFFECTIVE_UID..EFFECTIVE_UID + 4].copy_from_slice(&euid.to_le_bytes());
    record[GROUP_COUNT..GROUP_COUNT + 2].copy_from_slice(&1u16.to_le_bytes());
    record[FIRST_GROUP..FIRST_GROUP + 4].copy_from_slice(&egid.to_le_bytes());
    record[GROUP_PID..GROUP_PID + 4].copy_from_slice(&identity.group.to_le_bytes());
    record[TERMINAL_DEVICE..TERMINAL_DEVICE + 4].copy_from_slice(&(-1i32).to_le_bytes());
    record[TERMINAL_GROUP..TERMINAL_GROUP + 4].copy_from_slice(&(-1i32).to_le_bytes());
    if proc.pid == identity.session {
        record[EPROC_FLAGS..EPROC_FLAGS + 4].copy_from_slice(&EPROC_SLEADER.to_le_bytes());
    }

    project_kern_proc(&mut record, |pid| {
        let (traced, original, parent, exit) =
            super::super::ptrace::known_process_info(&proc.tracing, proc.pid, proc.ppid, pid)?;
        let signal = super::super::ptrace::known_signal_status(&proc.tracing, proc.pid, pid);
        Some((traced, original, signal, parent, exit))
    });
    req.out(ctx, &record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::darwin::{
        abi::{DarwinAbi, tables::nr},
        arch::Rv,
        process::bounded_tests::process_with_profile,
        syscall::bsd,
    };

    #[test]
    fn closed_self_pid_reports_guest_identity_and_native_copyout() {
        for abi in [DarwinAbi::Arm64, DarwinAbi::X86_64] {
            let mut run = process_with_profile(abi, true);
            let proc = &mut run.proc;
            proc.creds = (1234, 1235, 34, 35);
            proc.ppid = 123;
            let (_, mut thread) = proc.threads.pop_first().unwrap();
            let stack = thread.cpu.sp();
            let mib = stack - 64;
            let length = stack - 80;
            let output = stack - 1024;
            let mut ctx = Ctx {
                proc,
                thread: &mut thread,
                nr: i64::from(nr::SYSCTL),
                pc: 0,
            };
            let pid = ctx.proc.pid;
            for (index, word) in [1, 14, 1, pid].into_iter().enumerate() {
                ctx.write_u32(mib + 4 * index as u64, word as u32).unwrap();
            }
            let call = |ctx: &mut Ctx<'_>, old, new| {
                bsd::call(ctx, nr::SYSCTL, &[mib, 4, old, length, new, 4, 0, 0])
            };
            ctx.write_u64(length, 0).unwrap();
            assert_eq!(call(&mut ctx, 0, 0), Ok(Rv::one(0)));
            assert_eq!(ctx.read_u64(length).unwrap(), 3888);
            for room in [0, SIZE - 1] {
                ctx.write(output, &[0xa5; SIZE + 1]).unwrap();
                ctx.write_u64(length, room as u64).unwrap();
                assert_eq!(call(&mut ctx, output, 0), Err(Errno::ENOMEM));
                assert_eq!(ctx.read_u64(length).unwrap(), 0);
                assert_eq!(ctx.read(output, SIZE + 1).unwrap(), [0xa5; SIZE + 1]);
            }
            ctx.write_u64(length, SIZE as u64).unwrap();
            assert_eq!(call(&mut ctx, output, mib), Err(Errno::EPERM));
            assert_eq!(ctx.read_u64(length).unwrap(), SIZE as u64);
            assert_eq!(ctx.read(output, SIZE + 1).unwrap(), [0xa5; SIZE + 1]);
            assert_eq!(call(&mut ctx, output, 0), Ok(Rv::one(0)));
            assert_eq!(ctx.read_u64(length).unwrap(), SIZE as u64);
            assert_eq!(
                ctx.read_u32(output + FLAGS as u64).unwrap(),
                P_LP64 | P_EXEC
            );
            assert_eq!(ctx.read_u32(output + PID as u64).unwrap(), pid as u32);
            assert_eq!(ctx.read_u32(output + 560).unwrap(), 123);
            assert_eq!(ctx.read_u32(output + GROUP_PID as u64).unwrap(), pid as u32);
            assert_eq!(ctx.read_u32(output + REAL_UID as u64).unwrap(), 1234);
            assert_eq!(ctx.read_u32(output + EFFECTIVE_UID as u64).unwrap(), 1235);
            assert_eq!(ctx.read_u32(output + FIRST_GROUP as u64).unwrap(), 35);
            assert_eq!(ctx.read(output + SIZE as u64, 1).unwrap(), [0xa5]);
        }
    }
}
