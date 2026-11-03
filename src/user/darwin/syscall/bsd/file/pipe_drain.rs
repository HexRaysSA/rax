//! Closing a pipe slot commits EOF for entered reads and EPIPE for writes.
use crate::user::darwin::abi::Errno;
use crate::user::darwin::abi::tables::nr;
use crate::user::darwin::arch::Rv;
use crate::user::darwin::fd::FileRef;
use crate::user::darwin::process::Proc;

/// The covered Rosetta scalar-read entry exposes CF while its kernel service
/// is parked. Vector reads retain their entry flags. Install this once so a
/// later saved-state write survives a spurious readiness wake.
#[cfg(unix)]
pub(super) fn parked(ctx: &mut crate::user::darwin::syscall::Ctx<'_>, host: i32) {
    if matches!(ctx.nr as u32, nr::READ | nr::READ_NOCANCEL)
        && crate::user::darwin::host::anonymous_pipe(host)
        && let crate::user::darwin::arch::DarwinCpu::X86_64(cpu) = &mut ctx.thread.cpu
    {
        let flags = cpu.vcpu().user_rflags();
        cpu.vcpu_mut().set_user_rflags(flags | 1);
    }
}

pub(super) fn closed(proc: &mut Proc, fd: i32, file: &FileRef) {
    let Some(host) = pipe(file) else { return };
    let entered: Vec<_> = proc
        .threads
        .iter()
        .filter_map(|(&tid, thread)| {
            let entry = thread.pending_unix.as_ref()?;
            let write = match entry.nr {
                nr::READ | nr::READ_NOCANCEL | nr::READV | nr::READV_NOCANCEL => false,
                nr::WRITE
                | nr::WRITE_NOCANCEL
                | nr::WRITEV
                | nr::WRITEV_NOCANCEL
                | nr::GUARDED_WRITE_NP
                | nr::GUARDED_WRITEV_NP => true,
                _ => return None,
            };
            (entry.completed.is_none()
                && entry.args[0] as i32 == fd
                && thread.wait.as_ref().is_some_and(|wait| {
                    wait.fds.iter().any(|&(descriptor, reads, writes)| {
                        descriptor == host && if write { writes } else { reads }
                    })
                }))
            .then_some((tid, write))
        })
        .collect();
    for (tid, write) in entered {
        let mut thread = proc.threads.remove(&tid).expect("listed entered pipe call");
        #[cfg(unix)]
        if write && !super::nosigpipe(host) {
            let origin = crate::user::darwin::signal::Origin::own(proc);
            crate::user::darwin::signal::psignal(
                proc,
                Some(&mut thread),
                crate::user::darwin::signal::SIGPIPE,
                origin,
            );
        }
        // A readiness wait has no host I/O in flight. Commit the measured
        // native drain result before the closing descriptor releases the pipe.
        // The owning thread completes its kernel return through its scheduler.
        let result = if write {
            Err(Errno::EPIPE)
        } else {
            Ok(Rv::one(0))
        };
        crate::user::darwin::syscall::complete_unix(&mut thread, result);
        proc.threads.insert(tid, thread);
    }
}

fn pipe(file: &FileRef) -> Option<i32> {
    let descriptor = file.host_fd()?;
    #[cfg(unix)]
    if crate::user::darwin::host::anonymous_pipe(descriptor) {
        return Some(descriptor);
    }
    #[cfg(not(unix))]
    let _ = descriptor;
    None
}
