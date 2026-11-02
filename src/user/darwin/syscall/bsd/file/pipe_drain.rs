//! Closing a pipe descriptor commits EOF for reads entered through that slot.
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
    for thread in proc.threads.values_mut() {
        let Some(entry) = &mut thread.pending_unix else {
            continue;
        };
        if entry.completed.is_some()
            || entry.args[0] as i32 != fd
            || !matches!(
                entry.nr,
                nr::READ | nr::READ_NOCANCEL | nr::READV | nr::READV_NOCANCEL
            )
            || !thread.wait.as_ref().is_some_and(|wait| {
                wait.fds
                    .iter()
                    .any(|&(descriptor, read, _)| descriptor == host && read)
            })
        {
            continue;
        }
        // A readiness wait has no host read in flight. Commit the measured
        // native drain result before the closing descriptor releases the pipe.
        // The owning thread completes its kernel return through its scheduler.
        crate::user::darwin::syscall::complete_unix(thread, Ok(Rv::one(0)));
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
