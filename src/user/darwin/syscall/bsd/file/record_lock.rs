//! Timed advisory locks sleep cooperatively, retaining the kernel-entry copy.
use super::{Ctx, Duration, Errno, Instant, Rv, SysResult, Wait, cmd, host, lifetime, syscall};

/// Darwin's 24-byte flock, already resolved relative to its entry-time offset.
#[derive(Clone, Copy, Debug)]
pub(super) struct Entered {
    raw: [u8; 24],
    command: i32,
    deadline: Option<Instant>,
}

pub(super) fn wait(ctx: &mut Ctx<'_>, fd: i32, command: i32, argument: u64) -> SysResult {
    let retained = ctx
        .thread
        .file_io
        .as_ref()
        .filter(|entry| entry.fd == fd)
        .and_then(|entry| entry.lock.map(|lock| (entry.file.clone(), lock)));
    let (file, entered) = if let Some((file, lock)) = retained {
        if let Some(error) = crate::user::darwin::signal::sleep_interruption(ctx.proc, ctx.thread) {
            ctx.thread.file_io = None;
            return Err(error);
        }
        if lock
            .deadline
            .is_some_and(|deadline| deadline <= Instant::now())
        {
            ctx.thread.file_io = None;
            return Err(Errno::ETIMEDOUT);
        }
        (file, lock)
    } else {
        let file = ctx.proc.fds.file(fd)?;
        let descriptor = file.host_fd().ok_or(Errno::EBADF)?;
        let mode = host::fstat(descriptor)?.st_mode & libc::S_IFMT;
        // kern_descrip checks DTYPE_VNODE before copying flocktimeout.
        if mode == libc::S_IFIFO || mode == libc::S_IFSOCK {
            return Err(Errno::EBADF);
        }
        let bytes = ctx.read(argument, 40)?;
        let mut raw: [u8; 24] = bytes[..24].try_into().expect("flock bytes");
        let seconds = u64::from_le_bytes(bytes[24..32].try_into().expect("seconds"));
        let nanos = u64::from_le_bytes(bytes[32..40].try_into().expect("nanoseconds"));
        // XNU msleep uses unsigned nanosecond arithmetic, without timespec
        // validation. Exactly {0,0} means no deadline; {-1,1e9} times out
        // immediately only if the lock actually needs to wait.
        let deadline = (seconds != 0 || nanos != 0)
            .then(|| {
                Instant::now().checked_add(Duration::from_nanos(
                    seconds.wrapping_mul(1_000_000_000).wrapping_add(nanos),
                ))
            })
            .flatten();
        let whence = i16::from_le_bytes(raw[22..24].try_into().expect("whence"));
        let kind = i16::from_le_bytes(raw[20..22].try_into().expect("type"));
        // Native controls reject an invalid type before SEEK_END overflow,
        // whereas SEEK_CUR overflow is reported before type validation.
        if whence == libc::SEEK_END as i16 && !matches!(kind, 1..=3) {
            return Err(Errno::EINVAL);
        }
        if whence == libc::SEEK_CUR as i16 || whence == libc::SEEK_END as i16 {
            // A concurrent seek or resize must not redirect an entered lock.
            let offset = if whence == libc::SEEK_CUR as i16 {
                // SAFETY: the retained descriptor's current offset is queried.
                let offset = unsafe { libc::lseek(descriptor, 0, libc::SEEK_CUR) };
                if offset == -1 {
                    return Err(Errno::last());
                }
                offset
            } else {
                host::fstat(descriptor)?.st_size
            };
            let start = i64::from_le_bytes(raw[..8].try_into().expect("start"));
            let start = start.checked_add(offset).ok_or(Errno::EOVERFLOW)?;
            raw[..8].copy_from_slice(&start.to_le_bytes());
            raw[22..24].copy_from_slice(&(libc::SEEK_SET as i16).to_le_bytes());
        }
        (
            file,
            Entered {
                raw,
                command,
                deadline,
            },
        )
    };
    let descriptor = file.host_fd().ok_or(Errno::EBADF)?;
    // SAFETY: flock has no invalid zero initialization; fields are set below.
    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    lock.l_start = i64::from_le_bytes(entered.raw[..8].try_into().expect("start"));
    lock.l_len = i64::from_le_bytes(entered.raw[8..16].try_into().expect("length"));
    // Darwin accepts arbitrary input l_pid when setting a lock. Linux OFD
    // setting requires zero; the retained and user request bytes stay intact.
    lock.l_pid = 0;
    lock.l_type = match i16::from_le_bytes(entered.raw[20..22].try_into().expect("type")) {
        1 => libc::F_RDLCK as _,
        2 => libc::F_UNLCK as _,
        3 => libc::F_WRLCK as _,
        _ => return Err(Errno::EINVAL),
    };
    lock.l_whence = i16::from_le_bytes(entered.raw[22..24].try_into().expect("whence"));
    #[cfg(target_os = "macos")]
    let operation = if entered.command == cmd::F_OFD_SETLKWTIMEOUT {
        cmd::F_OFD_SETLK
    } else {
        libc::F_SETLK
    };
    #[cfg(not(target_os = "macos"))]
    let operation = if entered.command == cmd::F_OFD_SETLKWTIMEOUT {
        libc::F_OFD_SETLK
    } else {
        libc::F_SETLK
    };
    // SAFETY: the retained file and writable flock live for the bounded call.
    if unsafe { libc::fcntl(descriptor, operation, &mut lock) } == 0 {
        ctx.thread.file_io = None;
        return Ok(Rv::one(0));
    }
    let error = Errno::last();
    if error != Errno::EAGAIN && error != Errno::EACCES {
        return Err(error);
    }
    let now = Instant::now();
    if entered.deadline.is_some_and(|deadline| deadline <= now) {
        ctx.thread.file_io = None;
        return Err(Errno::ETIMEDOUT);
    }
    // Host fcntl cannot wake the guest scheduler. Poll at a bounded interval,
    // retaining one absolute timeout rather than restarting it on each wake.
    let retry = now + Duration::from_millis(1);
    let retry = entered
        .deadline
        .map_or(retry, |deadline| deadline.min(retry));
    let result = syscall::sleep(ctx, Wait::until(Some(retry)));
    if ctx.thread.wait.is_some() {
        ctx.thread.file_io = Some(lifetime::Use {
            fd,
            file,
            read: false,
            write: false,
            vectors: None,
            #[cfg(target_os = "macos")]
            read_job: None,
            lock: Some(entered),
        });
    } else {
        ctx.thread.file_io = None;
    }
    result
}
