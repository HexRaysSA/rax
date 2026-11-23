//! Syscall transfers and readiness for anonymous pipes without host handles.

use super::{Ctx, Errno, Rv, SysResult, lifetime};
use crate::error::MemoryAccessKind;
use crate::user::darwin::fd::pipe::{
    PIPE_BUF, POLL_WATCH, POLL_WRITE, POLLIN, POLLNVAL, POLLRDNORM, PipeCondition,
};
use crate::user::darwin::fd::{EmbeddedFile, FileKind, FileRef, NOFILE_HARD};
use crate::user::darwin::io;
use crate::user::darwin::syscall;
use crate::user::darwin::wait::{Wait, WaitKey};

/// The vector has already been decoded and bounded at syscall entry.
pub(super) fn transfer(
    ctx: &mut Ctx<'_>,
    fd: i32,
    file: &FileRef,
    vectors: Vec<(u64, u64)>,
    offset: Option<i64>,
    read: bool,
) -> SysResult {
    let end = file.pipe_end().expect("guest pipe");
    end.check(read, offset)?;
    let total = vectors.iter().map(|&(_, len)| len as usize).sum::<usize>();
    let entered = ctx.thread.file_io.as_ref();
    let started = entered.is_some();
    let done = entered.map_or(0, |entered| entered.pipe_written);
    if started && let Some(interruption) = super::signal::sleep_interruption(ctx.proc, ctx.thread) {
        return partial(done, interruption);
    }
    let nonblock = *file.flags.lock().map_err(|_| Errno::EIO)? & io::O_NONBLOCK != 0;
    if read {
        match end.read_with(total, |bytes| copy_out(ctx, &vectors, bytes)) {
            Ok(n) => Ok(Rv::one(n as u64)),
            Err(Errno::EAGAIN) if !nonblock => park(ctx, fd, file, vectors, PipeCondition::Read, 0),
            Err(error) => Err(error),
        }
    } else {
        let atomic = total <= PIPE_BUF;
        let remaining = total - done;
        let n = match end.write_with(remaining, atomic, !started, |count| {
            copy_in(ctx, &vectors, done, count)
        }) {
            Ok(n) => n,
            Err(Errno::EAGAIN) if !nonblock => 0,
            Err(Errno::EPIPE) => {
                if !end.no_sigpipe() {
                    super::post_sigpipe(ctx.proc, ctx.thread);
                }
                return Err(Errno::EPIPE);
            }
            Err(error) => return Err(error),
        };
        let done = done + n;
        if done == total || nonblock {
            return Ok(Rv::one(done as u64));
        }
        let space = if atomic { total } else { 1 };
        park(ctx, fd, file, vectors, PipeCondition::Write(space), done)
    }
}

fn partial(done: usize, error: Errno) -> SysResult {
    if done == 0 {
        Err(error)
    } else {
        Ok(Rv::one(done as u64))
    }
}

fn park(
    ctx: &mut Ctx<'_>,
    fd: i32,
    file: &FileRef,
    vectors: Vec<(u64, u64)>,
    condition: PipeCondition,
    done: usize,
) -> SysResult {
    let pipe = file.pipe_end().expect("guest pipe").wait(condition);
    let result = syscall::sleep(
        ctx,
        Wait {
            pipes: vec![pipe],
            ..Wait::until(None)
        },
    );
    if ctx.thread.wait.is_some() {
        lifetime::parked_pipe(
            ctx,
            fd,
            file,
            condition == PipeCondition::Read,
            vectors,
            done,
        );
        return result;
    }
    if done != 0 {
        return Ok(Rv::one(done as u64));
    }
    result
}

/// Return the guest spans covering a bounded section of an already-decoded vector.
fn spans(
    vectors: &[(u64, u64)],
    mut skip: usize,
    mut count: usize,
) -> impl Iterator<Item = Result<(u64, usize), Errno>> + '_ {
    vectors.iter().filter_map(move |&(base, len)| {
        let len = len as usize;
        if skip >= len {
            skip -= len;
            return None;
        }
        let n = (len - skip).min(count);
        let start = base.checked_add(skip as u64).ok_or(Errno::EFAULT);
        skip = 0;
        count -= n;
        (n != 0).then(|| start.map(|start| (start, n)))
    })
}

fn copy_in(
    ctx: &Ctx<'_>,
    vectors: &[(u64, u64)],
    skip: usize,
    count: usize,
) -> Result<Vec<u8>, Errno> {
    let mut bytes = Vec::with_capacity(count);
    for span in spans(vectors, skip, count) {
        let (base, n) = span?;
        bytes.extend(ctx.read(base, n)?);
    }
    Ok(bytes)
}

fn copy_out(ctx: &Ctx<'_>, vectors: &[(u64, u64)], bytes: &[u8]) -> Result<(), Errno> {
    for span in spans(vectors, 0, bytes.len()) {
        let (base, n) = span?;
        ctx.space()
            .probe(base, n, MemoryAccessKind::Write)
            .map_err(|_| Errno::EFAULT)?;
    }
    let mut offset = 0;
    for span in spans(vectors, 0, bytes.len()) {
        let (base, n) = span?;
        ctx.write(base, &bytes[offset..offset + n])?;
        offset += n;
    }
    Ok(())
}

pub(super) fn poll(ctx: &mut Ctx<'_>, fds: u64, nfds: u32, timeout: i32) -> SysResult {
    let count = u64::from(nfds);
    if count > NOFILE_HARD
        || (count > ctx.proc.rlimits[8].0 && (ctx.proc.creds.1 != 0 || count > 1024))
    {
        return Err(Errno::EINVAL);
    }
    let mut raw = ctx.read(fds, 8 * nfds as usize)?;
    let mut waits = Vec::new();
    let mut ready = 0;
    for entry in raw.chunks_exact_mut(8) {
        let fd = i32::from_le_bytes(entry[..4].try_into().expect("pollfd fd"));
        let events = i16::from_le_bytes([entry[4], entry[5]]);
        let revents = if fd < 0 || events & POLL_WATCH == 0 {
            0
        } else if let Ok(file) = ctx.proc.fds.file(fd) {
            match &file.kind {
                FileKind::Embedded(EmbeddedFile::Pipe(end)) => {
                    let revents = end.poll(events);
                    if revents == 0 && timeout != 0 {
                        waits.push(end.wait(PipeCondition::Poll(events)));
                    }
                    revents
                }
                FileKind::Embedded(EmbeddedFile::Input(_)) => events & (POLLIN | POLLRDNORM),
                FileKind::Embedded(EmbeddedFile::Output(..)) => events & POLL_WRITE,
                FileKind::Embedded(_) => events & (POLLIN | POLLRDNORM | POLL_WRITE),
                _ => POLLNVAL,
            }
        } else {
            POLLNVAL
        };
        entry[6..].copy_from_slice(&revents.to_le_bytes());
        ready += u64::from(revents != 0);
    }
    if ready != 0 || timeout == 0 || super::expired(ctx) {
        ctx.write(fds, &raw)?;
        return Ok(Rv::one(ready));
    }
    let timeout = (timeout >= 0).then(|| super::Duration::from_millis(timeout as u64));
    let deadline = super::deadline(ctx, timeout);
    syscall::sleep_no_restart(
        ctx,
        Wait {
            pipes: waits,
            keys: vec![WaitKey::DescriptorClosed],
            ..Wait::until(deadline)
        },
    )
}
