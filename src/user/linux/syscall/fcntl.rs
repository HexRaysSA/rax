//! Descriptor control: `fcntl` (`fs/fcntl.c`) and `ioctl` (`fs/ioctl.c`,
//! the terminal requests of `drivers/tty/tty_io.c`, and the socket
//! requests, which [`net::ioctl`](super::net::ioctl) answers).

use std::io::IsTerminal;

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::abi::open::*;
use super::super::fs::fd::{FileObject, FileType, OpenFile};
use super::super::fs::locks::Owner;
use super::super::host;
use super::io::nofile;
use super::{Ctx, SysResult};

/// `fcntl` commands (`asm-generic/fcntl.h`, 64-bit numbering).
mod fc {
    pub const F_DUPFD: u32 = 0;
    pub const F_GETFD: u32 = 1;
    pub const F_SETFD: u32 = 2;
    pub const F_GETFL: u32 = 3;
    pub const F_SETFL: u32 = 4;
    pub const F_GETLK: u32 = 5;
    pub const F_SETLK: u32 = 6;
    pub const F_SETLKW: u32 = 7;
    pub const F_SETOWN: u32 = 8;
    pub const F_GETOWN: u32 = 9;
    pub const F_SETSIG: u32 = 10;
    pub const F_GETSIG: u32 = 11;
    pub const F_OFD_GETLK: u32 = 36;
    pub const F_OFD_SETLK: u32 = 37;
    pub const F_OFD_SETLKW: u32 = 38;
    pub const F_DUPFD_QUERY: u32 = 1027;
    pub const F_CREATED_QUERY: u32 = 1028;
    pub const F_DUPFD_CLOEXEC: u32 = 1030;
    pub const F_SETPIPE_SZ: u32 = 1031;
    pub const F_GETPIPE_SZ: u32 = 1032;
    pub const F_ADD_SEALS: u32 = 1033;
    pub const F_GET_SEALS: u32 = 1034;
    pub const FD_CLOEXEC: u64 = 1;
}

/// `fcntl`.
pub fn fcntl(c: &mut Ctx<'_>, fd: i32, cmd: u32, arg: u64) -> SysResult {
    use fc::*;
    let limit = nofile(c);
    // check_fcntl_cmd: an O_PATH descriptor allows only these commands.
    if c.p.fds.file(fd)?.flags() & O_PATH != 0
        && !matches!(
            cmd,
            F_CREATED_QUERY
                | F_DUPFD
                | F_DUPFD_CLOEXEC
                | F_DUPFD_QUERY
                | F_GETFD
                | F_SETFD
                | F_GETFL
        )
    {
        return Err(Errno(EBADF));
    }
    match cmd {
        F_DUPFD | F_DUPFD_CLOEXEC => {
            let file = c.p.fds.file(fd)?;
            if arg as i64 >= limit as i64 || (arg as i32) < 0 {
                return Err(Errno(EINVAL));
            }
            c.p.fds
                .install_from(arg as usize, file, cmd == F_DUPFD_CLOEXEC, limit)
                .map(|n| n as u64)
        }
        F_GETFD => Ok(u64::from(c.p.fds.get(fd)?.cloexec)),
        F_SETFD => {
            c.p.fds.get_mut(fd)?.cloexec = arg & FD_CLOEXEC != 0;
            Ok(0)
        }
        F_GETFL => {
            // f_flags as the file was created: open() forces O_LARGEFILE;
            // pipes and anonymous-inode files have none.
            Ok(u64::from(c.p.fds.file(fd)?.flags()))
        }
        F_SETFL => {
            // SETFL_MASK: O_APPEND | O_NONBLOCK | O_DIRECT | O_NOATIME | FASYNC.
            let file = c.p.fds.file(fd)?;
            let settable = O_APPEND | O_NONBLOCK | O_NOATIME | FASYNC | c.p.abi.open_flags().direct;
            let new = arg as u32 & settable;
            let old = file.flags();
            if (old ^ new) & O_NONBLOCK != 0 {
                set_host_nonblocking(&file, new & O_NONBLOCK != 0)?;
            }
            file.state.lock().unwrap().flags = (old & !settable) | new;
            Ok(0)
        }
        F_GETLK => super::locks::getlk(c, fd, arg, Owner::Process),
        F_OFD_GETLK => super::locks::getlk(c, fd, arg, Owner::Description),
        F_SETLK | F_SETLKW => super::locks::setlk(c, fd, arg, Owner::Process, cmd == F_SETLKW),
        F_OFD_SETLK | F_OFD_SETLKW => {
            super::locks::setlk(c, fd, arg, Owner::Description, cmd == F_OFD_SETLKW)
        }
        F_GETOWN | F_GETSIG => c.p.fds.get(fd).map(|_| 0),
        F_SETOWN | F_SETSIG => c.p.fds.get(fd).map(|_| 0),
        F_GETPIPE_SZ | F_SETPIPE_SZ => {
            let file = c.p.fds.file(fd)?;
            if file.ftype != FileType::Fifo {
                return Err(Errno(EBADF));
            }
            Ok(65536)
        }
        F_ADD_SEALS => {
            let file = c.p.fds.file(fd)?;
            super::memfd::add_seals(c, &file, arg as u32)
        }
        F_GET_SEALS => {
            let file = c.p.fds.file(fd)?;
            super::memfd::get_seals(&file)
        }
        _ => Err(Errno(EINVAL)),
    }
}

/// Applies the guest's `O_NONBLOCK` to the host descriptor. Pipes the guest
/// created stay non-blocking on the host whatever the guest sets: their
/// blocking is emulated, so one thread's transfer never stops the host
/// thread that runs the others.
fn set_host_nonblocking(file: &OpenFile, on: bool) -> Result<(), Errno> {
    match &file.object {
        FileObject::Host(f) => host::set_nonblocking(f, on),
        FileObject::PipeRead(_) | FileObject::PipeWrite(_) => Ok(()),
        FileObject::Synthetic(_)
        | FileObject::PathOnly
        | FileObject::Anon(_)
        | FileObject::Socket(_) => Ok(()),
    }
}

/// Terminal `ioctl` requests (`asm-generic/ioctls.h`).
mod tio {
    pub const TCGETS: u32 = 0x5401;
    pub const TCSETS: u32 = 0x5402;
    pub const TCSETSW: u32 = 0x5403;
    pub const TCSETSF: u32 = 0x5404;
    pub const TIOCSCTTY: u32 = 0x540E;
    pub const TIOCGPGRP: u32 = 0x540F;
    pub const TIOCSPGRP: u32 = 0x5410;
    pub const TIOCGWINSZ: u32 = 0x5413;
    pub const TIOCSWINSZ: u32 = 0x5414;
    pub const FIONREAD: u32 = 0x541B;
    pub const TIOCNOTTY: u32 = 0x5422;
    pub const FIONBIO: u32 = 0x5421;
    pub const FIONCLEX: u32 = 0x5450;
    pub const FIOCLEX: u32 = 0x5451;
    pub const TIOCGPTN: u32 = 0x8004_5430;
}

/// `tty_std_termios` (`drivers/tty/tty_io.c`) as `struct termios`:
/// `c_iflag = ICRNL | IXON`, `c_oflag = OPOST | ONLCR`,
/// `c_cflag = B38400 | CS8 | CREAD | HUPCL`, `c_lflag = ISIG | ICANON | ECHO |
/// ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN`, `c_cc = INIT_C_CC`.
pub fn default_termios() -> [u8; 36] {
    let mut t = [0u8; 36];
    t[0..4].copy_from_slice(&0x0500u32.to_le_bytes());
    t[4..8].copy_from_slice(&0x0005u32.to_le_bytes());
    t[8..12].copy_from_slice(&0x04bfu32.to_le_bytes());
    t[12..16].copy_from_slice(&0x8a3bu32.to_le_bytes());
    t[16] = 0;
    let cc: [u8; 17] = [
        0o3, 0o34, 0o177, 0o25, 0o4, 0, 1, 0, 0o21, 0o23, 0o32, 0, 0o22, 0o17, 0o27, 0o26, 0,
    ];
    t[17..34].copy_from_slice(&cc);
    t
}

fn is_tty(file: &OpenFile) -> bool {
    match &file.object {
        FileObject::Host(f) => f.is_terminal(),
        _ => false,
    }
}

/// `ioctl`.
pub fn ioctl(c: &mut Ctx<'_>, fd: i32, req: u32, arg: u64) -> SysResult {
    use tio::*;
    let file = c.p.fds.file(fd)?;
    if let FileObject::Socket(s) = &file.object
        && !matches!(req, FIOCLEX | FIONCLEX | FIONBIO)
    {
        return super::net::ioctl(c, s, req, arg);
    }
    // do_vfs_ioctl handles these for every file; FIONREAD only for regular
    // files, which a pidfd is not to it.
    if let FileObject::Anon(super::super::fs::anon::Anon::Pid(t)) = &file.object
        && !matches!(req, FIOCLEX | FIONCLEX | FIONBIO)
    {
        return super::pidfd::ioctl(c, t, req, arg);
    }
    match req {
        FIOCLEX | FIONCLEX => {
            c.p.fds.get_mut(fd)?.cloexec = req == FIOCLEX;
            Ok(0)
        }
        FIONBIO => {
            let on = c.read_u32(arg)? != 0;
            set_host_nonblocking(&file, on)?;
            let mut st = file.state.lock().unwrap();
            if on {
                st.flags |= O_NONBLOCK;
            } else {
                st.flags &= !O_NONBLOCK;
            }
            Ok(0)
        }
        FIONREAD => {
            let n = match &file.object {
                FileObject::Host(f) if file.ftype == FileType::Regular => {
                    let len = f.metadata()?.len();
                    let pos = file.seek(0, 1)?;
                    len.saturating_sub(pos).min(i32::MAX as u64) as i32
                }
                FileObject::Host(f) => host::bytes_readable(f)?,
                FileObject::PipeRead(p) => host::bytes_readable(p)?,
                FileObject::Synthetic(d) => {
                    let pos = file.state.lock().unwrap().synth_pos;
                    (d.len() as u64).saturating_sub(pos) as i32
                }
                _ => return Err(Errno(ENOTTY)),
            };
            c.write_u32(arg, n as u32)?;
            Ok(0)
        }
        super::events::TFD_IOC_SET_TICKS
            if matches!(
                file.object,
                FileObject::Anon(super::super::fs::anon::Anon::Timer(_))
            ) =>
        {
            super::events::set_ticks(c, &file, arg)
        }
        TCGETS | TCSETS | TCSETSW | TCSETSF | TIOCGWINSZ | TIOCSWINSZ | TIOCGPGRP | TIOCSPGRP
        | TIOCSCTTY | TIOCNOTTY | TIOCGPTN => {
            if !is_tty(&file) {
                return Err(Errno(ENOTTY));
            }
            match req {
                TCGETS => c.write_mem(arg, &default_termios()).map(|_| 0),
                TCSETS | TCSETSW | TCSETSF => c.read_mem(arg, 36).map(|_| 0),
                TIOCGWINSZ => {
                    let FileObject::Host(f) = &file.object else {
                        return Err(Errno(ENOTTY));
                    };
                    let ws = host::window_size(f)?;
                    let b: Vec<u8> = ws.iter().flat_map(|v| v.to_le_bytes()).collect();
                    c.write_mem(arg, &b).map(|_| 0)
                }
                TIOCSWINSZ => c.read_mem(arg, 8).map(|_| 0),
                TIOCGPGRP => c.write_u32(arg, c.p.pid as u32).map(|_| 0),
                TIOCGPTN => Err(Errno(ENOTTY)),
                _ => Ok(0),
            }
        }
        _ => Err(Errno(ENOTTY)),
    }
}
