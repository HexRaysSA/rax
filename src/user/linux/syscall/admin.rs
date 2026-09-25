//! Machine administration (Linux 6.19): the calls that act on the machine
//! rather than on the caller's own objects — swap (`mm/swapfile.c`),
//! rebooting (`kernel/reboot.c`), process accounting (`kernel/acct.c`), the
//! host and domain names (`kernel/sys.c`), terminal hang-up and the root
//! directory (`fs/open.c`), I/O ports (`arch/x86/kernel/ioport.c`), modules
//! (`kernel/module/main.c`), kexec (`kernel/kexec.c`), and the kernel log
//! (`kernel/printk/printk.c`).
//!
//! Each call makes the kernel's checks in the kernel's order. At its
//! capability check an unprivileged caller fails with `EPERM`. Root holds
//! every capability (as `capget` reports), so it passes; the argument checks
//! that follow still apply, and the change itself is refused with
//! `EOPNOTSUPP`, since the machine is not the guest's to change.
//!
//! | Call | Before the capability check | Capability | Root, after it |
//! |---|---|---|---|
//! | `swapon` | flags outside `SWAP_FLAGS_VALID`: `EINVAL` | `CAP_SYS_ADMIN` | refused |
//! | `swapoff` | — | `CAP_SYS_ADMIN` | refused |
//! | `reboot` | — | `CAP_SYS_BOOT` | bad magic, unknown command (and `LINUX_REBOOT_CMD_KEXEC`, without kexec): `EINVAL`; `RESTART2`'s string: `EFAULT`; refused |
//! | `acct` | — | `CAP_SYS_PACCT` | accounting off (`NULL`): 0, as it is off; on: refused |
//! | `sethostname`, `setdomainname` | — | `CAP_SYS_ADMIN` | length outside 0..=64: `EINVAL`; the name: `EFAULT`; refused |
//! | `vhangup` | — | `CAP_SYS_TTY_CONFIG` | refused |
//! | `iopl` | level above 3: `EINVAL`; level 0 (the current one): 0 | `CAP_SYS_RAWIO` | refused |
//! | `ioperm` | range empty, wrapping, or past port 65535: `EINVAL`; turning off: 0 (no bitmap) | `CAP_SYS_RAWIO` | refused |
//! | `init_module` | — | `CAP_SYS_MODULE` | image shorter than an ELF header: `ENOEXEC`; larger than memory: `ENOMEM`; the image: `EFAULT`; refused |
//! | `finit_module` | — | `CAP_SYS_MODULE` | unknown flags: `EINVAL`; the descriptor: `EBADF`; refused |
//! | `delete_module` | — | `CAP_SYS_MODULE` | the name: `EFAULT`; no such module (none are loaded): `ENOENT` |
//! | `syslog` | — | `CAP_SYSLOG` (every action, with `dmesg_restrict` set) | an empty log (below) |
//! | `chroot` | the directory's lookup and search permission | `CAP_SYS_CHROOT` | refused |
//!
//! The kernel log is empty: this kernel writes no messages. `dmesg_restrict`
//! is 1 (`/proc/sys/kernel/dmesg_restrict`), so every `syslog` action needs
//! `CAP_SYSLOG`. For root, reading waits for a message that never comes
//! (until a signal, `-ERESTARTSYS`), reading all returns nothing, the
//! console actions and clearing succeed, the unread size is 0, and the
//! buffer size is `CONFIG_LOG_BUF_SHIFT`'s default, 128 KiB.
//!
//! kexec is absent (`ENOSYS`), as in a kernel built without `CONFIG_KEXEC`
//! and `CONFIG_KEXEC_FILE` such as the reference kernel.

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::procfs::ProcEntry;
use super::super::signal::deliver::restart::ERESTARTSYS;
use super::super::wait::{Resume, Wait};
use super::path::{self, AT_FDCWD, Target};
use super::{Ctx, Outcome, SysResult};

/// Whether the caller holds the capabilities (an effective UID of 0).
pub(super) fn capable(c: &Ctx<'_>) -> bool {
    c.p.creds.1 == 0
}

/// A capability check: `EPERM` unless the caller holds the capabilities.
pub(super) fn capability(c: &Ctx<'_>) -> Result<(), Errno> {
    if capable(c) {
        Ok(())
    } else {
        Err(Errno(EPERM))
    }
}

/// A privileged change to the machine, refused.
pub(super) fn refused() -> SysResult {
    Err(Errno(EOPNOTSUPP))
}

/// `SWAP_FLAGS_VALID` (`linux/swap.h`): the priority, `SWAP_FLAG_PREFER`,
/// and the three discard flags.
const SWAP_FLAGS_VALID: u32 = 0x7fff | 0x8000 | 0x1_0000 | 0x2_0000 | 0x4_0000;

/// `swapon`: the flags, then `CAP_SYS_ADMIN`.
pub fn swapon(c: &Ctx<'_>, flags: i32) -> SysResult {
    if flags as u32 & !SWAP_FLAGS_VALID != 0 {
        return Err(Errno(EINVAL));
    }
    capability(c)?;
    refused()
}

/// `swapoff`: `CAP_SYS_ADMIN` first.
pub fn swapoff(c: &Ctx<'_>) -> SysResult {
    capability(c)?;
    refused()
}

/// `reboot` magic numbers and commands (`linux/reboot.h`).
mod boot {
    pub const MAGIC1: u32 = 0xfee1_dead;
    pub const MAGIC2: [u32; 4] = [672_274_793, 85_072_278, 369_367_448, 537_993_216];
    pub const CMD_RESTART: u32 = 0x0123_4567;
    pub const CMD_HALT: u32 = 0xcdef_0123;
    pub const CMD_CAD_ON: u32 = 0x89ab_cdef;
    pub const CMD_CAD_OFF: u32 = 0;
    pub const CMD_POWER_OFF: u32 = 0x4321_fedc;
    pub const CMD_RESTART2: u32 = 0xa1b2_c3d4;
    pub const CMD_SW_SUSPEND: u32 = 0xd000_fce2;
}

/// `reboot`: `CAP_SYS_BOOT`, then the magic numbers, then the command
/// (`LINUX_REBOOT_CMD_KEXEC` is unknown without `CONFIG_KEXEC_CORE`;
/// `RESTART2` copies its string first).
pub fn reboot(c: &Ctx<'_>, magic1: i32, magic2: i32, cmd: u32, arg: u64) -> SysResult {
    use boot::*;
    capability(c)?;
    if magic1 as u32 != MAGIC1 || !MAGIC2.contains(&(magic2 as u32)) {
        return Err(Errno(EINVAL));
    }
    match cmd {
        CMD_RESTART2 => {
            // strncpy_from_user of at most 255 bytes: a longer string is
            // cut, not refused.
            c.p.space.read_cstr(arg, 254).map_err(|_| Errno(EFAULT))?;
            refused()
        }
        CMD_RESTART | CMD_HALT | CMD_CAD_ON | CMD_CAD_OFF | CMD_POWER_OFF | CMD_SW_SUSPEND => {
            refused()
        }
        _ => Err(Errno(EINVAL)),
    }
}

/// `acct`: `CAP_SYS_PACCT`; accounting is off, so turning it off succeeds.
pub fn acct(c: &Ctx<'_>, name: u64) -> SysResult {
    capability(c)?;
    if name == 0 { Ok(0) } else { refused() }
}

/// `__NEW_UTS_LEN`.
const NEW_UTS_LEN: i32 = 64;

/// `sethostname` and `setdomainname`: `CAP_SYS_ADMIN` over the UTS
/// namespace, then the length, then the name.
pub fn setname(c: &Ctx<'_>, name: u64, len: i32) -> SysResult {
    capability(c)?;
    if !(0..=NEW_UTS_LEN).contains(&len) {
        return Err(Errno(EINVAL));
    }
    if len > 0 {
        c.read_mem(name, len as usize)?;
    }
    refused()
}

/// `vhangup`: `CAP_SYS_TTY_CONFIG`.
pub fn vhangup(c: &Ctx<'_>) -> SysResult {
    capability(c)?;
    refused()
}

/// `iopl`: the level, then, to raise it above the current level 0,
/// `CAP_SYS_RAWIO`.
pub fn iopl(c: &Ctx<'_>, level: u32) -> SysResult {
    if level > 3 {
        return Err(Errno(EINVAL));
    }
    if level == 0 {
        return Ok(0);
    }
    capability(c)?;
    refused()
}

/// `IO_BITMAP_BITS`: the I/O port space.
const IO_BITMAP_BITS: u64 = 65536;

/// `ioperm`: the range, then, to grant ports, `CAP_SYS_RAWIO`; revoking
/// them from a thread without a bitmap changes nothing.
pub fn ioperm(c: &Ctx<'_>, from: u64, num: u64, turn_on: i32) -> SysResult {
    let end = from.wrapping_add(num);
    if end <= from || end > IO_BITMAP_BITS {
        return Err(Errno(EINVAL));
    }
    if turn_on == 0 {
        return Ok(0);
    }
    capability(c)?;
    refused()
}

/// The size of an ELF header (`sizeof(Elf64_Ehdr)`).
const ELF64_EHDR: u64 = 64;

/// `init_module`: `CAP_SYS_MODULE`, then the image (`copy_module_from_user`:
/// its length, the kernel's copy of it, which cannot outgrow memory, and
/// the copy).
pub fn init_module(c: &Ctx<'_>, image: u64, len: u64) -> SysResult {
    capability(c)?;
    if len < ELF64_EHDR {
        return Err(Errno(ENOEXEC));
    }
    if len > c.p.config.arena_bytes {
        return Err(Errno(ENOMEM));
    }
    c.p.space
        .probe(image, len as usize, crate::error::MemoryAccessKind::Read)
        .map_err(|_| Errno(EFAULT))?;
    refused()
}

/// `MODULE_INIT_IGNORE_MODVERSIONS`, `MODULE_INIT_IGNORE_VERMAGIC`, and
/// `MODULE_INIT_COMPRESSED_FILE` (`linux/module.h`).
const MODULE_INIT_FLAGS: u32 = 1 | 2 | 4;

/// `finit_module`: `CAP_SYS_MODULE`, then the flags, then the descriptor.
pub fn finit_module(c: &Ctx<'_>, fd: i32, flags: i32) -> SysResult {
    capability(c)?;
    if flags as u32 & !MODULE_INIT_FLAGS != 0 {
        return Err(Errno(EINVAL));
    }
    c.p.fds.file(fd)?;
    refused()
}

/// `MODULE_NAME_LEN` (`linux/moduleparam.h`): 64 bytes less a `long`.
const MODULE_NAME_LEN: usize = 64 - 8;

/// `delete_module`: `CAP_SYS_MODULE`, then the name; no module is loaded.
pub fn delete_module(c: &Ctx<'_>, name: u64) -> SysResult {
    capability(c)?;
    // strncpy_from_user of MODULE_NAME_LEN bytes: an empty or unterminated
    // name is ENOENT, as is every other name.
    c.p.space
        .read_cstr(name, MODULE_NAME_LEN - 1)
        .map_err(|_| Errno(EFAULT))?;
    Err(Errno(ENOENT))
}

/// `SYSLOG_ACTION_*` (`linux/syslog.h`).
mod log {
    pub const CLOSE: i32 = 0;
    pub const OPEN: i32 = 1;
    pub const READ: i32 = 2;
    pub const READ_ALL: i32 = 3;
    pub const READ_CLEAR: i32 = 4;
    pub const CLEAR: i32 = 5;
    pub const CONSOLE_OFF: i32 = 6;
    pub const CONSOLE_ON: i32 = 7;
    pub const CONSOLE_LEVEL: i32 = 8;
    pub const SIZE_UNREAD: i32 = 9;
    pub const SIZE_BUFFER: i32 = 10;
    /// `1 << CONFIG_LOG_BUF_SHIFT`, at its default of 17.
    pub const BUF_LEN: u64 = 1 << 17;
}

/// `syslog` (`do_syslog` from `SYSLOG_FROM_READER`): with `dmesg_restrict`
/// set every action needs `CAP_SYSLOG`; then the action, on an empty log.
pub fn syslog(c: &mut Ctx<'_>, action: i32, buf: u64, len: i32) -> Result<Outcome, Errno> {
    use log::*;
    capability(c)?;
    let read = |c: &Ctx<'_>| -> Result<bool, Errno> {
        if buf == 0 || len < 0 {
            return Err(Errno(EINVAL));
        }
        if len == 0 {
            return Ok(false);
        }
        if !super::events::access_ok(c, buf, len as u64) {
            return Err(Errno(EFAULT));
        }
        Ok(true)
    };
    let n = match action {
        CLOSE | OPEN | CLEAR | CONSOLE_OFF | CONSOLE_ON | SIZE_UNREAD => 0,
        READ => {
            if read(c)? {
                // syslog_print waits for a record; none is ever written.
                if c.signal_pending() {
                    return Err(Errno(ERESTARTSYS));
                }
                return Err(c.block(Wait::event(), Resume::Retry));
            }
            0
        }
        READ_ALL | READ_CLEAR => {
            read(c)?;
            0
        }
        CONSOLE_LEVEL => {
            if !(1..=8).contains(&len) {
                return Err(Errno(EINVAL));
            }
            0
        }
        SIZE_BUFFER => BUF_LEN,
        _ => return Err(Errno(EINVAL)),
    };
    Ok(Outcome::Return(n))
}

/// `X_OK`.
const X_OK: u32 = 1;

/// `chroot`: the directory's lookup (`LOOKUP_FOLLOW | LOOKUP_DIRECTORY`)
/// and search permission (`MAY_EXEC | MAY_CHDIR`), then `CAP_SYS_CHROOT`.
pub fn chroot(c: &Ctx<'_>, dir: u64) -> SysResult {
    searchable(c, path::resolve(c, AT_FDCWD, dir, 0, true)?)?;
    capability(c)?;
    refused()
}

/// Whether `t` is a directory the caller may search.
fn searchable(c: &Ctx<'_>, t: Target) -> Result<(), Errno> {
    match t {
        Target::Host { host, .. } => {
            if !std::fs::metadata(&host)?.is_dir() {
                return Err(Errno(ENOTDIR));
            }
            super::super::host::access(&host, X_OK, true, true)
        }
        Target::Proc(ProcEntry::Dir(_), _) => Ok(()),
        Target::Proc(ProcEntry::Link(link), _) => {
            searchable(c, path::resolve_str(c, AT_FDCWD, &link, true)?)
        }
        Target::Proc(..) => Err(Errno(ENOTDIR)),
        Target::Fd(f) => {
            if f.ftype == super::super::fs::fd::FileType::Directory {
                Ok(())
            } else {
                Err(Errno(ENOTDIR))
            }
        }
    }
}
