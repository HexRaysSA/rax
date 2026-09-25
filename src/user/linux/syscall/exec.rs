//! `execve` and `execveat` (`fs/exec.c`: `do_execveat_common`,
//! `alloc_bprm`, `do_open_execat`, `bprm_stack_limits`, `copy_strings`,
//! `exec_binprm`; `fs/binfmt_script.c`).
//!
//! Checks run in the kernel's order: the file name, then opening the file
//! for execution, then counting and copying the argument and environment
//! strings, then the binary handlers (a `#!` script names its interpreter,
//! up to five in a chain). Only a complete new image replaces the process
//! ([`commit_exec`](crate::user::linux::process::LinuxProcess::commit_exec)).
//!
//! A file readable only by its execute permission cannot be read on the
//! host, so it fails with `EACCES` where Linux runs it.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::exec::{self, BINPRM_BUF_SIZE, ImageRequest, ScriptError};
use super::super::fs::PATH_MAX;
use super::super::fsnotify::bits::IN_ACCESS;
use super::super::process::SpawnError;
use super::super::procfs::ProcEntry;
use super::path::{AT_EMPTY_PATH, AT_FDCWD, AT_SYMLINK_NOFOLLOW, Target, resolve_str};
use super::{Ctx, Outcome};

/// `MAX_ARG_STRLEN`: 32 pages, a string's length with its NUL.
const MAX_ARG_STRLEN: usize = 32 * 4096;
/// `MAX_ARG_STRINGS`.
const MAX_ARG_STRINGS: usize = 0x7fff_ffff;
/// `_STK_LIM`.
const STK_LIM: u64 = 8 << 20;
/// `ARG_MAX`: 32 pages of strings are always allowed.
const ARG_MAX: u64 = 32 * 4096;

/// A file opened for execution (`do_open_execat`).
struct ExecFile {
    /// Host path.
    host: PathBuf,
    /// Absolute guest path (`d_path`, for `/proc/self/exe`).
    guest: String,
}

/// Whether the caller may execute a file with `mode` owned by `uid`/`gid`
/// (`generic_permission` with `MAY_EXEC`; root needs one execute bit).
fn may_exec(c: &Ctx<'_>, meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    let mode = meta.permissions().mode();
    let (euid, egid) = (c.p.creds.1, c.p.creds.3);
    if euid == 0 {
        return mode & 0o111 != 0;
    }
    let bits = if meta.uid() == euid {
        mode >> 6
    } else if meta.gid() == egid {
        mode >> 3
    } else {
        mode
    };
    bits & 1 != 0
}

/// `do_open_execat` for `path` relative to `dirfd`: the file must be a
/// regular file the caller may execute (`EACCES`).
fn open_exec(c: &Ctx<'_>, dirfd: i32, path: &str, flags: u32) -> Result<ExecFile, Errno> {
    let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
    let target = if path.is_empty() {
        Target::Fd(c.p.fds.file(dirfd)?)
    } else {
        resolve_str(c, dirfd, path, follow)?
    };
    open_target(c, target, follow, 0)
}

fn open_target(c: &Ctx<'_>, target: Target, follow: bool, depth: u32) -> Result<ExecFile, Errno> {
    match target {
        Target::Proc(ProcEntry::Link(link), _) if follow && depth < 40 => {
            let next = resolve_str(c, AT_FDCWD, &link, true)?;
            open_target(c, next, true, depth + 1)
        }
        Target::Proc(ProcEntry::Link(_), _) => Err(Errno(ELOOP)),
        // Synthesized files are neither regular executables nor
        // executable.
        Target::Proc(..) => Err(Errno(EACCES)),
        Target::Fd(file) => {
            let host = file.host_path.clone().ok_or(Errno(EACCES))?;
            check_exec(c, &host, true)?;
            Ok(ExecFile {
                guest: c.p.vfs.guest_path_of(&host),
                host,
            })
        }
        Target::Host { guest: _, host } => {
            check_exec(c, &host, follow)?;
            let real = std::fs::canonicalize(&host).unwrap_or_else(|_| host.clone());
            Ok(ExecFile {
                guest: c.p.vfs.guest_path_of(&real),
                host,
            })
        }
    }
}

/// `may_open` with `MAY_EXEC`: a directory or other non-regular file is
/// `EACCES`, as is a file without execute permission; a symbolic link that
/// may not be followed is `ELOOP`.
fn check_exec(c: &Ctx<'_>, host: &std::path::Path, follow: bool) -> Result<(), Errno> {
    let meta = if follow {
        std::fs::metadata(host)?
    } else {
        let m = std::fs::symlink_metadata(host)?;
        if m.file_type().is_symlink() {
            return Err(Errno(ELOOP));
        }
        m
    };
    if !meta.is_file() || !may_exec(c, &meta) {
        return Err(Errno(EACCES));
    }
    Ok(())
}

/// `count`: the entries of a NULL-terminated pointer array (`EFAULT`,
/// `E2BIG`).
fn count(c: &Ctx<'_>, array: u64) -> Result<usize, Errno> {
    if array == 0 {
        return Ok(0);
    }
    let mut n = 0usize;
    loop {
        let p = c.read_u64(array + n as u64 * 8)?;
        if p == 0 {
            return Ok(n);
        }
        if n >= MAX_ARG_STRINGS {
            return Err(Errno(E2BIG));
        }
        n += 1;
    }
}

/// `copy_strings`: `n` strings of a pointer array, each at most
/// `MAX_ARG_STRLEN` bytes with its NUL (`E2BIG`), charged against `room`.
fn copy_strings(c: &Ctx<'_>, array: u64, n: usize, room: &mut u64) -> Result<Vec<Vec<u8>>, Errno> {
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let p = c.read_u64(array + i as u64 * 8)?;
        let s = match c.p.space.read_cstr(p, MAX_ARG_STRLEN - 1) {
            Ok(Some(s)) => s,
            Ok(None) => return Err(Errno(E2BIG)),
            Err(_) => return Err(Errno(EFAULT)),
        };
        charge(room, s.len())?;
        out.push(s);
    }
    Ok(out)
}

/// Charges a string and its NUL against the argument space.
fn charge(room: &mut u64, len: usize) -> Result<(), Errno> {
    *room = room.checked_sub(len as u64 + 1).ok_or(Errno(E2BIG))?;
    Ok(())
}

/// The `errno` of a failed image load.
fn load_errno(e: &SpawnError) -> Errno {
    Errno(match e {
        SpawnError::Unsupported(_) => ENOEXEC,
        SpawnError::Load(e) => e.errno(),
        SpawnError::Stack(super::super::stack::StackError::TooBig) => E2BIG,
        SpawnError::Stack(_) | SpawnError::Memory(_) => ENOMEM,
    })
}

/// `execve`.
pub fn execve(c: &mut Ctx<'_>, path: u64, argv: u64, envp: u64) -> Result<Outcome, Errno> {
    execveat(c, AT_FDCWD, path, argv, envp, 0)
}

/// `execveat` (`do_execveat_common`).
pub fn execveat(
    c: &mut Ctx<'_>,
    dirfd: i32,
    path: u64,
    argv: u64,
    envp: u64,
    flags: u32,
) -> Result<Outcome, Errno> {
    // getname / getname_flags: LOOKUP_EMPTY only with AT_EMPTY_PATH.
    let raw = c.read_cstr_raw(path, PATH_MAX - 1)?;
    if raw.is_empty() && flags & AT_EMPTY_PATH == 0 {
        return Err(Errno(ENOENT));
    }
    let name = String::from_utf8_lossy(&raw).into_owned();
    // alloc_bprm: the name the program sees (AT_EXECFN) and takes its
    // comm from.
    let by_fd = !(dirfd == AT_FDCWD || name.starts_with('/'));
    let (filename, comm_from_file) = if !by_fd {
        (name.clone(), false)
    } else if name.is_empty() {
        (format!("/dev/fd/{dirfd}"), true)
    } else {
        (format!("/dev/fd/{dirfd}/{name}"), false)
    };
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(Errno(EINVAL));
    }
    let mut file = open_exec(c, dirfd, &name, flags)?;
    // BINPRM_FLAGS_PATH_INACCESSIBLE: a name made from a close-on-exec
    // descriptor is gone once the program runs.
    let inaccessible = by_fd && c.p.fds.get(dirfd).is_ok_and(|f| f.cloexec);
    let argc = count(c, argv)?;
    let envc = count(c, envp)?;
    // bprm_stack_limits: a quarter of the stack (at most 3/4 of _STK_LIM,
    // at least ARG_MAX) holds the strings and their pointers.
    let stack = c.p.rlimits[3].0;
    let limit = (STK_LIM / 4 * 3).min(stack / 4).max(ARG_MAX);
    let pointers = (argc.max(1) as u64 + envc as u64) * 8;
    if limit <= pointers {
        return Err(Errno(E2BIG));
    }
    let mut room = limit - pointers;
    charge(&mut room, filename.len())?;
    let env = copy_strings(c, envp, envc, &mut room)?;
    let mut args = copy_strings(c, argv, argc, &mut room)?;
    if args.is_empty() {
        // An empty argv gets "" as argv[0].
        charge(&mut room, 0)?;
        args.push(Vec::new());
    }
    // exec_binprm: up to five interpreter rewrites.
    let mut interp = filename.clone().into_bytes();
    let mut depth = 0;
    // open_exec: each file the handlers read is opened for execution.
    let mut opened = super::notify::exec_open(c, &file.host);
    let bytes: std::sync::Arc<[u8]> = loop {
        if depth > 5 {
            return Err(Errno(ELOOP));
        }
        depth += 1;
        let data = std::fs::read(&file.host)?;
        // prepare_binprm's read (and the handlers' after it).
        if let Some(t) = &opened {
            t.event(IN_ACCESS);
        }
        match exec::parse_script(&data[..data.len().min(BINPRM_BUF_SIZE)]) {
            Err(ScriptError::NotScript) => break data.into(),
            Err(ScriptError::Bad) => return Err(Errno(ENOEXEC)),
            Ok((i_name, i_arg)) => {
                // The interpreter would not find the script.
                if inaccessible {
                    return Err(Errno(ENOENT));
                }
                // remove_arg_zero frees argv[0]'s space; the script's name,
                // the interpreter's argument, and its name are charged
                // (copy_string_kernel) and go in front.
                room += args.remove(0).len() as u64 + 1;
                charge(&mut room, interp.len())?;
                if let Some(a) = &i_arg {
                    charge(&mut room, a.len())?;
                }
                charge(&mut room, i_name.len())?;
                let mut front = vec![i_name.clone()];
                front.extend(i_arg);
                front.push(interp.clone());
                args.splice(0..0, front);
                interp = i_name.clone();
                let path = String::from_utf8_lossy(&i_name).into_owned();
                file = open_exec(c, AT_FDCWD, &path, 0)?;
                // load_script opens the interpreter, then exec_binprm
                // releases the script.
                let next = super::notify::exec_open(c, &file.host);
                drop(std::mem::replace(&mut opened, next));
            }
        }
    };
    let comm = if comm_from_file {
        exec::comm_of(file.guest.as_bytes())
    } else {
        exec::comm_of(filename.as_bytes())
    };
    let request = ImageRequest {
        bytes,
        exe_path: file.guest.clone(),
        exe_host: file.host.clone(),
        execfn: filename.as_bytes(),
        comm,
        argv: &args,
        envp: &env,
        stack_limit: stack,
        arena_bytes: c.p.config.arena_bytes,
        cpu: &c.p.config.cpu,
    };
    let creds = c.p.creds;
    let mut image =
        exec::load_image(request, &c.p.vfs, creds, &mut c.p.entropy).map_err(|e| load_errno(&e))?;
    // load_elf_binary opens and reads the interpreter.
    let interp_path = image.mm.program.interp_path.clone();
    if let Some(p) = interp_path {
        let host = c.p.vfs.host_path(&String::from_utf8_lossy(&p), true);
        if let Some(t) = super::notify::exec_open(c, &host) {
            t.event(IN_ACCESS);
            image.keep.push(t);
        }
    }
    if let Some(t) = opened {
        image.keep.insert(0, t);
    }
    Ok(Outcome::Exec(super::NewImage(Box::new(image))))
}
