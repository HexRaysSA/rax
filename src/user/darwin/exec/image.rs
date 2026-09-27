//! Image activation (`exec_activate_image` and its activators in
//! `bsd/kern/kern_exec.c`; `bsd/kern/mach_fat.c`).
//!
//! Everything here happens before `exec`'s point of no return: an error
//! is the call's error and leaves the caller as it was. The path is
//! looked up (following symbolic links) and checked — a regular file with
//! an execute bit, not empty, executable by the caller — and its first
//! page is offered to the activators in the kernel's order, Mach-O, fat,
//! interpreter script, at most three times: a fat file's slice goes round
//! again as an encapsulated binary, a `#!` script's interpreter is looked
//! up and goes round again as the image.
//!
//! The emulated machine follows the calling process: an arm64 process
//! runs on Apple silicon, which executes arm64 images and, translated as
//! by Rosetta, x86_64 ones (not x86_64h, and a fat file's x86_64 slice only
//! when it has no arm64 one); an x86-64 process runs on an Intel Mac, which
//! executes x86-64 images only, x86_64h first. The slice chosen is the one
//! the loader maps.

use std::ffi::CString;
use std::io::Read;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::sync::Arc;

use crate::user::darwin::abi::{DarwinAbi, Errno};
use crate::user::darwin::host;
use crate::user::darwin::loader::ImageFile;
use crate::user::darwin::syscall::Ctx;
use crate::user::darwin::syscall::util::MAXPATHLEN;
use crate::user::image::macho::{
    self, CPU_ARCH_MASK, CPU_SUBTYPE_ANY, CPU_SUBTYPE_MASK, CPU_TYPE_ANY, CPU_TYPE_ARM64,
    CPU_TYPE_X86_64, FAT_MAGIC, FatArch, HostCpu, MH_CIGAM, MH_CIGAM_64, MH_EXECUTE, MH_MAGIC,
    MH_MAGIC_64,
};

/// `IMG_SHSIZE`: how much of a script's first line is read.
pub const IMG_SHSIZE: usize = 512;

/// `EAI_ITERLIMIT`: activation passes (script, fat file, thin image).
const EAI_ITERLIMIT: u32 = 3;

/// `NBINPREFS`.
pub const NBINPREFS: usize = 4;

/// Where relative paths are resolved: the working directory, or the
/// directory a spawn's file actions changed to (a host descriptor).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    /// The process's working directory (the host's).
    Cwd,
    /// A directory descriptor.
    Fd(RawFd),
}

impl Dir {
    /// The host `*at` directory argument.
    pub fn raw(self) -> RawFd {
        match self {
            Dir::Cwd => libc::AT_FDCWD,
            Dir::Fd(fd) => fd,
        }
    }
}

/// A spawn's binary preferences (`psa_binprefs`, `psa_subcpuprefs`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Binprefs {
    /// CPU types, in order of preference; 0 ends the list.
    pub cpu: [u32; NBINPREFS],
    /// The subtypes that go with them (`CPU_SUBTYPE_ANY` for any).
    pub sub: [u32; NBINPREFS],
}

impl Binprefs {
    /// Whether there are preferences (`psa_binprefs[0] != 0`).
    pub fn active(&self) -> bool {
        self.cpu[0] != 0
    }
}

/// The emulated machine a process execs on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Machine {
    /// The calling process's ABI.
    pub abi: DarwinAbi,
}

impl Machine {
    /// The kernel's page size (the fat header's buffer).
    pub fn page_size(self) -> u64 {
        self.abi.page_size()
    }

    /// `grade_binary`: the preference for running an image of `cputype`
    /// and `cpusubtype` (capability bits included), and the ABI it runs
    /// with; `None` when this machine cannot run it.
    pub fn grade(self, cputype: u32, cpusubtype: u32) -> Option<(u32, DarwinAbi)> {
        let (target, host) = match (self.abi, cputype) {
            (DarwinAbi::Arm64, CPU_TYPE_ARM64) => (DarwinAbi::Arm64, HostCpu::ARM64E),
            // Translated on Apple silicon, which runs x86_64 slices but not
            // x86_64h ones ("Bad CPU type in executable").
            (DarwinAbi::Arm64, CPU_TYPE_X86_64) => (DarwinAbi::X86_64, HostCpu::X86_64),
            (DarwinAbi::X86_64, CPU_TYPE_X86_64) => (DarwinAbi::X86_64, HostCpu::X86_64H),
            _ => return None,
        };
        let g = macho::grade(
            host,
            cputype,
            cpusubtype & !CPU_SUBTYPE_MASK,
            cpusubtype & CPU_SUBTYPE_MASK,
        );
        (g > 0).then_some((g, target))
    }

    /// `fatfile_getbestarch`: the best slice of the machine's own CPU type
    /// (ignoring the ABI bits); on Apple silicon a file without one runs
    /// its best x86-64 slice translated.
    fn best_arch(self, arches: &[FatArch]) -> Option<FatArch> {
        let own = self.abi.host_cpu().cputype;
        let best = |cpu: u32| {
            best_graded(self, arches, |a| {
                a.cputype & !CPU_ARCH_MASK == cpu & !CPU_ARCH_MASK
            })
        };
        best(own).or_else(|| {
            (own == CPU_TYPE_ARM64)
                .then(|| best(CPU_TYPE_X86_64))
                .flatten()
        })
    }
}

/// The highest-graded slice `filter` admits.
fn best_graded(
    m: Machine,
    arches: &[FatArch],
    filter: impl Fn(&FatArch) -> bool,
) -> Option<FatArch> {
    let mut best: Option<(u32, FatArch)> = None;
    for a in arches.iter().filter(|a| filter(a)) {
        if let Some((g, _)) = m.grade(a.cputype, a.cpusubtype)
            && g > best.map_or(0, |(bg, _)| bg)
        {
            best = Some((g, *a));
        }
    }
    best.map(|(_, a)| a)
}

/// `binary_match`: whether an image of `cpu`/`sub` matches the requested
/// `req_cpu`/`req_sub`, ignoring the `mask` bits of the CPU type and the
/// capability bits of the subtype.
fn binary_match(mask: u32, req_cpu: u32, req_sub: u32, cpu: u32, sub: u32) -> bool {
    if cpu & !mask != req_cpu & !mask {
        return false;
    }
    let (sub, req_sub) = (sub & !CPU_SUBTYPE_MASK, req_sub & !CPU_SUBTYPE_MASK);
    sub == req_sub || req_sub == CPU_SUBTYPE_ANY & !CPU_SUBTYPE_MASK
}

/// An image ready to load.
#[derive(Debug)]
pub struct Activated {
    /// The file to load (the interpreter of a script), named by the path
    /// it was found under (`executable_path=`).
    pub image: ImageFile,
    /// The ABI it runs with.
    pub abi: DarwinAbi,
    /// A script's interpreter line, split into words (the interpreter
    /// first); empty for a binary.
    pub interp: Vec<Vec<u8>>,
    /// The path the caller passed.
    pub user_path: Vec<u8>,
}

/// Activates the image at the path `path_addr` names.
pub fn activate(
    ctx: &Ctx<'_>,
    path_addr: u64,
    dir: Dir,
    prefs: &Binprefs,
) -> Result<Activated, Errno> {
    // exec_save_path.
    let user_path = ctx.cstr(path_addr, MAXPATHLEN)?;
    activate_path(ctx, &user_path, dir, prefs)
}

/// [`activate`] for a path already copied in.
pub fn activate_path(
    ctx: &Ctx<'_>,
    user_path: &[u8],
    dir: Dir,
    prefs: &Binprefs,
) -> Result<Activated, Errno> {
    let machine = Machine { abi: ctx.proc.abi };
    let mut saved = user_path.to_vec();
    let mut interp: Vec<Vec<u8>> = Vec::new();
    let mut iterations = 0;
    'lookup: loop {
        let file = open_checked(ctx, &saved, dir)?;
        // The view the activators see: the whole file, then a slice.
        let (mut offset, mut size) = (0usize, file.bytes.len());
        // The fat table's CPU type for the slice (ip_origcputype).
        let mut orig: Option<(u32, u32)> = None;
        loop {
            iterations += 1;
            if iterations > EAI_ITERLIMIT {
                return Err(Errno::EBADEXEC);
            }
            let view = &file.bytes[offset..offset + size];
            if let Some(abi) = mach_imgact(machine, view, &mut orig, prefs)? {
                let mut image = file;
                if size != image.bytes.len() {
                    // The slice the fat activator chose is the one loaded.
                    image.slice = Some((offset as u64, size as u64));
                }
                return Ok(Activated {
                    image,
                    abi,
                    interp,
                    user_path: user_path.to_vec(),
                });
            }
            if let Some((o, s)) = fat_imgact(machine, view, &mut orig, prefs)? {
                // An encapsulated binary: the slice goes round again.
                offset += o;
                size = s;
                continue;
            }
            if interp.is_empty() && orig.is_none() {
                match shell_imgact(view) {
                    Some(Ok(words)) => {
                        // The interpreter is looked up and goes round again.
                        saved = interpreter_name(&words);
                        interp = words;
                        continue 'lookup;
                    }
                    Some(Err(e)) => return Err(e),
                    None => {}
                }
            }
            return Err(Errno::ENOEXEC);
        }
    }
}

/// `exec_mach_imgact` up to the point of no return: the ABI a thin
/// executable runs with (`None`: not one).
fn mach_imgact(
    m: Machine,
    view: &[u8],
    orig: &mut Option<(u32, u32)>,
    prefs: &Binprefs,
) -> Result<Option<DarwinAbi>, Errno> {
    let word = |at: usize| -> u32 {
        let mut b = [0u8; 4];
        for (i, byte) in b.iter_mut().enumerate() {
            *byte = view.get(at + i).copied().unwrap_or(0);
        }
        u32::from_le_bytes(b)
    };
    let magic = word(0);
    if magic == MH_CIGAM || magic == MH_CIGAM_64 {
        return Err(Errno::EBADARCH);
    }
    if (magic != MH_MAGIC && magic != MH_MAGIC_64) || word(12) != MH_EXECUTE {
        return Ok(None);
    }
    let (cpu, sub) = (word(4), word(8));
    match *orig {
        // The fat table's idea of the slice must be the slice's.
        Some(o) if o != (cpu, sub) => return Err(Errno::EBADARCH),
        Some(_) => {}
        None => *orig = Some((cpu, sub)),
    }
    if prefs.active() {
        let mut matched = false;
        for i in 0..NBINPREFS {
            let (pref, subpref) = (prefs.cpu[i], prefs.sub[i]);
            if pref == 0 {
                return Err(Errno::EBADARCH);
            }
            if pref == CPU_TYPE_ANY || binary_match(CPU_ARCH_MASK, pref, subpref, cpu, sub) {
                matched = true;
                break;
            }
        }
        if !matched {
            return Err(Errno::EBADARCH);
        }
    }
    match m.grade(cpu, sub) {
        Some((_, abi)) => Ok(Some(abi)),
        None => Err(Errno::EBADARCH),
    }
}

/// `exec_fat_imgact`: the offset and size of the slice to run (`None`:
/// not a fat file, or one inside a fat file).
fn fat_imgact(
    m: Machine,
    view: &[u8],
    orig: &mut Option<(u32, u32)>,
    prefs: &Binprefs,
) -> Result<Option<(usize, usize)>, Errno> {
    if orig.is_some() {
        return Ok(None);
    }
    let magic = view
        .get(..4)
        .map(|b| u32::from_be_bytes(b.try_into().expect("four bytes")));
    if magic != Some(FAT_MAGIC) {
        return Ok(None);
    }
    let arches = macho::fat_arches(view, m.page_size()).map_err(|e| Errno::from_host(e.errno()))?;
    let arch = if prefs.active() {
        choose_by_prefs(m, &arches, prefs)?
    } else {
        None
    };
    let arch = match arch {
        Some(a) => a,
        None => m.best_arch(&arches).ok_or(Errno::EBADARCH)?,
    };
    *orig = Some((arch.cputype, arch.cpusubtype));
    Ok(Some((arch.offset as usize, arch.size as usize)))
}

/// The slice a spawn's binary preferences select (`None`: grade as
/// usual, for `CPU_TYPE_ANY`).
fn choose_by_prefs(
    m: Machine,
    arches: &[FatArch],
    prefs: &Binprefs,
) -> Result<Option<FatArch>, Errno> {
    for i in 0..NBINPREFS {
        let (pref, subpref) = (prefs.cpu[i], prefs.sub[i]);
        if pref == 0 {
            return Err(Errno::EBADARCH);
        }
        if pref == CPU_TYPE_ANY {
            return Ok(None);
        }
        // fatfile_getbestarch_for_cputype: this exact CPU type.
        if let Some(a) = best_graded(m, arches, |a| {
            binary_match(0, pref, subpref, a.cputype, a.cpusubtype)
        }) {
            return Ok(Some(a));
        }
    }
    Err(Errno::EBADEXEC)
}

/// `IS_WHITESPACE`.
fn is_space(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

/// `IS_EOL`.
fn is_eol(c: u8) -> bool {
    c == b'#' || c == b'\n'
}

/// `exec_shell_imgact`: for a `#!` script, the words of its interpreter
/// line as `exec_extract_strings` splits them (`None`: not a script).
pub fn shell_imgact(view: &[u8]) -> Option<Result<Vec<Vec<u8>>, Errno>> {
    // The first page, zero-filled past the end of the file.
    let mut vdata = [0u8; IMG_SHSIZE];
    let n = view.len().min(IMG_SHSIZE);
    vdata[..n].copy_from_slice(&view[..n]);
    if vdata[0] != b'#' || vdata[1] != b'!' {
        return None;
    }
    let mut i = 2;
    while i < IMG_SHSIZE {
        if is_eol(vdata[i]) {
            // "#!\n": no interpreter.
            return Some(Err(Errno::ENOEXEC));
        }
        if !is_space(vdata[i]) {
            break;
        }
        i += 1;
    }
    if i == IMG_SHSIZE {
        return Some(Err(Errno::ENOEXEC));
    }
    let start = i;
    while i < IMG_SHSIZE && !is_eol(vdata[i]) {
        i += 1;
    }
    if i == IMG_SHSIZE {
        // No end of line within the limit.
        return Some(Err(Errno::ENOEXEC));
    }
    // Back up over the end of line and trailing blanks.
    while is_eol(vdata[i]) || is_space(vdata[i]) {
        i -= 1;
    }
    let line = &vdata[start..=i];
    Some(Ok(split_interp(line)))
}

/// `exec_extract_strings`' tokenizing of the interpreter line: words
/// separated by blanks, the line ending at a NUL byte.
fn split_interp(line: &[u8]) -> Vec<Vec<u8>> {
    let mut words = Vec::new();
    let mut at = 0;
    loop {
        let mut end = at;
        while end < line.len() && line[end] != 0 && !is_space(line[end]) {
            end += 1;
        }
        words.push(line[at..end].to_vec());
        if end >= line.len() || line[end] == 0 {
            return words;
        }
        at = end + 1;
        while at < line.len() && is_space(line[at]) {
            at += 1;
        }
    }
}

/// The interpreter's path: the first word as a C string.
fn interpreter_name(words: &[Vec<u8>]) -> Vec<u8> {
    words.first().cloned().unwrap_or_default()
}

/// `namei` and `exec_check_permissions`, then the file's contents.
fn open_checked(ctx: &Ctx<'_>, guest: &[u8], dir: Dir) -> Result<ImageFile, Errno> {
    if guest.is_empty() {
        return Err(Errno::ENOENT);
    }
    let cpath = host::path(&ctx.proc.vfs, guest)?;
    let st = host::fstatat(dir.raw(), &cpath, 0)?;
    if st.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(Errno::EACCES);
    }
    if st.st_mode & (libc::S_IXUSR | libc::S_IXGRP | libc::S_IXOTH) == 0 {
        return Err(Errno::EACCES);
    }
    if st.st_size == 0 {
        return Err(Errno::ENOEXEC);
    }
    // SAFETY: `cpath` is NUL-terminated for the call's duration.
    host::check(unsafe {
        libc::faccessat(dir.raw(), cpath.as_ptr(), libc::X_OK, libc::AT_EACCESS)
    })
    .map_err(|_| Errno::EACCES)?;
    read_image(&ctx.proc.vfs, guest, &cpath, dir, &st)
}

/// Reads the whole executable.
fn read_image(
    vfs: &crate::user::darwin::vfs::Vfs,
    guest: &[u8],
    cpath: &CString,
    dir: Dir,
    st: &libc::stat,
) -> Result<ImageFile, Errno> {
    // SAFETY: `cpath` is NUL-terminated for the call's duration.
    let fd = host::check(unsafe {
        libc::openat(dir.raw(), cpath.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC)
    })?;
    // SAFETY: `fd` was just returned by the host and is owned here.
    let mut file = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    let vnode_path = crate::user::darwin::loader::vnode_path(
        vfs,
        fd,
        std::path::Path::new(std::ffi::OsStr::from_bytes(cpath.as_bytes())),
    );
    let mut bytes = Vec::with_capacity(st.st_size as usize);
    file.read_to_end(&mut bytes)
        .map_err(|e| Errno::from_io(&e))?;
    // For information: relative to the spawn's directory descriptor when
    // there is one.
    let host_path = match dir {
        Dir::Fd(d) if cpath.as_bytes().first() != Some(&b'/') => {
            format!("/dev/fd/{d}/{}", String::from_utf8_lossy(cpath.as_bytes())).into()
        }
        _ => std::path::PathBuf::from(std::ffi::OsStr::from_bytes(cpath.as_bytes())),
    };
    Ok(ImageFile {
        path: String::from_utf8_lossy(guest).into_owned(),
        host_path,
        vnode_path,
        bytes: Arc::from(bytes),
        file_id: (st.st_dev as u64, st.st_ino as u64),
        slice: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn script(text: &[u8]) -> Option<Result<Vec<Vec<u8>>, Errno>> {
        shell_imgact(text)
    }

    fn words(v: &[&str]) -> Vec<Vec<u8>> {
        v.iter().map(|s| s.as_bytes().to_vec()).collect()
    }

    #[test]
    fn interpreter_lines_split_into_words() {
        assert_eq!(
            script(b"#!  /bin/sh -e  x\t y \n").unwrap().unwrap(),
            words(&["/bin/sh", "-e", "x", "y"])
        );
        // A comment ends the line.
        assert_eq!(
            script(b"#!/usr/bin/env python # hi\n").unwrap().unwrap(),
            words(&["/usr/bin/env", "python"])
        );
        // A NUL byte ends the argument list.
        assert_eq!(
            script(b"#!/bin/sh \0 x\n").unwrap().unwrap(),
            words(&["/bin/sh", ""])
        );
        assert_eq!(
            script(b"#!/bin/a\0b\n").unwrap().unwrap(),
            words(&["/bin/a"])
        );
    }

    #[test]
    fn malformed_interpreter_lines_are_enoexec() {
        assert_eq!(script(b"#!\n"), Some(Err(Errno::ENOEXEC)));
        assert_eq!(script(b"#!   # comment\n"), Some(Err(Errno::ENOEXEC)));
        // No end of line in the first 512 bytes (the rest reads as zero).
        assert_eq!(script(b"#!/bin/sh"), Some(Err(Errno::ENOEXEC)));
        let mut long = b"#!/bin/sh ".to_vec();
        long.resize(IMG_SHSIZE, b'x');
        long.push(b'\n');
        assert_eq!(script(&long), Some(Err(Errno::ENOEXEC)));
        let mut blanks = b"#!".to_vec();
        blanks.resize(IMG_SHSIZE, b' ');
        assert_eq!(script(&blanks), Some(Err(Errno::ENOEXEC)));
        assert_eq!(script(b"#"), None);
        assert_eq!(script(b"# !/bin/sh\n"), None);
    }

    #[test]
    fn apple_silicon_runs_arm64_and_translated_x86_64() {
        let m = Machine {
            abi: DarwinAbi::Arm64,
        };
        assert_eq!(
            m.grade(CPU_TYPE_ARM64, 0).map(|g| g.1),
            Some(DarwinAbi::Arm64)
        );
        assert_eq!(
            m.grade(CPU_TYPE_X86_64, 3).map(|g| g.1),
            Some(DarwinAbi::X86_64)
        );
        // Rosetta does not run x86_64h.
        assert_eq!(m.grade(CPU_TYPE_X86_64, 8), None);
        assert_eq!(m.grade(7, 3), None); // i386
        assert_eq!(m.grade(0x0100_0012, 0), None); // ppc64
        let intel = Machine {
            abi: DarwinAbi::X86_64,
        };
        assert_eq!(intel.grade(CPU_TYPE_ARM64, 0), None);
        assert_eq!(
            intel.grade(CPU_TYPE_X86_64, 3).map(|g| g.1),
            Some(DarwinAbi::X86_64)
        );
        // A Haswell Mac prefers x86_64h.
        let (h, all) = (
            intel.grade(CPU_TYPE_X86_64, 8),
            intel.grade(CPU_TYPE_X86_64, 3),
        );
        assert!(h.unwrap().0 > all.unwrap().0);
    }

    fn arch(cputype: u32, cpusubtype: u32) -> FatArch {
        FatArch {
            cputype,
            cpusubtype,
            offset: 0x4000,
            size: 0x10,
            align: 14,
        }
    }

    #[test]
    fn fat_grading_prefers_the_native_slice() {
        let m = Machine {
            abi: DarwinAbi::Arm64,
        };
        let both = [arch(CPU_TYPE_X86_64, 3), arch(CPU_TYPE_ARM64, 0)];
        assert_eq!(m.best_arch(&both).unwrap().cputype, CPU_TYPE_ARM64);
        let x86 = [arch(CPU_TYPE_X86_64, 3)];
        assert_eq!(m.best_arch(&x86).unwrap().cputype, CPU_TYPE_X86_64);
        // Translated: the x86_64 slice, never the x86_64h one.
        let h = [arch(CPU_TYPE_X86_64, 8), arch(CPU_TYPE_X86_64, 3)];
        assert_eq!(m.best_arch(&h).unwrap().cpusubtype, 3);
        assert!(m.best_arch(&h[..1]).is_none());
        let intel = Machine {
            abi: DarwinAbi::X86_64,
        };
        assert_eq!(intel.best_arch(&both).unwrap().cputype, CPU_TYPE_X86_64);
        assert!(intel.best_arch(&[arch(CPU_TYPE_ARM64, 0)]).is_none());
    }

    #[test]
    fn binary_preferences_select_or_refuse() {
        let m = Machine {
            abi: DarwinAbi::Arm64,
        };
        let both = [arch(CPU_TYPE_X86_64, 3), arch(CPU_TYPE_ARM64, 0)];
        let prefs = |cpu: [u32; 4]| Binprefs {
            cpu,
            sub: [CPU_SUBTYPE_ANY; 4],
        };
        let x86 = choose_by_prefs(m, &both, &prefs([CPU_TYPE_X86_64, 0, 0, 0])).unwrap();
        assert_eq!(x86.unwrap().cputype, CPU_TYPE_X86_64);
        // A preference nothing matches, then the end of the list.
        assert_eq!(
            choose_by_prefs(m, &both, &prefs([0x0100_0012, 0, 0, 0])),
            Err(Errno::EBADARCH)
        );
        // Four preferences, none matched.
        assert_eq!(
            choose_by_prefs(m, &both, &prefs([18, 19, 20, 21])),
            Err(Errno::EBADEXEC)
        );
        assert_eq!(
            choose_by_prefs(m, &both, &prefs([18, CPU_TYPE_ANY, 0, 0])),
            Ok(None)
        );
        // A subtype preference must match.
        let sub = Binprefs {
            cpu: [CPU_TYPE_ARM64, 0, 0, 0],
            sub: [2, 0, 0, 0],
        };
        assert_eq!(choose_by_prefs(m, &both, &sub), Err(Errno::EBADARCH));
    }

    #[test]
    fn thin_images_check_preferences_ignoring_abi_bits() {
        let mut header = vec![0u8; 32];
        header[..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
        header[4..8].copy_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
        header[12..16].copy_from_slice(&MH_EXECUTE.to_le_bytes());
        let m = Machine {
            abi: DarwinAbi::Arm64,
        };
        let run = |header: &[u8], prefs: Binprefs| {
            mach_imgact(m, header, &mut None, &prefs).map(|c| c.is_some())
        };
        assert_eq!(run(&header, Binprefs::default()), Ok(true));
        // CPU_TYPE_ARM matches CPU_TYPE_ARM64 once the ABI bits are masked.
        let arm = Binprefs {
            cpu: [12, 0, 0, 0],
            sub: [CPU_SUBTYPE_ANY; 4],
        };
        assert_eq!(run(&header, arm), Ok(true));
        let x86 = Binprefs {
            cpu: [CPU_TYPE_X86_64, 0, 0, 0],
            sub: [CPU_SUBTYPE_ANY; 4],
        };
        assert_eq!(run(&header, x86), Err(Errno::EBADARCH));
        header[12] = 6; // MH_DYLIB
        assert_eq!(run(&header, Binprefs::default()), Ok(false));
        header[..4].copy_from_slice(&MH_CIGAM_64.to_le_bytes());
        assert_eq!(run(&header, Binprefs::default()), Err(Errno::EBADARCH));
    }
}
