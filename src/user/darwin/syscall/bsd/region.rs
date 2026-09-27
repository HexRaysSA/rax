//! `shared_region_check_np` and `shared_region_map_and_slide_2_np`.

use std::sync::Arc;

use crate::user::darwin::abi::Errno;
use crate::user::darwin::arch::{Rv, SysResult};
use crate::user::darwin::shared_region::{SharedRegion, SlidSource, SlideInfo};
use crate::user::darwin::syscall::Ctx;
use crate::user::darwin::vm::{self, VmFlags};
use crate::user::mm::{Backing, BytesSource, HostFileSource, Mapping};

/// `DYLD_VM_END_MWL`: disallow `map_with_linking_np` from now on.
const DYLD_VM_END_MWL: u64 = u64::MAX;
/// `_SR_FILE_MAPPINGS_MAX_FILES`.
const MAX_FILES: u32 = 256;
/// `SFM_MAX`.
const SFM_MAX: u32 = 1024;
/// `SANE_SLIDE_INFO_SIZE`.
const SANE_SLIDE_INFO_SIZE: u64 = 2560 * 1024;
/// `VM_PROT_ZF`: zero-fill the mapping instead of mapping the file.
const VM_PROT_ZF: u32 = 0x10;

/// `shared_region_check_np(start_address)`.
pub fn check_np(ctx: &mut Ctx<'_>, addr: u64) -> SysResult {
    if addr == DYLD_VM_END_MWL {
        return Ok(Rv::one(0));
    }
    let Some(region) = ctx.proc.shared_region.clone() else {
        // The task has a shared region with no mappings yet:
        // vm_shared_region_start_address fails.
        return Err(Errno::ENOMEM);
    };
    if addr == 0 {
        // dyld unmapped the region.
        for (a, s) in &region.mappings {
            let _ = ctx.proc.space.unmap(*a, *s);
        }
        ctx.proc.shared_region = None;
        return Ok(Rv::one(0));
    }
    ctx.write(addr, &region.base.to_le_bytes())?;
    Ok(Rv::one(0))
}

/// One `shared_file_mapping_slide_np`.
#[derive(Clone, Copy, Debug)]
struct SlideMapping {
    address: u64,
    size: u64,
    file_offset: u64,
    slide_size: u64,
    slide_start: u64,
    max_prot: u32,
    init_prot: u32,
}

/// `shared_region_map_and_slide_2_np(files_count, files, mappings_count,
/// mappings)`.
pub fn map_and_slide_2(
    ctx: &mut Ctx<'_>,
    nfiles: u32,
    files: u64,
    nmaps: u32,
    maps: u64,
) -> SysResult {
    if nfiles == 0 || nmaps == 0 {
        return Ok(Rv::one(0));
    }
    if nfiles > MAX_FILES || nmaps > SFM_MAX {
        return Err(Errno::EINVAL);
    }
    if ctx.proc.shared_region.is_some() {
        return Err(Errno::EINVAL);
    }
    let fraw = ctx.read(files, 12 * nfiles as usize)?;
    let mraw = ctx.read(maps, 48 * nmaps as usize)?;
    let page = ctx.proc.vm.page;
    let mut mappings = Vec::with_capacity(nmaps as usize);
    for c in mraw.chunks(48) {
        let q = |o: usize| u64::from_le_bytes(c[o..o + 8].try_into().expect("8 bytes"));
        let m = SlideMapping {
            address: q(0),
            size: q(8),
            file_offset: q(16),
            slide_size: q(24),
            slide_start: q(32),
            max_prot: u32::from_le_bytes(c[40..44].try_into().expect("4 bytes")),
            init_prot: u32::from_le_bytes(c[44..48].try_into().expect("4 bytes")),
        };
        if m.address & (page - 1) != 0 || m.size & (page - 1) != 0 {
            return Err(Errno::EINVAL);
        }
        mappings.push(m);
    }
    // The slide: ASLR is disabled.
    let slide = 0u64;
    let mut next = 0usize;
    let mut region = SharedRegion {
        base: 0,
        slide,
        mappings: Vec::new(),
    };
    // The files' mappings, in order. Slide info lives in the cache's
    // __LINKEDIT, which this call maps: `sms_slide_start` is its address
    // there, so every unslid mapping is entered before any slid one reads
    // its slide info (vm_shared_region_map_file maps, then slides).
    let mut plan: Vec<(i32, SlideMapping)> = Vec::with_capacity(mappings.len());
    for f in fraw.chunks(12) {
        let fd = i32::from_le_bytes(f[0..4].try_into().expect("4 bytes"));
        let count = u32::from_le_bytes(f[4..8].try_into().expect("4 bytes")) as usize;
        if next + count > mappings.len() {
            return Err(Errno::EINVAL);
        }
        if fd == -1 && count > 1 {
            return Err(Errno::EINVAL);
        }
        plan.extend(mappings[next..next + count].iter().map(|&m| (fd, m)));
        next += count;
    }
    let mut hosts = std::collections::HashMap::new();
    for &(fd, _) in &plan {
        if fd == -1 || hosts.contains_key(&fd) {
            continue;
        }
        let file = ctx.proc.fds.file(fd).map_err(|_| Errno::EBADF)?;
        let h = file.host_fd().ok_or(Errno::EINVAL)?;
        if *file.flags.lock().unwrap() & crate::user::darwin::io::O_ACCMODE
            == crate::user::darwin::io::O_WRONLY
        {
            return Err(Errno::EPERM);
        }
        hosts.insert(fd, h);
    }
    let dup = |h: i32| -> Result<std::fs::File, Errno> {
        // SAFETY: F_DUPFD_CLOEXEC on a live descriptor the table owns.
        let d = unsafe { libc::fcntl(h, libc::F_DUPFD_CLOEXEC, 3) };
        if d < 0 {
            return Err(Errno::last());
        }
        // SAFETY: `d` is a new descriptor owned by the returned file.
        Ok(unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(d) })
    };
    for slid in [false, true] {
        for &(fd, m) in &plan {
            if (m.slide_size > 0) != slid {
                continue;
            }
            let addr = m.address + slide;
            let backing = if fd == -1 {
                // Data from the caller's own memory (dyld's dynamic
                // config).
                let data = ctx.read(m.file_offset, m.size as usize)?;
                Backing::Source {
                    source: Arc::new(BytesSource::new(data.into())),
                    offset: 0,
                }
            } else if m.init_prot & VM_PROT_ZF != 0 {
                Backing::Anonymous
            } else if slid {
                if m.slide_size > SANE_SLIDE_INFO_SIZE {
                    return Err(Errno::EINVAL);
                }
                let raw = ctx.read(m.slide_start, m.slide_size as usize)?;
                let info = SlideInfo::parse(&raw).map_err(|_| Errno::EINVAL)?;
                let src = SlidSource::new(dup(hosts[&fd])?, m.file_offset, m.size, info, slide)
                    .map_err(Errno::from)?;
                Backing::Source {
                    source: Arc::new(src),
                    offset: m.file_offset,
                }
            } else {
                Backing::Source {
                    source: Arc::new(HostFileSource::new(dup(hosts[&fd])?).map_err(Errno::from)?),
                    offset: m.file_offset,
                }
            };
            map_region(ctx, addr, m.size, backing, m)?;
            region.mappings.push((addr, m.size));
        }
    }
    region.mappings.sort_unstable();
    region.base = region.mappings.first().map_or(0, |m| m.0);
    ctx.proc.shared_region = Some(region);
    Ok(Rv::one(0))
}

fn map_region(
    ctx: &mut Ctx<'_>,
    addr: u64,
    size: u64,
    backing: Backing,
    m: SlideMapping,
) -> Result<(), Errno> {
    if size == 0 {
        return Ok(());
    }
    let init = m.init_prot & vm::VM_PROT_ALL;
    let max = m.max_prot & vm::VM_PROT_ALL;
    ctx.proc
        .space
        .map(
            addr,
            size,
            Mapping {
                perms: vm::perms(init),
                backing,
                shared: false,
                name: Some(Arc::from("[shared region]")),
                flags: VmFlags::new(max, vm::VM_INHERIT_SHARE, vm::VM_MEMORY_SHARED_PMAP)
                    .in_shared_region()
                    .bits(),
            },
        )
        .map_err(|_| Errno::ENOMEM)
}
