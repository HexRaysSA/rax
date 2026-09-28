//! The host's Mach interfaces the bridge uses: rights in the emulator's
//! own space, `mach_msg`, notification requests, and the port set its
//! kqueue watches.

use std::os::fd::{FromRawFd, OwnedFd};

/// A host port name (`mach_port_name_t`).
pub type Name = u32;

/// `MACH_PORT_NULL`.
pub const NULL: Name = 0;
/// `MACH_PORT_DEAD`.
pub const DEAD: Name = !0;

/// `MACH_PORT_RIGHT_*`.
pub mod right {
    pub const SEND: u32 = 0;
    pub const RECEIVE: u32 = 1;
    pub const SEND_ONCE: u32 = 2;
    pub const PORT_SET: u32 = 3;
    pub const DEAD_NAME: u32 = 4;
}

/// `MACH_MSG_TYPE_*`.
pub mod disp {
    pub const MOVE_RECEIVE: u32 = 16;
    pub const MOVE_SEND: u32 = 17;
    pub const MOVE_SEND_ONCE: u32 = 18;
    pub const COPY_SEND: u32 = 19;
    pub const MAKE_SEND: u32 = 20;
    pub const MAKE_SEND_ONCE: u32 = 21;
}

/// `MACH_NOTIFY_*` message IDs and request kinds.
pub mod notify {
    pub const NO_SENDERS: i32 = 0o106;
    pub const SEND_ONCE: i32 = 0o107;
    pub const DEAD_NAME: i32 = 0o110;
}

/// `mach_msg` options.
pub mod opt {
    pub const SEND_MSG: i32 = 0x1;
    pub const RCV_MSG: i32 = 0x2;
    pub const RCV_LARGE: i32 = 0x4;
    pub const SEND_TIMEOUT: i32 = 0x10;
    pub const RCV_TIMEOUT: i32 = 0x100;
    /// `MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
    /// MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT)`.
    pub const TRAILER_AUDIT: i32 = 3 << 24;
}

/// `mach_msg2` options (`MACH64_*`): the 32-bit ones, and the call class
/// the destination must match.
pub mod opt64 {
    pub const SEND_MSG: u64 = 0x1;
    pub const RCV_MSG: u64 = 0x2;
    pub const RCV_LARGE: u64 = 0x4;
    pub const SEND_TIMEOUT: u64 = 0x10;
    /// `MACH_RCV_TRAILER_AUDIT` in `MACH_RCV_TRAILER_FORMAT_0`.
    pub const TRAILER_AUDIT: u64 = 3 << 24;
    pub const KOBJECT_CALL: u64 = 0x2_0000_0000;
    pub const MQ_CALL: u64 = 0x4_0000_0000;
    pub const ANY: u64 = 0x8_0000_0000;
}

/// `mach_msg` results.
pub mod mr {
    pub const SUCCESS: i32 = 0;
    pub const SEND_INVALID_DEST: i32 = 0x1000_0003;
    pub const RCV_TIMED_OUT: i32 = 0x1000_4003;
    pub const RCV_TOO_LARGE: i32 = 0x1000_4004;
}

/// `MACH_MSG_TIMEOUT_NONE`.
pub const TIMEOUT_NONE: u32 = 0;

unsafe extern "C" {
    static mach_task_self_: Name;
    fn mach_msg(
        msg: *mut u8,
        option: i32,
        send_size: u32,
        rcv_size: u32,
        rcv_name: Name,
        timeout: u32,
        notify: Name,
    ) -> i32;
    fn mach_msg2_internal(
        data: *mut u8,
        option64: u64,
        bits_and_send_size: u64,
        remote_and_local: u64,
        voucher_and_id: u64,
        desc_count_and_rcv_name: u64,
        rcv_size_and_priority: u64,
        timeout: u64,
    ) -> i32;
    fn mach_port_allocate(task: Name, right: u32, name: *mut Name) -> i32;
    fn mach_port_construct(task: Name, options: *const u8, context: u64, name: *mut Name) -> i32;
    fn mach_port_deallocate(task: Name, name: Name) -> i32;
    fn mach_port_mod_refs(task: Name, name: Name, right: u32, delta: i32) -> i32;
    fn mach_port_insert_right(task: Name, name: Name, poly: Name, disp: u32) -> i32;
    fn mach_port_extract_right(
        task: Name,
        name: Name,
        disp: u32,
        poly: *mut Name,
        poly_disp: *mut u32,
    ) -> i32;
    fn mach_port_move_member(task: Name, member: Name, after: Name) -> i32;
    fn mach_port_request_notification(
        task: Name,
        name: Name,
        id: i32,
        sync: u32,
        notify: Name,
        notify_disp: u32,
        previous: *mut Name,
    ) -> i32;
    fn mach_port_get_attributes(
        task: Name,
        name: Name,
        flavor: i32,
        info: *mut i32,
        count: *mut u32,
    ) -> i32;
    fn task_get_special_port(task: Name, which: i32, port: *mut Name) -> i32;
    fn mach_port_kobject(task: Name, name: Name, kotype: *mut u32, addr: *mut u64) -> i32;
    fn mach_make_memory_entry_64(
        task: Name,
        size: *mut u64,
        offset: u64,
        permission: i32,
        handle: *mut Name,
        parent: Name,
    ) -> i32;
    fn mach_host_self() -> Name;
    fn host_get_io_main(host: Name, io_main: *mut Name) -> i32;
    fn task_create_identity_token(task: Name, token: *mut Name) -> i32;
    fn vm_deallocate(task: Name, address: usize, size: usize) -> i32;
    fn mach_vm_region(
        task: Name,
        address: *mut u64,
        size: *mut u64,
        flavor: i32,
        info: *mut i32,
        count: *mut u32,
        object: *mut Name,
    ) -> i32;
    fn mach_vm_map(
        task: Name,
        address: *mut u64,
        size: u64,
        mask: u64,
        flags: i32,
        object: Name,
        offset: u64,
        copy: i32,
        cur: i32,
        max: i32,
        inheritance: u32,
    ) -> i32;
    fn mach_vm_region_recurse(
        task: Name,
        address: *mut u64,
        size: *mut u64,
        depth: *mut u32,
        info: *mut i32,
        count: *mut u32,
    ) -> i32;
    fn task_info(task: Name, flavor: i32, info: *mut i32, count: *mut u32) -> i32;
}

/// `VM_FLAGS_*` of `mach_vm_map` (`osfmk/mach/vm_statistics.h`).
pub mod vmflags {
    pub const FIXED: i32 = 0;
    pub const ANYWHERE: i32 = 1;
    pub const OVERWRITE: i32 = 0x4000;
}

/// `VM_INHERIT_*`.
pub mod inherit {
    pub const SHARE: u32 = 0;
    pub const NONE: u32 = 2;
}

/// `SM_*`: how a region's memory is shared (`osfmk/mach/vm_region.h`).
pub mod share {
    pub const SHARED: u8 = 4;
    pub const TRUESHARED: u8 = 5;
    pub const PRIVATE_ALIASED: u8 = 6;
    pub const SHARED_ALIASED: u8 = 7;
}

/// `MAP_MEM_VM_SHARE`: a memory entry of the memory itself, not a copy.
const MAP_MEM_VM_SHARE: i32 = 0x40_0000;

/// The emulator's task port.
pub fn task() -> Name {
    // SAFETY: libsystem initializes mach_task_self_ before main.
    unsafe { mach_task_self_ }
}

/// `mach_msg`.
///
/// # Safety
/// `buf` must hold `max(send_size, rcv_size)` bytes, and any out-of-line
/// memory the message describes must stay live for the call.
pub unsafe fn msg(buf: *mut u8, option: i32, send: u32, rcv: u32, from: Name, timeout: u32) -> i32 {
    // SAFETY: as the caller promises.
    unsafe { mach_msg(buf, option, send, rcv, from, timeout, NULL) }
}

/// A message's header fields for [`msg2`].
pub struct Header {
    pub bits: u32,
    pub size: u32,
    pub remote: Name,
    pub local: Name,
    pub id: i32,
    /// The descriptor count (0 for a simple message).
    pub descs: u32,
}

/// `mach_msg2` of the message in `buf` with `option64`, receiving into
/// `buf` (`rcv_size` bytes) from `rcv_name` when it asks to.
///
/// # Safety
/// As [`msg`].
pub unsafe fn msg2(
    buf: *mut u8,
    option64: u64,
    h: &Header,
    rcv_name: Name,
    rcv_size: u32,
    timeout: u32,
) -> i32 {
    let pair = |lo: u32, hi: u32| u64::from(lo) | (u64::from(hi) << 32);
    // SAFETY: as the caller promises.
    unsafe {
        mach_msg2_internal(
            buf,
            option64,
            pair(h.bits, h.size),
            pair(h.remote, h.local),
            pair(0, h.id as u32),
            pair(h.descs, rcv_name),
            pair(rcv_size, 0),
            u64::from(timeout),
        )
    }
}

/// A new right of kind `right` (receive, port set).
pub fn allocate(right: u32) -> Option<Name> {
    let mut n = NULL;
    // SAFETY: `n` receives the name.
    (unsafe { mach_port_allocate(task(), right, &mut n) } == 0).then_some(n)
}

/// A new reply port (`MPO_REPLY_PORT`): the receive right of a port whose
/// only send-once right a message's reply field makes, as services that
/// enforce reply-port semantics require.
pub fn reply_port() -> Option<Name> {
    // mach_port_options_t: flags, mpl_qlimit, then a 64-bit union.
    let mut options = [0u8; 24];
    options[0..4].copy_from_slice(&0x1000u32.to_le_bytes());
    let mut n = NULL;
    // SAFETY: `options` is a mach_port_options_t; `n` receives the name.
    (unsafe { mach_port_construct(task(), options.as_ptr(), 0, &mut n) } == 0).then_some(n)
}

/// Drops a user reference to a send, send-once, or dead-name right.
pub fn deallocate(name: Name) {
    // SAFETY: a name in the emulator's own space.
    unsafe { mach_port_deallocate(task(), name) };
}

/// Adds `delta` references to `name`'s right of kind `right`.
pub fn mod_refs(name: Name, right: u32, delta: i32) -> bool {
    // SAFETY: a name in the emulator's own space.
    unsafe { mach_port_mod_refs(task(), name, right, delta) == 0 }
}

/// Makes a send right to the receive right `name` (the same name).
pub fn make_send(name: Name) -> bool {
    // SAFETY: a receive right in the emulator's own space.
    unsafe { mach_port_insert_right(task(), name, name, disp::MAKE_SEND) == 0 }
}

/// Makes a send-once right to the receive right `name` (a new name).
pub fn make_send_once(name: Name) -> Option<Name> {
    let (mut poly, mut d) = (NULL, 0u32);
    // SAFETY: a receive right in the emulator's own space.
    let kr =
        unsafe { mach_port_extract_right(task(), name, disp::MAKE_SEND_ONCE, &mut poly, &mut d) };
    (kr == 0).then_some(poly)
}

/// Puts the receive right `member` in the port set `set`.
pub fn join(member: Name, set: Name) -> bool {
    // SAFETY: names in the emulator's own space.
    unsafe { mach_port_move_member(task(), member, set) == 0 }
}

/// Asks for notification `id` about `name`, sent through a send-once right
/// made from the receive right `notify`.
pub fn request(name: Name, id: i32, sync: u32, notify: Name) -> bool {
    let mut prev = NULL;
    // SAFETY: names in the emulator's own space; `prev` receives a right
    // to a previous request's port, which is released.
    let kr = unsafe {
        mach_port_request_notification(
            task(),
            name,
            id,
            sync,
            notify,
            disp::MAKE_SEND_ONCE,
            &mut prev,
        )
    };
    if prev != NULL {
        deallocate(prev);
    }
    kr == 0
}

/// The make-send count of the receive right `name`
/// (`MACH_PORT_RECEIVE_STATUS`).
pub fn mscount(name: Name) -> u32 {
    // mach_port_status_t: mps_pset, mps_seqno, mps_mscount, ...
    let mut status = [0i32; 10];
    let mut count = status.len() as u32;
    // SAFETY: `status` holds MACH_PORT_RECEIVE_STATUS_COUNT words.
    let kr = unsafe { mach_port_get_attributes(task(), name, 2, status.as_mut_ptr(), &mut count) };
    if kr == 0 { status[2] as u32 } else { 0 }
}

/// The emulator's task special port `which` (a new send right).
pub fn special_port(which: i32) -> Name {
    let mut p = NULL;
    // SAFETY: `p` receives the right.
    unsafe { task_get_special_port(task(), which, &mut p) };
    p
}

/// `mach_port_kobject` of the emulator's right `name`: the type of the
/// object behind it (0 when the host refuses).
pub fn kobject(name: Name) -> u32 {
    let (mut t, mut a) = (0u32, 0u64);
    // SAFETY: `t` and `a` receive the answer.
    let kr = unsafe { mach_port_kobject(task(), name, &mut t, &mut a) };
    if kr == 0 { t } else { 0 }
}

/// A send right to the host port.
pub fn host_port() -> Name {
    // SAFETY: takes no arguments; returns a new send right.
    unsafe { mach_host_self() }
}

/// A new identity token of the emulator's own task.
pub fn identity_token() -> Option<Name> {
    let mut t = NULL;
    // SAFETY: `t` receives the token's send right.
    let kr = unsafe { task_create_identity_token(task(), &mut t) };
    (kr == 0 && t != NULL).then_some(t)
}

/// A send right to IOKit's main port.
pub fn io_main() -> Option<Name> {
    let mut p = NULL;
    // SAFETY: `p` receives the right.
    let kr = unsafe { host_get_io_main(host_port(), &mut p) };
    (kr == 0 && p != NULL).then_some(p)
}

/// A send right to the emulator's own task port.
pub fn task_port() -> Option<Name> {
    mod_refs(task(), right::SEND, 1).then(task)
}

/// Releases out-of-line memory a received message carried.
pub fn free(addr: u64, size: u64) {
    if addr != 0 && size != 0 {
        // SAFETY: a region the kernel mapped into this task for a message.
        unsafe { vm_deallocate(task(), addr as usize, size as usize) };
    }
}

/// A host memory entry for `len` bytes of host file `fd` from `offset`
/// (a page boundary), with protection `prot`: the file mapped shared into
/// the emulator for as long as the entry is made.
pub fn memory_entry(fd: i32, offset: u64, len: u64, prot: u32) -> Result<Name, i32> {
    // SAFETY: sysconf takes no pointers.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
    let (base, skip) = (offset & !(page - 1), offset & (page - 1));
    let span = (skip + len + page - 1) & !(page - 1);
    // SAFETY: a shared mapping of the file, unmapped below.
    let addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            span as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            base as libc::off_t,
        )
    };
    if addr == libc::MAP_FAILED {
        return Err(3); // KERN_NO_SPACE
    }
    let mut size = len;
    let mut h = NULL;
    // SAFETY: the range is mapped; `size` and `h` receive the answer.
    let kr = unsafe {
        mach_make_memory_entry_64(
            task(),
            &mut size,
            addr as u64 + skip,
            prot as i32,
            &mut h,
            NULL,
        )
    };
    // SAFETY: the mapping made above; the entry keeps the memory.
    unsafe { libc::munmap(addr, span as usize) };
    if kr != 0 { Err(kr) } else { Ok(h) }
}

/// The contents of `size` bytes of the memory object behind host right
/// `object` from `offset`, mapped into the emulator (readable, with the
/// guest's protections `cur` and `max`, `VM_PROT_IS_MASK` included, as the
/// host's entry allows them) and copied out, with the protections the
/// mapping got.
pub fn map_copy(
    object: Name,
    size: u64,
    offset: u64,
    cur: u32,
    max: u32,
) -> Result<(Vec<u8>, u32, u32), i32> {
    let mut addr = 0u64;
    // VM_FLAGS_ANYWHERE, a copy; VM_INHERIT_NONE.
    // SAFETY: `addr` receives the mapping's address.
    let kr = unsafe {
        mach_vm_map(
            task(),
            &mut addr,
            size,
            0,
            1,
            object,
            offset,
            1,
            (cur | 1) as i32,
            (max | 1) as i32,
            2,
        )
    };
    if kr != 0 {
        return Err(kr);
    }
    // VM_REGION_BASIC_INFO_64: protection, max_protection, ...
    let (mut raddr, mut rsize, mut obj) = (addr, 0u64, NULL);
    let mut info = [0i32; 9];
    let mut count = info.len() as u32;
    // SAFETY: `info` holds VM_REGION_BASIC_INFO_COUNT_64 words.
    let kr = unsafe {
        mach_vm_region(
            task(),
            &mut raddr,
            &mut rsize,
            9,
            info.as_mut_ptr(),
            &mut count,
            &mut obj,
        )
    };
    if obj != NULL {
        deallocate(obj);
    }
    let (got_cur, got_max) = if kr == 0 {
        (info[0] as u32, info[1] as u32)
    } else {
        (cur & 7, max & 7)
    };
    let data = read(addr, size);
    free(addr, size);
    // The guest's own protections, masked by what the entry allowed.
    let keep = |asked: u32, got: u32| {
        if asked & 0x40 != 0 {
            asked & 7 & got
        } else {
            asked & 7
        }
    };
    Ok((data, keep(cur, got_cur), keep(max, got_max)))
}

/// A region of the emulator's address space, as
/// `mach_vm_region_recurse` reports it at depth 0
/// (`VM_REGION_SUBMAP_INFO_64`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    pub start: u64,
    pub end: u64,
    /// `VM_PROT_*` now, and at most.
    pub prot: u32,
    pub max: u32,
    pub inheritance: u32,
    pub tag: u32,
    /// `SM_*`.
    pub share_mode: u8,
    pub submap: bool,
}

/// The region at or after `addr`.
pub fn region_from(addr: u64) -> Option<Region> {
    let (mut a, mut size, mut depth) = (addr, 0u64, 0u32);
    // vm_region_submap_info_64 (V3, 21 words, packed to 4 bytes).
    let mut info = [0i32; 21];
    let mut count = info.len() as u32;
    // SAFETY: `info` holds VM_REGION_SUBMAP_INFO_COUNT_64 words; the other
    // pointers receive the answer.
    let kr = unsafe {
        mach_vm_region_recurse(
            task(),
            &mut a,
            &mut size,
            &mut depth,
            info.as_mut_ptr(),
            &mut count,
        )
    };
    if kr != 0 || size == 0 {
        return None;
    }
    Some(Region {
        start: a,
        end: a.saturating_add(size),
        prot: info[0] as u32,
        max: info[1] as u32,
        inheritance: info[2] as u32,
        tag: info[5] as u32,
        // share_mode is byte 47, the last of word 11.
        share_mode: (info[11] as u32 >> 24) as u8,
        submap: info[12] != 0,
    })
}

/// Every region of the emulator's address space, in address order.
pub fn regions() -> Vec<Region> {
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(r) = region_from(at) {
        at = r.end;
        out.push(r);
    }
    out
}

/// The emulator's virtual size and region count (`TASK_VM_INFO`), which
/// change when a region is made.
pub fn vm_stamp() -> (u64, u32) {
    // task_vm_info_data_t, packed to 4 bytes: virtual_size, region_count.
    let mut info = [0i32; 128];
    let mut count = info.len() as u32;
    // SAFETY: `info` holds `count` words; TASK_VM_INFO is 22.
    let kr = unsafe { task_info(task(), 22, info.as_mut_ptr(), &mut count) };
    if kr != 0 {
        return (0, 0);
    }
    let size = u64::from(info[0] as u32) | (u64::from(info[1] as u32) << 32);
    (size, info[2] as u32)
}

/// Reserves `[addr, addr + len)` (free host pages) with an inaccessible
/// mapping tagged `tag`, which a host child does not inherit.
pub fn reserve(addr: u64, len: u64, tag: u32) -> bool {
    let mut a = addr;
    // SAFETY: a fixed mapping of free address space, no memory object.
    let kr = unsafe {
        mach_vm_map(
            task(),
            &mut a,
            len,
            0,
            vmflags::FIXED | (tag << 24) as i32,
            NULL,
            0,
            0,
            0,
            0,
            inherit::NONE,
        )
    };
    kr == 0 && a == addr
}

/// A memory entry of the emulator's memory `[addr, addr + len)` itself
/// (`MAP_MEM_VM_SHARE`), allowing `prot`.
pub fn share_entry(addr: u64, len: u64, prot: u32) -> Result<Name, i32> {
    let mut size = len;
    let mut h = NULL;
    // SAFETY: `size` and `h` receive the answer.
    let kr = unsafe {
        mach_make_memory_entry_64(
            task(),
            &mut size,
            addr,
            prot as i32 | MAP_MEM_VM_SHARE,
            &mut h,
            NULL,
        )
    };
    if kr != 0 { Err(kr) } else { Ok(h) }
}

/// A memory entry of `len` bytes of entry `parent` from `offset`, allowing
/// `prot`.
pub fn sub_entry(parent: Name, offset: u64, len: u64, prot: u32) -> Result<Name, i32> {
    let mut size = len;
    let mut h = NULL;
    // SAFETY: `size` and `h` receive the answer.
    let kr = unsafe {
        mach_make_memory_entry_64(task(), &mut size, offset, prot as i32, &mut h, parent)
    };
    if kr != 0 { Err(kr) } else { Ok(h) }
}

/// Maps `len` bytes of memory entry `entry` from `offset` over `at`,
/// replacing what is there, shared (and with a host child), with `prot`.
///
/// # Safety
/// `[at, at + len)` must be the caller's own host-page-aligned memory that
/// nothing references while it is replaced.
pub unsafe fn map_entry_at(at: u64, entry: Name, offset: u64, len: u64, prot: u32) -> i32 {
    let mut a = at;
    // SAFETY: as the caller promises; the entry is a right of this task.
    let kr = unsafe {
        mach_vm_map(
            task(),
            &mut a,
            len,
            0,
            vmflags::FIXED | vmflags::OVERWRITE,
            entry,
            offset,
            0,
            prot as i32,
            prot as i32,
            inherit::SHARE,
        )
    };
    if kr == 0 && a != at { 3 } else { kr }
}

/// Reads up to `buf.len()` bytes of memory entry `entry` of `size` bytes
/// from `offset`, through a mapping of it made for the read.
pub fn read_entry(entry: Name, size: u64, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
    let n = (buf.len() as u64).min(size.saturating_sub(offset));
    if n == 0 {
        return Ok(0);
    }
    // SAFETY: sysconf takes no pointers.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
    let (base, skip) = (offset & !(page - 1), offset & (page - 1));
    let span = (skip + n).div_ceil(page) * page;
    let mut a = 0u64;
    // SAFETY: a new read-only mapping anywhere, unmapped below.
    let kr = unsafe {
        mach_vm_map(
            task(),
            &mut a,
            span,
            0,
            vmflags::ANYWHERE,
            entry,
            base,
            0,
            1,
            1,
            inherit::NONE,
        )
    };
    if kr != 0 {
        return Err(std::io::Error::other(format!("mach_vm_map: {kr:#x}")));
    }
    // SAFETY: the mapping made above holds `span` readable bytes.
    let src = unsafe { std::slice::from_raw_parts((a + skip) as *const u8, n as usize) };
    buf[..n as usize].copy_from_slice(src);
    free(a, span);
    Ok(n as usize)
}

/// A shared mapping into the emulator of `size` bytes of the memory
/// object behind host right `object` from `offset` (with the guest's
/// maximum protection `max`, `VM_PROT_IS_MASK` included, made readable, as
/// the host's entry allows it, and that current protection; inherited as a
/// copy): its address, and the protections the guest's mapping of it gets
/// (`cur`, `max` as the guest asked).
pub fn map_shared(
    object: Name,
    size: u64,
    offset: u64,
    cur: u32,
    max: u32,
) -> Result<(u64, u32, u32), i32> {
    let mut addr = 0u64;
    // SAFETY: `addr` receives the mapping's address.
    let kr = unsafe {
        mach_vm_map(
            task(),
            &mut addr,
            size,
            0,
            vmflags::ANYWHERE,
            object,
            offset,
            0,
            (max | 1) as i32,
            (max | 1) as i32,
            1,
        )
    };
    if kr != 0 {
        return Err(kr);
    }
    // The entry allowed at most what the mapping got (the guest's current
    // protection is within its maximum).
    let (got_cur, got_max) = match region_from(addr) {
        Some(r) if r.start == addr => (r.max, r.max),
        _ => (cur & 7, max & 7),
    };
    let keep = |asked: u32, got: u32| {
        if asked & 0x40 != 0 {
            asked & 7 & got
        } else {
            asked & 7
        }
    };
    Ok((addr, keep(cur, got_cur), keep(max, got_max)))
}

/// Reads `len` bytes of host memory at `addr` (a received out-of-line
/// region).
pub fn read(addr: u64, len: u64) -> Vec<u8> {
    if addr == 0 || len == 0 {
        return Vec::new();
    }
    // SAFETY: the kernel mapped `len` bytes at `addr` for the message.
    unsafe { std::slice::from_raw_parts(addr as *const u8, len as usize) }.to_vec()
}

/// A kqueue that is readable while the port set `set` holds a message.
pub fn watch(set: Name) -> Option<OwnedFd> {
    // SAFETY: kqueue takes no arguments.
    let kq = unsafe { libc::kqueue() };
    if kq < 0 {
        return None;
    }
    // SAFETY: `kq` was just created and is owned here.
    let owned = unsafe { OwnedFd::from_raw_fd(kq) };
    let ev = libc::kevent {
        ident: set as usize,
        filter: libc::EVFILT_MACHPORT,
        flags: libc::EV_ADD,
        fflags: 0,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    // SAFETY: registers one event; no events are returned.
    let r = unsafe { libc::kevent(kq, &ev, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
    (r == 0).then_some(owned)
}
