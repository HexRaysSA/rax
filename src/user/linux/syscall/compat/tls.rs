//! i386 thread-local storage (`arch/x86/kernel/tls.c`, `asm/desc.h`
//! `fill_ldt`, `LDT_empty`, `LDT_zero`): `set_thread_area` and
//! `get_thread_area` over the thread's GDT entries 12-14, as a
//! `struct user_desc`.

use super::super::super::abi::errno::Errno;
use super::super::super::abi::errno_table::*;
use super::super::super::arch::GuestCpu;
use super::super::Ctx;
use crate::isa::x86_64::{GDT_ENTRY_TLS_MAX, GDT_ENTRY_TLS_MIN};

/// `sizeof(struct user_desc)`.
const USER_DESC: usize = 16;
/// `GDT_ENTRY_TLS_ENTRIES`.
const TLS_ENTRIES: usize = 3;

/// `struct user_desc` (`uapi/asm/ldt.h`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UserDesc {
    pub entry_number: u32,
    pub base_addr: u32,
    pub limit: u32,
    pub seg_32bit: bool,
    pub contents: u32,
    pub read_exec_only: bool,
    pub limit_in_pages: bool,
    pub seg_not_present: bool,
    pub useable: bool,
}

impl UserDesc {
    /// From the guest's 16 bytes. `lm` is not read: a 32-bit caller may
    /// leave it uninitialized.
    pub fn decode(b: &[u8]) -> UserDesc {
        let word = |i: usize| u32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap());
        let bits = word(3);
        UserDesc {
            entry_number: word(0),
            base_addr: word(1),
            limit: word(2),
            seg_32bit: bits & 1 != 0,
            contents: (bits >> 1) & 3,
            read_exec_only: bits & (1 << 3) != 0,
            limit_in_pages: bits & (1 << 4) != 0,
            seg_not_present: bits & (1 << 5) != 0,
            useable: bits & (1 << 6) != 0,
        }
    }

    /// The guest's 16 bytes (`lm` clear).
    pub fn encode(&self) -> [u8; USER_DESC] {
        let bits = u32::from(self.seg_32bit)
            | self.contents << 1
            | u32::from(self.read_exec_only) << 3
            | u32::from(self.limit_in_pages) << 4
            | u32::from(self.seg_not_present) << 5
            | u32::from(self.useable) << 6;
        let mut b = [0u8; USER_DESC];
        for (i, w) in [self.entry_number, self.base_addr, self.limit, bits]
            .iter()
            .enumerate()
        {
            b[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        b
    }

    /// `LDT_empty`: the documented "no segment".
    fn empty(&self) -> bool {
        self.base_addr == 0
            && self.limit == 0
            && self.contents == 0
            && self.read_exec_only
            && !self.seg_32bit
            && !self.limit_in_pages
            && self.seg_not_present
            && !self.useable
    }

    /// `LDT_zero`: all zero, which programs use for "no segment" too.
    fn zero(&self) -> bool {
        self.base_addr == 0
            && self.limit == 0
            && self.contents == 0
            && !self.read_exec_only
            && !self.seg_32bit
            && !self.limit_in_pages
            && !self.seg_not_present
            && !self.useable
    }

    /// `tls_desc_okay`: no segment, or a present 32-bit data segment.
    fn okay(&self) -> bool {
        self.empty()
            || self.zero()
            || (self.seg_32bit && self.contents <= 1 && !self.seg_not_present)
    }

    /// `fill_ldt`: the descriptor, accessed, DPL 3, never 64-bit code.
    fn descriptor(&self) -> u64 {
        if self.empty() || self.zero() {
            return 0;
        }
        let ty = u64::from(u32::from(!self.read_exec_only) << 1 | self.contents << 2 | 1);
        let base = u64::from(self.base_addr);
        let limit = u64::from(self.limit);
        (limit & 0xFFFF)
            | (base & 0xFF_FFFF) << 16
            | ty << 40
            | 1 << 44
            | 3 << 45
            | u64::from(!self.seg_not_present) << 47
            | ((limit >> 16) & 0xF) << 48
            | u64::from(self.useable) << 52
            | u64::from(self.seg_32bit) << 54
            | u64::from(self.limit_in_pages) << 55
            | ((base >> 24) & 0xFF) << 56
    }

    /// `fill_user_desc`: entry `index`'s descriptor as a `user_desc`.
    fn from_descriptor(index: u32, d: u64) -> UserDesc {
        let ty = ((d >> 40) & 0xF) as u32;
        UserDesc {
            entry_number: index,
            base_addr: ((d >> 16) & 0xFF_FFFF | ((d >> 56) & 0xFF) << 24) as u32,
            limit: ((d & 0xFFFF) | ((d >> 48) & 0xF) << 16) as u32,
            seg_32bit: d & (1 << 54) != 0,
            contents: ty >> 2,
            read_exec_only: ty & 2 == 0,
            limit_in_pages: d & (1 << 55) != 0,
            seg_not_present: d & (1 << 47) == 0,
            useable: d & (1 << 52) != 0,
        }
    }
}

fn x86<'c>(c: &'c mut Ctx<'_>) -> Result<&'c mut crate::user::cpu::x86_64::X86UserCpu, Errno> {
    match &mut c.t.cpu {
        GuestCpu::X86_64(cpu) => Ok(cpu),
        _ => Err(Errno(ENOSYS)),
    }
}

/// `do_set_thread_area` for the calling thread (`idx` -1 takes the
/// entry number from the descriptor, and -1 there allocates a free entry
/// when `can_allocate`, written back).
pub fn do_set_thread_area(
    c: &mut Ctx<'_>,
    idx: i32,
    u_info: u64,
    can_allocate: bool,
) -> Result<u64, Errno> {
    let b = c.read_mem(u_info, USER_DESC)?;
    let info = UserDesc::decode(&b);
    if !info.okay() {
        return Err(Errno(EINVAL));
    }
    let mut idx = if idx == -1 {
        info.entry_number as i32
    } else {
        idx
    };
    if idx == -1 && can_allocate {
        let cpu = x86(c)?;
        let free = (0..TLS_ENTRIES)
            .map(|i| GDT_ENTRY_TLS_MIN + i)
            .find(|&i| cpu.vcpu().user_gdt_entry(i) == Some(0));
        let Some(free) = free else {
            return Err(Errno(ESRCH));
        };
        idx = free as i32;
        c.write_u32(u_info, idx as u32)?;
    }
    if !(GDT_ENTRY_TLS_MIN as i32..=GDT_ENTRY_TLS_MAX as i32).contains(&idx) {
        return Err(Errno(EINVAL));
    }
    let cpu = x86(c)?;
    cpu.vcpu_mut()
        .set_user_tls_entry(idx as usize, info.descriptor());
    // The registers holding the entry load it again.
    cpu.vcpu_mut().reload_user_segments((idx as u16) << 3 | 3);
    Ok(0)
}

/// `set_thread_area(u_info)`.
pub fn set_thread_area(c: &mut Ctx<'_>, u_info: u64) -> Result<u64, Errno> {
    do_set_thread_area(c, -1, u_info, true)
}

/// `get_thread_area(u_info)` (`do_get_thread_area`).
pub fn get_thread_area(c: &mut Ctx<'_>, u_info: u64) -> Result<u64, Errno> {
    let idx = c.read_u32(u_info)? as i32;
    if !(GDT_ENTRY_TLS_MIN as i32..=GDT_ENTRY_TLS_MAX as i32).contains(&idx) {
        return Err(Errno(EINVAL));
    }
    let d = x86(c)?.vcpu().user_gdt_entry(idx as usize).unwrap_or(0);
    c.write_mem(u_info, &UserDesc::from_descriptor(idx as u32, d).encode())?;
    Ok(0)
}
