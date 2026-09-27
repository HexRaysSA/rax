//! The global descriptor table a Linux x86-64 kernel gives user mode
//! (`arch/x86/kernel/cpu/common.c` `gdt_page`, `setup_getcpu`;
//! `arch/x86/include/asm/segment.h`): the kernel's code and data segments
//! (DPL 0), `__USER32_CS` (entry 4, selector 0x23), `__USER_DS` (5, 0x2b),
//! and `__USER_CS` (6, 0x33), the task-state segment (8-9), the three
//! thread-local-storage entries `set_thread_area` fills (12-14, selectors
//! 0x63, 0x6b, 0x73), and the CPU-and-node entry (15, 0x7b) whose limit
//! `LSL` reads.
//!
//! The table is not in guest memory: GDTR points at [`USER_GDT_BASE`], a
//! kernel-half address no user mapping reaches, and the MMU serves the
//! supervisor accesses there from the table. Segment loads, far transfers,
//! `LAR`/`LSL`/`VERR`/`VERW`, and the accessed-bit stores therefore see the
//! descriptors as they would the kernel's GDT. Each thread's vCPU has its own
//! table, as each task has its own TLS entries.

use super::cpu::X86_64Vcpu;
use super::execute::system::{
    X86SegmentLoadTarget, X86SegmentSelectorLoadFault, X86SystemDescriptorFault,
};
use super::memory::Mmu;

/// Where GDTR points in user mode.
pub const USER_GDT_BASE: u64 = 0xFFFF_FE00_0000_0000;
/// `GDT_ENTRIES` (x86-64).
pub const GDT_ENTRIES: usize = 16;
/// `GDT_ENTRY_TLS_MIN` and `GDT_ENTRY_TLS_MAX`.
pub const GDT_ENTRY_TLS_MIN: usize = 12;
pub const GDT_ENTRY_TLS_MAX: usize = 14;
/// `GDT_ENTRY_CPUNODE`.
pub const GDT_ENTRY_CPUNODE: usize = 15;

// `desc_defs.h`: the flags `GDT_ENTRY_INIT` takes.
const ACCESSED: u16 = 0x0001;
const WRITABLE_READABLE: u16 = 0x0002;
const EXECUTABLE: u16 = 0x0008;
const S: u16 = 0x0010;
const PRESENT: u16 = 0x0080;
const LONG: u16 = 0x2000;
const DB: u16 = 0x4000;
const GRANULARITY_4K: u16 = 0x8000;
const fn dpl(level: u16) -> u16 {
    level << 5
}
const DATA: u16 = S | PRESENT | ACCESSED | WRITABLE_READABLE;
const CODE: u16 = S | PRESENT | ACCESSED | WRITABLE_READABLE | EXECUTABLE;
const DATA64: u16 = DATA | GRANULARITY_4K | DB;
const CODE32: u16 = CODE | GRANULARITY_4K | DB;
const CODE64: u16 = CODE | GRANULARITY_4K | LONG;
const USER: u16 = dpl(3);

/// `GDT_ENTRY_INIT(flags, base, limit)` as the 8-byte descriptor.
pub const fn gdt_entry(flags: u16, base: u32, limit: u32) -> u64 {
    let flags = flags as u64;
    let base = base as u64;
    let limit = limit as u64;
    (limit & 0xFFFF)
        | (base & 0xFF_FFFF) << 16
        | (flags & 0xFF) << 40
        | ((limit >> 16) & 0xF) << 48
        | ((flags >> 12) & 0xF) << 52
        | ((base >> 24) & 0xFF) << 56
}

/// A segment register of a user-mode thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86UserSegment {
    /// CS.
    Cs,
    /// SS.
    Ss,
    /// DS.
    Ds,
    /// ES.
    Es,
    /// FS.
    Fs,
    /// GS.
    Gs,
}

/// The exception a segment-register load raises (SDM Vol. 2B `MOV`,
/// "Protected Mode Exceptions"), with its selector error code (the
/// selector with RPL cleared, or zero).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86SegmentFault {
    /// #GP.
    GeneralProtection(u16),
    /// #NP: a data segment not present.
    NotPresent(u16),
    /// #SS: a stack segment not present.
    StackSegment(u16),
}

/// The table, as bytes.
#[derive(Clone)]
pub(super) struct UserTables {
    gdt: [u8; GDT_ENTRIES * 8],
}

impl UserTables {
    /// The GDT at boot of CPU 0, node 0.
    fn linux() -> Self {
        let mut entries = [0u64; GDT_ENTRIES];
        entries[1] = gdt_entry(CODE32, 0, 0xFFFFF);
        entries[2] = gdt_entry(CODE64, 0, 0xFFFFF);
        entries[3] = gdt_entry(DATA64, 0, 0xFFFFF);
        entries[4] = gdt_entry(CODE32 | USER, 0, 0xFFFFF);
        entries[5] = gdt_entry(DATA64 | USER, 0, 0xFFFFF);
        entries[6] = gdt_entry(CODE64 | USER, 0, 0xFFFFF);
        // A busy 64-bit TSS (a system descriptor, DPL 0); its base is
        // kernel memory the table does not show.
        entries[8] = gdt_entry(PRESENT | 0xB, 0, 0x67);
        // setup_getcpu: read-only expand-down accessed data, DPL 3, 32-bit,
        // the CPU (0) and node (0) in the limit.
        entries[GDT_ENTRY_CPUNODE] = gdt_entry(S | PRESENT | USER | DB | 0x5, 0, 0);
        let mut gdt = [0u8; GDT_ENTRIES * 8];
        for (i, e) in entries.iter().enumerate() {
            gdt[i * 8..i * 8 + 8].copy_from_slice(&e.to_le_bytes());
        }
        UserTables { gdt }
    }

    fn entry(&self, index: usize) -> u64 {
        u64::from_le_bytes(self.gdt[index * 8..index * 8 + 8].try_into().unwrap())
    }

    fn set_entry(&mut self, index: usize, descriptor: u64) {
        self.gdt[index * 8..index * 8 + 8].copy_from_slice(&descriptor.to_le_bytes());
    }

    /// The table's bytes at `vaddr..vaddr + len`, if they lie wholly in it.
    fn range(&self, vaddr: u64, len: usize) -> Option<std::ops::Range<usize>> {
        let start = usize::try_from(vaddr.checked_sub(USER_GDT_BASE)?).ok()?;
        let end = start.checked_add(len)?;
        (end <= self.gdt.len()).then_some(start..end)
    }
}

impl Mmu {
    pub(super) fn set_user_tables(&mut self, tables: Option<Box<UserTables>>) {
        self.user_tables = tables;
    }

    pub(super) fn user_tables(&self) -> Option<&UserTables> {
        self.user_tables.as_deref()
    }

    pub(super) fn user_tables_mut(&mut self) -> Option<&mut UserTables> {
        self.user_tables.as_deref_mut()
    }

    /// Serves a supervisor read at `vaddr` from the user-mode tables. `None`
    /// when no table is installed or the access is not wholly inside one.
    pub(super) fn user_table_read(&self, vaddr: u64, buf: &mut [u8]) -> Option<()> {
        let tables = self.user_tables()?;
        let range = tables.range(vaddr, buf.len())?;
        buf.copy_from_slice(&tables.gdt[range]);
        Some(())
    }

    /// Serves a supervisor write (an accessed bit) at `vaddr` to the
    /// user-mode tables, as [`Mmu::user_table_read`].
    pub(super) fn user_table_write(&mut self, vaddr: u64, buf: &[u8]) -> Option<()> {
        let tables = self.user_tables_mut()?;
        let range = tables.range(vaddr, buf.len())?;
        tables.gdt[range].copy_from_slice(buf);
        Some(())
    }
}

impl X86_64Vcpu {
    /// Installs Linux's user-mode GDT and points GDTR at it.
    pub(super) fn install_user_gdt(&mut self) {
        self.mmu
            .set_user_tables(Some(Box::new(UserTables::linux())));
        self.sregs.gdt.base = USER_GDT_BASE;
        self.sregs.gdt.limit = (GDT_ENTRIES * 8 - 1) as u16;
    }

    /// GDT entry `index` of the user-mode table (`None` outside it or
    /// without user mode).
    pub fn user_gdt_entry(&self, index: usize) -> Option<u64> {
        let tables = self.mmu.user_tables()?;
        (index < GDT_ENTRIES).then(|| tables.entry(index))
    }

    /// Copies `other`'s DS, ES, FS, and GS (selectors, cached descriptors,
    /// and so the FS/GS bases), as a new thread starts with its creator's.
    pub fn copy_user_data_segments(&mut self, other: &X86_64Vcpu) {
        self.sregs.ds = other.sregs.ds.clone();
        self.sregs.es = other.sregs.es.clone();
        self.sregs.fs = other.sregs.fs.clone();
        self.sregs.gs = other.sregs.gs.clone();
    }

    /// Replaces thread-local-storage entry `index`
    /// ([`GDT_ENTRY_TLS_MIN`]..=[`GDT_ENTRY_TLS_MAX`]) with `descriptor`
    /// (`set_thread_area`'s `fill_ldt`). Like a descriptor-table store, it
    /// leaves the segment registers' cached descriptors alone; the caller
    /// reloads those holding the entry (`do_set_thread_area`). False for
    /// another index or without user mode.
    pub fn set_user_tls_entry(&mut self, index: usize, descriptor: u64) -> bool {
        if !(GDT_ENTRY_TLS_MIN..=GDT_ENTRY_TLS_MAX).contains(&index) {
            return false;
        }
        let Some(tables) = self.mmu.user_tables_mut() else {
            return false;
        };
        tables.set_entry(index, descriptor);
        true
    }

    /// Replaces GDT entry `index` with `descriptor`, for embedders whose
    /// operating system lays out more of the table than Linux does (the
    /// Windows personality uses entry 10 for its TEB, selector 0x53).
    /// This is a synthetic layout, not a native WoW64 selector guarantee. The null
    /// entry, the kernel and user code/data entries (1-6), and the TSS
    /// (8-9) cannot be replaced: user mode's own selectors depend on them.
    /// Like [`X86_64Vcpu::set_user_tls_entry`], the segment registers'
    /// cached descriptors are unchanged until reloaded. False for a
    /// protected or out-of-range index, or without user mode.
    pub fn set_user_gdt_entry(&mut self, index: usize, descriptor: u64) -> bool {
        if index >= GDT_ENTRIES || index <= 6 || index == 8 || index == 9 {
            return false;
        }
        let Some(tables) = self.mmu.user_tables_mut() else {
            return false;
        };
        tables.set_entry(index, descriptor);
        true
    }

    /// The selector segment register `seg` holds.
    pub fn user_selector(&self, seg: X86UserSegment) -> u16 {
        match seg {
            X86UserSegment::Cs => self.sregs.cs.selector,
            X86UserSegment::Ss => self.sregs.ss.selector,
            X86UserSegment::Ds => self.sregs.ds.selector,
            X86UserSegment::Es => self.sregs.es.selector,
            X86UserSegment::Fs => self.sregs.fs.selector,
            X86UserSegment::Gs => self.sregs.gs.selector,
        }
    }

    /// Loads `selector` into SS, DS, ES, FS, or GS as a `MOV` to the
    /// register at the thread's privilege level would: the descriptor
    /// checks, the accessed-bit store, and the hidden part. On a fault the
    /// register is unchanged. CS is not loaded this way
    /// ([`X86_64Vcpu::set_user_compat`] selects the code segment).
    pub fn load_user_segment(
        &mut self,
        seg: X86UserSegment,
        selector: u16,
    ) -> Result<(), X86SegmentFault> {
        let target = match seg {
            X86UserSegment::Ss => X86SegmentLoadTarget::Ss,
            X86UserSegment::Ds => X86SegmentLoadTarget::Ds,
            X86UserSegment::Es => X86SegmentLoadTarget::Es,
            X86UserSegment::Fs => X86SegmentLoadTarget::Fs,
            X86UserSegment::Gs => X86SegmentLoadTarget::Gs,
            X86UserSegment::Cs => return Err(X86SegmentFault::GeneralProtection(selector & !3)),
        };
        let code = |e: u32| e as u16;
        match self.load_segment_selector(target, selector, false) {
            Ok(()) => Ok(()),
            Err(X86SegmentSelectorLoadFault::Architectural(fault)) => Err(match fault {
                X86SystemDescriptorFault::GeneralProtection { error_code } => {
                    X86SegmentFault::GeneralProtection(code(error_code))
                }
                X86SystemDescriptorFault::SegmentNotPresent { error_code } => {
                    X86SegmentFault::NotPresent(code(error_code))
                }
            }),
            Err(X86SegmentSelectorLoadFault::StackSegment { error_code }) => {
                Err(X86SegmentFault::StackSegment(code(error_code)))
            }
            // The table is served by the MMU and a direct load never
            // preflights: neither happens in user mode.
            Err(
                X86SegmentSelectorLoadFault::Memory(_) | X86SegmentSelectorLoadFault::NativeDeopt,
            ) => Err(X86SegmentFault::GeneralProtection(selector & !3)),
        }
    }
}

#[cfg(test)]
#[path = "user_gdt_tests.rs"]
mod tests;
