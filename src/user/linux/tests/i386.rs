//! The i386 compatibility ABI against Linux 6.19 on x86-64
//! (`CONFIG_IA32_EMULATION`): the layout of a compatibility task
//! (`page_64_types.h` `IA32_PAGE_OFFSET`, `elf.h`
//! `COMPAT_ELF_ET_DYN_BASE`, `x86/mm/mmap.c`), ELF32 acceptance
//! (`elf_check_arch_ia32`), the `syscall_32.tbl` numbers, the initial stack
//! in 4-byte words with `AT_PLATFORM` `i686` (`compat_binfmt_elf.c`), `int
//! $0x80` as the task's own system-call entry, `set_thread_area` and
//! `get_thread_area` (`arch/x86/kernel/tls.c`, `fill_ldt`), `mmap2`'s page
//! offset, `struct compat_iovec`, the terminal `ioctl`s passed through, and
//! `ENOSYS` for calls without a 32-bit conversion yet.

use super::harness::{CODE, Harness};
use crate::user::image::elf::ElfClass;
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::arch::{CpuEvent, GuestCpu};
use crate::vm::vcpu::VCpu;

fn put(h: &Harness, at: u64, bytes: &[u8]) {
    h.proc.state.space.write_raw(at, bytes).unwrap();
}

fn u32_at(h: &Harness, at: u64) -> u32 {
    let mut b = [0u8; 4];
    h.proc.state.space.read_raw(at, &mut b).unwrap();
    u32::from_le_bytes(b)
}

fn cstr(h: &Harness, at: u64) -> String {
    let mut out = Vec::new();
    let mut b = [0u8];
    let mut p = at;
    loop {
        h.proc.state.space.read_raw(p, &mut b).unwrap();
        if b[0] == 0 {
            break;
        }
        out.push(b[0]);
        p += 1;
    }
    String::from_utf8(out).unwrap()
}

/// A `struct user_desc`: entry, base, limit, and the flag bits
/// (`seg_32bit` 0, `contents` 1-2, `read_exec_only` 3, `limit_in_pages` 4,
/// `seg_not_present` 5, `useable` 6).
fn user_desc(entry: u32, base: u32, limit: u32, bits: u32) -> Vec<u8> {
    [entry, base, limit, bits]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect()
}

const SEG_32BIT: u32 = 1;
const READ_EXEC_ONLY: u32 = 1 << 3;
const LIMIT_IN_PAGES: u32 = 1 << 4;
const SEG_NOT_PRESENT: u32 = 1 << 5;
const USEABLE: u32 = 1 << 6;

fn gdt(h: &Harness, index: usize) -> u64 {
    let GuestCpu::X86_64(cpu) = &h.proc.threads[0].cpu else {
        panic!("an x86 CPU");
    };
    cpu.vcpu().user_gdt_entry(index).unwrap()
}

#[test]
fn a_compatibility_task_has_the_i386_layout_and_numbers() {
    let a = LinuxAbi::I386;
    assert_eq!((a.task_size(), a.stack_top()), (0xFFFF_E000, 0xFFFF_E000));
    assert_eq!(a.elf_et_dyn_base(), 0x5655_5000);
    // max(8 MiB + stack_guard_gap, 128 MiB) below the top.
    assert_eq!(a.mmap_base(8 << 20), 0xF7FF_E000);
    assert_eq!((a.word_size(), a.audit_arch()), (4, 0x4000_0003));
    // uname -m of a compatibility task without PER_LINUX32.
    assert_eq!(a.machine(), "x86_64");
    // elf_check_arch_ia32: EM_386 or EM_486, as ELFCLASS32.
    assert_eq!(LinuxAbi::from_elf(3, Some(ElfClass::Elf32)), Some(a));
    assert_eq!(LinuxAbi::from_elf(6, Some(ElfClass::Elf32)), Some(a));
    assert_eq!(LinuxAbi::from_elf(3, Some(ElfClass::Elf64)), None);
    // unistd_32.h.
    for (nr, s) in [
        (1, Sysno::Exit),
        (4, Sysno::Write),
        (146, Sysno::Writev),
        (192, Sysno::Mmap2),
        (243, Sysno::SetThreadArea),
        (252, Sysno::ExitGroup),
    ] {
        assert_eq!(a.sysno(nr), Some(s));
        assert_eq!(a.number(s), Some(nr));
    }
    // 90 is the old mmap, its arguments in a structure.
    assert_eq!(a.number(Sysno::Mmap), Some(90));
}

#[test]
fn an_i386_program_starts_in_compatibility_mode_with_a_32_bit_stack() {
    let h = Harness::new(LinuxAbi::I386);
    assert_eq!(h.proc.state.abi, LinuxAbi::I386);
    let GuestCpu::X86_64(cpu) = &h.proc.threads[0].cpu else {
        panic!("an x86 CPU");
    };
    assert!(cpu.compat());
    assert_eq!(cpu.vcpu().get_sregs().unwrap().cs.selector, 0x23);
    assert!(
        h.scratch >= 0x1_0000 && h.scratch < 0xF7FF_E000,
        "{:#x}",
        h.scratch
    );
    // argc, argv[0], NULL, envp NULL, then auxv pairs: 4-byte words.
    let sp = h.proc.threads[0].cpu.sp();
    assert_eq!(sp % 16, 0);
    assert!(sp < 0xFFFF_E000);
    assert_eq!(u32_at(&h, sp), 1);
    assert_eq!(cstr(&h, u64::from(u32_at(&h, sp + 4))), "prog");
    assert_eq!((u32_at(&h, sp + 8), u32_at(&h, sp + 12)), (0, 0));
    let mut aux = std::collections::BTreeMap::new();
    let mut at = sp + 16;
    loop {
        let (tag, val) = (u32_at(&h, at), u32_at(&h, at + 4));
        if tag == 0 {
            break;
        }
        aux.insert(tag, val);
        at += 8;
    }
    assert_eq!(aux.get(&6), Some(&4096), "AT_PAGESZ");
    assert_eq!(cstr(&h, u64::from(aux[&15])), "i686", "AT_PLATFORM");
    assert!(aux.contains_key(&51), "AT_MINSIGSTKSZ");
    assert!(!aux.contains_key(&33), "no AT_SYSINFO_EHDR without a vDSO");
    assert_eq!(aux[&16], cpu.vcpu().cpuid(1, 0).3, "AT_HWCAP: CPUID.1:EDX");
}

#[test]
fn int_0x80_is_the_system_call_of_a_compatibility_task() {
    let mut h = Harness::new(LinuxAbi::I386);
    // mov $20,%eax (getpid); mov $7,%ebx; int $0x80
    put(&h, CODE, &[0xB8, 20, 0, 0, 0, 0xBB, 7, 0, 0, 0, 0xCD, 0x80]);
    h.proc.threads[0].cpu.set_pc(CODE);
    let event = h.proc.threads[0].cpu.run(1000);
    let CpuEvent::Syscall { nr, args } = event else {
        panic!("a system call, got {event:?}");
    };
    assert_eq!((nr, args[0]), (20, 7));
    assert_eq!(h.proc.threads[0].cpu.pc(), CODE + 12);
}

#[test]
fn set_thread_area_fills_allocates_and_reads_back_tls_entries() {
    let mut h = Harness::new(LinuxAbi::I386);
    let at = h.scratch;
    let bits = SEG_32BIT | LIMIT_IN_PAGES | USEABLE;
    // entry -1: the first free entry, written back.
    put(&h, at, &user_desc(u32::MAX, 0x1234_5000, 0xFFFFF, bits));
    assert_eq!(h.call(Sysno::SetThreadArea, &[at]), 0);
    assert_eq!(u32_at(&h, at), 12);
    // fill_ldt: accessed writable data, S, DPL 3, present, AVL, D, G.
    assert_eq!(gdt(&h, 12), 0x12DF_F334_5000_FFFF);
    // get_thread_area gives the fields back.
    put(&h, at, &user_desc(12, 0, 0, 0));
    assert_eq!(h.call(Sysno::GetThreadArea, &[at]), 0);
    let back: Vec<u32> = (0..4).map(|i| u32_at(&h, at + 4 * i)).collect();
    assert_eq!(back, [12, 0x1234_5000, 0xFFFFF, bits]);
    // Two more, then none free.
    for want in [13, 14] {
        put(&h, at, &user_desc(u32::MAX, 0x1000, 0xFFFFF, bits));
        assert_eq!(h.call(Sysno::SetThreadArea, &[at]), 0);
        assert_eq!(u32_at(&h, at), want);
    }
    put(&h, at, &user_desc(u32::MAX, 0x1000, 0xFFFFF, bits));
    assert_eq!(h.call(Sysno::SetThreadArea, &[at]), -i64::from(ESRCH));
    // tls_desc_okay: no 16-bit, code, or non-present segments.
    for bad in [
        LIMIT_IN_PAGES,
        SEG_32BIT | 2 << 1,
        SEG_32BIT | SEG_NOT_PRESENT,
    ] {
        put(&h, at, &user_desc(12, 0x1000, 1, bad));
        assert_eq!(
            h.call(Sysno::SetThreadArea, &[at]),
            -i64::from(EINVAL),
            "{bad:#x}"
        );
    }
    // Outside the TLS entries.
    for entry in [11, 15] {
        put(&h, at, &user_desc(entry, 0x1000, 1, bits));
        assert_eq!(h.call(Sysno::SetThreadArea, &[at]), -i64::from(EINVAL));
        put(&h, at, &user_desc(entry, 0, 0, 0));
        assert_eq!(h.call(Sysno::GetThreadArea, &[at]), -i64::from(EINVAL));
    }
    // LDT_zero and LDT_empty clear an entry.
    put(&h, at, &user_desc(13, 0, 0, 0));
    assert_eq!(h.call(Sysno::SetThreadArea, &[at]), 0);
    put(
        &h,
        at,
        &user_desc(14, 0, 0, READ_EXEC_ONLY | SEG_NOT_PRESENT),
    );
    assert_eq!(h.call(Sysno::SetThreadArea, &[at]), 0);
    assert_eq!((gdt(&h, 13), gdt(&h, 14)), (0, 0));
    // An unreadable descriptor.
    assert_eq!(h.call(Sysno::SetThreadArea, &[8]), -i64::from(EFAULT));
}

#[test]
fn set_thread_area_reloads_the_registers_holding_the_entry() {
    let mut h = Harness::new(LinuxAbi::I386);
    let at = h.scratch;
    let bits = SEG_32BIT | LIMIT_IN_PAGES;
    put(&h, at, &user_desc(12, 0x0010_0000, 0xFFFFF, bits));
    assert_eq!(h.call(Sysno::SetThreadArea, &[at]), 0);
    // mov $0x63,%eax; mov %eax,%gs; int $0x80
    put(&h, CODE, &[0xB8, 0x63, 0, 0, 0, 0x8E, 0xE8, 0xCD, 0x80]);
    h.proc.threads[0].cpu.set_pc(CODE);
    h.proc.threads[0].cpu.run(1000);
    let gs = |h: &Harness| {
        let GuestCpu::X86_64(cpu) = &h.proc.threads[0].cpu else {
            panic!("an x86 CPU");
        };
        let sregs = cpu.vcpu().get_sregs().unwrap();
        (sregs.gs.selector, sregs.gs.base)
    };
    assert_eq!(gs(&h), (0x63, 0x0010_0000));
    put(&h, at, &user_desc(12, 0x0020_0000, 0xFFFFF, bits));
    assert_eq!(h.call(Sysno::SetThreadArea, &[at]), 0);
    assert_eq!(gs(&h), (0x63, 0x0020_0000));
}

#[test]
fn compat_calls_convert_or_refuse() {
    let mut h = Harness::new(LinuxAbi::I386);
    // Four pages: PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, fd -1.
    let at = h.call(Sysno::Mmap2, &[0, 0x4000, 3, 0x22, u64::from(u32::MAX), 0]) as u64;
    // writev with struct compat_iovec: "ab" then "cde".
    let mut fds = [0u8; 8];
    assert_eq!(h.call(Sysno::Pipe2, &[at, 0]), 0);
    h.proc.state.space.read_raw(at, &mut fds).unwrap();
    let (rd, wr) = (
        u64::from(u32::from_le_bytes(fds[..4].try_into().unwrap())),
        u64::from(u32::from_le_bytes(fds[4..].try_into().unwrap())),
    );
    let data = at + 0x100;
    put(&h, data, b"abcde");
    let iov = at + 0x200;
    let vec: Vec<u8> = [data as u32, 2, data as u32 + 2, 3]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
    put(&h, iov, &vec);
    assert_eq!(h.call(Sysno::Writev, &[wr, iov, 2]), 5);
    // A compat_ssize_t length below zero: EINVAL.
    put(&h, iov + 4, &0x8000_0000u32.to_le_bytes());
    assert_eq!(h.call(Sysno::Writev, &[wr, iov, 2]), -i64::from(EINVAL));
    // FIONREAD passes through: an int.
    assert_eq!(h.call(Sysno::Ioctl, &[rd, 0x541B, at]), 0);
    assert_eq!(u32_at(&h, at), 5);
    // An ioctl without a conversion: ENOTTY.
    assert_eq!(h.call(Sysno::Ioctl, &[rd, 0x8912, at]), -i64::from(ENOTTY));
    // mmap2's offset is in pages: a two-page file's second page.
    put(&h, at + 0x300, b"i386\0");
    let fd = h.call(Sysno::MemfdCreate, &[at + 0x300, 0]) as u64;
    let pages = at + 0x400;
    put(&h, pages, &[1; 4096]);
    assert_eq!(h.call(Sysno::Write, &[fd, pages, 0xC00]), 0xC00);
    let second: Vec<u8> = vec![2; 0x1400];
    put(&h, pages, &second);
    assert_eq!(h.call(Sysno::Write, &[fd, pages, 0x1400]), 0x1400);
    // PROT_READ, MAP_SHARED, page offset 1.
    let map = h.call(Sysno::Mmap2, &[0, 4096, 1, 1, fd, 1]) as u64;
    assert!(map < 0xF7FF_E000);
    let mut b = [0u8; 4];
    h.proc.state.space.read_raw(map, &mut b).unwrap();
    assert_eq!(b, [2; 4], "the file's second page");
    // The old mmap reads struct mmap_arg_struct32; its offset is in bytes.
    let args: Vec<u8> = [0u32, 4096, 1, 1, fd as u32, 4096]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
    put(&h, at + 0x3000, &args);
    let map = h.call(Sysno::Mmap, &[at + 0x3000]) as u64;
    h.proc.state.space.read_raw(map, &mut b).unwrap();
    assert_eq!(b, [2; 4]);
    put(&h, at + 0x3014, &100u32.to_le_bytes());
    assert_eq!(h.call(Sysno::Mmap, &[at + 0x3000]), -i64::from(EINVAL));
    // Calls without a 32-bit conversion yet.
    for s in [Sysno::Stat64, Sysno::Socketcall, Sysno::RtSigaction] {
        assert_eq!(h.call(s, &[0, 0, 0, 0]), -i64::from(ENOSYS), "{s:?}");
    }
}

/// `cp_compat_stat` (`fs/stat.c`): `struct compat_stat` (64 bytes) with
/// 16-bit mode, link count, and IDs (`high2lowuid`: 65534 past 16 bits),
/// and `EOVERFLOW` for an inode, link count, or size its fields cannot hold.
#[test]
fn compat_stat_is_the_32_bit_layout() {
    use crate::user::linux::abi::types::{Stat, Timespec};
    let st = Stat {
        dev_major: 8,
        dev_minor: 1,
        ino: 0x1234_5678,
        mode: 0o100644,
        nlink: 3,
        uid: 70000,
        gid: 100,
        rdev_major: 0,
        rdev_minor: 0,
        size: 4096,
        blksize: 4096,
        blocks: 8,
        atime: Timespec { sec: 1, nsec: 2 },
        mtime: Timespec { sec: 3, nsec: 4 },
        ctime: Timespec { sec: 5, nsec: 6 },
        ..Default::default()
    };
    let b = st.encode(LinuxAbi::I386);
    assert_eq!(b.len(), 64);
    let u32at = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
    let u16at = |o: usize| u16::from_le_bytes(b[o..o + 2].try_into().unwrap());
    // new_encode_dev(8:1) = 0x801.
    assert_eq!((u32at(0), u32at(4)), (0x801, 0x1234_5678));
    assert_eq!(
        (u16at(8), u16at(10), u16at(12), u16at(14)),
        (0o100644, 3, 65534, 100)
    );
    assert_eq!((u32at(20), u32at(24), u32at(28)), (4096, 4096, 8));
    assert_eq!((u32at(32), u32at(36), u32at(40), u32at(52)), (1, 2, 3, 6));
    assert!(!st.compat_overflow());
    for big in [
        Stat { ino: 1 << 32, ..st },
        Stat {
            nlink: 1 << 16,
            ..st
        },
        Stat {
            size: 1 << 31,
            ..st
        },
    ] {
        assert!(big.compat_overflow());
    }
}
