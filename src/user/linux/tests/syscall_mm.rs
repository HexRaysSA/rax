//! Memory-management system calls driven through [`dispatch`] on a spawned
//! process without executing guest code. Expected results follow the Linux
//! 6.19 sources named in each test (`mm/mprotect.c`, `mm/madvise.c`,
//! `mm/mmap.c`, `kernel/exec_domain.c`), not the implementation.

use super::harness::{Harness, each_abi};
use crate::error::MemoryAccessKind;
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, READ_IMPLIES_EXEC, Sysno, vma_flags};
use crate::user::mm::Perms;

const P: u64 = 4096;
const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const PROT_EXEC: u64 = 4;
const PROT_BTI: u64 = 0x10;
const PROT_GROWSDOWN: u64 = 0x0100_0000;
const PROT_GROWSUP: u64 = 0x0200_0000;
const RW: u64 = PROT_READ | PROT_WRITE;
const MAP_SHARED: u64 = 1;
const MAP_PRIVATE: u64 = 2;
const MAP_FIXED: u64 = 0x10;
const MAP_ANONYMOUS: u64 = 0x20;
const O_RDONLY: u64 = 0;
const O_RDWR: u64 = 2;
const AT_FDCWD: u64 = -100i64 as u64;
const MADV_DONTNEED: u64 = 4;
const MADV_FREE: u64 = 8;
const MADV_REMOVE: u64 = 9;
const MADV_POPULATE_READ: u64 = 22;
const MADV_POPULATE_WRITE: u64 = 23;
const MADV_GUARD_INSTALL: u64 = 102;

// ------------------------------------------------------------------ madvise

#[test]
fn dontneed_drops_private_pages_and_keeps_shared_ones() {
    // madvise_dontneed_single_vma() zaps the PTEs; a private anonymous page
    // refaults as zero, a private file page from the file, and a shared
    // page from shmem or the page cache, which still holds the data.
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let pa = h.anon(2 * P, RW, false);
        let sa = h.anon(2 * P, RW, true);
        h.fill(pa, 2 * P, 0x11);
        h.fill(sa, 2 * P, 0x22);
        h.ok(Sysno::Madvise, &[pa, 2 * P, MADV_DONTNEED]);
        h.ok(Sysno::Madvise, &[sa, 2 * P, MADV_DONTNEED]);
        assert_eq!((h.byte(pa), h.byte(pa + 2 * P - 1)), (0, 0));
        assert_eq!((h.byte(sa), h.byte(sa + 2 * P - 1)), (0x22, 0x22));

        let fd = h.file("dontneed", P as usize, b'f', O_RDWR);
        let pf = h.map_file(fd, P, RW, MAP_PRIVATE);
        h.fill(pf, 1, b'x');
        h.ok(Sysno::Madvise, &[pf, P, MADV_DONTNEED]);
        assert_eq!(
            h.byte(pf),
            b'f',
            "a private file page refaults from the file"
        );
    });
}

#[test]
fn free_applies_only_to_private_anonymous_memory() {
    // madvise_free_single_vma(): `if (!vma_is_anonymous(vma)) return -EINVAL`.
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let pa = h.anon(P, RW, false);
        let sa = h.anon(P, RW, true);
        h.ok(Sysno::Madvise, &[pa, P, MADV_FREE]);
        assert_eq!(h.err(Sysno::Madvise, &[sa, P, MADV_FREE]), EINVAL);
        let fd = h.file("free", P as usize, 1, O_RDONLY);
        let pf = h.map_file(fd, P, PROT_READ, MAP_PRIVATE);
        assert_eq!(h.err(Sysno::Madvise, &[pf, P, MADV_FREE]), EINVAL);
    });
}

#[test]
fn remove_requires_a_shared_mapping_that_may_be_written() {
    // madvise_remove(): no file -> EINVAL; !vma_is_shared_maywrite -> EACCES;
    // otherwise the backing store is punched, so shmem reads back zero.
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let pa = h.anon(P, RW, false);
        assert_eq!(h.err(Sysno::Madvise, &[pa, P, MADV_REMOVE]), EINVAL);

        let sa = h.anon(2 * P, RW, true);
        h.fill(sa, 2 * P, 0x33);
        h.ok(Sysno::Madvise, &[sa, P, MADV_REMOVE]);
        assert_eq!((h.byte(sa), h.byte(sa + P)), (0, 0x33));
        // VM_MAYWRITE survives mprotect(PROT_READ): still removable.
        h.ok(Sysno::Mprotect, &[sa + P, P, PROT_READ]);
        h.ok(Sysno::Madvise, &[sa + P, P, MADV_REMOVE]);

        let ro = h.file("remove-ro", P as usize, 1, O_RDONLY);
        let pf = h.map_file(ro, P, PROT_READ, MAP_PRIVATE);
        assert_eq!(h.err(Sysno::Madvise, &[pf, P, MADV_REMOVE]), EACCES);
        let sf = h.map_file(ro, P, PROT_READ, MAP_SHARED);
        assert_eq!(h.err(Sysno::Madvise, &[sf, P, MADV_REMOVE]), EACCES);
        // A writable shared file mapping: the file is punched (its bytes
        // read back as zero, its size kept), through the mapping and the
        // file alike.
        let rw = h.file("remove-rw", 2 * P as usize, 1, O_RDWR);
        let swf = h.map_file(rw, 2 * P, RW, MAP_SHARED);
        assert_eq!(h.byte(swf), 1);
        h.ok(Sysno::Madvise, &[swf, P, MADV_REMOVE]);
        assert_eq!((h.byte(swf), h.byte(swf + P)), (0, 1));
        let fs = h.ok(Sysno::Fstat, &[rw, h.scratch]);
        assert_eq!(fs, 0);
        let buf = h.scratch + 0x800;
        assert_eq!(h.ok(Sysno::Pread64, &[rw, buf, 2, P - 1]), 2);
        assert_eq!((h.byte(buf), h.byte(buf + 1)), (0, 1));
    });
}

#[test]
fn advice_skips_holes_then_reports_enomem() {
    // madvise_walk_vmas(): unmapped gaps set unmapped_error = -ENOMEM but the
    // walk continues, so both VMAs are advised.
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let q = h.anon(3 * P, RW, false);
        h.fill(q, 3 * P, 0x44);
        h.ok(Sysno::Munmap, &[q + P, P]);
        assert_eq!(h.err(Sysno::Madvise, &[q, 3 * P, MADV_DONTNEED]), ENOMEM);
        assert_eq!((h.byte(q), h.byte(q + 2 * P)), (0, 0));
        // A range that starts in a hole, and one that runs past the last
        // VMA, fail the same way.
        h.fill(q + 2 * P, 1, 0x55);
        assert_eq!(
            h.err(Sysno::Madvise, &[q + P, 2 * P, MADV_DONTNEED]),
            ENOMEM
        );
        assert_eq!(h.byte(q + 2 * P), 0);
        // A VMA that refuses the advice ends the walk with its own error,
        // leaving later VMAs unadvised.
        let shared = MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED;
        h.ok(Sysno::Mmap, &[q + P, P, RW, shared, u64::MAX, 0]);
        h.fill(q + 2 * P, 1, 0x66);
        assert_eq!(h.err(Sysno::Madvise, &[q, 3 * P, MADV_FREE]), EINVAL);
        assert_eq!(h.byte(q + 2 * P), 0x66);
    });
}

#[test]
fn populate_faults_pages_in_or_reports_why_it_cannot() {
    // madvise_populate(): no VMA -> ENOMEM; incompatible permissions ->
    // EINVAL; a fault that would raise SIGBUS or SIGSEGV -> EFAULT.
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let w = h.anon(2 * P, RW, false);
        assert!(!h.proc.state.space.is_resident(w));
        h.ok(Sysno::Madvise, &[w, 2 * P, MADV_POPULATE_WRITE]);
        assert!(h.proc.state.space.is_resident(w));
        assert!(h.proc.state.space.is_resident(w + P));
        assert_eq!(h.byte(w), 0, "populating does not change contents");

        let r = h.anon(P, PROT_READ, false);
        h.ok(Sysno::Madvise, &[r, P, MADV_POPULATE_READ]);
        assert_eq!(h.err(Sysno::Madvise, &[r, P, MADV_POPULATE_WRITE]), EINVAL);

        let fd = h.file("populate", 100, 7, O_RDONLY);
        let f = h.map_file(fd, 2 * P, PROT_READ, MAP_PRIVATE);
        assert_eq!(
            h.err(Sysno::Madvise, &[f, 2 * P, MADV_POPULATE_READ]),
            EFAULT
        );

        let q = h.anon(3 * P, RW, false);
        h.ok(Sysno::Munmap, &[q + P, P]);
        assert_eq!(
            h.err(Sysno::Madvise, &[q, 3 * P, MADV_POPULATE_WRITE]),
            ENOMEM
        );
        assert!(h.proc.state.space.is_resident(q), "pages before the hole");
    });
}

#[test]
fn populating_for_reading_needs_vm_read() {
    // check_vma_flags: a read fault-in needs VM_READ, which a write-only or
    // execute-only protection lacks even where its pages can be read.
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let w = h.anon(P, PROT_WRITE, false);
        assert!(h.perms(w).contains(Perms::READ), "write implies read");
        assert_eq!(h.err(Sysno::Madvise, &[w, P, MADV_POPULATE_READ]), EINVAL);
        h.ok(Sysno::Madvise, &[w, P, MADV_POPULATE_WRITE]);
        h.ok(Sysno::Mprotect, &[w, P, RW]);
        h.ok(Sysno::Madvise, &[w, P, MADV_POPULATE_READ]);
        h.ok(Sysno::Mprotect, &[w, P, PROT_EXEC]);
        assert_eq!(h.err(Sysno::Madvise, &[w, P, MADV_POPULATE_READ]), EINVAL);
    });
}

#[test]
fn guard_regions_are_refused_rather_than_ignored() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let a = h.anon(P, RW, false);
        assert_eq!(h.err(Sysno::Madvise, &[a, P, MADV_GUARD_INSTALL]), EINVAL);
    });
}

// ----------------------------------------------------------------- mprotect

#[test]
fn mprotect_validates_in_kernel_order() {
    // do_mprotect_pkey(): the PROT_GROWSDOWN|PROT_GROWSUP check precedes the
    // alignment and length checks; arch_validate_prot() follows them.
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let a = h.anon(P, RW, false);
        let both = PROT_READ | PROT_GROWSDOWN | PROT_GROWSUP;
        assert_eq!(h.err(Sysno::Mprotect, &[a, 0, both]), EINVAL);
        assert_eq!(h.call(Sysno::Mprotect, &[a, 0, 0x1000]), 0);
        assert_eq!(h.err(Sysno::Mprotect, &[a + 1, P, PROT_READ]), EINVAL);
        assert_eq!(h.err(Sysno::Mprotect, &[a, P, 0x1000]), EINVAL);
        // arm64 accepts PROT_BTI only when system_supports_bti(); the
        // emulated core does not advertise HWCAP2_BTI, and the other
        // architectures never accept it.
        assert_eq!(
            h.err(Sysno::Mprotect, &[a, P, PROT_READ | PROT_BTI]),
            EINVAL
        );
        // VM_GROWSUP does not exist on these architectures.
        assert_eq!(
            h.err(Sysno::Mprotect, &[a, P, PROT_READ | PROT_GROWSUP]),
            EINVAL
        );
    });
}

#[test]
fn mprotect_applies_up_to_the_first_hole() {
    // The VMA walk stops at a hole with ENOMEM after changing earlier VMAs.
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let a = h.anon(3 * P, RW, false);
        h.ok(Sysno::Munmap, &[a + P, P]);
        assert_eq!(h.err(Sysno::Mprotect, &[a, 3 * P, PROT_READ]), ENOMEM);
        assert_eq!(h.perms(a), Perms::READ);
        assert_eq!(h.perms(a + 2 * P), Perms::READ | Perms::WRITE);
        // A range starting in a hole changes nothing.
        assert_eq!(h.err(Sysno::Mprotect, &[a + P, 2 * P, PROT_READ]), ENOMEM);
        assert_eq!(h.perms(a + 2 * P), Perms::READ | Perms::WRITE);
    });
}

#[test]
fn growsdown_extends_to_the_start_of_the_stack() {
    // With PROT_GROWSDOWN the range starts at vma->vm_start, which must be
    // a VM_GROWSDOWN VMA (glibc's _dl_make_stack_executable relies on it).
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let stack = h
            .proc
            .state
            .space
            .vma_snapshot()
            .into_iter()
            .find(|v| v.name.as_deref() == Some("[stack]"))
            .unwrap();
        assert_ne!(stack.flags & vma_flags::GROWSDOWN, 0);
        let page = stack.end - P;
        h.ok(Sysno::Mprotect, &[page, P, RW | PROT_EXEC | PROT_GROWSDOWN]);
        let vmas = h.proc.state.space.vmas_in(stack.start, stack.end);
        assert_eq!(vmas.len(), 1, "the whole stack changed as one VMA");
        assert!(vmas[0].perms.contains(Perms::EXEC));

        let a = h.anon(P, RW, false);
        assert_eq!(
            h.err(Sysno::Mprotect, &[a, P, PROT_READ | PROT_GROWSDOWN]),
            EINVAL
        );
    });
}

#[test]
fn shared_mappings_of_read_only_files_never_become_writable() {
    // do_mmap(): MAP_SHARED of a file without FMODE_WRITE clears
    // VM_MAYWRITE, and mprotect refuses PROT_WRITE with EACCES; a private
    // mapping of the same file keeps VM_MAYWRITE (copy-on-write).
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let fd = h.file("ro-shared", P as usize, 3, O_RDONLY);
        assert_eq!(h.err(Sysno::Mmap, &[0, P, RW, MAP_SHARED, fd, 0]), EACCES);
        let s = h.map_file(fd, P, PROT_READ, MAP_SHARED);
        assert_eq!(h.err(Sysno::Mprotect, &[s, P, RW]), EACCES);
        h.ok(Sysno::Mprotect, &[s, P, PROT_READ | PROT_EXEC]);
        let p = h.map_file(fd, P, PROT_READ, MAP_PRIVATE);
        h.ok(Sysno::Mprotect, &[p, P, RW]);
        h.fill(p, 1, 9);
        assert_eq!(h.byte(p), 9);
    });
}

// -------------------------------------------------------------- personality

#[test]
fn personality_returns_the_previous_value() {
    // SYSCALL_DEFINE1(personality): returns the old value and installs the
    // new one unless it is 0xffffffff.
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        assert_eq!(h.ok(Sysno::Personality, &[0xffff_ffff]), 0);
        assert_eq!(h.ok(Sysno::Personality, &[u64::from(READ_IMPLIES_EXEC)]), 0);
        assert_eq!(
            h.ok(Sysno::Personality, &[0xffff_ffff]),
            u64::from(READ_IMPLIES_EXEC)
        );
        assert_eq!(h.ok(Sysno::Personality, &[0]), u64::from(READ_IMPLIES_EXEC));
        assert_eq!(h.ok(Sysno::Personality, &[0xffff_ffff]), 0);
    });
}

#[test]
fn read_implies_exec_grants_exec_to_readable_mappings() {
    // do_mmap() and do_mprotect_pkey() add PROT_EXEC to PROT_READ requests
    // under READ_IMPLIES_EXEC.
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let before = h.anon(P, PROT_READ, false);
        assert!(!h.perms(before).contains(Perms::EXEC));
        h.ok(Sysno::Personality, &[u64::from(READ_IMPLIES_EXEC)]);
        let after = h.anon(P, PROT_READ, false);
        assert!(h.perms(after).contains(Perms::EXEC));
        let wo = h.anon(P, PROT_WRITE, false);
        assert!(
            h.perms(wo).contains(Perms::WRITE) && !h.perms(wo).contains(Perms::EXEC),
            "only PROT_READ requests gain PROT_EXEC"
        );
        h.ok(Sysno::Mprotect, &[before, P, PROT_READ]);
        assert!(h.perms(before).contains(Perms::EXEC));
        assert!(
            h.proc
                .state
                .space
                .translate(after, MemoryAccessKind::Fetch)
                .is_ok()
        );
    });
}

const MREMAP_MAYMOVE: u64 = 1;
const MREMAP_DONTUNMAP: u64 = 4;
const MS_SYNC: u64 = 4;

/// The whole of `/proc/self/maps`.
fn maps(h: &mut Harness) -> String {
    let at = h.scratch;
    h.proc
        .state
        .space
        .write_raw(at, b"/proc/self/maps\0")
        .unwrap();
    let fd = h.ok(Sysno::Openat, &[AT_FDCWD, at, O_RDONLY, 0]);
    let buf = h.anon(16 * P, RW, false);
    let n = h.ok(Sysno::Read, &[fd, buf, 16 * P]);
    h.ok(Sysno::Close, &[fd]);
    let mut b = vec![0u8; n as usize];
    h.proc.state.space.read(buf, &mut b).unwrap();
    String::from_utf8(b).unwrap()
}

/// The permission column of the `/proc/self/maps` line covering `at`.
fn maps_perms(h: &mut Harness, at: u64) -> String {
    let all = maps(h);
    let line = all
        .lines()
        .find(|l| {
            let (lo, hi) = l.split(' ').next().unwrap().split_once('-').unwrap();
            let lo = u64::from_str_radix(lo, 16).unwrap();
            let hi = u64::from_str_radix(hi, 16).unwrap();
            (lo..hi).contains(&at)
        })
        .unwrap_or_else(|| panic!("no mapping at {at:#x} in\n{all}"));
    line.split(' ').nth(1).unwrap().to_owned()
}

#[test]
fn maps_shows_vm_read_rather_than_readable_pages() {
    // show_map_vma prints VM_READ: a PROT_WRITE mapping is "-w-p" and a
    // PROT_EXEC one "--xp" although their pages read in user mode, and
    // mprotect changes the column with the protection.
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let a = h.anon(3 * P, PROT_WRITE, false);
        assert_eq!(maps_perms(&mut h, a), "-w-p");
        h.ok(Sysno::Mprotect, &[a + P, P, PROT_EXEC]);
        assert_eq!(maps_perms(&mut h, a), "-w-p");
        assert_eq!(maps_perms(&mut h, a + P), "--xp");
        assert_eq!(maps_perms(&mut h, a + 2 * P), "-w-p");
        h.ok(Sysno::Mprotect, &[a, 3 * P, RW]);
        assert_eq!(maps_perms(&mut h, a), "rw-p", "one VMA again");
        let r = h.anon(P, PROT_READ | PROT_EXEC, false);
        assert_eq!(maps_perms(&mut h, r), "r-xp");
        h.ok(Sysno::Mprotect, &[r, P, 0]);
        assert_eq!(maps_perms(&mut h, r), "---p");
    });
}

#[test]
fn shared_anonymous_memory_is_one_shmem_object() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let s = h.anon(2 * P, RW, true);
        let m = maps(&mut h);
        let line = m
            .lines()
            .find(|l| l.starts_with(&format!("{s:08x}-")))
            .unwrap()
            .to_string();
        assert!(line.contains(" rw-s 00000000 00:01 "), "{abi:?}: {line}");
        assert!(line.ends_with(" /dev/zero (deleted)"), "{line}");
        // mremap of zero bytes: a second mapping of the same pages, with
        // the checks in do_mremap's order.
        assert_eq!(
            h.err(Sysno::Mremap, &[0x10000, 0, P, MREMAP_MAYMOVE, 0]),
            EFAULT
        );
        assert_eq!(h.err(Sysno::Mremap, &[s, 0, P, 0, 0]), ENOMEM);
        let flags = MREMAP_MAYMOVE | MREMAP_DONTUNMAP;
        assert_eq!(h.err(Sysno::Mremap, &[s, 0, P, flags, 0]), EINVAL);
        let d = h.ok(Sysno::Mremap, &[s + P, 0, P, MREMAP_MAYMOVE, 0]);
        h.fill(d, 1, 0x5a);
        assert_eq!(h.byte(s + P), 0x5a);
        let private = h.anon(P, RW, false);
        assert_eq!(
            h.err(Sysno::Mremap, &[private, 0, P, MREMAP_MAYMOVE, 0]),
            EINVAL
        );
        // Grown past the object: the new pages are bus errors.
        let g = h.ok(Sysno::Mremap, &[s, 2 * P, 3 * P, MREMAP_MAYMOVE, 0]);
        assert_eq!(h.byte(g + P), 0x5a);
        assert_eq!(
            h.proc
                .state
                .space
                .classify_fault(g + 2 * P, MemoryAccessKind::Read),
            crate::user::mm::FaultClass::BeyondSource
        );
    });
}

#[test]
fn shared_file_mappings_are_the_files_pages() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let fd = h.file("writeback", 2 * P as usize, b'a', O_RDWR);
        let m = h.map_file(fd, 2 * P, RW, MAP_SHARED);
        // Stores reach pread; pwrite reaches the mapping.
        h.fill(m + 3, 1, b'X');
        let buf = h.scratch + 0x800;
        assert_eq!(h.ok(Sysno::Pread64, &[fd, buf, 1, 3]), 1);
        assert_eq!(h.byte(buf), b'X');
        h.proc.state.space.write_raw(buf, b"Y").unwrap();
        assert_eq!(h.ok(Sysno::Pwrite64, &[fd, buf, 1, P + 1]), 1);
        assert_eq!(h.byte(m + P + 1), b'Y');
        assert_eq!(h.ok(Sysno::Msync, &[m, 2 * P, MS_SYNC]), 0);
        // MREMAP_DONTUNMAP leaves the old range mapping the file.
        let flags = MREMAP_MAYMOVE | MREMAP_DONTUNMAP;
        let moved = h.ok(Sysno::Mremap, &[m, 2 * P, 2 * P, flags, 0]);
        assert_eq!((h.byte(moved + 3), h.byte(m + 3)), (b'X', b'X'), "{abi:?}");
        // Truncation drops the pages past the new end (ftruncate).
        h.ok(Sysno::Ftruncate, &[fd, P]);
        let space = &h.proc.state.space;
        assert_eq!(
            space.classify_fault(moved + P, MemoryAccessKind::Read),
            crate::user::mm::FaultClass::BeyondSource
        );
        assert!(space.read(moved + P, &mut [0u8]).is_err());
        assert_eq!(h.byte(moved + 3), b'X');
        // ...and through truncate(2) and O_TRUNC.
        h.ok(Sysno::Ftruncate, &[fd, 2 * P]);
        assert_eq!(h.byte(moved + P + 1), 0);
        let path = h.scratch + 0x100;
        let host = std::env::temp_dir().join(format!(
            "rax-user-mm-{}-writeback-{abi:?}",
            std::process::id()
        ));
        let name = format!("{}\0", host.display());
        h.proc.state.space.write_raw(path, name.as_bytes()).unwrap();
        h.ok(Sysno::Truncate, &[path, P]);
        assert!(h.proc.state.space.read(moved + P, &mut [0u8]).is_err());
        h.ok(Sysno::Ftruncate, &[fd, 2 * P]);
        assert_eq!(h.byte(moved + P), 0);
        let again = h.ok(Sysno::Openat, &[AT_FDCWD, path, O_RDWR | 0o1000, 0]);
        assert!(h.proc.state.space.read(moved, &mut [0u8]).is_err());
        h.ok(Sysno::Close, &[again]);
    });
}

const MFD_CLOEXEC: u64 = 0x1;
const MFD_ALLOW_SEALING: u64 = 0x2;
const MFD_HUGETLB: u64 = 0x4;
const F_ADD_SEALS: u64 = 1033;
const F_GET_SEALS: u64 = 1034;

#[test]
fn memfd_create_checks_flags_then_name() {
    each_abi(|abi| {
        let mut h = Harness::new(abi);
        let name = h.scratch;
        h.proc.state.space.write_raw(name, b"m\0").unwrap();
        // Flags first: a bad flag is EINVAL even with a bad name.
        assert_eq!(h.err(Sysno::MemfdCreate, &[0x10, 0x100]), EINVAL);
        assert_eq!(h.err(Sysno::MemfdCreate, &[0x10, 0]), EFAULT);
        // The huge-page size encoding is only for MFD_HUGETLB.
        assert_eq!(h.err(Sysno::MemfdCreate, &[name, 21 << 26]), EINVAL);
        let huge = h.ok(Sysno::MemfdCreate, &[name, MFD_HUGETLB | (21 << 26)]);
        // An empty pool: the file cannot be mapped.
        assert_eq!(h.err(Sysno::Mmap, &[0, P, RW, MAP_SHARED, huge, 0]), ENOMEM);
        let fd = h.ok(Sysno::MemfdCreate, &[name, MFD_CLOEXEC | MFD_ALLOW_SEALING]);
        assert_eq!(h.ok(Sysno::Fcntl, &[fd, 1, 0]), 1);
        assert_eq!(h.ok(Sysno::Fcntl, &[fd, F_GET_SEALS, 0]), 0);
        h.ok(Sysno::Ftruncate, &[fd, P]);
        assert_eq!(h.ok(Sysno::Fcntl, &[fd, F_ADD_SEALS, 0x4]), 0);
        assert_eq!(h.ok(Sysno::Fcntl, &[fd, F_GET_SEALS, 0]), 0x4);
        assert_eq!(h.err(Sysno::Ftruncate, &[fd, 2 * P]), EPERM, "{abi:?}");
        // A write-sealed memfd maps shared only for reading, and the
        // mapping never becomes writable.
        assert_eq!(h.ok(Sysno::Fcntl, &[fd, F_ADD_SEALS, 0x8]), 0);
        let r = h.ok(Sysno::Mmap, &[0, P, PROT_READ, MAP_SHARED, fd, 0]);
        assert_ne!(h.perms(r) & Perms::READ, Perms::empty());
        let vma = h.proc.state.space.vma_at(r).unwrap();
        assert_ne!(vma.flags & vma_flags::DENY_WRITE, 0);
        assert_eq!(h.err(Sysno::Mprotect, &[r, P, RW]), EACCES);
    });
}
