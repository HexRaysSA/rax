//! Memory-management system calls driven through [`dispatch`] on a spawned
//! process without executing guest code. Expected results follow the Linux
//! 6.19 sources named in each test (`mm/mprotect.c`, `mm/madvise.c`,
//! `mm/mmap.c`, `kernel/exec_domain.c`), not the implementation.

use super::loader::{Seg, image};
use crate::error::MemoryAccessKind;
use crate::user::image::elf::{EM_AARCH64, EM_RISCV, EM_X86_64, ET_EXEC, PF_R, PF_X};
use crate::user::linux::abi::errno_table::*;
use crate::user::linux::abi::{LinuxAbi, READ_IMPLIES_EXEC, Sysno, vma_flags};
use crate::user::linux::loader::ImageFile;
use crate::user::linux::syscall::{Outcome, dispatch};
use crate::user::linux::{LinuxConfig, LinuxProcess};
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

struct Harness {
    proc: LinuxProcess,
    scratch: u64,
    files: Vec<std::path::PathBuf>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        for f in &self.files {
            let _ = std::fs::remove_file(f);
        }
    }
}

impl Harness {
    fn new(abi: LinuxAbi) -> Self {
        let machine = match abi {
            LinuxAbi::X86_64 => EM_X86_64,
            LinuxAbi::Aarch64 => EM_AARCH64,
            LinuxAbi::Riscv64 => EM_RISCV,
        };
        let bytes = image(
            machine,
            ET_EXEC,
            0x40_1000,
            &[Seg::load(0x40_0000, 0, 0x2000, 0x2000, PF_R | PF_X)],
            None,
        );
        let mut config = LinuxConfig::new("/prog", vec![b"prog".to_vec()], vec![]);
        config.arena_bytes = 256 << 20;
        config.seed = Some(1);
        let proc = LinuxProcess::spawn(config, ImageFile::new(bytes, "/prog")).unwrap();
        let mut h = Harness {
            proc,
            scratch: 0,
            files: Vec::new(),
        };
        h.scratch = h.ok(
            Sysno::Mmap,
            &[0, P, RW, MAP_PRIVATE | MAP_ANONYMOUS, u64::MAX, 0],
        );
        h
    }

    fn abi(&self) -> LinuxAbi {
        self.proc.state.abi
    }

    /// Raw result register value, as a signed integer.
    fn call(&mut self, s: Sysno, args: &[u64]) -> i64 {
        let mut a = [0u64; 6];
        a[..args.len()].copy_from_slice(args);
        let nr = self.abi().number(s).unwrap();
        let (p, t) = (&mut self.proc.state, &mut self.proc.threads[0]);
        match dispatch(p, t, nr, a) {
            Outcome::Return(v) => v as i64,
            other => panic!("{s:?} did not return: {other:?}"),
        }
    }

    fn ok(&mut self, s: Sysno, args: &[u64]) -> u64 {
        let r = self.call(s, args);
        assert!(r >= 0, "{s:?}{args:x?} failed with errno {}", -r);
        r as u64
    }

    fn err(&mut self, s: Sysno, args: &[u64]) -> i32 {
        let r = self.call(s, args);
        assert!(r < 0, "{s:?}{args:x?} succeeded with {r:#x}");
        (-r) as i32
    }

    fn anon(&mut self, len: u64, prot: u64, shared: bool) -> u64 {
        let kind = if shared { MAP_SHARED } else { MAP_PRIVATE };
        self.ok(
            Sysno::Mmap,
            &[0, len, prot, kind | MAP_ANONYMOUS, u64::MAX, 0],
        )
    }

    /// Creates a host file of `len` bytes of `fill` and opens it in the
    /// guest with `flags`.
    fn file(&mut self, name: &str, len: usize, fill: u8, flags: u64) -> u64 {
        let path = std::env::temp_dir().join(format!(
            "rax-user-mm-{}-{name}-{:?}",
            std::process::id(),
            self.abi()
        ));
        std::fs::write(&path, vec![fill; len]).unwrap();
        self.files.push(path.clone());
        let mut s = path.to_string_lossy().into_owned().into_bytes();
        s.push(0);
        self.proc.state.space.write_raw(self.scratch, &s).unwrap();
        self.ok(Sysno::Openat, &[AT_FDCWD, self.scratch, flags, 0])
    }

    fn map_file(&mut self, fd: u64, len: u64, prot: u64, kind: u64) -> u64 {
        self.ok(Sysno::Mmap, &[0, len, prot, kind, fd, 0])
    }

    fn fill(&self, addr: u64, len: u64, byte: u8) {
        self.proc
            .state
            .space
            .write(addr, &vec![byte; len as usize])
            .unwrap();
    }

    fn byte(&self, addr: u64) -> u8 {
        let mut b = [0u8];
        self.proc.state.space.read(addr, &mut b).unwrap();
        b[0]
    }

    fn perms(&self, addr: u64) -> Perms {
        self.proc.state.space.vma_at(addr).unwrap().perms
    }
}

fn each_abi(f: impl Fn(LinuxAbi)) {
    for abi in LinuxAbi::ALL {
        f(abi);
    }
}

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
        // A host file cannot be punched portably; the filesystem-level
        // refusal is reported (a deliberate, documented deviation).
        let rw = h.file("remove-rw", P as usize, 1, O_RDWR);
        let swf = h.map_file(rw, P, RW, MAP_SHARED);
        assert_eq!(h.err(Sysno::Madvise, &[swf, P, MADV_REMOVE]), EOPNOTSUPP);
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
