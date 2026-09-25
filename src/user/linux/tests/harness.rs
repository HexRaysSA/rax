//! A spawned process whose system calls tests drive through [`dispatch`]
//! without executing guest code, plus helpers to write guest code and run.

use super::loader::{Seg, image};
use crate::user::image::elf::{EM_AARCH64, EM_RISCV, EM_X86_64, ET_EXEC, PF_R, PF_W, PF_X};
use crate::user::linux::abi::{LinuxAbi, Sysno};
use crate::user::linux::loader::ImageFile;
use crate::user::linux::syscall::Outcome;
use crate::user::linux::{LinuxConfig, LinuxProcess};
use crate::user::mm::Perms;

pub(crate) const P: u64 = 4096;
const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const RW: u64 = PROT_READ | PROT_WRITE;
const MAP_SHARED: u64 = 1;
const MAP_PRIVATE: u64 = 2;
const MAP_ANONYMOUS: u64 = 0x20;
const AT_FDCWD: u64 = -100i64 as u64;

/// Base of the program's executable segment (`[CODE, CODE + 8 KiB)`).
pub(crate) const CODE: u64 = 0x40_0000;
/// Base of the program's writable data segment (`[DATA, DATA + 8 KiB)`).
pub(crate) const DATA: u64 = 0x60_0000;

pub(crate) struct Harness {
    pub proc: LinuxProcess,
    pub scratch: u64,
    files: Vec<std::path::PathBuf>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        for f in &self.files {
            let _ = std::fs::remove_file(f);
        }
        let _ = std::fs::remove_dir_all(self.proc.state.ipc.ns.dir());
        if let Some(h) = &self.proc.state.fsnotify {
            let _ = std::fs::remove_dir_all(h.dir());
        }
    }
}

impl Harness {
    pub(crate) fn new(abi: LinuxAbi) -> Self {
        Self::with_fsnotify(abi, None)
    }

    /// A harness whose inotify instances come from `backend` (`None`: an
    /// emulated namespace of its own).
    pub(crate) fn with_fsnotify(
        abi: LinuxAbi,
        backend: Option<crate::user::linux::fsnotify::Backend>,
    ) -> Self {
        let machine = match abi {
            LinuxAbi::X86_64 => EM_X86_64,
            LinuxAbi::Aarch64 => EM_AARCH64,
            LinuxAbi::Riscv64 => EM_RISCV,
        };
        let bytes = image(
            machine,
            ET_EXEC,
            0x40_1000,
            &[
                Seg::load(CODE, 0, 0x2000, 0x2000, PF_R | PF_X),
                Seg::load(DATA, 0x2000, 0x1000, 0x2000, PF_R | PF_W),
            ],
            None,
        );
        let mut config = LinuxConfig::new("/prog", vec![b"prog".to_vec()], vec![]);
        config.arena_bytes = 256 << 20;
        config.seed = Some(1);
        // A System V IPC namespace of its own: harnesses run in parallel in
        // one host process.
        static IPC: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = IPC.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("rax-user-ipc-test-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        config.ipc_dir = Some(dir);
        // And an emulated file-system notification namespace of its own.
        let notify =
            std::env::temp_dir().join(format!("rax-user-fsnotify-test-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&notify);
        config.fsnotify = backend.unwrap_or(crate::user::linux::fsnotify::Backend::Emulated(Some(
            notify,
        )));
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

    pub(crate) fn abi(&self) -> LinuxAbi {
        self.proc.state.abi
    }

    /// Raw result register value, as a signed integer.
    pub(crate) fn call(&mut self, s: Sysno, args: &[u64]) -> i64 {
        match self.dispatch(s, args) {
            Outcome::Return(v) => v as i64,
            other => panic!("{s:?} did not return: {other:?}"),
        }
    }

    /// The final outcome of a call of the first thread, sleeping on the
    /// host while it sleeps.
    pub(crate) fn dispatch(&mut self, s: Sysno, args: &[u64]) -> Outcome {
        self.dispatch_on(0, s, args)
    }

    /// The final outcome of a call of thread `idx`.
    pub(crate) fn dispatch_on(&mut self, idx: usize, s: Sysno, args: &[u64]) -> Outcome {
        let mut a = [0u64; 6];
        a[..args.len()].copy_from_slice(args);
        let nr = self.abi().number(s).unwrap();
        self.proc.dispatch_to_completion(idx, nr, a)
    }

    /// Runs a call of thread `idx` as the scheduler would: `Some(result
    /// register)` if it completed, `None` if the thread now sleeps.
    pub(crate) fn start(&mut self, idx: usize, s: Sysno, args: &[u64]) -> Option<i64> {
        let mut a = [0u64; 6];
        a[..args.len()].copy_from_slice(args);
        let nr = self.abi().number(s).unwrap();
        let tid = self.proc.threads[idx].tid;
        self.proc
            .syscall(idx, crate::user::linux::syscall::Call::new(nr, a));
        // A thread that exited is gone from the list.
        let idx = self.proc.threads.iter().position(|t| t.tid == tid)?;
        self.proc.threads[idx]
            .blocked
            .is_none()
            .then(|| self.result(idx))
    }

    /// Thread `idx`'s result register, as a signed integer.
    pub(crate) fn result(&self, idx: usize) -> i64 {
        self.proc.threads[idx].cpu.syscall_return_value() as i64
    }

    /// The list index of the thread with TID `tid`.
    pub(crate) fn index_of(&self, tid: i32) -> usize {
        self.proc
            .threads
            .iter()
            .position(|t| t.tid == tid)
            .expect("thread exists")
    }

    pub(crate) fn ok(&mut self, s: Sysno, args: &[u64]) -> u64 {
        let r = self.call(s, args);
        assert!(r >= 0, "{s:?}{args:x?} failed with errno {}", -r);
        r as u64
    }

    pub(crate) fn err(&mut self, s: Sysno, args: &[u64]) -> i32 {
        let r = self.call(s, args);
        assert!(r < 0, "{s:?}{args:x?} succeeded with {r:#x}");
        (-r) as i32
    }

    pub(crate) fn anon(&mut self, len: u64, prot: u64, shared: bool) -> u64 {
        let kind = if shared { MAP_SHARED } else { MAP_PRIVATE };
        self.ok(
            Sysno::Mmap,
            &[0, len, prot, kind | MAP_ANONYMOUS, u64::MAX, 0],
        )
    }

    /// Creates a host file of `len` bytes of `fill` and opens it in the
    /// guest with `flags`.
    pub(crate) fn file(&mut self, name: &str, len: usize, fill: u8, flags: u64) -> u64 {
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

    pub(crate) fn map_file(&mut self, fd: u64, len: u64, prot: u64, kind: u64) -> u64 {
        self.ok(Sysno::Mmap, &[0, len, prot, kind, fd, 0])
    }

    pub(crate) fn fill(&self, addr: u64, len: u64, byte: u8) {
        self.proc
            .state
            .space
            .write(addr, &vec![byte; len as usize])
            .unwrap();
    }

    pub(crate) fn byte(&self, addr: u64) -> u8 {
        let mut b = [0u8];
        self.proc.state.space.read(addr, &mut b).unwrap();
        b[0]
    }

    pub(crate) fn perms(&self, addr: u64) -> Perms {
        self.proc.state.space.vma_at(addr).unwrap().perms
    }
}

pub(crate) fn each_abi(f: impl Fn(LinuxAbi)) {
    for abi in LinuxAbi::ALL {
        f(abi);
    }
}
