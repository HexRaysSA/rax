//! Synthetic lifecycle continuations establish the documented personality
//! order; these tests do not constitute a native Windows ordering oracle.

use super::tests::{args, fixture, native, returned};
use super::*;
use crate::user::windows::arch::WinArch;
use crate::user::windows::dll::crt::{STDIO_EXPORTS, UCRT_STDIO_EXPORTS};
use crate::user::windows::fs::{FileIdentity, FileLifetime};
use crate::user::windows::hle::{Item, Value};
use crate::user::windows::loader::{ModuleTls, SymRef};
use crate::user::windows::memory::{Mem, mem, prot};
use crate::user::windows::objects::{FileObj, Object};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

struct Output(PathBuf);
impl Drop for Output {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
impl Output {
    fn bytes(&self) -> Vec<u8> {
        std::fs::read(&self.0).unwrap()
    }
}

fn call(c: &mut Ctx, name: &str, values: &[u64]) -> u64 {
    let api = STDIO_EXPORTS
        .iter()
        .chain(UCRT_STDIO_EXPORTS)
        .find_map(|export| match &export.item {
            Item::Func(api) if api.name == name => Some(api),
            _ => None,
        })
        .unwrap();
    let index = c.p.modules.by_name("ucrtbase.dll").unwrap();
    c.entry_pc = loader::lookup(c.p, index, &SymRef::Name(name.as_bytes().to_vec(), None))
        .unwrap()
        .unwrap();
    c.api = api;
    assert_eq!(values.len(), api.args.len());
    for (i, &value) in values.iter().enumerate() {
        match c.arch() {
            WinArch::X86 => c
                .mem()
                .w32(c.entry_sp + 4 + i as u64 * 4, value as u32)
                .unwrap(),
            WinArch::X64 => c.t.cpu.set_gpr([1, 2, 8, 9][i], value),
            WinArch::Arm64 => c.t.cpu.set_gpr(i, value),
        }
    }
    match (api.imp)(c).unwrap() {
        Flow::Ret(Value::Int(value)) => value,
        _ => panic!("immediate successful stdio operation"),
    }
}

fn queue(p: &mut Proc, t: &mut Thread, bytes: &[u8]) -> Output {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let (path, host) = loop {
        let path = std::env::temp_dir().join(format!(
            "rax-ucrt-detach-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(host) => break (path, host),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("owned test output: {error}"),
        }
    };
    let identity = FileIdentity::of(&path, &host.metadata().unwrap()).unwrap();
    let handle = p.objects.insert(Object::File(FileObj {
        host: Some(host),
        host_path: path.clone(),
        path: "C:\\detach-unit.dat".into(),
        access: 0xC000_0000,
        share: 7,
        lifetime: Arc::new(FileLifetime::new(identity)),
        null: false,
        append: false,
        delete_on_close: false,
        directory: false,
        overlapped: false,
    }));
    let memory =
        p.vm.allocate(None, 0x1000, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap()
            .0;
    p.space.put_cstr(memory, b"wb").unwrap();
    p.space.wr(memory + 64, bytes).unwrap();
    let sp = t.cpu.sp();
    let mut c = Ctx {
        p,
        t,
        api: &EXIT_PROCESS,
        entry_pc: 0,
        entry_sp: sp,
        ret_addr: 0,
        cursor: sp,
    };
    let fd = call(&mut c, "_open_osfhandle", &[handle.into(), 0x8002]);
    assert!(fd >= 3);
    let file = call(&mut c, "_fdopen", &[fd, memory]);
    assert_ne!(file, 0);
    assert_eq!(
        call(
            &mut c,
            "fwrite",
            &[memory + 64, 1, bytes.len() as u64, file]
        ),
        bytes.len() as u64
    );
    let output = Output(path);
    assert!(output.bytes().is_empty());
    output
}

#[test]
fn ucrt_flush_runs_between_reverse_completed_native_notifications_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch);
        let p = process.state_mut();
        let before = native(p, "before-ucrt.dll", 0, true);
        let ucrt = loader::load_dll(p, "ucrtbase.dll").unwrap();
        let after = native(p, "after-ucrt.dll", 0, true);
        let output = queue(p, &mut t, b"buffered");
        assert_eq!(process_order(p), [before, ucrt, after]);
        assert_eq!(process_exit(p, &mut t, 63), Outcome::Continue);
        assert_eq!(t.cpu.pc(), p.modules.list[after].entry);
        assert_eq!(args(p, &t), [p.modules.list[after].base, 0, p.params]);
        assert!(output.bytes().is_empty());
        assert_eq!(returned(p, &mut t, 0), Outcome::Continue);
        assert_eq!(output.bytes(), b"buffered");
        assert!(!p.modules.list[ucrt].initialized);
        assert!(p.modules.is_live(ucrt));
        assert!(p.traps.lookup(p.modules.list[ucrt].text).is_some());
        assert_eq!(t.cpu.pc(), p.modules.list[before].entry);
        assert_eq!(returned(p, &mut t, 0), Outcome::ProcessExit(63));
        assert!(p.loader.is_idle());
        assert!(p.failure.is_none());
    }
}

#[test]
fn executable_pe_tls_follows_ucrt_flush_in_existing_exit_profile_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch);
        let p = process.state_mut();
        let ucrt = loader::load_dll(p, "ucrtbase.dll").unwrap();
        let output = queue(p, &mut t, b"before-exe-tls");
        let callbacks =
            p.vm.allocate(None, 0x1000, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let target = callbacks + 0x100;
        p.space.wptr(callbacks, arch.ptr_size(), target).unwrap();
        p.space
            .wptr(callbacks + arch.ptr_size(), arch.ptr_size(), 0)
            .unwrap();
        p.modules.list[0].tls = Some(ModuleTls {
            index: 0,
            template: 0,
            raw_size: 0,
            zero_fill: 0,
            callbacks,
        });
        p.modules.list[0].initialized = true;
        assert_eq!(process_exit(p, &mut t, 64), Outcome::Continue);
        assert_eq!(output.bytes(), b"before-exe-tls");
        assert!(!p.modules.list[ucrt].initialized);
        assert_eq!(t.cpu.pc(), target);
        assert_eq!(args(p, &t), [p.modules.list[0].base, 0, 0]);
        // Thus output from this EXE PE TLS callback (or later scheduler FLS)
        // is not covered by a claim of an unconditional final UCRT flush.
        assert_eq!(returned(p, &mut t, 0), Outcome::ProcessExit(64));
        assert!(p.loader.is_idle());
    }
}

#[test]
fn detach_buffer_fault_keeps_loader_guard_until_exact_retry_finishes_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch);
        let p = process.state_mut();
        let ucrt = loader::load_dll(p, "ucrtbase.dll").unwrap();
        let output = queue(p, &mut t, b"retry-output");
        // A missing errno page gives the actual checked flush job a repair
        // frontier before host I/O without depending on private FILE layout.
        let sp = t.cpu.sp();
        let mut c = Ctx {
            p,
            t: &mut t,
            api: &EXIT_PROCESS,
            entry_pc: 0,
            entry_sp: sp,
            ret_addr: 0,
            cursor: sp,
        };
        // `_errno` belongs to the real UCRT API but is outside the stdio list.
        let index = c.p.modules.by_name("ucrtbase.dll").unwrap();
        let address = loader::lookup(c.p, index, &SymRef::Name(b"_errno".to_vec(), None))
            .unwrap()
            .unwrap();
        let api = match c.p.traps.lookup(address).unwrap() {
            crate::user::windows::traps::Trap::Entry(api) => api,
            _ => panic!("errno API trap"),
        };
        c.api = api;
        c.entry_pc = address;
        let errno = match (api.imp)(&mut c).unwrap() {
            Flow::Ret(Value::Int(value)) => value,
            _ => panic!("errno"),
        };
        let page = errno & !0xFFF;
        c.p.vm.protect(page, 0x1000, prot::READONLY).unwrap();
        c.api = &EXIT_PROCESS;
        c.entry_pc = 0;
        let flow = with_lock(
            &mut c,
            Box::new(move |c, guard| {
                detach(
                    c,
                    guard,
                    Detach::new(vec![ucrt], 0, 0, true, false, Finish::Process(65)),
                )
            }),
        )
        .unwrap();
        let Flow::RetryFault { fault, retry } = flow else {
            panic!("retained flush fault");
        };
        assert!(fault.write);
        assert!(!c.p.loader.is_idle());
        assert!(output.bytes().is_empty());
        assert!(c.p.failure.is_none());
        c.p.vm.protect(page, 0x1000, prot::READWRITE).unwrap();
        assert!(matches!(retry(&mut c, 0).unwrap(), Flow::ExitProcess(65)));
        assert_eq!(output.bytes(), b"retry-output");
        assert!(c.p.loader.is_idle());
        assert!(c.p.failure.is_none());
    }
}
