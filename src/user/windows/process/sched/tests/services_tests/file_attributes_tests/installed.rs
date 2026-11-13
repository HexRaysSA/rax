//! Actual installed native/WoW64 leaves against independent native NT queries.

use crate::user::windows::arch::WinArch;
use crate::user::windows::loader::{self, SymRef};
use crate::user::windows::memory::{Mem, mem, prot};
use crate::user::windows::nt::status::STATUS_SUCCESS;
use crate::user::windows::process::sched::run_cpu;
use crate::user::windows::process::sched::{Outcome, handle_stop};
use crate::user::windows::process::{Proc, Thread, WindowsConfig, WindowsProcess};
use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

#[repr(C)]
struct Unicode {
    length: u16,
    maximum: u16,
    buffer: *const u16,
}
#[repr(C)]
struct Attributes {
    length: u32,
    root: *mut c_void,
    name: *const Unicode,
    flags: u32,
    security: *mut c_void,
    qos: *mut c_void,
}
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryAttributesFile(attrs: *const Attributes, info: *mut c_void) -> i32;
    fn NtQueryFullAttributesFile(attrs: *const Attributes, info: *mut c_void) -> i32;
}

fn reference(path: &Path, full: bool) -> Vec<u8> {
    let wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    assert!(wide.starts_with(&[92, 92, 63, 92]));
    let mut name: Vec<u16> = "\\??\\".encode_utf16().collect();
    name.extend_from_slice(&wide[4..]);
    let unicode = Unicode {
        length: (name.len() * 2) as u16,
        maximum: (name.len() * 2) as u16,
        buffer: name.as_ptr(),
    };
    let attrs = Attributes {
        length: std::mem::size_of::<Attributes>() as u32,
        root: std::ptr::null_mut(),
        name: &unicode,
        flags: 0x840,
        security: std::ptr::null_mut(),
        qos: std::ptr::null_mut(),
    };
    let mut output = [0u64; 7];
    // SAFETY: all arguments are exclusive initialized native allocations with
    // SDK layouts. Aligned output covers both records, and the synchronous NT
    // call retains no pointers. This independent oracle calls no emulator code.
    let status = unsafe {
        if full {
            NtQueryFullAttributesFile(&attrs, output.as_mut_ptr().cast())
        } else {
            NtQueryAttributesFile(&attrs, output.as_mut_ptr().cast())
        }
    };
    assert_eq!(status, 0);
    output
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .take(if full { 56 } else { 40 })
        .collect()
}

fn leaf(p: &mut Proc, t: &mut Thread, name: &str, attrs: u64, output: u64) -> u32 {
    let module = p.modules.nt_services.as_ref().unwrap().0;
    let entry = loader::lookup(p, module, &SymRef::Name(name.as_bytes().to_vec(), None))
        .unwrap()
        .unwrap();
    let saved = t.cpu.sp();
    let sp = saved - 128;
    let resume = p.traps.callback_return();
    t.cpu.set_sp(sp);
    t.cpu.set_pc(entry);
    match p.arch {
        WinArch::X86 => {
            p.space.w32(sp, resume as u32).unwrap();
            p.space.w32(sp + 4, attrs as u32).unwrap();
            p.space.w32(sp + 8, output as u32).unwrap();
        }
        WinArch::X64 => {
            p.space.w64(sp, resume).unwrap();
            t.cpu.set_gpr(1, attrs);
            t.cpu.set_gpr(2, output);
        }
        WinArch::Arm64 => {
            t.cpu.set_gpr(30, resume);
            t.cpu.set_gpr(0, attrs);
            t.cpu.set_gpr(1, output);
        }
    }
    let mut completed = false;
    for _ in 0..64 {
        let boundary = run_cpu(p, &mut t.cpu, 64);
        if t.cpu.pc() == resume {
            completed = true;
            break;
        }
        assert!(
            matches!(
                handle_stop(p, t, boundary),
                Outcome::Continue | Outcome::Yield
            ),
            "{}/{name}",
            p.arch
        );
    }
    assert!(completed);
    assert_eq!(
        t.cpu.sp(),
        sp + match p.arch {
            WinArch::X86 => 12,
            WinArch::X64 => 8,
            WinArch::Arm64 => 0,
        }
    );
    assert!(t.frames.is_empty());
    t.cpu.set_sp(saved);
    t.cpu.gpr(0) as u32
}

#[test]
fn native_file_attributes_installed_leaves_match_native_metadata_and_ret8() {
    let host = if cfg!(target_arch = "aarch64") {
        WinArch::Arm64
    } else if cfg!(target_arch = "x86_64") {
        WinArch::X64
    } else {
        WinArch::X86
    };
    for arch in if host == WinArch::X86 {
        vec![host]
    } else {
        vec![host, WinArch::X86]
    } {
        let image: &[u8] = match arch {
            WinArch::X86 => include_bytes!(
                "../../../../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe"
            ),
            WinArch::X64 => include_bytes!(
                "../../../../../../../../tests/fixtures/user/windows/bin/x64/smoke.exe"
            ),
            WinArch::Arm64 => include_bytes!(
                "../../../../../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe"
            ),
        };
        let mut config =
            WindowsConfig::embedded("C:\\attribute-leaf.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let p = process.state_mut();
        let host_path = p
            .native
            .as_ref()
            .unwrap()
            .dll("version.dll")
            .unwrap()
            .unwrap();
        let thread_id = *p.threads.keys().next().unwrap();
        let mut thread = p.threads.remove(&thread_id).unwrap();
        let base =
            p.vm.allocate(None, 0x4000, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                .unwrap()
                .0;
        let attrs = base + 4096;
        let width = arch.ptr_size();
        let size = if arch.is64() { 48 } else { 24 };
        let units: Vec<u16> = "\\??\\C:\\WINDOWS\\SYSTEM32\\VERSION.dll"
            .encode_utf16()
            .collect();
        p.space.wr(attrs, &vec![0; size]).unwrap();
        p.space.w32(attrs, size as u32).unwrap();
        p.space.wptr(attrs + 2 * width, width, attrs + 64).unwrap();
        p.space.w32(attrs + 3 * width, 0x840).unwrap();
        p.space.w16(attrs + 64, (units.len() * 2) as u16).unwrap();
        p.space.w16(attrs + 66, 0).unwrap();
        p.space
            .wptr(attrs + 64 + width, width, attrs + 128)
            .unwrap();
        p.space.put_wunits(attrs + 128, &units).unwrap();
        for (name, full) in [
            ("NtQueryAttributesFile", false),
            ("NtQueryFullAttributesFile", true),
        ] {
            let expected = reference(&host_path, full);
            p.space.wr(base, &[0xa5; 64]).unwrap();
            assert_eq!(
                leaf(p, &mut thread, name, attrs, base),
                STATUS_SUCCESS,
                "{arch}/{name}"
            );
            let length = if !full && arch == WinArch::X86 {
                36
            } else {
                expected.len()
            };
            assert_eq!(
                p.space.bytes(base, length).unwrap(),
                expected[..length],
                "{arch}/{name}"
            );
            assert_eq!(
                p.space.bytes(base + length as u64, 64 - length).unwrap(),
                vec![0xa5; 64 - length]
            );
            assert_eq!(
                reference(&host_path, full),
                expected,
                "native DLL metadata changed during leaf comparison"
            );
        }
    }
}
