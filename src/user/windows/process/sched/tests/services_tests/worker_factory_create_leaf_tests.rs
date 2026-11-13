//! Execute installed NtCreateWorkerFactory/NtClose leaves and actual caller cleanup.
use super::*;
use crate::user::windows::{
    loader::{self, SymRef},
    process::{WindowsConfig, WindowsProcess},
};

#[test]
fn installed_worker_factory_create_leaf_constructs_closes_and_returns_all_caller_arguments() {
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
            WinArch::X86 => {
                include_bytes!("../../../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
            }
            WinArch::X64 => {
                include_bytes!("../../../../../../../tests/fixtures/user/windows/bin/x64/smoke.exe")
            }
            WinArch::Arm64 => include_bytes!(
                "../../../../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe"
            ),
        };
        let mut config =
            WindowsConfig::embedded("C:\\native-worker-factory.exe", vec![], vec![], 4096).unwrap();
        config.native_libraries = true;
        config.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let module = loader::load_dll(p, "ntdll.dll").unwrap();
        let sp = t.cpu.sp() - 256;
        let port = p.objects.insert(Object::CompletionPort {
            queue: Default::default(),
            concurrency: 4,
        });
        let out = sp - 128;
        let resume = p.traps.callback_return();
        let before_handles = p.objects.handle_count();
        let before_objects = p.objects.iter().count();
        for count in [0, 512, u32::MAX] {
            let mut handle = 0;
            for name in ["NtCreateWorkerFactory", "NtClose"] {
                let args = if name == "NtCreateWorkerFactory" {
                    p.space.wr(out, &[0xA5; 16]).unwrap();
                    vec![
                        out,
                        0xF00FF,
                        0,
                        u64::from(port),
                        arch.ptr(u64::MAX),
                        0x12345678,
                        0x87654321,
                        u64::from(count),
                        0,
                        0,
                    ]
                } else {
                    vec![handle]
                };
                let entry =
                    loader::lookup(p, module, &SymRef::Name(name.as_bytes().to_vec(), None))
                        .unwrap()
                        .unwrap();
                t.cpu.set_sp(sp);
                t.cpu.set_pc(entry);
                for (index, value) in args.iter().copied().enumerate() {
                    match arch {
                        WinArch::X86 => p
                            .space
                            .w32(sp + 4 + index as u64 * 4, value as u32)
                            .unwrap(),
                        WinArch::X64 => {
                            if index < 4 {
                                t.cpu.set_gpr([1, 2, 8, 9][index], value);
                            } else {
                                p.space.w64(sp + 8 + index as u64 * 8, value).unwrap();
                            }
                        }
                        WinArch::Arm64 => {
                            if index < 8 {
                                t.cpu.set_gpr(index, value);
                            } else {
                                p.space.w64(sp + (index as u64 - 8) * 8, value).unwrap();
                            }
                        }
                    }
                }
                match arch {
                    WinArch::X86 => p.space.w32(sp, resume as u32).unwrap(),
                    WinArch::X64 => p.space.w64(sp, resume).unwrap(),
                    WinArch::Arm64 => t.cpu.set_gpr(30, resume),
                }
                let mut returned = false;
                for _ in 0..32 {
                    let boundary = run_cpu(p, &mut t.cpu, 64);
                    if t.cpu.pc() == resume {
                        returned = true;
                        break;
                    }
                    assert!(
                        matches!(
                            handle_stop(p, &mut t, boundary),
                            Outcome::Continue | Outcome::Yield
                        ),
                        "{arch}/{name}: installed leaf failed"
                    );
                }
                assert!(
                    returned,
                    "{arch}/{name}: no caller return within 2048 instructions"
                );
                assert_eq!(t.cpu.gpr(0), 0);
                assert!(t.frames.is_empty());
                assert_eq!(
                    t.cpu.sp(),
                    sp + match arch {
                        WinArch::X86 => 4 + 4 * args.len() as u64,
                        WinArch::X64 => 8,
                        WinArch::Arm64 => 0,
                    }
                );
                if name == "NtCreateWorkerFactory" {
                    handle = p.space.ptr(out, arch.ptr_size()).unwrap();
                    assert_eq!(p.objects.access(handle), Some(0xF00FF));
                    assert!(
                        matches!(p.objects.get(handle), Some(Object::WorkerFactory{maximum, reserve:65536, commit:4096,..}) if *maximum == count)
                    );
                    assert_eq!(p.objects.handle_count(), before_handles + 1);
                    assert_eq!(p.objects.iter().count(), before_objects + 1);
                    assert_eq!(
                        p.space
                            .bytes(out + arch.ptr_size(), 16 - arch.ptr_size() as usize)
                            .unwrap(),
                        vec![0xA5; 16 - arch.ptr_size() as usize]
                    );
                } else {
                    assert_eq!(p.objects.handle_count(), before_handles);
                    assert_eq!(p.objects.iter().count(), before_objects);
                    assert!(p.objects.get(handle).is_none());
                }
            }
        }
    }
}
