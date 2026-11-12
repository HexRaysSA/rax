use super::*;
use crate::user::windows::layout::offsets;

fn corpus(arch: WinArch) -> &'static str {
    match arch {
        WinArch::Arm64 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-clear-event/arm64-native-v2.txt"
        )),
        WinArch::X64 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-clear-event/x64-native-v2.txt"
        )),
        WinArch::X86 => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/docs/specifications/windows/native-clear-event/x86-native-v2.txt"
        )),
    }
}

#[test]
fn clear_event_replays_all_834_native_access_type_tag_lifetime_and_state_rows() {
    let mut seen = 0;
    for arch in WinArch::ALL {
        let (mut process, mut t, _) = setup(arch);
        let p = process.state_mut();
        let original_handles = p.objects.handle_count();
        let original_objects = p.objects.iter().count();
        let mut index = 0;
        for line in corpus(arch).lines() {
            let row: Vec<_> = line
                .split_whitespace()
                .skip(1)
                .map(|v| u32::from_str_radix(v, 16).unwrap())
                .collect();
            assert_eq!(row.len(), 17);
            assert_eq!(row[0], index);
            let category = row[1];
            let mut object = None;
            let mut hold = None;
            let mut target_handle = None;
            let target = if category == 2 {
                match row[2] {
                    0..=3 => u64::from(row[2]),
                    4 => arch.ptr(u64::MAX),
                    5 => arch.ptr(u64::MAX - 1),
                    _ => unreachable!(),
                }
            } else {
                let value = if category == 1 {
                    match row[2] {
                        0 => Object::Semaphore { count: 0, max: 2 },
                        1 => Object::Mutex {
                            owner: None,
                            count: 0,
                            abandoned: false,
                        },
                        2 => Object::Process {
                            pid: p.pid,
                            exit_code: None,
                        },
                        3 => Object::Thread {
                            tid: t.tid,
                            exit_code: None,
                        },
                        _ => unreachable!(),
                    }
                } else {
                    assert_eq!(row[9], 0);
                    assert_eq!(row[10], row[2]);
                    assert_eq!(row[11], row[3]);
                    Object::Event {
                        manual: row[2] == 0,
                        signaled: row[3] as i32,
                    }
                };
                let id = p.objects.create(value);
                object = Some(id);
                hold = Some(p.objects.open(id, false));
                let handle = p.objects.open_access(id, false, row[5]).unwrap();
                if category == 3 {
                    p.objects.close(u64::from(handle)).unwrap();
                } else {
                    target_handle = Some(handle);
                }
                u64::from(handle) | u64::from(row[6])
            };
            let before = object.map(|id| format!("{:?}", p.objects.obj(id).unwrap()));
            let last_error = t.teb + offsets(arch).teb_last_error;
            p.space.w32(last_error, 0x7654_3210).unwrap();
            for (call_index, expected) in [row[7], row[15]].into_iter().enumerate() {
                assert_eq!(
                    status(p, &mut t, "NtClearEvent", &[target]),
                    expected,
                    "{arch}/row{index}/call{call_index}"
                );
                assert_eq!(p.space.u32(last_error).unwrap(), row[8]);
                if category == 0 || category == 3 {
                    assert_eq!(row[12], 0);
                    assert_eq!(row[13], row[2]);
                    let Some(Object::Event { manual, signaled }) = p.objects.obj(object.unwrap())
                    else {
                        panic!("event changed type")
                    };
                    assert_eq!(*manual, row[2] == 0);
                    assert_eq!(*signaled as u32, row[if call_index == 0 { 14 } else { 16 }]);
                } else if let Some(id) = object {
                    assert_eq!(
                        format!("{:?}", p.objects.obj(id).unwrap()),
                        before.as_ref().unwrap().as_str()
                    );
                }
            }
            if let Some(handle) = target_handle {
                p.objects.close(u64::from(handle)).unwrap();
            }
            if let Some(handle) = hold {
                p.objects.close(u64::from(handle)).unwrap();
            }
            assert_eq!(p.objects.handle_count(), original_handles);
            assert_eq!(p.objects.iter().count(), original_objects);
            index += 1;
            seen += 1;
        }
        assert_eq!(index, 278);
    }
    assert_eq!(seen, 834);
}

#[test]
fn clear_event_has_no_previous_state_probe_and_does_not_consume_unused_guard() {
    for arch in WinArch::ALL {
        let (mut process, mut t, scratch) = setup(arch);
        let p = process.state_mut();
        let id = p.objects.create(Object::Event {
            manual: true,
            signaled: 255,
        });
        let handle = p.objects.open_access(id, false, 2).unwrap();
        let bytes = p.space.bytes(scratch, PAGE_SIZE as usize).unwrap();
        p.vm.protect(scratch, PAGE_SIZE, prot::READWRITE | prot::GUARD)
            .unwrap();
        // The unused second scalar is a guarded address, not an output parameter.
        assert_eq!(
            status(p, &mut t, "NtClearEvent", &[u64::from(handle), scratch]),
            0
        );
        assert_eq!(
            p.vm.query(scratch).unwrap().protect,
            prot::READWRITE | prot::GUARD
        );
        assert!(matches!(
            p.objects.obj(id),
            Some(Object::Event { signaled: 0, .. })
        ));
        p.vm.protect(scratch, PAGE_SIZE, prot::READWRITE).unwrap();
        assert_eq!(p.space.bytes(scratch, PAGE_SIZE as usize).unwrap(), bytes);
        p.objects.close(u64::from(handle)).unwrap();
    }
}

#[test]
fn clear_event_append_preserves_all_prior_ordinals_and_shares_raw_one_argument_entry() {
    use crate::user::windows::dll::{self, BuiltinDll};
    use crate::user::windows::hle::{Arg, Conv, Item};
    use crate::user::windows::loader::builtin;
    let current = dll::find("ntdll.dll").unwrap();
    let family = current
        .exports
        .iter()
        .position(|entries| entries.iter().any(|entry| entry.name == "NtClearEvent"))
        .unwrap();
    assert_eq!(current.exports[family].len(), 1);
    assert_eq!(current.exports[family][0].name, "NtClearEvent");
    let previous = BuiltinDll {
        name: current.name,
        display: current.display,
        subsystem: current.subsystem,
        exports: &current.exports[..family],
    };
    let with_clear = BuiltinDll {
        name: current.name,
        display: current.display,
        subsystem: current.subsystem,
        exports: &current.exports[..=family],
    };
    for arch in WinArch::ALL {
        let before = builtin::build(&previous, arch, 0, &[]);
        let after = builtin::build(&with_clear, arch, 0, &[]);
        assert_eq!(after.ordinal_base, before.ordinal_base);
        assert_eq!(after.symbols.len(), before.symbols.len() + 1);
        assert_eq!(&after.symbols[..before.symbols.len()], before.symbols);
        let Item::Func(api) = &current.exports[family][0].item else {
            panic!("not a function")
        };
        assert_eq!(api.args, &[Arg::Ptr]);
        assert_eq!(api.conv, Conv::Stdcall);
        let raw = dll::nt_service("NtClearEvent", arch).unwrap();
        assert_eq!(raw.args, api.args);
        assert_eq!(raw.conv, api.conv);
        assert!(std::ptr::fn_addr_eq(raw.imp, api.imp));
    }
}

#[cfg(windows)]
#[test]
fn clear_event_installed_leaf_returns_with_exact_one_argument_stack_cleanup() {
    use crate::user::windows::loader::{self, SymRef};
    use crate::user::windows::process::{WindowsConfig, WindowsProcess};
    let host = if cfg!(target_arch = "aarch64") {
        WinArch::Arm64
    } else if cfg!(target_arch = "x86_64") {
        WinArch::X64
    } else {
        WinArch::X86
    };
    let arches = if host == WinArch::X86 {
        vec![host]
    } else {
        vec![host, WinArch::X86]
    };
    for arch in arches {
        let image: &[u8] = match arch {
            WinArch::X86 => include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/user/windows/bin/x86/smoke.exe"
            )),
            WinArch::X64 => include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/user/windows/bin/x64/smoke.exe"
            )),
            WinArch::Arm64 => include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/user/windows/bin/arm64/smoke.exe"
            )),
        };
        let mut cfg =
            WindowsConfig::embedded("C:\\native-clear-event.exe", vec![], vec![], 4096).unwrap();
        cfg.native_libraries = true;
        cfg.arena_bytes = 256 << 20;
        let mut process = WindowsProcess::spawn_image(cfg, image.to_vec()).unwrap();
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let module = loader::load_dll(p, "ntdll.dll").unwrap();
        let entry = loader::lookup(p, module, &SymRef::Name(b"NtClearEvent".to_vec(), None))
            .unwrap()
            .unwrap();
        let id = p.objects.create(Object::Event {
            manual: true,
            signaled: 1,
        });
        let handle = p.objects.open_access(id, false, 2).unwrap();
        let sp = t.cpu.sp() - 128;
        let resume = p.traps.callback_return();
        t.cpu.set_sp(sp);
        t.cpu.set_pc(entry);
        match arch {
            WinArch::X86 => {
                p.space.w32(sp, resume as u32).unwrap();
                p.space.w32(sp + 4, handle).unwrap();
            }
            WinArch::X64 => {
                p.space.w64(sp, resume).unwrap();
                t.cpu.set_gpr(1, u64::from(handle));
            }
            WinArch::Arm64 => {
                t.cpu.set_gpr(30, resume);
                t.cpu.set_gpr(0, u64::from(handle));
            }
        }
        let mut returned = false;
        for _ in 0..64 {
            let stop = t.cpu.run(64);
            if t.cpu.pc() == resume {
                returned = true;
                break;
            }
            assert!(matches!(
                handle_stop(p, &mut t, stop),
                Outcome::Continue | Outcome::Yield
            ));
        }
        assert!(returned);
        assert_eq!(t.cpu.gpr(0), 0);
        assert!(t.frames.is_empty());
        assert_eq!(
            t.cpu.sp(),
            sp + match arch {
                WinArch::X86 => 8,
                WinArch::X64 => 8,
                WinArch::Arm64 => 0,
            }
        );
        assert!(matches!(
            p.objects.obj(id),
            Some(Object::Event { signaled: 0, .. })
        ));
        p.objects.close(u64::from(handle)).unwrap();
    }
}
