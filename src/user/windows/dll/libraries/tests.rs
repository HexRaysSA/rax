use super::*;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{Api, Conv, Item, Value};
use crate::user::windows::{WindowsConfig, WindowsProcess};

static TEST_API: Api = Api {
    name: "loader-lock-test",
    args: &[],
    conv: Conv::Custom,
    imp: |_| Flow::void(),
};

fn process(arch: WinArch) -> WindowsProcess {
    let name = match arch {
        WinArch::X86 => "x86",
        WinArch::X64 => "x64",
        WinArch::Arm64 => "arm64",
    };
    let mut config = WindowsConfig::new(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("tests/fixtures/user/windows/bin/{name}/smoke.exe")),
        Vec::new(),
    );
    config.arena_bytes = 64 << 20;
    config.seed = Some(1);
    WindowsProcess::spawn(config).unwrap()
}

fn context<'a>(p: &'a mut Proc, t: &'a mut Thread, api: &'static Api) -> Ctx<'a> {
    let sp = t.cpu.sp();
    Ctx {
        p,
        t,
        api,
        entry_pc: 0,
        entry_sp: sp,
        ret_addr: 0,
        cursor: sp.saturating_sub(32) & !15,
    }
}

fn dynamic_process(arch: WinArch) -> WindowsProcess {
    let name = match arch {
        WinArch::X86 => "x86",
        WinArch::X64 => "x64",
        WinArch::Arm64 => "arm64",
    };
    let mut config = WindowsConfig::new(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
            "tests/fixtures/user/windows/lifecycle/bin/{name}/dynamic.exe"
        )),
        Vec::new(),
    );
    config.arena_bytes = 64 << 20;
    config.seed = Some(1);
    WindowsProcess::spawn(config).unwrap()
}

fn invoke(p: &mut Proc, t: &mut Thread, name: &str, arguments: &[u64]) -> ApiResult {
    let api = EXPORTS
        .iter()
        .find_map(|export| match &export.item {
            Item::Func(api) if export.name == name => Some(api),
            _ => None,
        })
        .unwrap();
    assert_eq!(arguments.len(), api.args.len());
    let sp = t.cpu.sp();
    for (index, &argument) in arguments.iter().enumerate() {
        match p.arch {
            WinArch::X86 => p
                .space
                .w32(sp + 4 + index as u64 * 4, argument as u32)
                .unwrap(),
            WinArch::X64 => t.cpu.set_gpr([1, 2, 8, 9][index], argument),
            WinArch::Arm64 => t.cpu.set_gpr(index, argument),
        }
    }
    (api.imp)(&mut context(p, t, api))
}

#[test]
fn module_handle_ex_address_count_unchanged_pin_and_name_all_abis() {
    for arch in WinArch::ALL {
        let mut process = dynamic_process(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let observer = p.modules.by_name("observer.dll").unwrap();
        // Spawn constructs mappings; this API model represents the ready
        // module that an ordinary application caller sees after startup.
        loader::attach_started(p, observer, false).unwrap();
        loader::attach_succeeded(p, observer).unwrap();
        let base = p.modules.list[observer].base;
        let out = t.cpu.sp() - 0x100;
        let text = out - 0x100;
        p.space.write(text, b"observer.dll\0").unwrap();
        assert_eq!(p.modules.list[observer].load_count, 0);
        for (name, flags, address, expected_count) in [
            ("GetModuleHandleExW", 4, base + 0x100, 1),
            ("GetModuleHandleExW", 6, base, 1),
            ("GetModuleHandleExA", 0, text, 2),
            ("GetModuleHandleExW", 5, base, u32::MAX),
        ] {
            let result = invoke(p, &mut t, name, &[flags, address, out]).unwrap();
            assert!(matches!(result, Flow::Ret(Value::Int(1))));
            assert_eq!(p.space.ptr(out, arch.ptr_size()).unwrap(), base);
            assert_eq!(p.modules.list[observer].load_count, expected_count);
            assert!(p.loader.is_idle());
        }
        let release = loader::begin_unload(p, base).unwrap();
        assert!(release.detach.is_empty());
        loader::finish_unload(p, &mut t, release.id).unwrap();
        assert_eq!(p.modules.list[observer].load_count, u32::MAX);
        assert!(p.modules.is_live(observer));
        let failed = invoke(p, &mut t, "GetModuleHandleExW", &[4, 0, out]).unwrap();
        assert!(matches!(failed, Flow::Ret(Value::Int(0))));
        assert_eq!(p.space.ptr(out, arch.ptr_size()).unwrap(), 0);
        assert_eq!(
            context(p, &mut t, &TEST_API).last_error().unwrap(),
            ERROR_MOD_NOT_FOUND
        );
        assert!(p.loader.is_idle());
    }
}

#[test]
fn unready_native_handles_cannot_acquire_counted_or_pinned_ownership_all_abis() {
    for arch in WinArch::ALL {
        let mut process = dynamic_process(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let index = p.modules.by_name("observer.dll").unwrap();
        assert!(!p.modules.list[index].initialized);
        let base = p.modules.list[index].base;
        let out = t.cpu.sp() - 0x100;
        for flags in [4, 5] {
            p.space
                .wptr(out, arch.ptr_size(), arch.ptr(u64::MAX))
                .unwrap();
            let result = invoke(p, &mut t, "GetModuleHandleExW", &[flags, base, out]).unwrap();
            assert!(matches!(result, Flow::Ret(Value::Int(0))));
            assert_eq!(
                context(p, &mut t, &TEST_API).last_error().unwrap(),
                ERROR_NOT_SUPPORTED
            );
            assert_eq!(p.modules.list[index].load_count, 0);
            assert_eq!(p.space.ptr(out, arch.ptr_size()).unwrap(), 0);
            assert!(p.loader.is_idle());
            assert!(p.loader.abandoned.borrow().is_empty());
        }
        let borrowed = invoke(p, &mut t, "GetModuleHandleExW", &[6, base, out]).unwrap();
        assert!(matches!(borrowed, Flow::Ret(Value::Int(1))));
        assert_eq!(p.space.ptr(out, arch.ptr_size()).unwrap(), base);
        assert_eq!(p.modules.list[index].load_count, 0);
        assert!(p.loader.is_idle());
    }
}

#[test]
fn disable_thread_calls_rejects_executable_data_and_static_tls_all_abis() {
    for arch in WinArch::ALL {
        let mut process = dynamic_process(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let data = loader::begin_load(p, &mut t, "data.exe").unwrap();
        assert!(data.initialize.is_empty());
        loader::commit_load(p, data.id).unwrap();
        let leaf = loader::begin_load(p, &mut t, "leaf.dll").unwrap();
        for index in [0, data.root, leaf.root] {
            let base = p.modules.list[index].base;
            let before = p.modules.list[index].thread_calls;
            let result = invoke(p, &mut t, "DisableThreadLibraryCalls", &[base]).unwrap();
            assert!(matches!(result, Flow::Ret(Value::Int(0))));
            assert_eq!(
                context(p, &mut t, &TEST_API).last_error().unwrap(),
                ERROR_INVALID_PARAMETER
            );
            assert_eq!(p.modules.list[index].thread_calls, before);
            assert!(p.loader.is_idle());
        }
        let observer = p.modules.by_name("observer.dll").unwrap();
        let base = p.modules.list[observer].base;
        let success = invoke(p, &mut t, "DisableThreadLibraryCalls", &[base]).unwrap();
        assert!(matches!(success, Flow::Ret(Value::Int(1))));
        assert!(!p.modules.list[observer].thread_calls);
        loader::begin_rollback(
            p,
            leaf.id,
            LoadError {
                status: STATUS_UNSUCCESSFUL,
                message: "unit cleanup".into(),
            },
            None,
        )
        .unwrap();
        loader::finish_rollback(p, &mut t, leaf.id).unwrap();
        let release = loader::begin_unload(p, p.modules.list[data.root].base).unwrap();
        loader::finish_unload(p, &mut t, release.id).unwrap();
    }
}

#[test]
fn free_and_exit_unmaps_data_without_returning_to_guest_code_all_abis() {
    for arch in WinArch::ALL {
        let mut process = dynamic_process(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        t.attached = true;
        let plan = loader::begin_load(p, &mut t, "data.exe").unwrap();
        assert!(plan.initialize.is_empty());
        loader::commit_load(p, plan.id).unwrap();
        let base = p.modules.list[plan.root].base;
        let result = invoke(p, &mut t, "FreeLibraryAndExitThread", &[base, 19]).unwrap();
        assert!(matches!(result, Flow::ExitThread(19)));
        assert!(t.attached, "normal thread detach remains a scheduler stage");
        assert_eq!(p.modules.by_base(base), None);
        assert_eq!(
            p.vm.query(base).unwrap().state,
            crate::user::windows::memory::mem::FREE
        );
        assert!(p.loader.is_idle());
        assert!(p.loader.abandoned.borrow().is_empty());
    }
}

#[test]
fn abandoned_native_initializer_cleans_resources_before_reporting_failure_all_abis() {
    for arch in WinArch::ALL {
        let mut process = dynamic_process(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let text = t.cpu.sp() - 0x100;
        p.space.write(text, b"leaf.dll\0").unwrap();
        let flow = invoke(p, &mut t, "LoadLibraryA", &[text]).unwrap();
        assert!(matches!(flow, Flow::Call { .. }));
        let index = p.modules.by_name("leaf.dll").unwrap();
        let base = p.modules.list[index].base;
        assert_ne!(t.tls_array, 0);
        drop(flow); // Models an HLE frame dropping its captured continuation.
        let error = cleanup_abandoned(p, &mut t).unwrap_err();
        assert!(error.contains("resource journals cleaned"));
        assert!(p.loader.is_idle());
        assert!(p.loader.abandoned.borrow().is_empty());
        assert_eq!(p.modules.by_name("leaf.dll"), None);
        assert_eq!(p.modules.by_base(base), None);
        assert_eq!(
            p.vm.query(base).unwrap().state,
            crate::user::windows::memory::mem::FREE
        );
        assert_eq!(t.tls_array, 0);
        assert!(t.tls_blocks.is_empty());
    }
}

#[test]
fn loader_lock_is_reentrant_and_released_before_normal_return_all_abis() {
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let mut c = context(p, &mut t, &TEST_API);
        let result = with_lock(
            &mut c,
            Box::new(|c, mut outer| {
                assert_eq!(c.p.loader.owner, Some((c.t.tid, 1)));
                let nested = with_lock(
                    c,
                    Box::new(|c, mut inner| {
                        assert_eq!(c.p.loader.owner, Some((c.t.tid, 2)));
                        inner.finish(c)?;
                        Flow::ret(7)
                    }),
                )?;
                assert!(matches!(nested, Flow::Ret(Value::Int(7))));
                assert_eq!(c.p.loader.owner, Some((c.t.tid, 1)));
                outer.finish(c)?;
                Flow::ret(9)
            }),
        )
        .unwrap();
        assert!(matches!(result, Flow::Ret(Value::Int(9))));
        assert!(c.p.loader.is_idle());
        assert!(c.p.loader.abandoned.borrow().is_empty());
    }
}

#[test]
fn abandoned_nested_guards_release_every_level_all_abis() {
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let mut c = context(p, &mut t, &TEST_API);
        let result = with_lock(
            &mut c,
            Box::new(|c, outer| {
                with_lock(
                    c,
                    Box::new(move |_, inner| {
                        drop(inner);
                        drop(outer);
                        Flow::void()
                    }),
                )
            }),
        )
        .unwrap();
        assert!(matches!(result, Flow::Ret(Value::None)));
        assert_eq!(c.p.loader.abandoned.borrow().len(), 2);
        let error = cleanup_abandoned(c.p, c.t).unwrap_err();
        assert!(error.contains("resource journals cleaned"));
        assert!(c.p.loader.is_idle(), "neither reentrant level may leak");
        assert!(c.p.loader.abandoned.borrow().is_empty());
    }
}

#[test]
fn distinct_thread_parks_and_guest_address_wakes_cannot_unlock_loader_all_abis() {
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut owner = p.threads.remove(&tid).unwrap();
        let other_tid = crate::user::windows::process::thread::create(p, 0, 0, 0, false).unwrap();
        let mut other = p.threads.remove(&other_tid).unwrap();
        let holding = with_lock(
            &mut context(p, &mut owner, &TEST_API),
            Box::new(|_, mut guard| {
                Flow::call(0, Vec::new(), move |c, _| {
                    guard.finish(c)?;
                    Flow::void()
                })
            }),
        )
        .unwrap();
        let waiting = with_lock(
            &mut context(p, &mut other, &TEST_API),
            Box::new(|c, mut guard| {
                guard.finish(c)?;
                Flow::ret(11)
            }),
        )
        .unwrap();
        let Flow::Block { wait, then: resume } = waiting else {
            panic!("second thread must park");
        };
        assert!(matches!(
            wait,
            Wait::Address {
                key: LOADER_WAIT_KEY,
                deadline: None
            }
        ));
        crate::user::windows::sync::on_block(p, other_tid, &wait).unwrap();
        p.sync.wake(u128::from(u64::MAX), usize::MAX);
        assert_eq!(
            crate::user::windows::sync::poll(p, other_tid, &wait, std::time::Instant::now(), false)
                .unwrap(),
            None
        );
        let Flow::Call {
            then: release_owner,
            ..
        } = holding
        else {
            panic!("owner continuation");
        };
        release_owner(&mut context(p, &mut owner, &TEST_API), 0).unwrap();
        assert_eq!(
            crate::user::windows::sync::poll(p, other_tid, &wait, std::time::Instant::now(), false)
                .unwrap(),
            Some(0)
        );
        crate::user::windows::sync::on_cancel(p, other_tid, &wait).unwrap();
        let result = resume(&mut context(p, &mut other, &TEST_API), 0).unwrap();
        assert!(matches!(result, Flow::Ret(Value::Int(11))));
        assert!(p.loader.is_idle());
    }
}

#[test]
fn module_handle_ex_invalid_flags_do_not_publish_or_acquire_all_abis() {
    let api = EXPORTS
        .iter()
        .find_map(|export| match &export.item {
            Item::Func(api) if export.name == "GetModuleHandleExW" => Some(api),
            _ => None,
        })
        .unwrap();
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        // ABI preparation independently follows the declared scalar signature.
        for flags in [3, 8, u32::MAX] {
            let sp = t.cpu.sp();
            let out = sp - 0x100;
            p.space
                .wptr(out, arch.ptr_size(), arch.ptr(u64::MAX))
                .unwrap();
            match arch {
                WinArch::X86 => {
                    p.space.w32(sp + 4, flags).unwrap();
                    p.space.w32(sp + 8, 0).unwrap();
                    p.space.w32(sp + 12, out as u32).unwrap();
                }
                WinArch::X64 => {
                    t.cpu.set_gpr(1, flags.into());
                    t.cpu.set_gpr(2, 0);
                    t.cpu.set_gpr(8, out);
                }
                WinArch::Arm64 => {
                    t.cpu.set_gpr(0, flags.into());
                    t.cpu.set_gpr(1, 0);
                    t.cpu.set_gpr(2, out);
                }
            }
            let mut c = context(p, &mut t, api);
            assert!(matches!(
                (api.imp)(&mut c).unwrap(),
                Flow::Ret(Value::Int(0))
            ));
            assert_eq!(c.last_error().unwrap(), ERROR_INVALID_PARAMETER);
            assert_eq!(c.read_ptr(out).unwrap(), 0);
            assert!(c.p.loader.is_idle());
            assert!(c.p.loader.abandoned.borrow().is_empty());
        }
    }
}
