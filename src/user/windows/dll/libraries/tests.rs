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
    process_for_profile(arch, false)
}

fn process_for_profile(arch: WinArch, gameos: bool) -> WindowsProcess {
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
    config.gameos = gameos;
    WindowsProcess::spawn(config).unwrap()
}

#[test]
fn gameos_peb_loader_lock_serializes_guest_and_loader_ownership() {
    for arch in WinArch::ALL {
        let mut process = process_for_profile(arch, true);
        let p = process.state_mut();
        let mut t = p.threads.pop_first().unwrap().1;
        let at = p.peb + crate::user::windows::layout::offsets(arch).peb_loader_lock;
        let lock = p.space.ptr(at, arch.ptr_size()).unwrap();
        assert_eq!(p.loader.guest_lock, Some(lock));

        let other = t.tid + 4;
        assert!(sync::cs_try_enter(p, lock, other).unwrap());
        let mut c = context(p, &mut t, &TEST_API);
        let Ok(Flow::Block {
            wait: Wait::CritSec { addr },
            then,
        }) = with_lock(
            &mut c,
            Box::new(move |c, mut guard| {
                assert!(c.p.loader.held_by(c.t.tid));
                assert_eq!(sync::cs_recursion(c.p, lock, c.t.tid).unwrap(), 1);
                guard.finish(c)?;
                Flow::void()
            }),
        )
        else {
            panic!("a foreign guest owner must block loader operations");
        };
        assert_eq!(addr, lock);
        let wait = Wait::CritSec { addr };
        sync::on_block(c.p, c.t.tid, &wait).unwrap();
        assert!(sync::cs_leave(c.p, lock, other).unwrap());
        assert!(
            sync::poll(
                c.p,
                c.t.tid,
                &wait,
                crate::host::time::Instant::now(),
                false
            )
            .unwrap()
            .is_some()
        );
        sync::on_cancel(c.p, c.t.tid, &wait).unwrap();
        then(&mut c, 0).unwrap();
        assert!(c.p.loader.is_idle());
        assert!(!sync::cs_owned_by(c.p, lock, c.t.tid).unwrap());
    }
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
        .chain(NTDLL_EXPORTS)
        .chain(IMAGE_OPTIONS_EXPORTS)
        .chain(super::super::security_descriptor::EXPORTS)
        .chain(super::super::splay::EXPORTS)
        .chain(super::super::kernel::PROCESS_SESSION_EXPORTS)
        .chain(API_SET_QUERY_EXPORTS)
        .chain(FILE_NAME_EXPORTS)
        .chain(LOAD_EX_EXPORTS)
        .chain(DELAY_EXPORTS)
        .chain(super::super::native::EXPORTS)
        .chain(super::super::native::TOKEN_PACKAGE_EXPORTS)
        .chain(super::super::native::WIN32_PROCESS_TOKEN_EXPORTS)
        .chain(super::super::native::USER_CLASSES_EXPORTS)
        .chain(super::super::native::WIN32_TOKEN_EXPORTS)
        .chain(super::super::native::WELL_KNOWN_SID_EXPORTS)
        .chain(super::super::threadpool::WORK_EXPORTS)
        .chain(super::super::threadpool::WAIT_EXPORTS)
        .chain(super::super::environment::EXPORTS)
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
            WinArch::X64 if index < 4 => t.cpu.set_gpr([1, 2, 8, 9][index], argument),
            WinArch::X64 => p.space.w64(sp + 8 + index as u64 * 8, argument).unwrap(),
            WinArch::Arm64 => t.cpu.set_gpr(index, argument),
        }
    }
    (api.imp)(&mut context(p, t, api))
}

#[test]
fn process_id_to_session_id_reads_the_guest_peb_all_abis() {
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let mut t = p.threads.pop_first().unwrap().1;
        let pid = u64::from(p.pid);
        let output = t.cpu.sp() - 0x100;
        let address = p.peb + crate::user::windows::layout::offsets(arch).peb_session_id;
        p.space.w32(address, 17).unwrap();
        assert!(matches!(
            invoke(p, &mut t, "ProcessIdToSessionId", &[pid, output]).unwrap(),
            Flow::Ret(Value::Int(1))
        ));
        assert_eq!(p.space.u32(output).unwrap(), 17);
        assert!(matches!(
            invoke(p, &mut t, "ProcessIdToSessionId", &[pid + 4, output]).unwrap(),
            Flow::Ret(Value::Int(0))
        ));
        assert_eq!(p.space.u32(output).unwrap(), 17);
    }
}

#[test]
fn create_well_known_sid_reports_size_and_writes_guest_sids_all_abis() {
    use crate::user::windows::nt::error::ERROR_INSUFFICIENT_BUFFER;
    use crate::user::windows::security::sid_text;

    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let mut t = p.threads.pop_first().unwrap().1;
        let output = t.cpu.sp() - 0x100;
        let size = output + 0x50;
        p.space.w32(size, 0).unwrap();
        assert!(matches!(
            invoke(p, &mut t, "CreateWellKnownSid", &[24, 0, 0, size]).unwrap(),
            Flow::Ret(Value::Int(0))
        ));
        assert_eq!(p.space.u32(size).unwrap(), 12);
        assert_eq!(
            context(p, &mut t, &TEST_API).last_error().unwrap(),
            ERROR_INSUFFICIENT_BUFFER
        );
        for (kind, domain, sid) in [
            (24, 0, "S-1-5-20"),
            (26, 0, "S-1-5-32-544"),
            (38, output, "S-1-5-32-544-500"),
        ] {
            p.space.w32(size, 68).unwrap();
            assert!(matches!(
                invoke(
                    p,
                    &mut t,
                    "CreateWellKnownSid",
                    &[kind, domain, output, size]
                )
                .unwrap(),
                Flow::Ret(Value::Int(1))
            ));
            let bytes = p
                .space
                .bytes(output, p.space.u32(size).unwrap() as usize)
                .unwrap();
            assert_eq!(sid_text(&bytes).as_deref(), Some(sid));
        }
    }
}

#[test]
fn image_options_read_selected_guest_dwords_all_abis() {
    use crate::user::windows::registry::{IfeoTree, Registry, Value as RegistryValue};

    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let mut t = p.threads.pop_first().unwrap().1;
        let descriptor = t.cpu.sp() - 0x200;
        let path = descriptor + 0x20;
        let option = descriptor + 0x80;
        let output = descriptor + 0xd0;
        let size = output + 4;
        let text: Vec<_> = "D:\\image.exe".encode_utf16().collect();
        p.space.put_wstr(path, &text).unwrap();
        p.space.w16(descriptor, (text.len() * 2) as u16).unwrap();
        p.space
            .w16(descriptor + 2, (text.len() * 2 + 2) as u16)
            .unwrap();
        p.space
            .wptr(descriptor + arch.ptr_size(), arch.ptr_size(), path)
            .unwrap();
        let option_name: Vec<_> = "RpcRuntimeConfigFlags".encode_utf16().collect();
        p.space.put_wstr(option, &option_name).unwrap();
        let arguments = [descriptor, option, 4, output, 4, size];
        assert!(matches!(
            invoke(p, &mut t, "LdrQueryImageFileExecutionOptions", &arguments).unwrap(),
            Flow::Ret(Value::Int(value)) if value == u64::from(STATUS_OBJECT_NAME_NOT_FOUND)
        ));
        p.registry = Registry::selected((0..=u16::MAX).collect(), vec![])
            .unwrap()
            .with_ifeo(IfeoTree {
                values: vec![],
                children: vec![(
                    "image.exe".encode_utf16().collect(),
                    IfeoTree {
                        values: vec![RegistryValue {
                            name: option_name,
                            kind: 4,
                            data: vec![1, 0, 0, 0],
                        }],
                        children: vec![],
                    },
                )],
            })
            .unwrap();
        assert!(matches!(
            invoke(p, &mut t, "LdrQueryImageFileExecutionOptions", &arguments).unwrap(),
            Flow::Ret(Value::Int(0))
        ));
        assert_eq!(p.space.u32(output).unwrap(), 1);
        assert_eq!(p.space.u32(size).unwrap(), 4);
    }
}

#[test]
fn absolute_security_descriptor_retains_guest_acl_and_ace_all_abis() {
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let mut t = p.threads.pop_first().unwrap().1;
        let acl = t.cpu.sp() - 0x200;
        let sid = acl + 0x40;
        let descriptor = acl + 0x60;
        let sid_bytes = [1, 1, 0, 0, 0, 0, 0, 5, 7, 0, 0, 0];
        p.space.wr(sid, &sid_bytes).unwrap();
        for (name, arguments) in [
            ("InitializeAcl", &[acl, 28, 2][..]),
            ("AddAccessAllowedAce", &[acl, 2, 0x8000_0000, sid][..]),
            ("InitializeSecurityDescriptor", &[descriptor, 1][..]),
            ("SetSecurityDescriptorDacl", &[descriptor, 1, acl, 0][..]),
        ] {
            assert!(matches!(
                invoke(p, &mut t, name, arguments).unwrap(),
                Flow::Ret(Value::Int(1))
            ));
        }
        assert_eq!(p.space.u16(acl + 4).unwrap(), 1);
        assert_eq!(p.space.u16(acl + 10).unwrap(), 20);
        assert_eq!(p.space.u32(acl + 12).unwrap(), 0x8000_0000);
        assert_eq!(p.space.bytes(acl + 16, 12).unwrap(), sid_bytes);
        assert_eq!(p.space.u16(descriptor + 2).unwrap(), 4);
        assert_eq!(
            p.space
                .ptr(descriptor + 4 * arch.ptr_size(), arch.ptr_size())
                .unwrap(),
            acl
        );
    }
}

#[test]
fn rtl_splay_repairs_parent_and_child_links_all_abis() {
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let mut t = p.threads.pop_first().unwrap().1;
        let width = arch.ptr_size();
        let grandparent = t.cpu.sp() - 0x400;
        let parent = grandparent + 3 * width;
        let node = parent + 3 * width;
        let subtree = node + 3 * width;
        for (address, links) in [
            (grandparent, [grandparent, parent, 0]),
            (parent, [grandparent, 0, node]),
            (node, [parent, 0, subtree]),
            (subtree, [node, 0, 0]),
        ] {
            for (index, value) in links.into_iter().enumerate() {
                p.space
                    .wptr(address + index as u64 * width, width, value)
                    .unwrap();
            }
        }
        assert!(matches!(
            invoke(p, &mut t, "RtlSplay", &[node]).unwrap(),
            Flow::Ret(Value::Int(address)) if address == node
        ));
        for (address, links) in [
            (node, [node, parent, grandparent]),
            (parent, [node, 0, 0]),
            (grandparent, [node, subtree, 0]),
            (subtree, [grandparent, 0, 0]),
        ] {
            for (index, value) in links.into_iter().enumerate() {
                assert_eq!(
                    p.space.ptr(address + index as u64 * width, width).unwrap(),
                    value
                );
            }
        }
        let root = grandparent - width;
        p.space.wptr(root, width, node).unwrap();
        assert!(matches!(
            invoke(p, &mut t, "RtlDeleteNoSplay", &[node, root]).unwrap(),
            Flow::Ret(Value::None)
        ));
        assert_eq!(p.space.ptr(root, width).unwrap(), parent);
        assert_eq!(p.space.ptr(parent, width).unwrap(), parent);
        assert_eq!(p.space.ptr(parent + 2 * width, width).unwrap(), grandparent);
        assert_eq!(p.space.ptr(grandparent, width).unwrap(), parent);
        assert!(matches!(
            invoke(p, &mut t, "RtlDelete", &[parent]).unwrap(),
            Flow::Ret(Value::Int(address)) if address == grandparent
        ));
        assert_eq!(p.space.ptr(grandparent, width).unwrap(), grandparent);
    }
}

#[test]
fn package_claims_leaves_unclaimed_identity_outputs_untouched_all_abis() {
    use crate::user::windows::nt::status::{
        STATUS_ACCESS_DENIED, STATUS_INVALID_HANDLE, STATUS_NO_TOKEN, STATUS_NOT_FOUND,
    };
    use crate::user::windows::objects::Object;
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let mut t = p.threads.pop_first().unwrap().1;
        t.cpu.set_sp(t.cpu.sp() - 0x100);
        let attributes = p.peb + 0x800;
        let claim = attributes + 8;
        let token = p.objects.create(Object::PrimaryToken);
        let opened = p.objects.open_access(token, false, 8).unwrap();
        let denied = p.objects.open_access(token, false, 0).unwrap();
        for (handle, status) in [
            (arch.ptr(u64::MAX - 3), STATUS_NOT_FOUND),
            (arch.ptr(u64::MAX - 5), STATUS_NOT_FOUND),
            (arch.ptr(u64::MAX - 4), STATUS_NO_TOKEN),
            (u64::from(opened), STATUS_NOT_FOUND),
            (u64::from(denied), STATUS_ACCESS_DENIED),
            (0, STATUS_INVALID_HANDLE),
        ] {
            p.space.w64(attributes, u64::MAX).unwrap();
            p.space.w64(claim, u64::MAX).unwrap();
            let result = invoke(
                p,
                &mut t,
                "RtlQueryPackageClaims",
                &[handle, 0, 0, 0, 0, 0, claim, attributes],
            );
            assert!(
                matches!(result, Ok(Flow::Ret(Value::Int(value))) if value == u64::from(status))
            );
            assert_eq!(p.space.u64(attributes).unwrap(), 0);
            assert_eq!(p.space.u64(claim).unwrap(), u64::MAX);
        }
    }
}

#[test]
fn gameos_open_process_token_preserves_portable_elevation_state() {
    let mut process = process_for_profile(WinArch::X64, true);
    let p = process.state_mut();
    let mut t = p.threads.pop_first().unwrap().1;
    t.cpu.set_sp(t.cpu.sp() - 0x100);
    let out = p.peb + 0x800;
    let returned = out + 8;
    assert!(matches!(
        invoke(p, &mut t, "OpenProcessToken", &[u64::MAX, 8, out]),
        Ok(Flow::Ret(Value::Int(1)))
    ));
    let token = p.space.u64(out).unwrap();
    assert_eq!(p.objects.access(token), Some(8));
    assert!(matches!(
        invoke(
            p,
            &mut t,
            "GetTokenInformation",
            &[token, 20, out, 4, returned]
        ),
        Ok(Flow::Ret(Value::Int(1)))
    ));
    assert_eq!(p.space.u32(out).unwrap(), 0);
    assert_eq!(p.space.u32(returned).unwrap(), 4);
    p.space.w64(out, u64::MAX).unwrap();
    assert!(matches!(
        invoke(
            p,
            &mut t,
            "RegOpenUserClassesRoot",
            &[token, 0, 0x20019, out]
        ),
        Ok(Flow::Ret(Value::Int(2)))
    ));
    assert_eq!(p.space.u64(out).unwrap(), 0);
    p.space.w64(out, u64::MAX).unwrap();
    assert!(matches!(
        invoke(
            p,
            &mut t,
            "RegOpenUserClassesRoot",
            &[token, 1, 0x20019, out]
        ),
        Ok(Flow::Ret(Value::Int(87)))
    ));
    assert_eq!(p.space.u64(out).unwrap(), u64::MAX);
}

#[test]
fn portable_token_security_attributes_report_empty_versioned_record_all_abis() {
    use crate::user::windows::nt::status::STATUS_BUFFER_TOO_SMALL;
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let mut t = p.threads.pop_first().unwrap().1;
        t.cpu.set_sp(t.cpu.sp() - 0x100);
        let output = p.peb + 0x800;
        let length = output + 32;
        let token = arch.ptr(u64::MAX - 3);
        let required = 8 + arch.ptr_size();
        for (buffer, size, status) in [(0, 0, STATUS_BUFFER_TOO_SMALL), (output, 24, 0)] {
            p.space.wr(output, &[0xa5; 24]).unwrap();
            let result = invoke(
                p,
                &mut t,
                "NtQueryInformationToken",
                &[token, 39, buffer, size, length],
            );
            assert!(
                matches!(result, Ok(Flow::Ret(Value::Int(value))) if value == u64::from(status))
            );
            assert_eq!(u64::from(p.space.u32(length).unwrap()), required);
            if status == 0 {
                assert_eq!(p.space.u64(output).unwrap(), 1);
                assert_eq!(p.space.ptr(output + 8, arch.ptr_size()).unwrap(), 0);
                assert_eq!(p.space.u8(output + required).unwrap(), 0xa5);
            } else {
                assert_eq!(p.space.u8(output).unwrap(), 0xa5);
            }
        }
    }
}

#[test]
fn thread_pool_work_preserves_registration_until_close_all_abis() {
    use crate::user::windows::objects::Object;
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let mut t = p.threads.pop_first().unwrap().1;
        let Ok(Flow::Ret(Value::Int(work))) =
            invoke(p, &mut t, "CreateThreadpoolWork", &[0x1234, 0x5678, 0])
        else {
            panic!("expected a work registration");
        };
        assert!(matches!(
            p.objects.get(work),
            Some(Object::ThreadpoolWork {
                callback: 0x1234,
                context: 0x5678,
                pending: 0,
            })
        ));
        invoke(p, &mut t, "WaitForThreadpoolWorkCallbacks", &[work, 0]).unwrap();
        invoke(p, &mut t, "SubmitThreadpoolWork", &[work]).unwrap();
        assert!(matches!(
            invoke(p, &mut t, "WaitForThreadpoolWorkCallbacks", &[work, 0]),
            Ok(Flow::Block { .. })
        ));
        invoke(p, &mut t, "WaitForThreadpoolWorkCallbacks", &[work, 1]).unwrap();
        assert!(p.sync.pool_workers.is_empty());

        let id = p.objects.id(work).unwrap();
        invoke(p, &mut t, "SubmitThreadpoolWork", &[work]).unwrap();
        let tid = *p.sync.pool_workers.keys().next().unwrap();
        let mut worker = p.threads.remove(&tid).unwrap();
        let args = super::super::threadpool::work_arguments(p, tid, worker.param).unwrap();
        assert_ne!(args[0], 0);
        assert_eq!(&args[1..], &[0x5678, work]);
        let event = p.objects.create(Object::Event {
            manual: true,
            signaled: 0,
        });
        let event_handle = u64::from(p.objects.open_access(event, false, 2).unwrap());
        invoke(
            p,
            &mut worker,
            "SetEventWhenCallbackReturns",
            &[args[0], event_handle],
        )
        .unwrap();
        assert!(matches!(
            p.objects.obj(event),
            Some(Object::Event { signaled: 0, .. })
        ));
        invoke(p, &mut t, "CloseThreadpoolWork", &[work]).unwrap();
        assert!(p.objects.get(work).is_none());
        assert!(p.objects.obj(id).is_some());
        super::super::threadpool::retire_work(p, tid, true);
        assert!(p.objects.obj(id).is_none());
        assert!(matches!(
            p.objects.obj(event),
            Some(Object::Event { signaled: 1, .. })
        ));
        crate::user::windows::process::thread::destroy(p, worker, 0);
    }
}

#[test]
fn thread_pool_event_wait_queues_one_callback_per_arm_all_abis() {
    use super::super::threadpool::{poll_event_waits, retire_work, work_arguments};
    use crate::user::windows::objects::Object;
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let mut t = p.threads.pop_first().unwrap().1;
        let Ok(Flow::Ret(Value::Int(wait))) =
            invoke(p, &mut t, "CreateThreadpoolWait", &[0x1234, 0x5678, 0])
        else {
            panic!("expected a wait registration");
        };
        let event = p.objects.create(Object::Event {
            manual: false,
            signaled: 1,
        });
        let handle = u64::from(p.objects.open_access(event, false, 0x0010_0000).unwrap());
        invoke(p, &mut t, "SetThreadpoolWait", &[wait, handle, 0]).unwrap();
        poll_event_waits(p).unwrap();
        poll_event_waits(p).unwrap();
        assert_eq!(p.sync.pool_workers.len(), 1);
        assert!(p.sync.pool_waits.is_empty());
        assert!(matches!(
            p.objects.obj(event),
            Some(Object::Event { signaled: 0, .. })
        ));
        assert!(matches!(
            invoke(p, &mut t, "WaitForThreadpoolWaitCallbacks", &[wait, 0]),
            Ok(Flow::Block { .. })
        ));
        let tid = *p.sync.pool_workers.keys().next().unwrap();
        let worker = p.threads.remove(&tid).unwrap();
        let args = work_arguments(p, tid, worker.param).unwrap();
        assert_ne!(args[0], 0);
        assert_eq!(&args[1..], &[0x5678, wait, 0]);
        retire_work(p, tid, true);
        crate::user::windows::process::thread::destroy(p, worker, 0);
        invoke(p, &mut t, "SetThreadpoolWait", &[wait, handle, 0]).unwrap();
        p.objects.close(handle).unwrap();
        assert!(p.objects.obj(event).is_some());
        invoke(p, &mut t, "CloseThreadpoolWait", &[wait]).unwrap();
        assert!(p.objects.obj(event).is_none());
        assert!(p.sync.pool_waits.is_empty());
    }
}

#[test]
fn api_set_query_uses_counted_guest_names_and_single_byte_results() {
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let mut t = p.threads.pop_first().unwrap().1;
        let descriptor = p.peb + 0x800;
        let buffer = descriptor + 32;
        let out = descriptor + 200;
        p.space
            .wptr(descriptor + arch.ptr_size(), arch.ptr_size(), buffer)
            .unwrap();
        for (name, expected) in [
            ("API-MS-WIN-EVENTING-PROVIDER-L1-1-0", 1u8),
            ("ext-ms-win-ntuser-private-l1-1-0", 0),
            ("kernelbase.dll", 0),
        ] {
            let text: Vec<u16> = name.encode_utf16().collect();
            let bytes = (text.len() * 2) as u16;
            p.space.w16(descriptor, bytes).unwrap();
            p.space.w16(descriptor + 2, bytes).unwrap();
            p.space.put_wunits(buffer, &text).unwrap();
            p.space.w16(out, 0xfeed).unwrap();
            let result = invoke(p, &mut t, "ApiSetQueryApiSetPresence", &[descriptor, out]);
            assert!(matches!(result, Ok(Flow::Ret(Value::Int(0)))));
            assert_eq!(p.space.u16(out).unwrap(), 0xfe00 | u16::from(expected));
        }
        p.space.w16(descriptor, 1).unwrap();
        let result = invoke(p, &mut t, "ApiSetQueryApiSetPresence", &[descriptor, out]);
        assert!(
            matches!(result, Ok(Flow::Ret(Value::Int(status))) if status == u64::from(STATUS_INVALID_PARAMETER))
        );
        assert_eq!(p.space.u16(out).unwrap(), 0xfe00);
    }
}

#[test]
fn resolve_delay_import_initializes_dependency_and_publishes_pointer_slots_all_abis() {
    use crate::user::image::pe::DataDirectory;

    for arch in WinArch::ALL {
        let mut process = dynamic_process(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let base = p.modules.exe().base;
        let descriptor = 0x3100;
        let name = 0x3140;
        let module = 0x3160;
        let thunk = 0x3170;
        let lookup = 0x3190;
        let export = 0x31b0;
        let width = arch.ptr_size();
        p.modules.list[0].delay_imports = DataDirectory {
            rva: descriptor,
            size: 64,
        };
        for (index, field) in [1, name, module, thunk, lookup, 0, 0, 0]
            .into_iter()
            .enumerate()
        {
            p.space
                .w32(base + u64::from(descriptor) + index as u64 * 4, field)
                .unwrap();
        }
        let [descriptor, name, module, thunk, lookup, export] =
            [descriptor, name, module, thunk, lookup, export].map(|rva| base + u64::from(rva));
        p.space.put_cstr(name, b"leaf.dll").unwrap();
        p.space.put_cstr(export + 2, b"LeafReady").unwrap();
        p.space.wptr(lookup, width, export - base).unwrap();
        p.space.wptr(thunk, width, 0x1234).unwrap();
        let args = [base, descriptor, 0, 0, thunk, 0];

        let mut invalid = args;
        invalid[4] = thunk + width;
        let result = invoke(p, &mut t, "ResolveDelayLoadedAPI", &invalid).unwrap();
        assert!(matches!(result, Flow::Ret(Value::Int(0))));
        assert_eq!(p.modules.by_name("leaf.dll"), None);
        assert_eq!(p.space.ptr(module, width).unwrap(), 0);
        assert_eq!(p.space.ptr(thunk, width).unwrap(), 0x1234);

        let api = match &DELAY_EXPORTS[0].item {
            Item::Func(api) => api,
            _ => unreachable!(),
        };
        let mut result = invoke(p, &mut t, "ResolveDelayLoadedAPI", &args).unwrap();
        let index = p.modules.by_name("leaf.dll").unwrap();
        let mut callbacks = 0;
        while let Flow::Call { then, .. } = result {
            assert_eq!(p.space.ptr(module, width).unwrap(), 0);
            assert_eq!(p.space.ptr(thunk, width).unwrap(), 0x1234);
            callbacks += 1;
            result = then(&mut context(p, &mut t, api), 1).unwrap();
        }
        assert!(callbacks > 0);
        let expected = loader::lookup(p, index, &SymRef::Ordinal(1))
            .unwrap()
            .unwrap();
        assert!(matches!(result, Flow::Ret(Value::Int(address)) if address == expected));
        assert_eq!(p.space.ptr(thunk, width).unwrap(), expected);
        assert_eq!(
            p.space.ptr(module, width).unwrap(),
            p.modules.list[index].base
        );
        assert_eq!(p.modules.list[index].load_count, 0);
        assert!(p.modules.list[index].initialized);
        assert!(p.loader.is_idle());
    }
}

#[test]
fn extended_load_restricts_root_and_dependency_search_for_all_guest_abis() {
    for arch in WinArch::ALL {
        let mut process = dynamic_process(arch);
        let p = process.state_mut();
        let app = p.modules.exe().path.rsplit_once('\\').unwrap().0.to_owned();
        let system = loader::system_dir(arch);
        let fixture_dir = p.cfg.exe_host_path.parent().unwrap().to_path_buf();
        let config = std::sync::Arc::make_mut(&mut p.cfg);
        config.host_filesystem = false;
        config.guest_image_path = Some(format!("{app}\\dynamic.exe"));
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let text = t.cpu.sp() - 0x100;
        let supply = |dir: &str, module: &str| {
            let data = std::fs::read(fixture_dir.join(module)).unwrap();
            (format!("{dir}\\{module}").to_ascii_lowercase(), data.into())
        };
        std::sync::Arc::make_mut(&mut p.cfg).supplied_dlls.extend([
            supply(&app, "root.dll"),
            supply(system, "root.dll"),
            supply(&app, "observer.dll"),
            supply(&app, "leaf.dll"),
        ]);
        p.space
            .put_wstr(text, &"root.dll".encode_utf16().collect::<Vec<_>>())
            .unwrap();
        for (reserved, flags, expected) in [
            (1, 0x800, ERROR_INVALID_PARAMETER),
            (0, 2, ERROR_NOT_SUPPORTED),
            (0, 0x800, ERROR_MOD_NOT_FOUND),
        ] {
            let flow = invoke(p, &mut t, "LoadLibraryExW", &[text, reserved, flags]).unwrap();
            assert!(matches!(flow, Flow::Ret(Value::Int(0))));
            assert_eq!(
                context(p, &mut t, &TEST_API).last_error().unwrap(),
                expected
            );
            assert_eq!(p.modules.by_name("root.dll"), None);
            assert!(p.loader.is_idle());
        }

        // Rollback restores ordinary lookup after a restricted bind failure.
        p.space.put_cstr(text, b"root.dll").unwrap();
        let flow = invoke(p, &mut t, "LoadLibraryA", &[text]).unwrap();
        assert!(matches!(flow, Flow::Call { .. }));
        let index = p.modules.by_name("root.dll").unwrap();
        assert_eq!(p.modules.list[index].path, format!("{app}\\root.dll"));
        drop(flow);
        cleanup_abandoned(p, &mut t).unwrap_err();

        std::sync::Arc::make_mut(&mut p.cfg).supplied_dlls.extend([
            supply(system, "observer.dll"),
            supply(system, "leaf.dll"),
            supply(system, "data.exe"),
            supply(&app, "data.exe"),
        ]);
        let flow = invoke(p, &mut t, "LoadLibraryExA", &[text, 0, 0xa00]).unwrap();
        assert!(matches!(flow, Flow::Call { .. }));
        let index = p.modules.by_name("root.dll").unwrap();
        assert_eq!(p.modules.list[index].path, format!("{app}\\root.dll"));
        drop(flow);
        cleanup_abandoned(p, &mut t).unwrap_err();

        p.space.put_cstr(text, b"data.exe").unwrap();
        let flow = invoke(p, &mut t, "LoadLibraryExA", &[text, 0, 0x800]).unwrap();
        let index = p.modules.by_name("data.exe").unwrap();
        assert!(matches!(flow, Flow::Ret(Value::Int(base)) if base == p.modules.list[index].base));
        assert_eq!(p.modules.list[index].path, format!("{system}\\data.exe"));
    }
}

#[test]
fn guest_environment_queries_share_case_insensitive_wide_and_ansi_values() {
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let name = t.cpu.sp() - 0x300;
        let out = name + 128;
        p.space.put_cstr(name, b"sYsTeMrOoT").unwrap();
        let small = invoke(p, &mut t, "GetEnvironmentVariableA", &[name, out, 2]).unwrap();
        assert!(matches!(small, Flow::Ret(Value::Int(11))));
        let result = invoke(p, &mut t, "GetEnvironmentVariableA", &[name, out, 11]).unwrap();
        assert!(matches!(result, Flow::Ret(Value::Int(10))));
        assert_eq!(p.space.cstr(out, 11).unwrap(), br"C:\Windows");
        p.space
            .put_wstr(name, &"SystemRoot".encode_utf16().collect::<Vec<_>>())
            .unwrap();
        let result = invoke(p, &mut t, "GetEnvironmentVariableW", &[name, out, 11]).unwrap();
        assert!(matches!(result, Flow::Ret(Value::Int(10))));
        assert_eq!(
            String::from_utf16(&p.space.wstr(out, 11).unwrap()).unwrap(),
            r"C:\Windows"
        );
        p.space.put_cstr(name, b"RAX_MISSING_ENV").unwrap();
        let result = invoke(p, &mut t, "GetEnvironmentVariableA", &[name, out, 11]).unwrap();
        assert!(matches!(result, Flow::Ret(Value::Int(0))));
        assert_eq!(
            context(p, &mut t, &TEST_API).last_error().unwrap(),
            ERROR_ENVVAR_NOT_FOUND
        );
    }
}

#[test]
fn module_file_name_reports_guest_path_and_terminates_truncation() {
    for arch in WinArch::ALL {
        let mut process = process(arch);
        let p = process.state_mut();
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        let out = t.cpu.sp() - 0x600;
        let path: Vec<_> = p.modules.list[0].path.encode_utf16().collect();
        let size = path.len() as u64 + 1;
        let main = p.modules.list[0].base;
        for module in [0, main] {
            let result = invoke(p, &mut t, "GetModuleFileNameW", &[module, out, size]).unwrap();
            assert!(matches!(result, Flow::Ret(Value::Int(n)) if n == size - 1));
            assert_eq!(p.space.wstr(out, size as usize).unwrap(), path);
        }
        let result = invoke(p, &mut t, "GetModuleFileNameW", &[main, out, 3]).unwrap();
        assert!(matches!(result, Flow::Ret(Value::Int(3))));
        assert_eq!(p.space.wstr(out, 3).unwrap(), path[..2]);
        assert_eq!(p.space.u16(out + 4).unwrap(), 0);
        assert_eq!(
            context(p, &mut t, &TEST_API).last_error().unwrap(),
            ERROR_INSUFFICIENT_BUFFER
        );
        let result = invoke(p, &mut t, "GetModuleFileNameW", &[main + 1, out, size]).unwrap();
        assert!(matches!(result, Flow::Ret(Value::Int(0))));
        assert_eq!(
            context(p, &mut t, &TEST_API).last_error().unwrap(),
            ERROR_MOD_NOT_FOUND
        );
        let ansi = crate::user::windows::dll::crt::startup::encode_process_ansi(&path);
        let capacity = ansi.len() as u64 + 1;
        let result = invoke(p, &mut t, "GetModuleFileNameA", &[0, out, capacity]).unwrap();
        assert!(matches!(result, Flow::Ret(Value::Int(n)) if n == capacity - 1));
        assert_eq!(p.space.cstr(out, capacity as usize).unwrap(), ansi);
        let result = invoke(p, &mut t, "GetModuleFileNameA", &[main, out, 3]).unwrap();
        assert!(matches!(result, Flow::Ret(Value::Int(3))));
        assert_eq!(p.space.cstr(out, 3).unwrap(), ansi[..2]);
        assert_eq!(p.space.u8(out + 2).unwrap(), 0);
        assert_eq!(
            context(p, &mut t, &TEST_API).last_error().unwrap(),
            ERROR_INSUFFICIENT_BUFFER
        );
    }
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
        loader::attach_started(p, index, true).unwrap();
        let pin = invoke(p, &mut t, "GetModuleHandleExW", &[5, base, out]).unwrap();
        assert!(matches!(pin, Flow::Ret(Value::Int(1))));
        assert_eq!(p.space.ptr(out, arch.ptr_size()).unwrap(), base);
        loader::attach_succeeded(p, index).unwrap();
        assert_eq!(p.modules.list[index].load_count, u32::MAX);
    }
}

#[test]
fn dynamic_dll_attach_pins_become_permanent_only_on_commit_all_abis() {
    for arch in WinArch::ALL {
        for commit in [false, true] {
            let mut process = dynamic_process(arch);
            let p = process.state_mut();
            let tid = *p.threads.keys().next().unwrap();
            let mut t = p.threads.remove(&tid).unwrap();
            let plan = loader::begin_load(p, &mut t, "leaf.dll").unwrap();
            let index = plan.root;
            let base = p.modules.list[index].base;
            let out = t.cpu.sp() - 0x100;
            loader::attach_started(p, index, true).unwrap();
            let pin = invoke(p, &mut t, "GetModuleHandleExW", &[5, base, out]).unwrap();
            assert!(matches!(pin, Flow::Ret(Value::Int(1))));
            assert_eq!(p.space.ptr(out, arch.ptr_size()).unwrap(), base);
            assert_eq!(p.modules.list[index].load_count, 1);
            loader::attach_succeeded(p, index).unwrap();
            if commit {
                loader::commit_load(p, plan.id).unwrap();
                assert_eq!(p.modules.list[index].load_count, u32::MAX);
                let unload = invoke(p, &mut t, "FreeLibrary", &[base]).unwrap();
                assert!(matches!(unload, Flow::Ret(Value::Int(1))));
                assert_eq!(p.modules.by_base(base), Some(index));
            } else {
                let failure = LoadError {
                    status: STATUS_DLL_INIT_FAILED,
                    message: "test rejected attach transaction".into(),
                };
                assert_eq!(
                    loader::begin_rollback(p, plan.id, failure, None).unwrap(),
                    vec![index]
                );
                loader::detach_completed(p, index).unwrap();
                loader::finish_rollback(p, &mut t, plan.id).unwrap();
                assert_eq!(p.modules.by_base(base), None);
            }
            assert!(p.loader.is_idle());
        }
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
        let static_tls = p.modules.list[leaf.root].base;
        let native = invoke(p, &mut t, "LdrDisableThreadCalloutsForDll", &[static_tls]).unwrap();
        assert!(matches!(native, Flow::Ret(Value::Int(0))));
        assert!(p.modules.list[leaf.root].thread_calls);
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
            crate::user::windows::sync::poll(
                p,
                other_tid,
                &wait,
                crate::host::time::Instant::now(),
                false
            )
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
            crate::user::windows::sync::poll(
                p,
                other_tid,
                &wait,
                crate::host::time::Instant::now(),
                false
            )
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
