use super::*;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiErr, Value as Return};
use crate::user::windows::loader::{self, SymRef};
use crate::user::windows::memory::{mem, prot};
use crate::user::windows::nt::error::*;
use crate::user::windows::objects::Object;
use crate::user::windows::process::{Proc, Thread, WindowsConfig, WindowsProcess};
use crate::user::windows::registry::{IFEO_KEY, KeyTree, Registry, Value};
use crate::user::windows::traps::Trap;

fn each_arch(test: impl Fn(&mut Proc, &mut Thread, u64)) {
    for arch in WinArch::ALL {
        let image = match arch {
            WinArch::X86 => include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/user/windows/bin/x86/smoke.exe"
            ))
            .as_slice(),
            WinArch::X64 => include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/user/windows/bin/x64/smoke.exe"
            ))
            .as_slice(),
            WinArch::Arm64 => include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/user/windows/bin/arm64/smoke.exe"
            ))
            .as_slice(),
        };
        let mut config = WindowsConfig::new("reg-test.exe", vec![]);
        config.seed = Some(1);
        config.arena_bytes = 64 << 20;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let p = process.state_mut();
        assert_eq!(arch, p.arch);
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
        t.cpu.set_sp(t.cpu.sp() - 128);
        let data =
            p.vm.allocate(
                None,
                2 * PAGE_SIZE,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE,
            )
            .unwrap()
            .0;
        p.vm.protect(data + PAGE_SIZE, PAGE_SIZE, prot::NOACCESS)
            .unwrap();
        test(p, &mut t, data);
    }
}

// Resolve the public name through its actual API-set contract before calling
// the registered HLE implementation with the guest's ABI argument locations.
fn call(p: &mut Proc, t: &mut Thread, name: &str, args: &[u64]) -> Result<u32, ApiErr> {
    let contract = if name == "RegOpenKeyW" {
        "api-ms-win-core-registry-l2-1-0.dll"
    } else {
        "api-ms-win-core-registry-l1-1-0.dll"
    };
    let host = loader::load_dll(p, contract).unwrap();
    let addr = loader::lookup(p, host, &SymRef::Name(name.as_bytes().to_vec(), None))
        .unwrap()
        .unwrap();
    let Some(Trap::Entry(api)) = p.traps.lookup(addr) else {
        panic!("{name} did not bind to a function")
    };
    assert_eq!(api.args.len(), args.len());
    let sp = t.cpu.sp();
    for (i, &arg) in args.iter().enumerate() {
        match p.arch {
            WinArch::X86 => p.space.w32(sp + 4 + i as u64 * 4, arg as u32).unwrap(),
            WinArch::X64 if i < 4 => t.cpu.set_gpr([1, 2, 8, 9][i], arg),
            WinArch::X64 => p.space.w64(sp + 8 + i as u64 * 8, arg).unwrap(),
            WinArch::Arm64 => t.cpu.set_gpr(i, arg),
        }
    }
    let flow = (api.imp)(&mut Ctx {
        p,
        t,
        api,
        entry_pc: addr,
        entry_sp: sp,
        ret_addr: 0,
        cursor: sp,
    })?;
    let Flow::Ret(Return::Int(code)) = flow else {
        panic!("{name} did not return LSTATUS")
    };
    Ok(u32::try_from(code).unwrap())
}

fn check(p: &mut Proc, t: &mut Thread, name: &str, args: &[u64], expected: u32) {
    assert_eq!(call(p, t, name, args).unwrap(), expected, "{name}");
}
fn snapshot() -> Registry {
    let upcase = (0..=u16::MAX)
        .map(|u| if (97..=122).contains(&u) { u - 32 } else { u })
        .collect();
    let tree = KeyTree {
        values: vec![],
        children: vec![(
            "Example".encode_utf16().collect(),
            KeyTree {
                values: vec![
                    Value {
                        name: vec![],
                        kind: 3,
                        data: vec![0xba, 0xdc, 0xfe],
                    },
                    Value {
                        name: "Options".encode_utf16().collect(),
                        kind: 4,
                        data: 27u32.to_le_bytes().to_vec(),
                    },
                    Value {
                        name: "Label".encode_utf16().collect(),
                        kind: 1,
                        data: vec![b'X', 0],
                    },
                ],
                children: vec![],
            },
        )],
    };
    Registry::selected(upcase, vec![])
        .unwrap()
        .with_ifeo(tree)
        .unwrap()
}

#[test]
fn gets_typed_snapshot_values_and_zeros_failures() {
    each_arch(|p, t, base| {
        let root = p.arch.ptr(0xffff_ffff_8000_0002);
        let name = base + 512;
        let output = base + 768;
        let kind = output + 32;
        let size = kind + 4;
        let subkey = format!(
            "{}\\Example",
            IFEO_KEY.strip_prefix(r"\Registry\Machine\").unwrap()
        );
        p.space
            .put_wstr(base, &subkey.encode_utf16().collect::<Vec<_>>())
            .unwrap();
        p.space
            .put_wstr(name, &"Options".encode_utf16().collect::<Vec<_>>())
            .unwrap();
        let args = [
            root,
            base,
            name,
            u64::from(RRF_ZEROONFAILURE | 0x18),
            kind,
            output,
            size,
        ];
        let handles = p.objects.handle_count();
        p.space.w32(size, 4).unwrap();
        p.space.w32(output, u32::MAX).unwrap();
        check(p, t, "RegGetValueW", &args, ERROR_FILE_NOT_FOUND);
        assert_eq!(p.space.u32(output).unwrap(), 0);

        p.registry = snapshot();
        p.space.w32(size, 4).unwrap();
        check(p, t, "RegGetValueW", &args, 0);
        assert_eq!(p.space.u32(output).unwrap(), 27);
        assert_eq!(p.space.u32(kind).unwrap(), 4);

        p.space.w32(size, 2).unwrap();
        p.space.w32(output, u32::MAX).unwrap();
        check(p, t, "RegGetValueW", &args, ERROR_MORE_DATA);
        assert_eq!(p.space.u32(output).unwrap(), 0xffff_0000);
        assert_eq!(p.space.u32(size).unwrap(), 4);

        p.space
            .put_wstr(name, &"Label".encode_utf16().collect::<Vec<_>>())
            .unwrap();
        check(p, t, "RegGetValueW", &args, ERROR_UNSUPPORTED_TYPE);
        let mut args = args;
        args[3] = 2; // RRF_RT_REG_SZ
        check(p, t, "RegGetValueW", &args, 0);
        assert_eq!(p.space.u32(output).unwrap(), u32::from(b'X'));
        assert_eq!(p.space.u32(size).unwrap(), 4);
        assert_eq!(p.objects.handle_count(), handles);
    });
}

#[test]
fn async_registry_notification_retains_and_signals_the_guest_event_on_key_close() {
    each_arch(|p, t, buf| {
        let hklm = p.arch.ptr(0xffff_ffff_8000_0002);
        p.registry = snapshot();
        let path = IFEO_KEY.strip_prefix(r"\Registry\Machine\").unwrap();
        p.space
            .put_wstr(buf, &path.encode_utf16().collect::<Vec<_>>())
            .unwrap();
        let out = buf + 512;
        check(p, t, "RegOpenKeyExW", &[hklm, buf, 0, 0x10, out], 0);
        let key = p.space.ptr(out, p.arch.ptr_size()).unwrap();
        let event = p.objects.create(Object::Event {
            manual: true,
            signaled: 1,
        });
        let handle = u64::from(p.objects.open_access(event, false, 2).unwrap());
        let flags = u64::from(key_notify::THREAD_AGNOSTIC | 1);
        check(
            p,
            t,
            "RegNotifyChangeKeyValue",
            &[key, 1, flags, handle, 1],
            0,
        );
        assert!(matches!(
            p.objects.obj(event),
            Some(Object::Event { signaled: 0, .. })
        ));
        check(p, t, "RegCloseKey", &[key], 0);
        crate::user::windows::process::registry_notify::finish(p, t).unwrap();
        assert!(matches!(
            p.objects.obj(event),
            Some(Object::Event { signaled: 1, .. })
        ));
    });
}

#[test]
fn wide_registry_contracts_open_query_and_close_guest_snapshot_keys() {
    each_arch(|p, t, buf| {
        let hklm = p.arch.ptr(0xffff_ffff_8000_0002);
        let name = buf + 64;
        let payload = buf + 512;
        let kind = buf + 544;
        let size = buf + 548;
        let out = buf;
        let base_handles = p.objects.handle_count();
        let path = IFEO_KEY.strip_prefix(r"\Registry\Machine\").unwrap();
        p.space
            .put_wstr(
                name,
                &path.to_lowercase().encode_utf16().collect::<Vec<_>>(),
            )
            .unwrap();
        check(
            p,
            t,
            "RegOpenKeyW",
            &[hklm, name, out],
            ERROR_FILE_NOT_FOUND,
        );
        p.registry = snapshot();
        check(p, t, "RegOpenKeyW", &[hklm, name, out], 0);
        let root = p.space.ptr(out, p.arch.ptr_size()).unwrap();
        check(p, t, "RegOpenKeyExW", &[root, 0, 0, 1, out], 0);
        let reopened = p.space.ptr(out, p.arch.ptr_size()).unwrap();
        assert_ne!(root, reopened);
        assert_eq!(p.objects.access(reopened), Some(1));
        check(p, t, "RegCloseKey", &[reopened], 0);
        p.space.put_cstr(name, b"eXample").unwrap();
        check(p, t, "RegOpenKeyExA", &[root, name, 0, 1, out], 0);
        let ansi = p.space.ptr(out, p.arch.ptr_size()).unwrap();
        assert_eq!(p.objects.access(ansi), Some(1));
        check(p, t, "RegCloseKey", &[ansi], 0);
        p.space
            .put_wstr(name, &"missing".encode_utf16().collect::<Vec<_>>())
            .unwrap();
        check(
            p,
            t,
            "RegOpenKeyW",
            &[root, name, out],
            ERROR_FILE_NOT_FOUND,
        );
        p.space
            .put_wstr(name, &"example".encode_utf16().collect::<Vec<_>>())
            .unwrap();
        check(p, t, "RegOpenKeyW", &[root, name, out], 0);
        let child = p.space.ptr(out, p.arch.ptr_size()).unwrap();
        assert_ne!(root, child);
        check(p, t, "RegCloseKey", &[root], 0);
        check(p, t, "RegOpenKeyW", &[child, 0, out], 0);
        assert_eq!(p.space.ptr(out, p.arch.ptr_size()).unwrap(), child);
        check(p, t, "RegQueryValueExW", &[child, 0, 0, kind, 0, size], 0);
        assert_eq!(p.space.u32(kind).unwrap(), 3);
        assert_eq!(p.space.u32(size).unwrap(), 3);
        p.space.w32(size, 2).unwrap();
        p.space.w32(payload, u32::MAX).unwrap();
        check(
            p,
            t,
            "RegQueryValueExW",
            &[child, 0, 0, kind, payload, size],
            ERROR_MORE_DATA,
        );
        assert_eq!(p.space.u32(size).unwrap(), 3);
        assert_eq!(p.space.u32(payload).unwrap(), u32::MAX);
        check(
            p,
            t,
            "RegQueryValueExW",
            &[child, 0, 0, kind, payload, size],
            0,
        );
        assert_eq!(p.space.bytes(payload, 4).unwrap(), [0xba, 0xdc, 0xfe, 0xff]);
        p.space
            .put_wstr(name, &"OPTIONS".encode_utf16().collect::<Vec<_>>())
            .unwrap();
        p.space.w32(size, 4).unwrap();
        check(
            p,
            t,
            "RegQueryValueExW",
            &[child, name, 0, kind, payload, size],
            0,
        );
        assert_eq!(
            (p.space.u32(kind).unwrap(), p.space.u32(payload).unwrap()),
            (4, 27)
        );
        p.space
            .put_wstr(name, &"absent".encode_utf16().collect::<Vec<_>>())
            .unwrap();
        check(
            p,
            t,
            "RegQueryValueExW",
            &[child, name, 0, kind, 0, 0],
            ERROR_FILE_NOT_FOUND,
        );
        check(
            p,
            t,
            "RegQueryValueExW",
            &[child, 0, 1, 0, 0, 0],
            ERROR_INVALID_PARAMETER,
        );
        check(
            p,
            t,
            "RegQueryValueExW",
            &[child, 0, 0, 0, payload, 0],
            ERROR_INVALID_PARAMETER,
        );
        let id = p.objects.id(child).unwrap();
        let denied = u64::from(p.objects.open_access(id, false, 0x10).unwrap());
        check(
            p,
            t,
            "RegQueryValueExW",
            &[denied, 0, 0, 0, 0, 0],
            ERROR_ACCESS_DENIED,
        );
        check(p, t, "RegCloseKey", &[denied], 0);
        check(p, t, "RegCloseKey", &[child], 0);
        check(p, t, "RegCloseKey", &[child], ERROR_INVALID_HANDLE);
        assert_eq!(p.objects.handle_count(), base_handles);
    });
}

#[test]
fn predefined_handles_foreign_objects_and_faulting_outputs_preserve_ownership() {
    each_arch(|p, t, buf| {
        let hklm = p.arch.ptr(0xffff_ffff_8000_0002);
        check(p, t, "RegOpenKeyW", &[hklm, 0, buf], 0);
        assert_eq!(p.space.ptr(buf, p.arch.ptr_size()).unwrap(), hklm);
        check(p, t, "RegCloseKey", &[hklm], 0);
        if p.arch.is64() {
            check(p, t, "RegCloseKey", &[0x8000_0002], ERROR_INVALID_HANDLE);
        }
        check(p, t, "RegOpenKeyW", &[hklm, 0, 0], ERROR_INVALID_PARAMETER);
        check(p, t, "RegCloseKey", &[0], ERROR_INVALID_HANDLE);
        let foreign = u64::from(p.objects.insert(Object::Event {
            manual: true,
            signaled: 0,
        }));
        check(p, t, "RegCloseKey", &[foreign], ERROR_INVALID_HANDLE);
        check(
            p,
            t,
            "RegQueryValueExW",
            &[foreign, 0, 0, 0, 0, 0],
            ERROR_INVALID_HANDLE,
        );
        assert!(p.objects.get(foreign).is_some());
        p.registry = snapshot();
        let path = IFEO_KEY.strip_prefix(r"\Registry\Machine\").unwrap();
        p.space
            .put_wstr(buf, &path.encode_utf16().collect::<Vec<_>>())
            .unwrap();
        let count = p.objects.handle_count();
        assert!(matches!(
            call(p, t, "RegOpenKeyW", &[hklm, buf, buf + PAGE_SIZE - 1]),
            Err(ApiErr::Fault(_))
        ));
        assert_eq!(count, p.objects.handle_count());
    });
}

#[test]
fn querying_predefined_current_user_uses_its_captured_hive_and_releases_the_handle() {
    use crate::user::windows::registry::HiveHeader;

    each_arch(|p, t, buf| {
        let opened = buf + 32;
        check(
            p,
            t,
            "RegOpenCurrentUser",
            &[1, opened],
            ERROR_FILE_NOT_FOUND,
        );
        assert_eq!(p.space.ptr(opened, p.arch.ptr_size()).unwrap(), 0);
        let sid = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        p.registry = snapshot()
            .with_primary_hive(
                &sid,
                Some(HiveHeader {
                    canonical: r"\Registry\User\.DEFAULT".encode_utf16().collect(),
                    children: 0,
                    values: vec![Value {
                        name: vec![],
                        kind: 1,
                        data: vec![65, 0],
                    }],
                }),
            )
            .unwrap();
        let hkcu = p.arch.ptr(0xffff_ffff_8000_0001);
        let before = p.objects.handle_count();
        check(p, t, "RegOpenCurrentUser", &[1, opened], 0);
        let handle = p.space.ptr(opened, p.arch.ptr_size()).unwrap();
        assert_ne!(handle, hkcu);
        assert_eq!(p.objects.handle_count(), before + 1);
        check(p, t, "RegCloseKey", &[handle], 0);
        assert_eq!(p.objects.handle_count(), before);
        p.space.w32(buf, 8).unwrap();
        p.space.w32(buf + 4, u32::MAX).unwrap();
        p.space.w32(buf + 8, u32::MAX).unwrap();
        check(
            p,
            t,
            "RegQueryValueExW",
            &[hkcu, 0, 0, buf + 8, buf + 4, buf],
            0,
        );
        assert_eq!(p.space.u32(buf).unwrap(), 2);
        assert_eq!(p.space.bytes(buf + 4, 4).unwrap(), [65, 0, 255, 255]);
        assert_eq!(p.space.u32(buf + 8).unwrap(), 1);
        assert_eq!(p.objects.handle_count(), before);
        assert!(matches!(
            call(
                p,
                t,
                "RegQueryValueExW",
                &[hkcu, 0, 0, buf + 8, buf + PAGE_SIZE - 1, buf]
            ),
            Err(ApiErr::Fault(_))
        ));
        assert_eq!(p.objects.handle_count(), before);
    });
}
