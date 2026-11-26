use super::*;
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{Api, ApiErr, Item, Value, args::stdcall_bytes};
use crate::user::windows::loader::{self, SymRef};
use crate::user::windows::memory::{mem, prot};
use crate::user::windows::process::{Proc, Thread, WindowsConfig, WindowsProcess};

fn each_arch(test: impl Fn(&mut Proc, &mut Thread, u64, u64)) {
    for (arch, image) in [
        (
            WinArch::X86,
            include_bytes!("../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
                .as_slice(),
        ),
        (
            WinArch::X64,
            include_bytes!("../../../../../tests/fixtures/user/windows/bin/x64/smoke.exe")
                .as_slice(),
        ),
        (
            WinArch::Arm64,
            include_bytes!("../../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe")
                .as_slice(),
        ),
    ] {
        let mut config = WindowsConfig::new("etw-test.exe", vec![]);
        config.seed = Some(1);
        config.arena_bytes = 64 << 20;
        let mut process = WindowsProcess::spawn_image(config, image.to_vec()).unwrap();
        let p = process.state_mut();
        assert_eq!(p.arch, arch);
        let tid = *p.threads.keys().next().unwrap();
        let mut t = p.threads.remove(&tid).unwrap();
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
        t.cpu.set_sp(t.cpu.sp() - 128);
        test(p, &mut t, data, data + PAGE_SIZE);
    }
}

fn api(name: &str) -> &'static Api {
    NTDLL_EXPORTS
        .iter()
        .find_map(|export| match &export.item {
            Item::Func(api) if api.name == name => Some(api),
            _ => None,
        })
        .unwrap_or_else(|| panic!("absent export {name}"))
}

fn call(p: &mut Proc, t: &mut Thread, name: &str, args: &[u64]) -> Result<Value, ApiErr> {
    let api = api(name);
    assert_eq!(args.len(), api.args.len(), "{name}");
    let sp = t.cpu.sp();
    let pc = t.cpu.pc();
    let frames = t.frames.len();
    if p.arch == WinArch::X86 {
        p.space.w32(sp, 0xdeadbeef).unwrap();
    }
    let mut slot = sp + 4;
    for (index, &value) in args.iter().enumerate() {
        match p.arch {
            WinArch::X86 if api.args[index] == I64 => {
                p.space.w64(slot, value).unwrap();
                slot += 8;
            }
            WinArch::X86 => {
                p.space.w32(slot, value as u32).unwrap();
                slot += 4;
            }
            WinArch::X64 if index < 4 => t.cpu.set_gpr([1, 2, 8, 9][index], value),
            WinArch::X64 => p.space.w64(sp + 8 + index as u64 * 8, value).unwrap(),
            WinArch::Arm64 => t.cpu.set_gpr(index, value),
        }
    }
    let result = (api.imp)(&mut Ctx {
        p,
        t,
        api,
        entry_pc: pc,
        entry_sp: sp,
        ret_addr: 0,
        cursor: sp,
    });
    assert_eq!((t.cpu.pc(), t.frames.len()), (pc, frames), "{name}");
    match result? {
        Flow::Ret(value) => Ok(value),
        _ => panic!("{name} scheduled guest execution"),
    }
}

fn expect(p: &mut Proc, t: &mut Thread, name: &str, args: &[u64], expected: u32) {
    assert_eq!(
        call(p, t, name, args).unwrap(),
        Value::Int(expected.into()),
        "{name}"
    );
}

#[test]
fn registration_captures_before_publication_and_closes_only_live_providers() {
    each_arch(|p, t, data, bad| {
        let guid = *b"dormant provider";
        let other = u64::from(p.objects.insert(Object::Event {
            manual: true,
            signaled: 0,
        }));
        let count = p.objects.handle_count();
        let objects = p.objects.iter().count();
        p.space.wr(data, &guid).unwrap();
        expect(
            p,
            t,
            "EtwEventRegister",
            &[0, bad, bad, data],
            ERROR_INVALID_PARAMETER,
        );
        for (input, output, write) in [(data, bad - 4, true), (bad - 8, data, false)] {
            assert!(
                matches!(call(p,t,"EtwEventRegister",&[input,bad,bad,output]),
                Err(ApiErr::Fault(MemFault { addr, write: access })) if addr == bad && access == write)
            );
        }
        assert_eq!(
            (p.objects.handle_count(), p.objects.iter().count()),
            (count, objects)
        );
        assert_eq!(p.space.bytes(data, 16).unwrap(), guid);
        expect(p, t, "EtwEventRegister", &[data, bad, bad, data], 0);
        let handle = p.space.u64(data).unwrap();
        assert_ne!(handle, 0);
        assert_eq!(p.objects.access(handle), Some(0x804));
        let Some(Object::EtwRegistration { request, .. }) = p.objects.get(handle) else {
            panic!("missing registration")
        };
        assert_eq!(&request[..16], &guid);
        assert!(request[16..].iter().all(|&b| b == 0));
        for invalid in [0, other, (1 << 32) | handle] {
            expect(p, t, "EtwEventUnregister", &[invalid], ERROR_INVALID_HANDLE);
        }
        assert!(p.objects.set_flags(handle, 2, 2));
        expect(p, t, "EtwEventUnregister", &[handle], ERROR_INVALID_HANDLE);
        assert!(p.objects.set_flags(handle, 2, 0));
        expect(p, t, "EtwEventUnregister", &[handle], 0);
        expect(p, t, "EtwEventUnregister", &[handle], ERROR_INVALID_HANDLE);
        assert!(p.objects.get(other).is_some());
        assert_eq!(
            (p.objects.handle_count(), p.objects.iter().count()),
            (count, objects)
        );
    });
}

#[test]
fn information_classes_capture_valid_data_and_preserve_state_on_failure() {
    each_arch(|p, t, data, bad| {
        expect(p, t, "EtwEventRegister", &[data, 0, 0, data + 16], 0);
        let h = p.space.u64(data + 16).unwrap();
        let name = "EtwEventSetInformation";
        expect(p, t, name, &[0, 3, data, 1], ERROR_INVALID_HANDLE);
        for class in [1, 4, 99] {
            expect(p, t, name, &[h, class, 0, 0], ERROR_NOT_SUPPORTED);
        }
        expect(p, t, name, &[h, 0, 0, 0], 0);
        expect(p, t, name, &[h, 0, data, 1], ERROR_INVALID_PARAMETER);
        for byte in [0, 1] {
            p.space.w8(data, byte).unwrap();
            expect(p, t, name, &[h, 3, data, 1], 0);
            assert!(
                matches!(p.objects.get(h),Some(Object::EtwRegistration {descriptor_type: Some(v),..}) if *v == (byte != 0))
            );
        }
        p.space.w8(data, 2).unwrap();
        for (ptr, len) in [(data, 0), (0, 1), (data, 1), (data, 2)] {
            expect(p, t, name, &[h, 3, ptr, len], ERROR_INVALID_PARAMETER);
        }
        assert!(
            matches!(call(p,t,name,&[h,3,bad,1]), Err(ApiErr::Fault(MemFault {addr,write:false})) if addr==bad)
        );
        assert!(matches!(
            p.objects.get(h),
            Some(Object::EtwRegistration {
                descriptor_type: Some(true),
                binary_tracking_class: Some(0),
                ..
            })
        ));
        expect(p, t, name, &[h, 2, 0, 3], ERROR_INVALID_PARAMETER);
        expect(p, t, name, &[h, 2, data, 65536], ERROR_INVALID_PARAMETER);
        expect(p, t, name, &[h, 2, data, 3], ERROR_FILE_CORRUPT);
        assert!(
            matches!(call(p,t,name,&[h,2,bad-1,3]), Err(ApiErr::Fault(MemFault {addr,write:false})) if addr==bad)
        );
        p.space.wr(data, &[4, 0, b'X', 0]).unwrap();
        expect(p, t, name, &[h, 2, data, 4], 0);
        p.space.w8(data + 2, b'Y').unwrap();
        expect(p, t, name, &[h, 2, bad, 4], ERROR_GEN_FAILURE);
        assert!(
            matches!(p.objects.get(h),Some(Object::EtwRegistration {traits: Some(bytes), ..}) if bytes.as_ref()==[4,0,b'X',0])
        );
    });
}

#[test]
fn dormant_writes_queries_and_classic_exports_do_not_access_payloads() {
    each_arch(|p, t, data, bad| {
        expect(p, t, "EtwEventRegister", &[data, bad, bad, data], 0);
        let h = p.space.u64(data).unwrap();
        for live in [true, false] {
            if !live {
                expect(p, t, "EtwEventUnregister", &[h], 0);
            }
            expect(p, t, "EtwEventEnabled", &[h, bad], 0);
            expect(p, t, "EtwEventProviderEnabled", &[h, 255, u64::MAX], 0);
            for (name, tail) in [
                ("EtwEventWrite", &[bad, 1, bad][..]),
                ("EtwEventWriteStartScenario", &[bad, 1, bad]),
                ("EtwEventWriteEndScenario", &[bad, 1, bad]),
                ("EtwEventWriteEx", &[bad, u64::MAX, 0, bad, bad, 1, bad]),
                ("EtwEventWriteTransfer", &[bad, bad, bad, 1, bad]),
                ("EtwEventWriteString", &[1, u64::MAX, bad]),
            ] {
                let args = [&[h][..], tail].concat();
                expect(
                    p,
                    t,
                    name,
                    &args,
                    if live { 0 } else { ERROR_INVALID_HANDLE },
                );
            }
        }
        p.space.wr(data, &[0xaa; 16]).unwrap();
        expect(p, t, "EtwEventActivityIdControl", &[1, data], 0);
        assert_eq!(p.space.bytes(data, 16).unwrap(), [0; 16]);
        p.space.w64(bad - 8, u64::MAX).unwrap();
        assert!(matches!(call(p,t,"EtwEventActivityIdControl",&[1,bad-8]),
            Err(ApiErr::Fault(MemFault {addr,write:true})) if addr==bad));
        assert_eq!(p.space.u64(bad - 8).unwrap(), u64::MAX);
        for name in ["EtwRegisterTraceGuidsA", "EtwRegisterTraceGuidsW"] {
            let mut args = [bad; 8];
            assert!(
                matches!(call(p,t,name,&args),Err(ApiErr::Fault(MemFault {addr,write:true})) if addr==bad)
            );
            args[7] = data;
            p.space.w64(data, u64::MAX).unwrap();
            expect(p, t, name, &args, 0);
            assert_eq!(p.space.u64(data).unwrap(), 0);
        }
        for (name, count) in [
            ("EtwEventActivityIdControl", 2),
            ("EtwCreateTraceInstanceId", 2),
            ("EtwUnregisterTraceGuids", 1),
            ("EtwLogTraceEvent", 2),
            ("EtwTraceEventInstance", 4),
            ("EtwTraceMessage", 4),
            ("EtwTraceMessageVa", 5),
            ("EtwGetTraceEnableFlags", 1),
            ("EtwGetTraceEnableLevel", 1),
        ] {
            expect(p, t, name, &[bad; 5][..count], 0);
        }
        assert_eq!(
            call(p, t, "EtwGetTraceLoggerHandle", &[bad]).unwrap(),
            Value::I64(0)
        );
    });
}

#[test]
fn desktop_export_pairs_resolve_to_one_address_with_the_x86_sdk_stack_widths() {
    each_arch(|p, _, _, _| {
        let kernel = loader::load_dll(p, "kernelbase.dll").unwrap();
        let ntdll = loader::load_dll(p, "ntdll.dll").unwrap();
        for (name, bytes) in [
            ("CreateTraceInstanceId", 8),
            ("EventActivityIdControl", 8),
            ("EventEnabled", 12),
            ("EventProviderEnabled", 20),
            ("EventRegister", 16),
            ("EventSetInformation", 20),
            ("EventUnregister", 8),
            ("EventWrite", 20),
            ("EventWriteEx", 40),
            ("EventWriteString", 24),
            ("EventWriteTransfer", 28),
            ("EventWriteStartScenario", 20),
            ("EventWriteEndScenario", 20),
            ("GetTraceEnableFlags", 8),
            ("GetTraceEnableLevel", 8),
            ("GetTraceLoggerHandle", 4),
            ("RegisterTraceGuidsA", 32),
            ("RegisterTraceGuidsW", 32),
            ("TraceEvent", 12),
            ("TraceEventInstance", 20),
            ("TraceMessage", 20),
            ("TraceMessageVa", 24),
            ("UnregisterTraceGuids", 8),
        ] {
            let native = if name == "TraceEvent" {
                "EtwLogTraceEvent".to_owned()
            } else {
                format!("Etw{name}")
            };
            let lookup = |p: &mut Proc, module, export: &str| {
                loader::lookup(p, module, &SymRef::Name(export.as_bytes().to_vec(), None))
                    .unwrap()
                    .unwrap()
            };
            let address = lookup(p, ntdll, &native);
            assert_ne!(address, 0);
            assert_eq!(lookup(p, kernel, name), address, "{name}");
            assert_eq!(stdcall_bytes(api(&native).args), bytes, "{native}");
            assert_eq!(
                api(&native).conv,
                if name == "TraceMessage" {
                    Variadic
                } else {
                    Stdcall
                }
            );
        }
    });
}
