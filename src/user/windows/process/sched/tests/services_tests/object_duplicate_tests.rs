use super::{file_open_tests::Harness, native_profile::kernel_profile};
use crate::user::windows::arch::WinArch;
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{CURRENT_PROCESS, CURRENT_THREAD, Object};

const NATIVE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/docs/specifications/windows/native-object-duplicate/nonclosing-29704-v1.json"
));
const INDIVIDUAL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/docs/specifications/windows/native-object-duplicate/individual-access-29704-v1.json"
));
const ABIS: [WinArch; 3] = [WinArch::Arm64, WinArch::X64, WinArch::X86];

fn invoke(h: &mut Harness, source: u64, out: u64, desired: u32, attrs: u32, options: u32) -> u32 {
    let current = h.process.state().arch.ptr(CURRENT_PROCESS);
    h.invoke_api(
        "NtDuplicateObject",
        &[
            current,
            source,
            current,
            out,
            desired.into(),
            attrs.into(),
            options.into(),
        ],
    )
}

#[test]
fn nonclosing_owned_handle_matrix_replays_native_outputs_on_every_guest_abi() {
    replay(NATIVE, 3500);
    replay(INDIVIDUAL, 370);
}

fn replay(fixture: &str, count: usize) {
    let native: serde_json::Value = serde_json::from_str(fixture).unwrap();
    let sources: Vec<(String, u32, u32)> =
        serde_json::from_value(native["sources"].clone()).unwrap();
    type Row = (usize, u32, u32, u32, u32, Option<u32>, Option<u32>);
    let rows: Vec<Row> = serde_json::from_value(native["rows"].clone()).unwrap();
    assert_eq!((sources.len(), rows.len()), (10, count));
    for arch in ABIS {
        let mut h = Harness::new(arch);
        let out = h.base;
        let width = arch.ptr_size();
        let p = h.process.state_mut();
        kernel_profile(p, 29704, 0xaa64);
        let thread = p
            .objects
            .iter()
            .find_map(|(id, obj)| matches!(obj, Object::Thread { .. }).then_some(id))
            .unwrap();
        let process = p
            .objects
            .iter()
            .find_map(|(id, obj)| {
                matches!(obj, Object::Process { pid, .. } if *pid == p.pid).then_some(id)
            })
            .unwrap();
        let event = p.objects.create(Object::Event {
            manual: true,
            signaled: 0,
        });
        let mut handles = Vec::new();
        for (role, grant, flags) in &sources {
            let (object, pseudo) = match role.as_str() {
                "pseudo-thread" => (thread, Some(CURRENT_THREAD)),
                "pseudo-process" => (process, Some(CURRENT_PROCESS)),
                "thread-full" | "thread-protected" | "thread-inherited" | "thread-both"
                | "thread-query" => (thread, None),
                "process-full" | "process-dup" => (process, None),
                "event" => (event, None),
                _ => panic!("unknown native source {role}"),
            };
            let handle = if let Some(value) = pseudo {
                arch.ptr(value)
            } else {
                let handle = u64::from(p.objects.open_access(object, false, *grant).unwrap());
                assert!(p.objects.set_flags(handle, 3, *flags));
                handle
            };
            handles.push((handle, object, pseudo.is_some()));
        }
        let before = p.objects.handle_count();
        for &(source, desired, attrs, options, status, grant, flags) in &rows {
            let (handle, object, pseudo) = handles[source];
            let poison = arch.ptr(0xa5a5_a5a5_a5a5_a5a5);
            h.process.state().space.wptr(out, width, poison).unwrap();
            let got = invoke(&mut h, handle, out, desired, attrs, options);
            let label = (&sources[source].0, desired, attrs, options);
            assert_eq!(got, status, "{arch:?} {label:x?}");
            let p = h.process.state_mut();
            let output = p.space.ptr(out, width).unwrap();
            if let Some(grant) = grant {
                assert_ne!(output, handle, "{arch:?} {label:x?}");
                assert_eq!(p.objects.id(output), Some(object), "{arch:?} {label:x?}");
                assert_eq!(p.objects.access(output), Some(grant), "{arch:?} {label:x?}");
                assert_eq!(p.objects.flags(output), flags, "{arch:?} {label:x?}");
                assert_eq!(p.objects.handle_count(), before + 1);
                assert!(p.objects.set_flags(output, 2, 0));
                assert!(p.objects.close(output).is_ok());
            } else {
                assert_eq!(output, 0, "{arch:?} {label:x?}");
            }
            assert_eq!(p.objects.handle_count(), before);
            if !pseudo {
                assert_eq!(p.objects.id(handle), Some(object));
                assert_eq!(p.objects.access(handle), Some(sources[source].1));
                assert_eq!(p.objects.flags(handle), Some(sources[source].2));
            }
        }
    }
}

#[test]
fn nonclosing_owned_handle_publishes_at_unaligned_outputs_and_preflights_faults() {
    for arch in ABIS {
        let mut h = Harness::new(arch);
        let p = h.process.state_mut();
        kernel_profile(p, 29704, 0xaa64);
        let before = p.objects.handle_count();
        let current = arch.ptr(CURRENT_PROCESS);
        let thread = arch.ptr(CURRENT_THREAD);
        let width = arch.ptr_size();
        let output = h.base + 1;
        for (from, source, to, code) in [
            (current, 0x4000_0000, current, STATUS_INVALID_HANDLE),
            (0, thread, current, STATUS_INVALID_HANDLE),
            (current, thread, 0, STATUS_INVALID_PARAMETER),
        ] {
            let call = |out| [from, source, to, out, 0x4a, 0, 0];
            let poison = arch.ptr(0xa5a5_a5a5_a5a5_a5a5);
            h.process.state().space.wptr(output, width, poison).unwrap();
            assert_eq!(
                h.invoke_api("NtDuplicateObject", &call(1)),
                STATUS_ACCESS_VIOLATION
            );
            assert_eq!(h.process.state().space.ptr(output, width).unwrap(), poison);
            assert_eq!(h.invoke_api("NtDuplicateObject", &call(output)), code);
            assert_eq!(h.process.state().space.ptr(output, width).unwrap(), 0);
            assert_eq!(h.process.state().objects.handle_count(), before);
        }
        assert_eq!(invoke(&mut h, thread, output, 0x4a, 0, 0), STATUS_SUCCESS);
        let p = h.process.state_mut();
        let duplicate = p.space.ptr(output, width).unwrap();
        assert_eq!(p.objects.access(duplicate), Some(0x184a));
        assert!(p.objects.close(duplicate).is_ok());
        assert_eq!(invoke(&mut h, thread, 0, 0x4a, 0, 0), STATUS_SUCCESS);
        assert_eq!(h.process.state().objects.handle_count(), before + 1);
    }
}
