//! Native class4 volume-device query and ABI capture boundaries.
use super::*;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::{Object, StdStream};

fn setup(arch: WinArch) -> (super::super::super::super::WindowsProcess, Thread, u64) {
    let (mut process, t) = fixture(arch, "NtQueryVolumeInformationFile", 0x49);
    let p = process.state_mut();
    let base =
        p.vm.allocate(
            None,
            6 * PAGE_SIZE,
            mem::RESERVE | mem::COMMIT,
            prot::READWRITE,
        )
        .unwrap()
        .0;
    p.space
        .wr(base, &vec![0xA5; 6 * PAGE_SIZE as usize])
        .unwrap();
    (process, t, base)
}

fn invoke(p: &mut Proc, t: &mut Thread, args: &[u64]) -> u32 {
    super::nls_tests::arguments(p, t, args);
    if p.arch != WinArch::Arm64 {
        t.cpu.set_gpr(0, 0x49);
    }
    let sp = t.cpu.sp();
    let result = if p.arch == WinArch::X86 {
        super::super::super::super::services::wow64(p, t, 0x1234_0000)
    } else {
        handle_stop(p, t, stop(p.arch, 0x49))
    };
    assert_eq!(result, Outcome::Continue, "{}", p.arch);
    assert_eq!(t.cpu.pc(), 0x1234_0004);
    assert_eq!(t.cpu.sp(), sp + if p.arch == WinArch::X86 { 4 } else { 0 });
    assert!(t.frames.is_empty());
    t.cpu.set_sp(sp);
    t.cpu.gpr(0) as u32
}

#[test]
fn native_volume_device_query_standard_objects_preserves_lengths_padding_and_last_error_all_abis() {
    for arch in WinArch::ALL {
        for role in 0..5 {
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            let (object, kind, flags) = match role {
                0 => (Object::Console(StdStream::In), 0x50, 0x20000),
                1 => (Object::Console(StdStream::Out), 0x50, 0x20000),
                2 => (Object::Console(StdStream::Err), 0x50, 0x20000),
                3 => (Object::Null, 0x15, 0x100),
                _ => (
                    Object::Pipe {
                        pipe: 1,
                        write: false,
                    },
                    0x11,
                    0x20000,
                ),
            };
            let handle = p.objects.insert(object);
            let error = t.teb + crate::user::windows::layout::offsets(arch).teb_last_error;
            p.space.w32(error, 0x1234_5678).unwrap();
            assert_eq!(
                invoke(p, &mut t, &[u64::from(handle), base, base + 64, 8, 4]),
                STATUS_SUCCESS
            );
            assert_eq!(p.space.u32(base + 64).unwrap(), kind);
            assert_eq!(p.space.u32(base + 68).unwrap(), flags);
            assert_eq!(p.space.ptr(base, arch.ptr_size()).unwrap(), 0);
            assert_eq!(
                p.space
                    .ptr(base + arch.ptr_size(), arch.ptr_size())
                    .unwrap(),
                8
            );
            assert_eq!(
                p.space.bytes(base + 2 * arch.ptr_size(), 16).unwrap(),
                [0xA5; 16]
            );
            assert_eq!(p.space.bytes(base + 72, 16).unwrap(), [0xA5; 16]);
            assert_eq!(p.space.u32(error).unwrap(), 0x1234_5678);
        }
    }
}

#[test]
fn native_volume_device_query_length_precedes_handle_and_guard_probes_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        p.vm.protect(base, PAGE_SIZE, prot::READWRITE | prot::GUARD)
            .unwrap();
        for length in [0, 1, 7] {
            assert_eq!(
                invoke(p, &mut t, &[0xDEAD, base, base + PAGE_SIZE, length, 4]),
                STATUS_INFO_LENGTH_MISMATCH
            );
            assert_eq!(
                p.vm.query(base).unwrap().protect,
                prot::READWRITE | prot::GUARD
            );
        }
    }
}

#[test]
fn native_volume_device_query_native_and_wow_probe_order_preserves_reached_guards() {
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        let handle = p.objects.insert(Object::Console(StdStream::In));
        for address in [base, base + PAGE_SIZE] {
            p.vm.protect(address, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                .unwrap();
        }
        assert_eq!(
            invoke(
                p,
                &mut t,
                &[u64::from(handle), base, base + PAGE_SIZE, 8, 4]
            ),
            STATUS_GUARD_PAGE_VIOLATION
        );
        let (consumed, untouched) = if arch == WinArch::X86 {
            (base + PAGE_SIZE, base)
        } else {
            (base, base + PAGE_SIZE)
        };
        assert_eq!(p.vm.query(consumed).unwrap().protect, prot::READWRITE);
        assert_eq!(
            p.vm.query(untouched).unwrap().protect,
            prot::READWRITE | prot::GUARD
        );
    }
}

#[path = "volume_query_tests/replay.rs"]
mod replay;

#[path = "volume_query_tests/attributes.rs"]
mod attributes;
#[path = "volume_query_tests/attributes_faults.rs"]
mod attributes_faults;

#[test]
fn native_volume_device_query_file_null_and_reduced_grants_match_standard_null_all_abis() {
    use crate::user::windows::fs::{FileIdentity, FileLifetime};
    use crate::user::windows::objects::FileObj;
    for arch in WinArch::ALL {
        let (mut process, mut t, base) = setup(arch);
        let p = process.state_mut();
        let object = p.objects.create(Object::File(FileObj {
            host: None,
            host_path: Default::default(),
            path: "NUL".into(),
            access: 0,
            share: 7,
            lifetime: Arc::new(FileLifetime::new(FileIdentity::Null)),
            null: true,
            append: false,
            delete_on_close: false,
            directory: false,
            overlapped: false,
        }));
        let handle = p.objects.open_access(object, false, 0).unwrap();
        assert_eq!(
            invoke(p, &mut t, &[u64::from(handle), base, base + 64, 16, 4]),
            STATUS_SUCCESS
        );
        assert_eq!(
            p.space.bytes(base + 64, 8).unwrap(),
            [0x15, 0, 0, 0, 0, 1, 0, 0]
        );
        assert_eq!(p.space.bytes(base + 72, 16).unwrap(), [0xA5; 16]);
        assert_eq!(p.objects.access(u64::from(handle)), Some(0));
    }
}

#[test]
fn native_volume_device_query_unimplemented_classes_are_explicit_without_output_or_guard_changes() {
    for arch in WinArch::ALL {
        for class in [0, 1, 3, u32::MAX] {
            let (mut process, mut t, base) = setup(arch);
            let p = process.state_mut();
            p.vm.protect(base, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                .unwrap();
            super::nls_tests::arguments(
                p,
                &mut t,
                &[0xDEAD, base, base + PAGE_SIZE, 8, u64::from(class)],
            );
            if arch != WinArch::Arm64 {
                t.cpu.set_gpr(0, 0x49);
            }
            let outcome = if arch == WinArch::X86 {
                super::super::super::super::services::wow64(p, &mut t, 0x1234_0000)
            } else {
                handle_stop(p, &mut t, stop(arch, 0x49))
            };
            assert!(
                matches!(outcome, Outcome::Fail(message) if message.contains(&format!("volume information class {class}")))
            );
            assert_eq!(
                p.vm.query(base).unwrap().protect,
                prot::READWRITE | prot::GUARD
            );
            assert_eq!(p.space.bytes(base + PAGE_SIZE, 32).unwrap(), [0xA5; 32]);
        }
    }
}
