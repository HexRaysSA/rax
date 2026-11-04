//! Original seven-argument NT section construction, all guest calling conventions.
use super::*;

const SERVICE: u32 = 0x4A;
#[path = "file_data_section_tests.rs"]
mod data;
#[path = "file_section_create_tests/create.rs"]
mod file;
#[cfg(windows)]
#[path = "section_create_leaf_tests.rs"]
mod installed;
#[path = "section_create_replay_tests.rs"]
mod replay;
fn invoke(p: &mut Proc, t: &mut Thread, args: &[u64]) -> Outcome {
    let sp = t.cpu.sp();
    t.cpu.set_pc(0x1234_0004);
    match p.arch {
        WinArch::X86 => {
            p.space.w32(sp, 0x1234_0004).unwrap();
            p.space.w32(sp + 4, 0x1234_0000).unwrap();
            for (i, &v) in args.iter().enumerate() {
                p.space.w32(sp + 8 + i as u64 * 4, v as u32).unwrap();
            }
            t.cpu.set_gpr(0, SERVICE.into());
        }
        WinArch::X64 => {
            t.cpu.set_gpr(0, SERVICE.into());
            t.cpu.set_gpr(1, 0x1234_0004);
            for (i, &v) in args.iter().enumerate() {
                if i < 4 {
                    t.cpu.set_gpr([10, 2, 8, 9][i], v);
                } else {
                    p.space.w64(sp + 40 + (i - 4) as u64 * 8, v).unwrap();
                }
            }
        }
        WinArch::Arm64 => {
            for (i, &v) in args.iter().enumerate() {
                if i < 8 {
                    t.cpu.set_gpr(i, v);
                } else {
                    p.space.w32(sp + (i - 8) as u64 * 8, v as u32).unwrap();
                }
            }
        }
    }
    let out = if p.arch == WinArch::X86 {
        super::super::super::super::services::wow64(p, t, 0x1234_0000)
    } else {
        handle_stop(p, t, stop(p.arch, SERVICE))
    };
    if out == Outcome::Continue {
        assert_eq!(t.cpu.pc(), 0x1234_0004);
        assert_eq!(t.cpu.sp(), sp + if p.arch == WinArch::X86 { 4 } else { 0 });
        assert!(t.frames.is_empty());
    }
    t.cpu.set_sp(sp);
    out
}
fn call(p: &mut Proc, t: &mut Thread, args: &[u64]) -> u32 {
    assert_eq!(
        invoke(p, t, args),
        Outcome::Continue,
        "{} {args:X?}",
        p.arch
    );
    t.cpu.gpr(0) as u32
}

fn scratch(p: &mut Proc) -> u64 {
    p.vm.allocate(None, 8 * 4096, mem::RESERVE | mem::COMMIT, prot::READWRITE)
        .unwrap()
        .0
}
fn ptr(p: &Proc, at: u64, value: u64) {
    p.space.wptr(at, p.arch.ptr_size(), value).unwrap();
}
fn get(p: &Proc, at: u64) -> u64 {
    p.space.ptr(at, p.arch.ptr_size()).unwrap()
}

#[test]
fn native_section_create_owns_zero_filled_page_rounded_backing_and_releases_last_handle() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch, "NtCreateSection", SERVICE);
        let p = process.state_mut();
        let out = scratch(p);
        let max = out + 64;
        let handles = p.objects.handle_count();
        let objects = p.objects.iter().count();
        for requested in [1u64, 4095, 4096, 4097, 65535, 65536, 65537] {
            p.space.w64(max, requested).unwrap();
            assert_eq!(
                call(p, &mut t, &[out, 0xF001F, 0, max, 4, 0x08000000, 0]),
                STATUS_SUCCESS
            );
            assert_eq!(p.space.u64(max).unwrap(), requested);
            let h = get(p, out);
            assert_eq!(p.objects.access(h), Some(0xF001F));
            let weak = match p.objects.get(h).unwrap() {
                Object::Mapping {
                    file: None,
                    size,
                    protect,
                    shared: Some(shared),
                    ..
                } => {
                    assert_eq!(*size, (requested + 4095) & !4095);
                    assert_eq!(*protect, 4);
                    assert_eq!(shared.len(), *size);
                    let mut data = vec![0xA5; *size as usize];
                    assert_eq!(shared.read_at(0, &mut data).unwrap(), data.len());
                    assert!(data.iter().all(|b| *b == 0));
                    std::sync::Arc::downgrade(shared)
                }
                other => panic!("actual section backing required: {other:?}"),
            };
            assert_eq!(p.objects.handle_count(), handles + 1);
            assert_eq!(p.objects.iter().count(), objects + 1);
            p.objects.close(h).unwrap();
            assert!(weak.upgrade().is_none());
            assert_eq!(p.objects.handle_count(), handles);
            assert_eq!(p.objects.iter().count(), objects);
        }
    }
}

#[test]
fn native_section_create_status_mapping_matches_installed_ntdll() {
    for (status, error) in [(0xC0000020, 193), (0xC0000040, 8), (0xC00000F4, 87)] {
        assert_eq!(crate::user::windows::nt::status_to_error(status), error);
    }
}

#[test]
fn native_section_create_unsupported_modes_do_not_publish_or_allocate() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch, "NtCreateSection", SERVICE);
        let p = process.state_mut();
        let out = scratch(p);
        let maximum = out + 64;
        let handles = p.objects.handle_count();
        let objects = p.objects.iter().count();
        for (size, access, allocation) in [
            (65536, 0xF001F, 0x08200000),
            (65536, 0x01000000, 0x08000000),
            (64 * 1024 * 1024 + 1, 0xF001F, 0x08000000),
        ] {
            p.space.wr(out, &[0xA5; 16]).unwrap();
            p.space.w64(maximum, size).unwrap();
            assert!(matches!(
                invoke(p, &mut t, &[out, access, 0, maximum, 4, allocation, 0]),
                Outcome::Fail(_)
            ));
            assert_eq!(p.space.bytes(out, 16).unwrap(), vec![0xA5; 16]);
            assert_eq!(p.objects.handle_count(), handles);
            assert_eq!(p.objects.iter().count(), objects);
        }
    }
}
#[test]
fn native_section_create_captures_aliased_maximum_before_publishing_and_duplicates_identity() {
    for arch in WinArch::ALL {
        let (mut process, mut t) = fixture(arch, "NtCreateSection", SERVICE);
        let p = process.state_mut();
        let out = scratch(p);
        p.space.w64(out, 4097).unwrap();
        assert_eq!(
            call(p, &mut t, &[out, 0xF001F, 0, out, 4, 0x08000000, 0]),
            0
        );
        let h = get(p, out);
        let id = p.objects.id(h).unwrap();
        let duplicate = p.objects.duplicate(h, false).unwrap();
        assert_eq!(p.objects.id(duplicate.into()), Some(id));
        p.objects.close(h).unwrap();
        let Object::Mapping {
            size,
            shared: Some(shared),
            ..
        } = p.objects.get(duplicate.into()).unwrap()
        else {
            panic!("shared backing")
        };
        assert_eq!(*size, 8192);
        let weak = std::sync::Arc::downgrade(shared);
        assert_eq!(shared.len(), 8192);
        p.objects.close(duplicate.into()).unwrap();
        assert!(weak.upgrade().is_none());
    }
}
