use super::*;
use crate::user::windows::loader::apiset_schema::ApiSetSchema;
use crate::user::windows::native::NativeRuntime;

const CLASS: u32 = 103;
const OPTIONS: u32 = 0xc301;
const ERROR_SENTINEL: u32 = 0x1234_5678;
const STATUS_SENTINEL: u32 = 0xc123_abcd;

fn setup(arch: WinArch) -> (super::super::super::super::WindowsProcess, Thread, u64) {
    let (mut process, t, scratch) = query_fixture(arch);
    let p = process.state_mut();
    let schema: Vec<_> = [6u32, 28, 0, 0, 28, 28, 0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    p.native = Some(NativeRuntime {
        directory: Default::default(),
        guest_root: "C:\\Windows".into(),
        guest_directory: "C:\\Windows\\System32".into(),
        version: p.cfg.version.clone(),
        apisets: ApiSetSchema::parse(&schema).unwrap(),
        registry: Default::default(),
        object_namespace: Default::default(),
        nls: None,
        appcompat: Default::default(),
        wnf_catalog: Default::default(),
        startup: None,
        gui: Default::default(),
        code_integrity: Ok(OPTIONS),
        code_integrity_policy: Err("code integrity policy not captured in this fixture".into()),
    });
    let offsets = crate::user::windows::layout::offsets(arch);
    p.space
        .w32(t.teb + offsets.teb_last_error, ERROR_SENTINEL)
        .unwrap();
    p.space
        .w32(t.teb + offsets.teb_last_status, STATUS_SENTINEL)
        .unwrap();
    (process, t, scratch)
}

fn errors_unchanged(p: &Proc, t: &Thread) {
    let offsets = crate::user::windows::layout::offsets(p.arch);
    assert_eq!(
        p.space.u32(t.teb + offsets.teb_last_error).unwrap(),
        ERROR_SENTINEL
    );
    assert_eq!(
        p.space.u32(t.teb + offsets.teb_last_status).unwrap(),
        STATUS_SENTINEL
    );
}

#[test]
fn code_integrity_requires_both_exact_lengths_and_ulong_alignment_on_every_abi() {
    for arch in WinArch::ALL {
        for (offset, length, embedded, status) in [
            (0, 8, 8, 0),
            (4, 8, 8, 0),
            (1, 8, 8, STATUS_DATATYPE_MISALIGNMENT),
            (3, 7, 0, STATUS_DATATYPE_MISALIGNMENT),
            (1, 0, 8, STATUS_INFO_LENGTH_MISMATCH),
            (0, 0, 8, STATUS_INFO_LENGTH_MISMATCH),
            (0, 7, 8, STATUS_INFO_LENGTH_MISMATCH),
            (0, 9, 8, STATUS_INFO_LENGTH_MISMATCH),
            (0, 16, 8, STATUS_INFO_LENGTH_MISMATCH),
            (0, 8, 0, STATUS_INFO_LENGTH_MISMATCH),
            (0, 8, 16, STATUS_INFO_LENGTH_MISMATCH),
            (0, 8, u32::MAX, STATUS_INFO_LENGTH_MISMATCH),
        ] {
            let (mut process, mut t, scratch) = setup(arch);
            let p = process.state_mut();
            let output = scratch + offset;
            p.space.w32(output, embedded).unwrap();
            let mut expected = p.space.bytes(scratch, 128).unwrap();
            query_arguments(p, &mut t, CLASS, output, length, scratch + 96);
            let sp = t.cpu.sp();
            assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
            assert_eq!(
                t.cpu.gpr(0),
                u64::from(status),
                "{arch}/{offset}/{length}/{embedded}"
            );
            assert_eq!(t.cpu.pc(), 0x1234_0004);
            assert_eq!(t.cpu.sp(), sp + if arch == WinArch::X86 { 4 } else { 0 });
            if status != STATUS_DATATYPE_MISALIGNMENT {
                expected[96..100].copy_from_slice(&8u32.to_le_bytes());
            }
            if status == 0 {
                expected[offset as usize + 4..offset as usize + 8]
                    .copy_from_slice(&OPTIONS.to_le_bytes());
            }
            assert_eq!(p.space.bytes(scratch, 128).unwrap(), expected);
            errors_unchanged(p, &t);
        }
    }
}

#[test]
fn code_integrity_preserves_full_options_and_writes_return_length_after_options() {
    for arch in WinArch::ALL {
        for options in [0, OPTIONS, u32::MAX] {
            for returned_offset in [None, Some(0), Some(4), Some(32), Some(33)] {
                let (mut process, mut t, scratch) = setup(arch);
                let p = process.state_mut();
                p.native.as_mut().unwrap().code_integrity = Ok(options);
                p.space.w32(scratch, 8).unwrap();
                let mut expected = p.space.bytes(scratch, 128).unwrap();
                expected[4..8].copy_from_slice(&options.to_le_bytes());
                let returned = returned_offset.map_or(0, |offset| scratch + offset);
                if let Some(offset) = returned_offset {
                    expected[offset as usize..offset as usize + 4]
                        .copy_from_slice(&8u32.to_le_bytes());
                }
                query_arguments(p, &mut t, CLASS, scratch, 8, returned);
                assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
                assert_eq!(t.cpu.gpr(0), 0);
                assert_eq!(p.space.bytes(scratch, 128).unwrap(), expected);
                errors_unchanged(p, &t);
            }
        }
    }
}

#[test]
fn code_integrity_output_probe_precedes_return_probe_and_preserves_failed_copy() {
    for arch in WinArch::ALL {
        for output_protection in [
            prot::READWRITE,
            prot::READONLY,
            prot::READWRITE | prot::GUARD,
            prot::READONLY | prot::GUARD,
        ] {
            for length in [0, 8] {
                let (mut process, mut t, scratch) = setup(arch);
                let p = process.state_mut();
                p.space.w32(scratch, 8).unwrap();
                let returned =
                    p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                        .unwrap()
                        .0;
                p.space.w32(returned, 0xfefe_fefe).unwrap();
                p.vm.protect(scratch, PAGE_SIZE, output_protection).unwrap();
                p.vm.protect(returned, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                    .unwrap();
                query_arguments(p, &mut t, CLASS, scratch, length, returned);
                assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
                let output_first = length != 0 && output_protection != prot::READWRITE;
                let status = if output_first && output_protection == prot::READONLY {
                    STATUS_ACCESS_VIOLATION
                } else {
                    STATUS_GUARD_PAGE_VIOLATION
                };
                assert_eq!(t.cpu.gpr(0), u64::from(status));
                assert_eq!(
                    p.vm.query(returned).unwrap().protect & prot::GUARD != 0,
                    output_first
                );
                assert_eq!(
                    p.vm.query(scratch).unwrap().protect & prot::GUARD != 0,
                    length == 0 && output_protection & prot::GUARD != 0
                );
                p.vm.protect(scratch, PAGE_SIZE, prot::READWRITE).unwrap();
                p.vm.protect(returned, PAGE_SIZE, prot::READWRITE).unwrap();
                assert_eq!(p.space.u32(scratch).unwrap(), 8);
                assert_eq!(p.space.u32(scratch + 4).unwrap(), 0xa5a5_a5a5);
                assert_eq!(p.space.u32(returned).unwrap(), 0xfefe_fefe);
                errors_unchanged(p, &t);
            }
        }
        let (mut process, mut t, scratch) = setup(arch);
        let p = process.state_mut();
        let output =
            p.vm.allocate(
                None,
                2 * PAGE_SIZE,
                mem::RESERVE | mem::COMMIT,
                prot::READWRITE,
            )
            .unwrap()
            .0 + PAGE_SIZE
                - 4;
        p.space.w32(output, 8).unwrap();
        p.space.w32(output + 4, 0xa5a5_a5a5).unwrap();
        p.vm.protect(output + 4, PAGE_SIZE, prot::READONLY).unwrap();
        query_arguments(p, &mut t, CLASS, output, 8, scratch + 96);
        assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
        assert_eq!(t.cpu.gpr(0), u64::from(STATUS_ACCESS_VIOLATION));
        assert_eq!(p.space.u32(output).unwrap(), 8);
        assert_eq!(p.space.u32(output + 4).unwrap(), 0xa5a5_a5a5);
        assert_eq!(p.space.u32(scratch + 96).unwrap(), 0xa5a5_a5a5);
        errors_unchanged(p, &t);
    }
}

#[test]
fn code_integrity_maximum_length_visits_output_guard_before_length_or_returned() {
    for arch in WinArch::ALL {
        for protection in [prot::READWRITE | prot::GUARD, prot::READONLY | prot::GUARD] {
            let (mut process, mut t, scratch) = setup(arch);
            let p = process.state_mut();
            p.space.w32(scratch, 8).unwrap();
            let returned =
                p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
                    .unwrap()
                    .0;
            p.space.w32(returned, 0xfefe_fefe).unwrap();
            p.vm.protect(scratch, PAGE_SIZE, protection).unwrap();
            p.vm.protect(returned, PAGE_SIZE, prot::READWRITE | prot::GUARD)
                .unwrap();
            query_arguments(p, &mut t, CLASS, scratch, u32::MAX, returned);
            assert_eq!(dispatch_query(p, &mut t), Outcome::Continue);
            assert_eq!(t.cpu.gpr(0), u64::from(STATUS_GUARD_PAGE_VIOLATION));
            assert_eq!(p.vm.query(scratch).unwrap().protect & prot::GUARD, 0);
            assert_ne!(p.vm.query(returned).unwrap().protect & prot::GUARD, 0);
            p.vm.protect(returned, PAGE_SIZE, prot::READWRITE).unwrap();
            assert_eq!(p.space.u32(scratch).unwrap(), 8);
            assert_eq!(p.space.u32(scratch + 4).unwrap(), 0xa5a5_a5a5);
            assert_eq!(p.space.u32(returned).unwrap(), 0xfefe_fefe);
            errors_unchanged(p, &t);
        }
    }
}

#[test]
fn code_integrity_missing_metadata_is_explicit_and_does_not_fabricate_zero_options() {
    for arch in WinArch::ALL {
        for absent_runtime in [false, true] {
            let (mut process, mut t, scratch) = setup(arch);
            let p = process.state_mut();
            if absent_runtime {
                p.native = None;
            } else {
                p.native.as_mut().unwrap().code_integrity =
                    Err("controlled missing snapshot".into());
            }
            p.space.w32(scratch, 8).unwrap();
            query_arguments(p, &mut t, CLASS, scratch, 8, scratch + 96);
            assert!(
                matches!(dispatch_query(p, &mut t), Outcome::Fail(reason) if reason.contains("SystemCodeIntegrityInformation") && reason.contains(if absent_runtime { "requires selected native inputs" } else { "controlled missing snapshot" }))
            );
            assert_eq!(p.space.u32(scratch).unwrap(), 8);
            assert_eq!(p.space.u32(scratch + 4).unwrap(), 0xa5a5_a5a5);
            assert_eq!(p.space.u32(scratch + 96).unwrap(), 0xa5a5_a5a5);
            errors_unchanged(p, &t);
        }
    }
}
