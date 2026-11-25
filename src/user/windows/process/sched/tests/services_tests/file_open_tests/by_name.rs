//! Native by-name metadata translates guest buffers and admission independently.

use super::*;
use crate::user::windows::nt::status::{
    STATUS_DATATYPE_MISALIGNMENT, STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_INFO_CLASS,
    STATUS_INVALID_PARAMETER,
};

fn query(h: &mut Harness, attrs: u64, io: u64, output: u64, length: u64, class: u64) -> u32 {
    h.invoke_api(
        "NtQueryInformationByName",
        &[attrs, io, output, length, class],
    )
}

#[test]
fn native_file_by_name_rejects_class_length_and_output_before_publication() {
    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        let output = h.base;
        let io = output + 256;
        let width = arch.ptr_size();
        for (class, size) in [(68, 72), (70, 96), (71, 4), (77, 104)] {
            assert_eq!(
                query(&mut h, 0, 0, 0, size - 1, class),
                STATUS_INFO_LENGTH_MISMATCH,
                "{arch}/class {class}"
            );
        }
        assert_eq!(query(&mut h, 0, 0, 0, 104, 0), STATUS_INVALID_INFO_CLASS);
        for class in [4, 76] {
            assert_eq!(query(&mut h, 0, 0, 0, 104, class), STATUS_INVALID_PARAMETER);
        }
        let attrs = h.attrs();
        assert_eq!(
            query(&mut h, attrs, io, output + 1, 104, 77),
            STATUS_DATATYPE_MISALIGNMENT
        );
        let unavailable = h.base + PAGE_SIZE;
        h.process
            .state_mut()
            .vm
            .protect(unavailable, PAGE_SIZE, prot::NOACCESS)
            .unwrap();
        assert_eq!(
            query(&mut h, attrs, io, unavailable - 104, 120, 77),
            STATUS_ACCESS_VIOLATION
        );
        let p = h.process.state();
        assert_eq!(
            p.space.bytes(io, (width * 2) as usize).unwrap(),
            vec![0xa5; (width * 2) as usize]
        );
        assert_eq!(p.space.bytes(output, 120).unwrap(), [0xa5; 120]);
    }
}

#[test]
fn native_file_by_name_publishes_native_capture_errors_and_preserves_wow64_conversion_errors() {
    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        let output = h.base;
        let io = output + 256;
        let width = arch.ptr_size();
        assert_eq!(
            query(&mut h, 0, io, output, 104, 77),
            STATUS_INVALID_PARAMETER
        );
        let p = h.process.state();
        assert_eq!(
            p.space.ptr(io, width).unwrap(),
            u64::from(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(p.space.ptr(io + width, width).unwrap(), 0);
        p.space.wr(io, &[0xa5; 16]).unwrap();
        let attrs = h.attrs();
        p.space.w32(attrs, 0).unwrap();
        assert_eq!(
            query(&mut h, attrs, io, output, 104, 77),
            STATUS_INVALID_PARAMETER
        );
        let p = h.process.state();
        if arch == WinArch::X86 {
            assert_eq!(p.space.bytes(io, 8).unwrap(), [0xa5; 8]);
        } else {
            assert_eq!(
                p.space.ptr(io, width).unwrap(),
                u64::from(STATUS_INVALID_PARAMETER)
            );
            assert_eq!(p.space.ptr(io + width, width).unwrap(), 0);
        }
        assert_eq!(p.space.bytes(output, 104).unwrap(), [0xa5; 104]);
    }
}

#[cfg(windows)]
#[test]
fn native_file_by_name_reads_closed_installed_metadata_without_granting_file_open() {
    use crate::user::windows::nt::status::STATUS_ACCESS_DENIED;
    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        let selected = selection(&mut h);
        std::fs::create_dir(selected.join("internal")).unwrap();
        let width = arch.ptr_size();
        let attrs = h.attrs();
        let output = h.base;
        let io = output + 256;
        let handle = output + 384;

        h.name(r"\??\C:\Windows\System32\unselected.exe");
        assert_eq!(query(&mut h, attrs, io, output, 88, 68), STATUS_SUCCESS);
        let p = h.process.state();
        assert_eq!(p.space.u64(output + 48).unwrap(), 10);
        assert_ne!(p.space.u64(output + 24).unwrap(), 0);
        assert_eq!(p.space.ptr(io, width).unwrap(), 0);
        assert_eq!(p.space.ptr(io + width, width).unwrap(), 72);
        assert_eq!(p.space.bytes(output + 72, 16).unwrap(), [0xa5; 16]);
        assert_eq!(query(&mut h, attrs, io + 1, output, 72, 68), STATUS_SUCCESS);
        let p = h.process.state();
        assert_eq!(p.space.ptr(io + 1, width).unwrap(), 0);
        assert_eq!(p.space.ptr(io + 1 + width, width).unwrap(), 72);
        assert_eq!(h.open(handle, io), STATUS_ACCESS_DENIED);

        h.name(r"\??\C:\Windows\System32");
        assert_eq!(h.open_with(handle, io, 0x100001, 7, 0x21), STATUS_SUCCESS);
        let directory = h.process.state().space.ptr(handle, width).unwrap();
        for name in ["unselected.exe", "missing.bin", "internal"] {
            h.name(name);
            let p = h.process.state();
            p.space.wptr(attrs + width, width, directory).unwrap();
            p.space.wr(output, &[0xa5; 88]).unwrap();
            let expected = if name == "unselected.exe" {
                STATUS_SUCCESS
            } else {
                STATUS_OBJECT_NAME_NOT_FOUND
            };
            assert_eq!(
                query(&mut h, attrs, io, output, 88, 68),
                expected,
                "{arch}/{name}"
            );
            let p = h.process.state();
            assert_eq!(p.space.ptr(io, width).unwrap(), u64::from(expected));
            if expected == STATUS_SUCCESS {
                assert_eq!(p.space.u64(output + 48).unwrap(), 10);
                assert_eq!(p.space.ptr(io + width, width).unwrap(), 72);
            } else {
                assert_eq!(p.space.bytes(output, 88).unwrap(), [0xa5; 88]);
                assert_eq!(p.space.ptr(io + width, width).unwrap(), 0);
            }
        }
        h.name(r"\??\C:\fixture.bin");
        assert_eq!(
            query(&mut h, attrs, io, output, 88, 68),
            STATUS_ACCESS_DENIED
        );
        assert!(!h.process.state().cfg.host_filesystem);
    }
}
