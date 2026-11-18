use super::{fixture, native_profile, registry_tests::call};
use crate::user::mm::PAGE_SIZE;
use crate::user::windows::arch::WinArch;
use crate::user::windows::memory::{Mem, mem, prot};
use crate::user::windows::nt::status::*;
use crate::user::windows::policy::{Catalog, DEVICE_FAMILY_NAME};
use std::sync::Arc;

#[test]
fn native_device_family_uses_the_captured_dword_and_native_output_lengths() {
    let (mut process, mut thread) = fixture(WinArch::Arm64, "NtQueryLicenseValue", 0x160);
    let p = process.state_mut();
    native_profile::kernel_profile(p, 29708, 0xaa64);
    let value = [0x78, 0x56, 0x34, 0x12];
    p.native.as_mut().unwrap().policy_catalog = Ok(Arc::new(Catalog::fixture([(
        DEVICE_FAMILY_NAME,
        4,
        value.to_vec(),
    )])));
    let (base, _) =
        p.vm.allocate(None, PAGE_SIZE, mem::RESERVE | mem::COMMIT, prot::READWRITE)
            .unwrap();
    let (name, data, kind, required) = (base + 64, base + 128, base + 256, base + 264);
    let units: Vec<_> = DEVICE_FAMILY_NAME.encode_utf16().collect();
    let bytes = 2 * units.len() as u16;
    p.space.w16(base, bytes).unwrap();
    p.space.w16(base + 2, bytes + 2).unwrap();
    p.space.w64(base + 8, name).unwrap();
    p.space.put_wunits(name, &units).unwrap();

    for capacity in [0, 1, 3, 4, 8] {
        p.space.wr(data, &[0xa5; 8]).unwrap();
        p.space.w32(kind, 0xa5a5a5a5).unwrap();
        p.space.w32(required, 0x5a5a5a5a).unwrap();
        let status = call(
            p,
            &mut thread,
            "NtQueryLicenseValue",
            &[
                base,
                kind,
                if capacity == 0 { 0 } else { data },
                capacity,
                required,
            ],
        );
        let mut expected = [0xa5; 8];
        if capacity >= 4 {
            expected[..4].copy_from_slice(&value);
            assert_eq!(status, STATUS_SUCCESS);
        } else {
            assert_eq!(status, STATUS_BUFFER_TOO_SMALL);
        }
        assert_eq!(p.space.bytes(data, 8).unwrap(), expected);
        assert_eq!(p.space.u32(kind).unwrap(), 4);
        assert_eq!(p.space.u32(required).unwrap(), 4);
    }

    assert_eq!(
        call(
            p,
            &mut thread,
            "NtQueryLicenseValue",
            &[base, 0, required, 4, required]
        ),
        STATUS_SUCCESS
    );
    assert_eq!(p.space.bytes(required, 4).unwrap(), value);

    for (output, length) in [(0, required), (data, 0)] {
        p.space.w32(kind, 0xa5a5a5a5).unwrap();
        p.space.w32(required, 0x5a5a5a5a).unwrap();
        assert_eq!(
            call(
                p,
                &mut thread,
                "NtQueryLicenseValue",
                &[base, kind, output, 4, length]
            ),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(p.space.u32(kind).unwrap(), 0xa5a5a5a5);
        assert_eq!(p.space.u32(required).unwrap(), 0x5a5a5a5a);
    }

    p.space.w16(name, u16::from(b'k')).unwrap();
    p.space.wr(data, &[0xa5; 8]).unwrap();
    assert_eq!(
        call(
            p,
            &mut thread,
            "NtQueryLicenseValue",
            &[base, kind, data, 4, required]
        ),
        STATUS_OBJECT_NAME_NOT_FOUND
    );
    assert_eq!(p.space.u32(required).unwrap(), 0);
    assert_eq!(p.space.u32(kind).unwrap(), 0xa5a5a5a5);
    assert_eq!(p.space.bytes(data, 8).unwrap(), [0xa5; 8]);
}
