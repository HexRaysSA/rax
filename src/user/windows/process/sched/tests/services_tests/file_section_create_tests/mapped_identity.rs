//! Mapped-file identity survives guest handle closure and ends with the view.
use super::super::super::section_map_tests;
use super::*;
use crate::user::mm::SharedObject;
use std::path::Path;

const COMPARE: &str = "NtAreMappedFilesTheSame";

fn invoke(p: &mut Proc, t: &mut Thread, name: &str, args: &[u64]) -> u32 {
    let module = p.modules.nt_services.as_ref().unwrap().0;
    p.modules.nt_services = Some((module, table(p.arch, name, 0x28)));
    section_map_tests::call(p, t, args)
}

fn map(p: &mut Proc, t: &mut Thread, out: u64, path: &Path, base: u64, attributes: u32) {
    let file = insert_file(p, path, 0x100021);
    assert_eq!(
        invoke(
            p,
            t,
            "NtCreateSection",
            &[out, 0xd, 0, 0, 2, attributes.into(), file]
        ),
        STATUS_SUCCESS
    );
    let section = get(p, out);
    p.objects.close(file).unwrap();
    let current = p.arch.ptr(u64::MAX);
    ptr(p, out, base);
    ptr(p, out + 16, 0);
    let status = invoke(
        p,
        t,
        "NtMapViewOfSection",
        &[section, current, out, 0, 0, 0, out + 16, 2, 0, 2],
    );
    assert_eq!(
        status,
        if attributes == 0x0800_0000 {
            STATUS_SUCCESS
        } else {
            STATUS_IMAGE_NOT_AT_BASE
        },
        "{attributes:#x} {base:#x}"
    );
    assert_eq!(get(p, out), base);
    p.objects.close(section).unwrap();
}

#[test]
fn native_mapped_file_identity_survives_close_and_matches_observed_roles() {
    for arch in WinArch::ALL {
        let directory = Directory::new();
        let original = directory.0.join("original.exe");
        let link = directory.0.join("link.exe");
        let copy = directory.0.join("copy.exe");
        std::fs::write(&original, image(arch)).unwrap();
        std::fs::hard_link(&original, &link).unwrap();
        std::fs::copy(&original, &copy).unwrap();
        let (mut process, mut thread) = fixture(arch, "NtCreateSection", SERVICE);
        let p = process.state_mut();
        let out = scratch(p);
        let handles = p.objects.handle_count();
        let mapped = [
            (&original, 0x0100_0000),
            (&original, 0x1100_0000),
            (&original, 0x0800_0000),
            (&original, 0x0800_0000),
            (&link, 0x0800_0000),
            (&copy, 0x0800_0000),
            (&copy, 0x0100_0000),
        ];
        let addresses: [u64; 11] =
            std::array::from_fn(|index| 0x5000_0000 + index as u64 * 0x10000);
        for ((path, attributes), address) in mapped.into_iter().zip(addresses) {
            map(p, &mut thread, out, path, address, attributes);
        }
        assert_eq!(p.objects.handle_count(), handles);
        let pagefile = Arc::new(SharedObject::anonymous(4096).unwrap());
        for address in &addresses[7..9] {
            p.vm.map_shared_view(pagefile.clone(), Some(*address), 0, 4096)
                .unwrap();
        }
        for (address, flags) in addresses[9..]
            .iter()
            .zip([mem::RESERVE | mem::COMMIT, mem::RESERVE])
        {
            p.vm.allocate(Some(*address), 4096, flags, prot::READWRITE)
                .unwrap();
        }
        // Literal rows from native kernel 10.0.29704, in the same role order.
        // S = success, D = different backing file, C = conflicting addresses.
        let rows = [
            b"SSSSSDDCCCC",
            b"SSSSSDDCCCC",
            b"CCCCCCCCCCC",
            b"CCCCCCCCCCC",
            b"CCCCCCCCCCC",
            b"CCCCCCCCCCC",
            b"DDDDDSSCCCC",
            b"CCCCCCCCCCC",
            b"CCCCCCCCCCC",
            b"CCCCCCCCCCC",
            b"CCCCCCCCCCC",
        ];
        for (i, (&first, row)) in addresses.iter().zip(rows).enumerate() {
            for (j, (&second, status)) in addresses.iter().zip(row).enumerate() {
                let expected = match status {
                    b'S' => STATUS_SUCCESS,
                    b'D' => STATUS_NOT_SAME_DEVICE,
                    b'C' => STATUS_CONFLICTING_ADDRESSES,
                    _ => unreachable!(),
                };
                for offset in [0, 0x40] {
                    assert_eq!(
                        invoke(p, &mut thread, COMPARE, &[first + offset, second + offset]),
                        expected,
                        "{arch} {i} {j} {offset:#x}"
                    );
                }
            }
        }
        for valid_or_invalid in addresses.into_iter().chain([0, 1]) {
            for invalid in [0, 1] {
                for args in [[invalid, valid_or_invalid], [valid_or_invalid, invalid]] {
                    assert_eq!(
                        invoke(p, &mut thread, COMPARE, &args),
                        STATUS_INVALID_ADDRESS
                    );
                }
            }
        }

        let [first, _, data, ..] = addresses;
        let current = arch.ptr(u64::MAX);
        assert_eq!(
            invoke(p, &mut thread, "NtUnmapViewOfSection", &[current, first]),
            STATUS_SUCCESS
        );
        assert_eq!(
            invoke(p, &mut thread, COMPARE, &[first, data]),
            STATUS_INVALID_ADDRESS
        );
        p.vm.allocate(
            Some(first),
            4096,
            mem::RESERVE | mem::COMMIT,
            prot::READWRITE,
        )
        .unwrap();
        assert_eq!(
            invoke(p, &mut thread, COMPARE, &[first, data]),
            STATUS_CONFLICTING_ADDRESSES
        );
    }
}
