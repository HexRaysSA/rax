//! Replay selected native extended section unmap against owned guest views.
use super::*;
use crate::user::mm::SharedObject;

const CAPTURE: &str = include_str!(
    "../../../../../../../docs/specifications/windows/native-unmap-section-ex/unmap-29708-v1.txt"
);

#[test]
fn native_section_unmap_ex_matches_measured_view_lifetime_and_status_order() {
    assert_eq!(CAPTURE.lines().count(), 96);
    for arch in WinArch::ALL {
        let (mut process, mut thread) = fixture(arch, "NtUnmapViewOfSectionEx", SERVICE);
        let p = process.state_mut();
        let self_handle = arch.ptr(u64::MAX);
        let process_id = p.objects.create(Object::Process {
            pid: p.pid,
            exit_code: None,
        });
        let allowed = u64::from(p.objects.open_access(process_id, false, 8).unwrap());
        let denied = u64::from(p.objects.open_access(process_id, false, 0x1000).unwrap());
        let wrong_id = p.objects.create(Object::PipeDirectory);
        let wrong = u64::from(p.objects.open_access(wrong_id, false, 8).unwrap());
        let private = scratch(p);
        for line in CAPTURE.lines() {
            let row: Vec<u32> = line
                .split_ascii_whitespace()
                .map(|field| u32::from_str_radix(field, 16).unwrap())
                .collect();
            let [
                case,
                flags,
                status,
                state_before,
                state_after,
                mirror,
                repeat,
            ] = row.try_into().expect("seven native fields");
            let backing = Arc::new(SharedObject::anonymous(65536).unwrap());
            let first =
                p.vm.map_shared_view(backing.clone(), None, 0, 65536)
                    .unwrap();
            let alias = p.vm.map_shared_view(backing, None, 0, 65536).unwrap();
            let view = first.base;
            p.space.w8(view + 4097, 0x71).unwrap();
            let (handle, address) = match case {
                0 => (self_handle, view),
                1 => (self_handle, view + 4097),
                2 => (allowed, view),
                3 => (denied, view + 4097),
                4 => (wrong, view),
                5 => (0, view + 4097),
                6 => (self_handle, private + 4097),
                7 => (self_handle, 0),
                8 => (self_handle, view + 4096),
                9 => (self_handle, view + 1),
                10 => (self_handle, view + 8192),
                11 => (self_handle, view + 65535),
                12 => (self_handle, private),
                13 => (self_handle, private + 4096),
                14 => (self_handle, 1),
                15 => (self_handle, 0x5000_0000),
                _ => panic!("unknown captured case {case}"),
            };
            let observation = match case {
                6 | 12 | 13 => Some(private),
                7 | 14 | 15 => {
                    assert!(p.vm.allocation(address).is_none());
                    None
                }
                _ => Some(view),
            };
            if let Some(base) = observation {
                assert_eq!(p.vm.query(base).unwrap().state, state_before);
            }
            let args = [handle, address, u64::from(flags)];
            assert_eq!(
                call(p, &mut thread, &args),
                status,
                "{arch} case={case} flags={flags:#x}"
            );
            if let Some(base) = observation {
                assert_eq!(p.vm.query(base).unwrap().state, state_after);
                let observed_mirror = if base == view {
                    alias.base + 4097
                } else {
                    address
                };
                assert_eq!(u32::from(p.space.u8(observed_mirror).unwrap()), mirror);
            }
            if repeat != u32::MAX {
                assert_eq!(call(p, &mut thread, &args), repeat);
            }
            p.vm.retire_shared_view(&first).unwrap();
            p.vm.retire_shared_view(&alias).unwrap();
        }
    }
}
