//! Independent native null-device opens through the real service dispatcher.
use super::*;
use crate::user::windows::objects::Object;

#[test]
fn native_null_device_opens_replay_all_46_observations_without_host_files() {
    let rows: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-null-device/open-observations-v1.json"
    )))
    .unwrap();
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 46);
    for arch in WinArch::ALL {
        let mut h = Harness::new(arch);
        // The null device has no host file and needs no filesystem capability.
        std::sync::Arc::make_mut(&mut h.process.state_mut().cfg).host_filesystem = false;
        let baseline = h.process.state().objects.handle_count();
        let mut simultaneous = Vec::new();
        for row in rows {
            let number = |key: &str| row[key].as_u64().unwrap();
            let id = number("id");
            h.name(row["name"].as_str().unwrap());
            let width = arch.ptr_size();
            let p = h.process.state_mut();
            p.space
                .w32(h.base + 8192 + 3 * width, number("flags") as u32)
                .unwrap();
            p.space.wr(h.base, &vec![0xff; width as usize]).unwrap();
            p.space
                .wr(h.base + 4096, &vec![0xff; 2 * width as usize])
                .unwrap();
            let access = number("access");
            let options = number("options");
            let share = number("share");
            let code = if row["create"].as_bool().unwrap() {
                h.invoke_api(
                    "NtCreateFile",
                    &[
                        h.base,
                        access,
                        h.attrs(),
                        h.base + 4096,
                        0,
                        0x80,
                        share,
                        number("disposition"),
                        options,
                        0,
                        0,
                    ],
                )
            } else {
                h.invoke_api(
                    "NtOpenFile",
                    &[h.base, access, h.attrs(), h.base + 4096, share, options],
                )
            };
            assert_eq!(code, number("status") as u32, "{arch}/native row {id}");
            let p = h.process.state_mut();
            if code == STATUS_SUCCESS {
                let handle = p.space.ptr(h.base, width).unwrap();
                assert_eq!(p.space.u32(h.base + 4096).unwrap(), 0);
                assert_eq!(p.space.ptr(h.base + 4096 + width, width).unwrap(), 0);
                let Object::File(file) = p.objects.get(handle).unwrap() else {
                    panic!("typed null file");
                };
                assert!(file.null && file.host.is_none() && !file.directory);
                if id >= 44 {
                    simultaneous.push(handle);
                } else {
                    drop(p.objects.close(handle).unwrap());
                }
            } else {
                let expected = if arch.is64() { arch.ptr(u64::MAX) } else { 0 };
                assert_eq!(p.space.ptr(h.base, width).unwrap(), expected);
                assert_eq!(p.space.u32(h.base + 4096).unwrap(), u32::MAX);
                assert_eq!(
                    p.space.ptr(h.base + 4096 + width, width).unwrap(),
                    arch.ptr(u64::MAX)
                );
            }
        }
        assert_eq!(simultaneous.len(), 2);
        for handle in simultaneous {
            drop(h.process.state_mut().objects.close(handle).unwrap());
        }
        assert_eq!(h.process.state().objects.handle_count(), baseline);
        assert_eq!(
            std::fs::read(h.directory.0.join("fixture.bin")).unwrap(),
            b"fixture"
        );
    }
}
