use super::*;
use crate::user::windows::fs::FileNameOrigin;

#[test]
fn file_information_all_preserves_guest_grants_name_extent_and_iosb_order() {
    let root = std::env::temp_dir().join(format!("rax-file-all-info-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("file-all.bin");
    std::fs::write(&path, b"file information fixture").unwrap();
    let name: Vec<u8> = "\\file-all.bin"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let full_length = 100 + name.len();
    for arch in WinArch::ALL {
        let (mut process, mut thread, base) = setup(arch);
        let state = process.state_mut();
        let output = base + PAGE_SIZE;
        for asynchronous in [false, true] {
            let id = state
                .objects
                .create(names::fixture_object(&path, asynchronous, 0));
            state.objects.set_file_name_origin(
                id,
                FileNameOrigin::capture(&root, Vec::new()).map_err(|e| e.to_string()),
            );
            let handle = u64::from(state.objects.open_access(id, false, 0).unwrap());
            for (length, skew, expected_status, information) in [
                (103, 0, STATUS_INFO_LENGTH_MISMATCH, 0),
                (104, 0, STATUS_BUFFER_OVERFLOW, 104),
                (105, 0, STATUS_BUFFER_OVERFLOW, 104),
                (512, 0, STATUS_SUCCESS, full_length),
                if arch == WinArch::X86 {
                    (512, 1, STATUS_SUCCESS, full_length)
                } else {
                    (512, 4, STATUS_DATATYPE_MISALIGNMENT, 0)
                },
            ] {
                state.space.wr(base, &[0xa5; 16]).unwrap();
                state.space.wr(output, &[0xa5; 520]).unwrap();
                assert_eq!(
                    invoke(
                        state,
                        &mut thread,
                        &[handle, base, output + skew, length, 18]
                    ),
                    expected_status,
                    "{arch}, length {length}, asynchronous {asynchronous}"
                );
                if information == 0 {
                    assert_eq!(state.space.bytes(base, 16).unwrap(), [0xa5; 16]);
                    assert_eq!(state.space.bytes(output, 520).unwrap(), [0xa5; 520]);
                    continue;
                }
                assert_eq!(state.space.u32(base).unwrap(), expected_status);
                let base_information = base + arch.ptr_size();
                assert_eq!(
                    state.space.u32(base_information).unwrap(),
                    information as u32
                );
                if arch != WinArch::X86 {
                    let status_high = if asynchronous { 0 } else { 0xa5a5_a5a5 };
                    assert_eq!(state.space.u32(base + 4).unwrap(), status_high);
                    assert_eq!(state.space.u32(base_information + 4).unwrap(), 0);
                }
                let address = output + skew;
                assert_eq!(state.space.u32(address + 76).unwrap(), 0);
                assert_eq!(state.space.u64(address + 80).unwrap(), 0);
                assert_eq!(
                    state.space.u32(address + 88).unwrap(),
                    if asynchronous { 0 } else { 0x20 }
                );
                assert_eq!(state.space.u32(address + 96).unwrap(), name.len() as u32);
                assert_eq!(
                    state.space.bytes(address + 100, information - 100).unwrap(),
                    name[..information - 100]
                );
                assert_eq!(state.space.u8(address + information as u64).unwrap(), 0xa5);
            }
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}
