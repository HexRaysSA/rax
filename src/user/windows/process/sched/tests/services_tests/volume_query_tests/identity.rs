//! Volume identity uses the initialized prefix and the requested label bytes.
use super::*;

fn assert_completion(p: &Proc, io: u64, output: u64, status: u32, data: &[u8], synchronous: bool) {
    let pointer = p.arch.ptr_size();
    assert_eq!(p.space.u32(io).unwrap(), status);
    if pointer == 8 {
        assert_eq!(
            p.space.u32(io + 4).unwrap(),
            if synchronous { 0xA5A5_A5A5 } else { 0 }
        );
    }
    assert_eq!(
        p.space.ptr(io + pointer, pointer).unwrap(),
        data.len() as u64
    );
    assert_eq!(p.space.bytes(io + 2 * pointer, 16).unwrap(), [0xA5; 16]);
    assert_eq!(p.space.bytes(output, data.len()).unwrap(), data);
    assert_eq!(
        p.space.bytes(output + data.len() as u64, 16).unwrap(),
        [0xA5; 16]
    );
}

#[test]
fn native_volume_identity_named_pipe_short_and_complete_records_all_abis() {
    let mut expected = [0u8; 36];
    expected[12] = 18;
    for (unit, slot) in "NamedPipe"
        .encode_utf16()
        .zip(expected[18..].chunks_exact_mut(2))
    {
        slot.copy_from_slice(&unit.to_le_bytes());
    }
    for arch in WinArch::ALL {
        for (length, status) in [
            (24, STATUS_BUFFER_OVERFLOW),
            (25, STATUS_BUFFER_OVERFLOW),
            (35, STATUS_BUFFER_OVERFLOW),
            (36, STATUS_SUCCESS),
            (64, STATUS_SUCCESS),
        ] {
            let (mut process, mut thread, base) = setup(arch);
            let p = process.state_mut();
            let pipe = p.objects.insert(Object::Pipe {
                pipe: 1,
                write: false,
            });
            let out = base + PAGE_SIZE;
            assert_eq!(
                invoke(p, &mut thread, &[u64::from(pipe), base, out, length, 1]),
                status
            );
            assert_completion(
                p,
                base,
                out,
                status,
                &expected[..expected.len().min(length as usize)],
                true,
            );
        }
    }
}

#[test]
fn native_volume_identity_rejects_short_misaligned_and_null_requests_all_abis() {
    for arch in WinArch::ALL {
        let (mut process, mut thread, base) = setup(arch);
        let p = process.state_mut();
        let null = u64::from(p.objects.insert(Object::Null));
        let out = base + PAGE_SIZE;
        for (handle, output, length, status) in [
            (0xDEAD, out + 4, 23, STATUS_INFO_LENGTH_MISMATCH),
            (null, out + 4, 24, STATUS_DATATYPE_MISALIGNMENT),
            (null, out, 24, STATUS_INVALID_DEVICE_REQUEST),
        ] {
            assert_eq!(
                invoke(p, &mut thread, &[handle, base, output, length, 1]),
                status
            );
            assert_eq!(p.space.bytes(base, 16).unwrap(), [0xA5; 16]);
            assert_eq!(p.space.bytes(out, 64).unwrap(), [0xA5; 64]);
        }
    }
}

#[cfg(windows)]
fn expected_disk(object: &Object) -> Vec<u8> {
    let Object::File(file) = object else {
        panic!("fixture expected a file");
    };
    attributes::native_record(file.host.as_ref().unwrap(), 1)
}

#[cfg(unix)]
fn expected_disk(object: &Object) -> Vec<u8> {
    use crate::user::windows::fs::FileIdentity;
    let Object::File(file) = object else {
        panic!("fixture expected a file");
    };
    let FileIdentity::Unix(device, _) = file.lifetime.identity else {
        panic!("fixture expected a Unix file");
    };
    let mut data = vec![0; 18];
    data[8..12].copy_from_slice(&(device as u32).to_le_bytes());
    data[16] = 1;
    data
}

#[test]
fn native_volume_identity_retained_file_and_directory_follow_handle_mode_all_abis() {
    for arch in WinArch::ALL {
        for directory in [false, true] {
            for asynchronous in [false, true] {
                let (object, path, _) = attributes::disk(directory, asynchronous);
                let expected = expected_disk(&object);
                let (mut process, mut thread, base) = setup(arch);
                let p = process.state_mut();
                let id = p.objects.create(object);
                let handle = p.objects.open_access(id, false, 0x12019f).unwrap();
                let out = base + PAGE_SIZE;
                assert_eq!(
                    invoke(p, &mut thread, &[u64::from(handle), base, out, 512, 1]),
                    STATUS_SUCCESS
                );
                assert_completion(p, base, out, STATUS_SUCCESS, &expected, !asynchronous);
                drop(p.objects.close(u64::from(handle)).unwrap());
                if directory {
                    std::fs::remove_dir(path).unwrap();
                } else {
                    std::fs::remove_file(path).unwrap();
                }
            }
        }
    }
}
