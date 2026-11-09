use super::*;
use vm_memory::{Bytes, GuestMemory};

const NAME: &str = "vm::memory::windows_backing::tests::reserved_ram_preserves_extent_aliases_and_zero_scan_without_padding_commit";
const CHILD: &str = "RAX_RESERVED_RAM_TEST_CHILD";

#[repr(C)]
struct Counters {
    bytes: u32,
    page_faults: u32,
    sizes: [usize; 9],
}

#[link(name = "psapi")]
unsafe extern "system" {
    fn GetProcessMemoryInfo(process: *mut c_void, counters: *mut Counters, bytes: u32) -> i32;
}

fn private_bytes() -> usize {
    let mut counters = Counters {
        bytes: std::mem::size_of::<Counters>() as u32,
        page_faults: 0,
        sizes: [0; 9],
    };
    // SAFETY: current-process pseudo-handle and initialized, exact-size
    // PROCESS_MEMORY_COUNTERS_EX storage with the native pointer width.
    assert_ne!(
        unsafe {
            GetProcessMemoryInfo(
                usize::MAX as *mut c_void,
                &mut counters,
                std::mem::size_of::<Counters>() as u32,
            )
        },
        0
    );
    counters.sizes[8]
}

#[test]
fn reserved_ram_preserves_extent_aliases_and_zero_scan_without_padding_commit() {
    if std::env::var_os(CHILD).is_none() {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--nocapture"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "isolated native RAM probe failed:\n{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(String::from_utf8_lossy(&result.stdout).contains("private_commit_delta_bytes="));
        return;
    }
    let bytes = (4usize << 30) + 65536;
    let before = private_bytes();
    let first = allocate(bytes).unwrap();
    let second = allocate(bytes).unwrap();
    assert_eq!(first.last_addr().0, bytes as u64 - 1);
    assert_eq!(second.last_addr().0, bytes as u64 - 1);
    let mut scratch = [0xff; 65536];
    for offset in (0..bytes).step_by(scratch.len()) {
        let count = scratch.len().min(bytes - offset);
        read(&first, offset as u64, &mut scratch[..count])
            .unwrap()
            .unwrap();
        assert!(scratch[..count].iter().all(|byte| *byte == 0));
    }
    first
        .write_slice(&[0x5a], GuestAddress(bytes as u64 - 1))
        .unwrap();
    second.write_slice(&[0x37], GuestAddress(0)).unwrap();
    let retained = first.clone();
    drop(first);
    let mut byte = [0];
    read(&retained, bytes as u64 - 1, &mut byte)
        .unwrap()
        .unwrap();
    assert_eq!(byte, [0x5a]);
    read(&second, bytes as u64 - 1, &mut byte).unwrap().unwrap();
    assert_eq!(byte, [0]);
    let delta = private_bytes().saturating_sub(before);
    assert!(
        delta < 128 << 20,
        "two full RAM extents charged {delta} private bytes"
    );
    println!("private_commit_delta_bytes={delta}");
    drop(second);
    drop(retained);
    let wrapper = super::super::GuestMemoryWrapper::new(65536).unwrap();
    assert_eq!(wrapper.size(), 65536);
    assert_eq!(wrapper.actual_size(), 65536 + (4u64 << 30));
}

#[test]
fn commitment_failure_and_invalid_ranges_never_publish_new_pages() {
    assert!(Owner::reserve(0).is_err());
    assert!(Owner::reserve(usize::MAX).is_err());
    let owner = Owner::reserve(65536).unwrap();
    owner.commit(0, 1).unwrap();
    let before = owner.committed.lock().unwrap().clone();
    let error = owner
        .commit_with(owner.page, 1, |_, _| {
            Err(io::Error::from(io::ErrorKind::OutOfMemory))
        })
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
    assert_eq!(*owner.committed.lock().unwrap(), before);
    for (offset, count) in [(65536, 1), (usize::MAX, 1), (1, usize::MAX)] {
        assert!(
            owner
                .commit_with(offset, count, |_, _| panic!(
                    "invalid range reached native commitment"
                ))
                .is_err()
        );
    }
    owner
        .commit_with(65536, 0, |_, _| {
            panic!("empty range reached native commitment")
        })
        .unwrap();
    let mut zeros = [1; 3];
    owner.read(owner.page - 1, &mut zeros).unwrap();
    assert_eq!(zeros, [0; 3]);
    assert_eq!(*owner.committed.lock().unwrap(), before);
}

#[test]
fn stopped_reads_preserve_cross_page_writes_and_fall_back_for_foreign_mappings() {
    let memory = allocate(65536).unwrap();
    let mut expected = vec![0; 65536];
    for (offset, bytes) in [
        (0, &[0x13][..]),
        (4095, &[1, 2, 3][..]),
        (65535, &[0x7f][..]),
    ] {
        memory
            .write_slice(bytes, GuestAddress(offset as u64))
            .unwrap();
        expected[offset..offset + bytes.len()].copy_from_slice(bytes);
    }
    let mut actual = vec![0xaa; expected.len()];
    super::super::read_checkpoint_memory(&memory, 0, &mut actual).unwrap();
    assert_eq!(actual, expected);
    let foreign = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 4096)]).unwrap();
    foreign.write_slice(&[0x53, 0x17], GuestAddress(0)).unwrap();
    assert!(read(&foreign, 0, &mut actual[..2]).is_none());
    super::super::read_checkpoint_memory(&foreign, 0, &mut actual[..2]).unwrap();
    assert_eq!(actual[..2], [0x53, 0x17]);
}
