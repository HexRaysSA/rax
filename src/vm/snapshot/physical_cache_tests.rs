//! Cached admission must remain bound to the exact image and projection.
use super::*;

fn fixture() -> (PhysicalMemorySnapshot, Vec<u8>, GuestMemoryMmap) {
    let memory =
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096), (GuestAddress(0x8000), 8192)])
            .unwrap();
    memory
        .write_slice(&vec![0x51; 4096], GuestAddress(0))
        .unwrap();
    memory
        .write_slice(&vec![0xa7; 8192], GuestAddress(0x8000))
        .unwrap();
    let (saved, projection) =
        PhysicalMemorySnapshot::capture_with_projection(&memory, 4096).unwrap();
    (saved, projection, memory)
}

#[test]
fn cached_images_reject_changed_frames_digests_and_declared_lengths() {
    let (saved, _, memory) = fixture();
    saved.verify().unwrap();
    for corruption in 0..3 {
        let mut corrupt = saved.clone();
        match corruption {
            0 => corrupt.regions[1].data[0] ^= 1,
            1 => corrupt.regions[1].digest[0] ^= 1,
            2 => corrupt.regions[1].size += 1,
            _ => unreachable!(),
        }
        // The last region fails admission before the first destination byte.
        memory.write_slice(&[0x99; 4096], GuestAddress(0)).unwrap();
        assert!(corrupt.restore(&memory).is_err());
        let mut first = [0; 4096];
        memory.read_slice(&mut first, GuestAddress(0)).unwrap();
        assert_eq!(first, [0x99; 4096]);
        assert!(corrupt.verify().is_err());
    }
    saved.verify().unwrap();
}

#[test]
fn projection_cache_checks_content_size_and_the_complete_physical_image() {
    let (saved, projection, _) = fixture();
    saved.verify_projection(&projection, 4096).unwrap();
    let changed = zstd::encode_all(&[0x52; 4096][..], 3).unwrap();
    assert!(saved.verify_projection(&changed, 4096).is_err());
    assert!(saved.verify_projection(&projection, 4095).is_err());
    let mut corrupt = saved.clone();
    corrupt.regions[1].digest[0] ^= 1;
    // Even a physical region beyond the legacy projection remains admitted.
    assert!(corrupt.verify_projection(&projection, 4096).is_err());
    saved.verify_projection(&projection, 4096).unwrap();
}

#[test]
fn wire_roundtrip_keeps_legacy_bytes_and_verifies_untrusted_images() {
    let (saved, projection, _) = fixture();
    let mut raw = Vec::new();
    saved.write_to(&mut raw).unwrap();
    assert_eq!(raw.len() as u64, saved.encoded_len().unwrap());
    assert_eq!(&raw[..8], b"RAXRAM01");
    let loaded =
        PhysicalMemorySnapshot::read_from(&mut raw.as_slice(), raw.len() as u64, 0).unwrap();
    for _ in 0..3 {
        loaded.verify().unwrap();
        loaded.verify_projection(&projection, 4096).unwrap();
    }
    let mut rewritten = Vec::new();
    loaded.write_to(&mut rewritten).unwrap();
    assert_eq!(rewritten, raw);
    let target =
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096), (GuestAddress(0x8000), 8192)])
            .unwrap();
    loaded.restore(&target).unwrap();
    for (address, size, expected) in [(0, 4096, 0x51), (0x8000, 8192, 0xa7)] {
        let mut bytes = vec![0; size];
        target
            .read_slice(&mut bytes, GuestAddress(address))
            .unwrap();
        assert!(bytes.iter().all(|&byte| byte == expected));
    }
}

#[test]
fn failed_visitors_cannot_certify_unvisited_invalid_regions() {
    let (saved, _, _) = fixture();
    let mut raw = Vec::new();
    saved.write_to(&mut raw).unwrap();
    let mut loaded =
        PhysicalMemorySnapshot::read_from(&mut raw.as_slice(), raw.len() as u64, 0).unwrap();
    loaded.regions[1].digest[0] ^= 1;
    assert!(loaded.visit(|_, _| Err(invalid("visitor failed"))).is_err());
    assert!(loaded.verify().is_err());
}
