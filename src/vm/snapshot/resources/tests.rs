use super::*;
fn wire(resources: Vec<CheckpointResource>) -> Vec<u8> {
    let snapshot = ResourcesSnapshot::capture(resources).unwrap();
    let mut raw = Vec::new();
    snapshot.write_to(&mut raw).unwrap();
    assert_eq!(raw.len() as u64, snapshot.encoded_len().unwrap());
    raw
}
fn decode(mut raw: &[u8]) -> Result<ResourcesSnapshot> {
    let length = raw.len() as u64;
    ResourcesSnapshot::read_from(&mut raw, length)
}
fn medium(bytes: &[u8]) -> CheckpointResource {
    CheckpointResource::boot_cdrom(Arc::new(bytes.to_vec())).unwrap()
}
#[test]
fn duplicate_cpu_bindings_share_complete_prepared_media() {
    let a = medium(b"previously unread sector bytes");
    let key = a.key();
    let raw = wire(vec![
        a.clone(),
        a,
        medium(b"previously unread sector bytes"),
    ]);
    let snapshot = decode(&raw).unwrap();
    assert_eq!(snapshot.keys().count(), 1);
    let first = snapshot.prepare().unwrap();
    let second = snapshot.prepare().unwrap();
    assert!(Arc::ptr_eq(&first, &second));
    assert!(Arc::ptr_eq(
        &first.resolve(key).unwrap(),
        &second.resolve(key).unwrap()
    ));
    assert_eq!(
        first.resolve(key).unwrap().as_slice(),
        b"previously unread sector bytes"
    );
}

#[test]
fn existing_binding_preparation_retains_the_original_arc_without_reencoding() {
    let bytes = Arc::new(vec![0xa5; 2048]);
    let binding = CheckpointResource::boot_cdrom(bytes.clone()).unwrap();
    let key = binding.key();
    let prepared = PreparedResources::from_bindings(vec![binding.clone(), binding]).unwrap();
    assert_eq!(prepared.keys().count(), 1);
    assert!(Arc::ptr_eq(&prepared.resolve(key).unwrap(), &bytes));
    assert_eq!(
        PreparedResources::from_bindings(Vec::new())
            .unwrap()
            .keys()
            .count(),
        0
    );
}
#[test]
fn empty_bound_medium_remains_present_and_differs_from_missing() {
    let input = medium(b"");
    let key = input.key();
    let raw = wire(vec![input]);
    let prepared = decode(&raw).unwrap().prepare().unwrap();
    assert_eq!(prepared.keys().collect::<Vec<_>>(), [key]);
    assert!(prepared.resolve(key).unwrap().is_empty());
    assert!(PreparedResources::default().resolve(key).is_err());
}
#[test]
fn every_truncation_and_unframed_trailer_is_rejected() {
    let raw = wire(vec![medium(b"alpha"), medium(b"beta")]);
    for end in 0..raw.len() {
        assert!(decode(&raw[..end]).is_err(), "prefix {end}");
    }
    let mut trailer = raw.clone();
    trailer.push(0);
    assert!(decode(&trailer).is_err());
    let mut reader = raw.as_slice();
    assert!(ResourcesSnapshot::read_from(&mut reader, MAX_SECTION + 1).is_err());
}

#[test]
fn bundle_budget_rejects_the_table_before_reading_any_resource_payload() {
    let raw = wire(vec![medium(b"alpha")]);
    let mut reader = Cursor::new(raw.as_slice());
    let error =
        ResourcesSnapshot::read_from_with_budget(&mut reader, raw.len() as u64, 4).unwrap_err();
    assert!(error.to_string().contains("budget"), "{error}");
    assert_eq!(reader.position(), HEADER + ROW);
    let mut reader = raw.as_slice();
    assert_eq!(
        ResourcesSnapshot::read_from_with_budget(&mut reader, raw.len() as u64, 5)
            .unwrap()
            .total_bytes(),
        5
    );
}
#[test]
fn duplicate_unordered_unknown_and_oversized_table_rows_are_rejected() {
    let raw = wire(vec![medium(b"alpha"), medium(b"beta")]);
    let mut duplicate = raw.clone();
    let first = duplicate[12..64].to_vec();
    duplicate[64..116].copy_from_slice(&first);
    assert!(decode(&duplicate).is_err());
    let mut unordered = raw.clone();
    let first = unordered[12..64].to_vec();
    let second = unordered[64..116].to_vec();
    unordered[12..64].copy_from_slice(&second);
    unordered[64..116].copy_from_slice(&first);
    assert!(decode(&unordered).is_err());
    for (offset, bytes) in [
        (12, u32::MAX.to_le_bytes().to_vec()),
        (16, u64::MAX.to_le_bytes().to_vec()),
        (56, u64::MAX.to_le_bytes().to_vec()),
    ] {
        let mut bad = raw.clone();
        bad[offset..offset + bytes.len()].copy_from_slice(&bytes);
        assert!(decode(&bad).is_err());
    }
}
#[test]
fn corrupted_digest_and_late_frame_are_rejected_before_publication() {
    let raw = wire(vec![medium(b"alpha"), medium(b"beta")]);
    let mut digest = raw.clone();
    digest[24] ^= 1;
    assert!(decode(&digest).is_err());
    let mut late = raw;
    *late.last_mut().unwrap() ^= 0xff;
    assert!(decode(&late).is_err());
}
#[test]
fn compressed_concatenation_and_skippable_trailers_are_rejected() {
    let raw = wire(vec![medium(b"alpha")]);
    for extra in [
        zstd::stream::encode_all(&b""[..], 3).unwrap(),
        vec![0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0],
        vec![0],
    ] {
        let mut bad = raw.clone();
        bad.extend_from_slice(&extra);
        let length = (bad.len() - 64) as u64;
        bad[56..64].copy_from_slice(&length.to_le_bytes());
        assert!(decode(&bad).is_err());
    }
}
#[test]
fn excessive_window_and_skippable_only_empty_resource_are_rejected() {
    let mut window = wire(vec![medium(&[b'A'; 1024])]);
    assert_eq!(
        window[68] & 0x20,
        0,
        "fixture must carry an explicit window descriptor"
    );
    window[69] = (27 - 10) << 3; // Valid 128 MiB window, above the wire's 8 MiB cap.
    assert!(decode(&window).is_err());
    let mut skip = wire(vec![medium(b"")]);
    skip.truncate(64);
    skip.extend_from_slice(&[0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0]);
    skip[56..64].copy_from_slice(&8u64.to_le_bytes());
    assert!(decode(&skip).is_err());
}
#[test]
fn complete_media_larger_than_cpu_context_limit_roundtrips() {
    let mut seed = 0x123456789abcdefu64;
    let bytes: Vec<u8> = (0..20 * 1024 * 1024)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed as u8
        })
        .collect();
    let input = medium(&bytes);
    let key = input.key();
    let raw = wire(vec![input]);
    assert!(raw.len() > 16 * 1024 * 1024);
    let restored = decode(&raw)
        .unwrap()
        .prepare()
        .unwrap()
        .resolve(key)
        .unwrap();
    assert_eq!(*restored, bytes);
}

#[test]
fn pc_buffer_resources_round_trip_and_keep_interpretation_distinct_from_boot_media() {
    let boot = medium(b"same bytes");
    let bytes = CheckpointResource::pc_device_bytes(b"same bytes".to_vec()).unwrap();
    assert_ne!(boot.key(), bytes.key());
    assert_eq!(boot.key().sha256(), bytes.key().sha256());
    let key = bytes.key();
    let raw = wire(vec![boot, bytes.clone(), bytes]);
    let snapshot = decode(&raw).unwrap();
    assert_eq!(snapshot.keys().count(), 2);
    assert_eq!(
        &**snapshot.prepare().unwrap().resolve(key).unwrap(),
        b"same bytes"
    );
}

#[test]
fn gsc_state_bounds_and_ap_flash_identity_are_admitted_before_use() {
    for size in [0, 8, MAX_GSC_STATE_BYTES as u64 + 1, u64::MAX] {
        assert!(
            ResourceKey {
                kind: GSC_STATE_RESOURCE,
                size,
                digest: [0; 32]
            }
            .validate()
            .is_err()
        );
    }
    let a = CheckpointResource::gsc_ap_flash(Arc::new(vec![1, 2, 3])).unwrap();
    let b = CheckpointResource::gsc_ap_flash(Arc::new(vec![1, 2, 3])).unwrap();
    let empty = CheckpointResource::gsc_ap_flash(Arc::new(Vec::new())).unwrap();
    assert_eq!(a.key(), b.key());
    assert_ne!(a.key(), empty.key());
    assert_eq!(a.key().kind(), GSC_AP_FLASH_RESOURCE);
    let prepared = PreparedResources::from_bindings(vec![a, b, empty]).unwrap();
    assert_eq!(prepared.keys().count(), 2);
}
