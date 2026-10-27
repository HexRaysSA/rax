use super::*;
use crate::user::windows::object_namespace::{ImageTemplate, image_tests};

#[test]
fn extension_query_classification_preserves_each_native_captured_kind() {
    let document: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../../../../docs/specifications/windows/native-image-extension-amd64/profiles-v1.json"
    ))
    .unwrap();
    let mut counts = [0; 3];
    for item in document["captures"].as_array().unwrap() {
        let capture = &item["capture"];
        assert_eq!(capture["state"], "complete");
        assert_eq!(capture["native_machine"], 0x8664);
        assert_eq!(capture["handles_before"], capture["handles_after"]);
        let build = capture["kernel"][2].as_u64().unwrap();
        assert_eq!(capture["samples"].as_array().unwrap().len(), 12);
        for sample in capture["samples"].as_array().unwrap() {
            for kind in 0..2 {
                let query = &sample["queries"][kind];
                assert_eq!(query["kind"], kind);
                assert_eq!(query["flags"], 0);
                assert_eq!(query["length"], 24);
                let status = query["status"].as_u64().unwrap() as u32;
                let expected = match (build, kind) {
                    (20348, _) => {
                        assert_eq!(status, STATUS_INVALID_INFO_CLASS);
                        counts[0] += 1;
                        Disposition::ClassUnavailable
                    }
                    (26100, 0) => {
                        assert_eq!(status, STATUS_SUCCESS);
                        assert_eq!(query["returned"], 24);
                        counts[1] += 1;
                        Disposition::Read
                    }
                    (26100, 1) => {
                        assert_eq!(status, STATUS_NOT_SUPPORTED);
                        assert_eq!(query["after"], query["before"]);
                        assert_eq!(query["returned"].as_u64(), Some(u64::MAX));
                        counts[2] += 1;
                        Disposition::KindUnavailable
                    }
                    _ => panic!("unexpected native profile"),
                };
                // Kind 1 is not reached after an unavailable class in the
                // snapshot. Its independent raw rejection remains verified.
                if build != 20348 || kind == 0 {
                    assert_eq!(classify(Some(0x8664), kind as u32, status), Ok(expected));
                }
            }
        }
    }
    assert_eq!(counts, [24, 12, 12]);
}

#[test]
fn extension_query_unavailable_kind_does_not_hide_other_failures() {
    for machine in [None, Some(0x14c), Some(0xaa64), Some(0xffff)] {
        assert_eq!(
            classify(machine, 1, STATUS_NOT_SUPPORTED),
            Err(STATUS_NOT_SUPPORTED)
        );
    }
    for (kind, status) in [
        (0, STATUS_NOT_SUPPORTED),
        (1, STATUS_INVALID_INFO_CLASS),
        (0, STATUS_ACCESS_DENIED),
        (1, STATUS_ACCESS_VIOLATION),
        (1, STATUS_INFO_LENGTH_MISMATCH),
    ] {
        assert_eq!(classify(Some(0x8664), kind, status), Err(status));
    }
}

#[test]
fn extension_query_policy_cannot_discard_payload_or_drift_between_rebases() {
    let native = || {
        let all =
            crate::user::windows::object_namespace::image_extension_tests::template(0x7000_0000);
        ImageTemplate::selected_extended(
            all.bytes.to_vec(),
            all.regions.clone(),
            [all.extensions[0].clone(), None],
        )
        .unwrap()
    };
    let captured =
        ImageTemplate::with_extension_query(native(), ExtensionQuery::NativeOnly).unwrap();
    assert_eq!(
        captured.extensions[0].as_ref().unwrap().bytes.as_ref(),
        vec![0xa5; 4096]
    );
    assert!(captured.extensions[1].is_none());
    assert_eq!(captured.allocation_size(), 12288);
    assert!(ImageTemplate::with_extension_query(native(), ExtensionQuery::Unavailable).is_err());
    let both = crate::user::windows::object_namespace::image_extension_tests::template(0x7000_0000);
    assert!(ImageTemplate::with_extension_query(both, ExtensionQuery::NativeOnly).is_err());
    let unavailable = ImageTemplate::with_extension_query(
        image_tests::template(0x7000_0000),
        ExtensionQuery::Unavailable,
    )
    .unwrap();
    assert_eq!(unavailable.extension_query, ExtensionQuery::Unavailable);
    let first = image_tests::template(0x5000_0000);
    let second = image_tests::template(0x5100_0000);
    assert!(ImageTemplate::with_rebase(unavailable, &first, &second).is_err());
}
