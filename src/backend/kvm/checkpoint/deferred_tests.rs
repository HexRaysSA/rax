use super::*;

#[test]
fn deferred_results_round_trip_both_codecs_without_changing_delivery_fields() {
    for exit in [
        VcpuExit::Hlt,
        VcpuExit::Shutdown,
        VcpuExit::SystemEvent {
            type_: u32::MAX,
            flags: u64::MAX,
        },
        VcpuExit::FailEntry { reason: u64::MAX },
        VcpuExit::InternalError,
        VcpuExit::Unknown(String::new()),
        VcpuExit::Unknown("native result: \u{3bb}".into()),
        VcpuExit::Unknown("x".repeat(MAX_DIAGNOSTIC_BYTES)),
    ] {
        let image = Image::capture(Some(&exit)).unwrap().unwrap();
        let json = serde_json::to_vec(&image).unwrap();
        let binary = crate::codec::serialize(&image).unwrap();
        for restored in [
            serde_json::from_slice::<Image>(&json).unwrap(),
            crate::codec::deserialize_strict::<Image>(&binary).unwrap(),
        ] {
            assert_eq!(restored, image);
            assert_eq!(
                format!("{:?}", restored.restore().unwrap()),
                format!("{exit:?}")
            );
        }
    }
    assert_eq!(Image::capture(None).unwrap(), None);
}

#[test]
fn deferred_records_reject_native_io_invalid_text_and_oversized_sequences() {
    for exit in [
        VcpuExit::IoIn { port: 1, size: 1 },
        VcpuExit::IoInString {
            port: 1,
            size: 1,
            count: 1,
        },
        VcpuExit::IoOut {
            port: 1,
            data: vec![0],
        },
        VcpuExit::MmioRead { addr: 1, size: 1 },
        VcpuExit::MmioWrite {
            addr: 1,
            data: vec![0],
        },
        VcpuExit::MmioRmw {
            addr: 1,
            size: 1,
            operation: crate::devices::bus::MmioRmwOp::Exchange(0),
        },
        VcpuExit::Debug,
        VcpuExit::Exception(1),
        VcpuExit::SystemCall,
        VcpuExit::Unknown("x".repeat(MAX_DIAGNOSTIC_BYTES + 1)),
    ] {
        assert!(Image::capture(Some(&exit)).is_err(), "{exit:?}");
    }
    for bytes in [vec![0xff], vec![0; MAX_DIAGNOSTIC_BYTES + 1]] {
        let image = Image::Unknown(bytes);
        assert!(image.validate().is_err());
        assert!(image.restore().is_err());
    }
    let oversized = Image::Unknown(vec![0; MAX_DIAGNOSTIC_BYTES + 1]);
    assert!(serde_json::from_slice::<Image>(&serde_json::to_vec(&oversized).unwrap()).is_err());
    assert!(
        crate::codec::deserialize_strict::<Image>(&crate::codec::serialize(&oversized).unwrap())
            .is_err()
    );
    assert!(
        serde_json::from_str::<Image>(r#"{"SystemEvent":{"type_":1,"flags":0,"extra":0}}"#)
            .is_err()
    );
    assert!(serde_json::from_str::<Image>(r#"{"IoIn":{"port":1,"size":1}}"#).is_err());
}
