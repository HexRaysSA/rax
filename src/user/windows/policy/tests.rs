use super::*;
use serde::Deserialize;

#[derive(Deserialize)]
struct Corpus {
    cases: Vec<Case>,
}
#[derive(Deserialize)]
struct Case {
    direction_sweep: String,
    index: u32,
    request_hex: String,
    native_status: u32,
    reply_context: Option<String>,
    reply_key: Option<u64>,
    cipher_prefix: Option<String>,
    plain_prefix: Option<String>,
    reply_fields: Option<Vec<String>>,
    native_output_bytes: Option<usize>,
}

fn decode(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn native_request_and_response_cipher_sweeps_replay_exact_defined_blocks() {
    let corpus: Corpus = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-system-policy/cipher-controls-v1.json"
    )))
    .unwrap();
    assert_eq!(corpus.cases.len(), 296);
    let catalog = Catalog::fixture([("Kernel-BrandingInfo", 4, 48u32.to_le_bytes().to_vec())]);
    let mut success = 0;
    for case in corpus.cases {
        let label = format!("{}/{}", case.direction_sweep, case.index);
        let request = decode(&case.request_hex);
        let native = blocks(&request).unwrap();
        let ctx: &[u8; 160] = native[1].try_into().unwrap();
        let key = u64::from_le_bytes(native[2].try_into().unwrap());
        let input = &native[0][..native[0].len() - 8];
        let plain = codec::transform(input, ctx, key, Direction::Request, true).unwrap();
        assert_eq!(
            codec::transform(&plain, ctx, key, Direction::Request, false).unwrap(),
            input,
            "{label}"
        );
        let actual = query(&catalog, &request);
        if case.native_status != 0 {
            assert!(
                matches!(actual,Err(Error::Status(status)) if status==case.native_status),
                "{label}: {actual:?}"
            );
            continue;
        }
        success += 1;
        let context = decode(case.reply_context.as_ref().unwrap());
        let context: &[u8; 160] = context.as_slice().try_into().unwrap();
        let key = case.reply_key.unwrap();
        let cipher = decode(case.cipher_prefix.as_ref().unwrap());
        let expected = decode(case.plain_prefix.as_ref().unwrap());
        assert_eq!(
            codec::transform(&cipher, context, key, Direction::Reply, true).unwrap(),
            expected,
            "{label}"
        );
        assert_eq!(
            codec::transform(&expected, context, key, Direction::Reply, false).unwrap(),
            cipher,
            "{label}"
        );
        let reply = actual.unwrap();
        assert_eq!(reply.len(), case.native_output_bytes.unwrap(), "{label}");
        let encoded = blocks(&reply).unwrap();
        assert_eq!(encoded[1], context);
        assert_eq!(encoded[2], key.to_le_bytes());
        let body = encoded[0];
        let plain = codec::transform(
            &body[..body.len() - 8],
            context,
            key,
            Direction::Reply,
            true,
        )
        .unwrap();
        assert_eq!(
            checksum(&plain),
            u64::from_le_bytes(body[body.len() - 8..].try_into().unwrap())
        );
        let size = word(&plain[4..8]).unwrap() as usize;
        let fields = blocks(&plain[8..8 + size]).unwrap();
        let expected: Vec<_> = case
            .reply_fields
            .unwrap()
            .iter()
            .map(|f| decode(f))
            .collect();
        assert_eq!(fields, expected, "{label}");
        assert!(plain[8 + size..].iter().all(|&byte| byte == 0));
        let mut damaged = request.clone();
        damaged[4 + native[0].len() - 1] ^= 0x80;
        assert!(matches!(
            query(&catalog, &damaged),
            Err(Error::Status(STATUS_UNSUCCESSFUL))
        ));
    }
    assert_eq!(success, 266);
}

#[test]
fn packet_extents_and_checksum_are_checked_before_policy_lookup() {
    let corpus: Corpus = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/specifications/windows/native-system-policy/cipher-controls-v1.json"
    )))
    .unwrap();
    let request = decode(&corpus.cases[0].request_hex);
    let catalog = Catalog::fixture([]);
    for size in 0..request.len() {
        assert!(
            query(&catalog, &request[..size]).is_err(),
            "truncation {size}"
        );
    }
    for size in [u32::MAX, u32::MAX - 3, 0, 8] {
        let mut bad = request.clone();
        bad[..4].copy_from_slice(&size.to_le_bytes());
        assert!(query(&catalog, &bad).is_err());
    }
    assert!(codec::transform(&[0; 7], &[0; 160], 0, Direction::Request, true).is_none());
}

#[test]
fn host_qualification_is_a_fixed_size_only_query_with_all_reply_selectors() {
    let request = qualification_request();
    let outer = blocks(&request).unwrap();
    let context: &[u8; 160] = outer[1].try_into().unwrap();
    assert!(context.iter().all(|&byte| byte == 255));
    let key = u64::from_le_bytes(outer[2].try_into().unwrap());
    let plain = codec::transform(
        &outer[0][..outer[0].len() - 8],
        context,
        key,
        Direction::Request,
        true,
    )
    .unwrap();
    let fields = blocks(&plain[8..8 + word(&plain[4..8]).unwrap() as usize]).unwrap();
    assert_eq!(fields[0], 0u32.to_le_bytes());
    assert_eq!(
        fields[4],
        "Kernel-BrandingInfo\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>()
    );
    assert_eq!(fields[6], 0u32.to_le_bytes());
    assert_eq!(&fields[1][128..159], &(0u8..31).collect::<Vec<_>>());
    let catalog = Catalog::fixture([("Kernel-BrandingInfo", 4, 48u32.to_le_bytes().to_vec())]);
    assert_eq!(query(&catalog, &request).unwrap().len(), 244);
}
