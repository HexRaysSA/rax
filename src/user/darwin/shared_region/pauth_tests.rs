//! Signed shared-cache page contents and key-domain cache isolation.

use super::*;
use crate::isa::arm::aarch64::pauth::PauthAlgorithm;
use crate::user::darwin::arch::DarwinCpu;
use crate::user::mm::BytesSource;

const BASE: u64 = 0x1_8000_0000;
const MAPPING: u64 = BASE + 0x4000;

fn raw_page() -> Arc<[u8]> {
    let mut bytes = vec![0u8; 8192];
    let code = 0x40 | (0x77 << 34) | (1u64 << 52) | (1u64 << 63);
    let data = 0x80 | (0x66 << 34) | (1u64 << 50) | (1u64 << 51) | (1u64 << 63);
    bytes[4096 + 0x10..4096 + 0x18].copy_from_slice(&code.to_le_bytes());
    bytes[4096 + 0x18..4096 + 0x20].copy_from_slice(&data.to_le_bytes());
    bytes.into()
}

fn source(bytes: Arc<[u8]>) -> SlidSource {
    SlidSource::from_source(
        Arc::new(BytesSource::new(bytes)),
        4096,
        4096,
        SlideInfo::V5 {
            page_size: 4096,
            page_starts: vec![0x10],
            value_add: BASE,
        },
        0,
    )
    .unwrap()
}

fn read(source: &SlidSource) -> [u64; 2] {
    let mut bytes = [0u8; 16];
    assert_eq!(source.read_at(4096 + 0x10, &mut bytes).unwrap(), 16);
    [
        u64::from_le_bytes(bytes[..8].try_into().unwrap()),
        u64::from_le_bytes(bytes[8..].try_into().unwrap()),
    ]
}

#[test]
fn darwin_pauth_shared_cache_v5_uses_guest_storage_address_and_independent_vectors() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../docs/specifications/arm/pauth/darwin-vectors.json"
    ))
    .unwrap();
    for (q, algorithm) in [(0, PauthAlgorithm::Qarma5), (1, PauthAlgorithm::Qarma3)] {
        let DarwinCpu::Arm64(cpu) = crate::user::darwin::pauth::tests::cpu(algorithm, true) else {
            unreachable!()
        };
        let auth = UserPauth::from_cpu(&cpu);
        let raw = raw_page();
        let source = source(raw.clone()).with_pauth(MAPPING, auth).unwrap();
        let expected = |name| {
            let vector = fixture["vectors"]
                .as_array()
                .unwrap()
                .iter()
                .find(|value| value["algorithm"] == q && value["name"] == name)
                .unwrap();
            u64::from_str_radix(vector["signed"].as_str().unwrap(), 16).unwrap()
        };
        let values = read(&source);
        assert_eq!(values, [expected("cache_code"), expected("cache_data")]);
        assert_eq!(
            read(&source),
            values,
            "cached second read preserves signed contents"
        );
        assert_eq!(
            auth.authenticate(values[0], PauthKeyKind::Ia, 0x77),
            BASE + 0x40
        );
        assert_eq!(
            auth.authenticate(values[1], PauthKeyKind::Da, blend(MAPPING + 0x18, 0x66)),
            BASE + 0x80
        );
        assert_ne!(
            u64::from_le_bytes(raw[4096 + 0x10..4096 + 0x18].try_into().unwrap()),
            values[0]
        );
    }
}

#[test]
fn darwin_pauth_shared_cache_sources_do_not_reuse_pages_across_keys_or_mappings() {
    let DarwinCpu::Arm64(mut cpu) =
        crate::user::darwin::pauth::tests::cpu(PauthAlgorithm::Qarma5, true)
    else {
        unreachable!()
    };
    let raw = raw_page();
    let initial = UserPauth::from_cpu(&cpu);
    let first = source(raw.clone()).with_pauth(MAPPING, initial).unwrap();
    let moved = source(raw.clone())
        .with_pauth(MAPPING + 0x4000, initial)
        .unwrap();
    let first_values = read(&first);
    let moved_values = read(&moved);
    assert_eq!(
        first_values[0], moved_values[0],
        "code pointer has no address diversity"
    );
    assert_ne!(
        first_values[1], moved_values[1],
        "data pointer includes its user storage address"
    );
    let mut keys = cpu.core().pauth_keys();
    keys.ia.lo = 0x1234;
    keys.da.lo = 0x5678;
    cpu.core_mut().set_pauth_keys(keys);
    let second = source(raw.clone())
        .with_pauth(MAPPING, UserPauth::from_cpu(&cpu))
        .unwrap();
    assert_eq!(
        first.identity(),
        second.identity(),
        "file identity remains diagnostic"
    );
    let second_values = read(&second);
    assert_ne!(first_values[0], second_values[0]);
    assert_ne!(first_values[1], second_values[1]);
    assert_eq!(
        read(&first),
        first_values,
        "old source remains bound to its original keys"
    );
    assert_eq!(
        read(&source(raw)),
        [BASE + 0x40, BASE + 0x80],
        "NOJOP mapping remains unsigned"
    );
}
