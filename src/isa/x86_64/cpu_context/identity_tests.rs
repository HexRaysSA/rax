//! Reject malformed new state before mutation and retain legacy codec layout.
use super::*;
use vm_memory::{GuestAddress, GuestMemoryMmap};

fn cpu(id: u32) -> X86_64Vcpu {
    X86_64Vcpu::new(
        id,
        Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 65536)]).unwrap()),
    )
}

#[test]
fn invalid_apic_state_and_cross_version_payloads_reject_before_publication() {
    let source = cpu(1);
    let raw = source.save_context().unwrap();
    let mut target = cpu(1);
    let before = target.save_context().unwrap();
    for value in [0, 0xfee0_0000, 0xfee0_0c00, 0xfee1_0800, u64::MAX] {
        let mut context = Context::decode(&raw, &source).unwrap();
        context.apic_base = value;
        let bad = context.encode().unwrap();
        let error = target.restore_context(&bad).unwrap_err().to_string();
        assert!(error.contains("APIC_BASE"), "{error}");
        assert_eq!(target.save_context().unwrap(), before);
    }
    for tag in [LEGACY_TAG, VERSION2_TAG] {
        let mut bad = raw.clone();
        bad[..8].copy_from_slice(tag);
        assert!(target.restore_context(&bad).is_err());
        assert_eq!(target.save_context().unwrap(), before);
    }
}

#[test]
fn version1_and_version2_base_bytes_remain_exact_after_migration() {
    for id in [0, 1] {
        let raw: &[u8] = if id == 0 {
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/development/x86-cpu-identity/legacy-v2-cpu-0.bin"
            ))
        } else {
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/development/x86-cpu-identity/legacy-v2-cpu-1.bin"
            ))
        };
        let target = cpu(id);
        let context = Context::decode(raw, &target).unwrap();
        let v2 = Version2 {
            base: &context,
            user_debug_status: None,
        };
        assert_eq!(&raw[8..], crate::codec::serialize(&v2).unwrap());
        let mut v1 = LEGACY_TAG.to_vec();
        v1.extend(crate::codec::serialize(&context).unwrap());
        let migrated = Context::decode(&v1, &target).unwrap();
        assert_eq!(
            migrated.apic_base,
            crate::isa::x86_64::identity::initial_apic_base(id)
        );
        assert_eq!(
            crate::codec::serialize(&migrated).unwrap(),
            crate::codec::serialize(&context).unwrap()
        );
    }
}
