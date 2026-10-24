//! Independent QEMU vectors and XNU pointer-conversion contracts.

use super::*;
use crate::isa::arm::aarch64::pauth::{PauthAlgorithm, PauthProfile};
use crate::user::darwin::abi::DarwinAbi;
use crate::user::darwin::thread_state::{self as ts, pauth as state_auth};
use crate::user::mm::{AddressSpace, SpaceConfig};

pub(crate) fn cpu(algorithm: PauthAlgorithm, jop: bool) -> DarwinCpu {
    let space = AddressSpace::new(SpaceConfig {
        arena_bytes: 16 << 20,
        va_limit: 1 << 47,
        reserved_phys: Vec::new(),
    })
    .unwrap();
    let mut cpu = DarwinCpu::new(DarwinAbi::Arm64, &space);
    TaskPauth {
        keys: PauthKeys {
            ia: PauthKey { lo: 1, hi: 2 },
            ib: PauthKey { lo: 3, hi: 4 },
            da: PauthKey { lo: 5, hi: 6 },
            db: PauthKey { lo: 7, hi: 8 },
            ga: PauthKey { lo: 9, hi: 10 },
        },
        jop,
    }
    .install(&mut cpu);
    let DarwinCpu::Arm64(core) = &mut cpu else {
        unreachable!()
    };
    core.core_mut().configure_pauth(PauthConfig {
        algorithm,
        profile: PauthProfile::FpacCombine,
    });
    cpu
}

fn u64_at(state: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(state[offset..offset + 8].try_into().unwrap())
}

fn flags(state: &[u8]) -> u32 {
    u32::from_le_bytes(state[268..272].try_into().unwrap())
}

#[test]
fn darwin_pauth_abi_selection_follows_the_xnu_version_range() {
    for version in 0..16u32 {
        for capability in [0, 0x8000_0000, 0x4000_0000, 0xc000_0000] {
            for subtype in [0, 1, 2, 3] {
                let value = capability | (version << 24) | subtype;
                assert_eq!(uses_abi(value), subtype == 2 && version <= 1, "{value:#x}");
            }
        }
    }
}

#[test]
fn darwin_pauth_kernel_signing_matches_independent_qemu_vectors() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../docs/specifications/arm/pauth/darwin-vectors.json"
    ))
    .unwrap();
    let mut count = 0;
    for vector in fixture["vectors"].as_array().unwrap() {
        let algorithm = if vector["algorithm"] == 0 {
            PauthAlgorithm::Qarma5
        } else {
            PauthAlgorithm::Qarma3
        };
        let DarwinCpu::Arm64(cpu) = cpu(algorithm, true) else {
            unreachable!()
        };
        let auth = UserPauth::from_cpu(&cpu);
        assert!(auth.enabled(), "personality must allow EL0 PAC use");
        let hex = |field: &str| u64::from_str_radix(vector[field].as_str().unwrap(), 16).unwrap();
        let kind = if vector["key"] == "ia" {
            PauthKeyKind::Ia
        } else {
            PauthKeyKind::Da
        };
        assert_eq!(
            auth.sign(hex("pointer"), kind, hex("modifier")),
            hex("signed"),
            "{vector}"
        );
        if !vector["name"].as_str().unwrap().ends_with("nonce") {
            assert_eq!(
                auth.authenticate(hex("signed"), kind, hex("modifier")),
                hex("pointer")
            );
        }
        count += 1;
    }
    assert_eq!(count, 20);
}

#[test]
fn darwin_pauth_thread_state_round_trip_and_ib_signed_lr_preservation() {
    for algorithm in [PauthAlgorithm::Qarma3, PauthAlgorithm::Qarma5] {
        let DarwinCpu::Arm64(mut cpu) = cpu(algorithm, true) else {
            unreachable!()
        };
        cpu.core_mut().set_pc(0x1_0000_1000);
        cpu.set_sp(0x70_0000_1000);
        cpu.core_mut().set_x(29, 0x70_0000_2000);
        cpu.core_mut().set_x(30, 0x1_0000_2000);
        let raw = ts::arm64_thread_state(&cpu, 0);
        let user = state_auth::to_user(&cpu, true, 0x7a00_0000);
        assert_eq!(flags(&user), 0x7a00_000c);
        for offset in [232, 240, 248, 256] {
            assert_ne!(
                u64_at(&user, offset),
                u64_at(&raw, offset),
                "offset {offset}"
            );
        }
        let restored = state_auth::from_user(&cpu, &user, 0x7a00_0000).unwrap();
        assert_eq!(&restored[..268], &raw[..268]);
        let auth = UserPauth::from_cpu(&cpu);
        let signed_lr = auth.sign(cpu.core().get_x(30), PauthKeyKind::Ib, cpu.sp());
        cpu.core_mut().set_x(30, signed_lr);
        let user = state_auth::to_user(&cpu, true, 0);
        assert_eq!(
            flags(&user) & state_auth::IB_SIGNED_LR,
            state_auth::IB_SIGNED_LR
        );
        assert_eq!(u64_at(&user, 240), signed_lr);
        assert_eq!(
            u64_at(&state_auth::from_user(&cpu, &user, 0).unwrap(), 240),
            signed_lr
        );

        let mut forged =
            ts::arm64_thread_state(&cpu, state_auth::NO_PTRAUTH | state_auth::IB_SIGNED_LR);
        forged[240..248].copy_from_slice(&0x1_0000_2000u64.to_le_bytes());
        let converted = state_auth::from_user(&cpu, &forged, 0).unwrap();
        assert_ne!(
            u64_at(&converted, 256),
            cpu.pc(),
            "NO_PTRAUTH must not bypass IA authentication"
        );
        assert_ne!(
            u64_at(&converted, 240),
            0x1_0000_2000,
            "unsigned LR cannot claim IB_SIGNED_LR"
        );
    }
}

#[test]
fn darwin_pauth_kernel_auth_failure_poison_preserves_the_other_input_bits() {
    let DarwinCpu::Arm64(cpu) = cpu(PauthAlgorithm::Qarma5, true) else {
        unreachable!()
    };
    let auth = UserPauth::from_cpu(&cpu);
    for kind in [
        PauthKeyKind::Ia,
        PauthKeyKind::Ib,
        PauthKeyKind::Da,
        PauthKeyKind::Db,
    ] {
        let signed = auth.sign(0x1_0000_1000, kind, 0x1234);
        let bad = signed ^ (1 << 48);
        let shift = if kind.data() { 53 } else { 61 };
        let code = if kind.key_b() { 2 } else { 1 };
        assert_eq!(
            auth.authenticate(bad, kind, 0x1234),
            (bad & !(3 << shift)) | (code << shift)
        );
        assert_ne!(auth.authenticate(bad, kind, 0x1234), 0x1_0000_1000);
    }
}

#[test]
fn darwin_pauth_domains_are_fresh_per_exec_and_inherited_without_key_changes() {
    let mut entropy = Entropy::new(Some(0x1234));
    let parent = TaskPauth::new(&mut entropy, true).unwrap();
    let child = parent.clone();
    assert_eq!(
        parent.keys, child.keys,
        "fork preserves every architectural key"
    );
    let next_exec = TaskPauth::new(&mut entropy, true).unwrap();
    assert_ne!(parent.keys, next_exec.keys);
    let repeat = TaskPauth::new(&mut Entropy::new(Some(0x1234)), true).unwrap();
    assert_eq!(
        parent.keys, repeat.keys,
        "an explicit deterministic seed is reproducible"
    );
    let space = AddressSpace::new(SpaceConfig {
        arena_bytes: 16 << 20,
        va_limit: 1 << 47,
        reserved_phys: Vec::new(),
    })
    .unwrap();
    let mut first = DarwinCpu::new(DarwinAbi::Arm64, &space);
    let mut second = DarwinCpu::new(DarwinAbi::Arm64, &space);
    parent.install(&mut first);
    parent.install(&mut second);
    let (DarwinCpu::Arm64(first), DarwinCpu::Arm64(second)) = (first, second) else {
        unreachable!()
    };
    assert_eq!(first.core().pauth_keys(), second.core().pauth_keys());
    assert_eq!(
        first.core().pauth_controls(),
        second.core().pauth_controls()
    );
    assert_eq!(first.core().pauth_keys(), parent.keys);
}

#[test]
fn darwin_pauth_null_state_and_nojop_keep_their_abi_contracts() {
    for jop in [false, true] {
        let DarwinCpu::Arm64(cpu) = cpu(PauthAlgorithm::Qarma5, jop) else {
            unreachable!()
        };
        let state = state_auth::to_user(&cpu, jop, 0);
        for offset in [232, 240, 248, 256] {
            assert_eq!(u64_at(&state, offset), 0);
        }
        assert_eq!(flags(&state), if jop { 12 } else { 1 });
        let raw = state_auth::from_user(&cpu, &state, 0).unwrap();
        assert_eq!(&raw[..268], &state[..268]);
        assert_eq!(UserPauth::from_cpu(&cpu).enabled(), jop);
        assert_eq!(
            cpu.core().pauth_controls().key_enabled(PauthKeyKind::Ib),
            Ok(true)
        );
    }
}
