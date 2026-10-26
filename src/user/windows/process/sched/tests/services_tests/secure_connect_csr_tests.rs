//! Primary native startup reply fields plus real independent client/peer VMs.
use super::*;
use crate::user::mm::SharedObject;
use crate::user::windows::object_namespace::csr::{CsrMetadata, CsrServer};
use crate::user::windows::object_namespace::data::{DataRegion, DataSection};

const BASE: u64 = 0x0000_7FF5_F57C_0000;
#[cfg(all(windows, target_arch = "aarch64"))]
#[path = "secure_connect_csr_leaf_tests.rs"]
mod installed_csr;

pub(in super::super) fn server() -> (Arc<DataSection>, Arc<CsrServer>) {
    let mut prefix = vec![0; 5 * 4096];
    prefix[40..48].copy_from_slice(&BASE.to_le_bytes());
    prefix[48..56].copy_from_slice(&BASE.to_le_bytes());
    let section = DataSection::selected(
        0x20004,
        STATUS_PRIVILEGE_NOT_HELD,
        false,
        1 << 20,
        vec![
            DataRegion {
                offset: 0,
                size: 5 * 4096,
                bytes: Some(prefix.into()),
            },
            DataRegion {
                offset: 5 * 4096,
                size: (1 << 20) - 5 * 4096,
                bytes: None,
            },
        ],
    )
    .unwrap();
    let metadata = CsrMetadata {
        arch: WinArch::Arm64,
        session: 0,
        server_base: BASE,
        statics_offset: 0x750,
        server_pid: 0x348,
    };
    let server = CsrServer::selected(section.clone(), metadata).unwrap();
    (section, server)
}

fn setup(p: &mut Proc, b: u64) -> [u64; 9] {
    let (section, server) = server();
    p.object_namespace = selected_namespace();
    p.object_namespace.select_data_section(section).unwrap();
    p.object_namespace.select_csr_server(server).unwrap();
    Arc::make_mut(&mut p.cfg).version.major = 10;
    Arc::make_mut(&mut p.cfg).version.build = 29683;
    packet(p, b, None)
}

fn packet(p: &mut Proc, b: u64, section: Option<u32>) -> [u64; 9] {
    let section = section.unwrap_or_else(|| {
        let backing = Arc::new(SharedObject::anonymous(65536).unwrap());
        let id = p.objects.create(Object::Mapping {
            file: None,
            size: 65536,
            protect: prot::READWRITE,
            attributes: 0x0800_0000,
            shared: Some(backing),
        });
        let section = p.objects.open_access(id, false, 0xF001F).unwrap();
        section
    });
    name(p, b + 128, b + 256, "\\Windows\\ApiPort");
    p.space
        .wr(b + 512, &[0, 0, 0, 0, 2, 0, 0, 0, 1, 1, 0, 0])
        .unwrap();
    p.space.w32(b + 1024, 48).unwrap();
    p.space.w64(b + 1032, section.into()).unwrap();
    p.space.w64(b + 1048, 65536).unwrap();
    p.space.w32(b + 2048, 24).unwrap();
    p.space
        .wr(b + 3072, &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0])
        .unwrap();
    p.space.w32(b + 4096, 0).unwrap();
    p.space.w32(b + 12288, 48).unwrap();
    p.space.w64(b + 5152, 1).unwrap();
    p.space.w64(b + 5160, 0x1234_5678_9ABC_DEF0).unwrap();
    [
        b,
        b + 128,
        b + 512,
        b + 1024,
        b + 3072,
        b + 2048,
        b + 4096,
        b + 5120,
        b + 12288,
    ]
}

#[test]
fn native_secure_connect_csr_replies_with_owned_aliases_preserved_tail_and_native_fields() {
    for build in [29683, 29695] {
        let (mut process, mut thread) = fixture(WinArch::Arm64, "NtSecureConnectPort", SERVICE);
        let p = process.state_mut();
        Arc::make_mut(&mut p.cfg).version.build = build;
        let b = scratch(p, 65536);
        let args = setup(p, b);
        let initial = p.vm.committed_bytes();
        assert_eq!(invoke(p, &mut thread, &args), Outcome::Continue);
        assert_eq!(thread.cpu.gpr(0), 0);
        let handle = p.space.u64(b).unwrap();
        let local = p.space.u64(args[3] + 32).unwrap();
        let remote = p.space.u64(args[3] + 40).unwrap();
        assert!(p.vm.is_shared_view(local));
        assert_eq!(p.vm.committed_bytes(), initial + 65536);
        assert_eq!(p.objects.access(handle), Some(0x001F_0001));
        assert_eq!(p.objects.get(handle).unwrap().type_name(), "ALPC Port");
        assert_eq!(p.space.u32(args[6]).unwrap(), 952);
        assert_eq!(p.space.u32(args[8]).unwrap(), 48);
        assert_eq!(p.space.bytes(args[5], 24).unwrap(), vec![0; 24]);
        assert_eq!(p.space.u64(args[7]).unwrap(), BASE);
        assert_eq!(p.space.u64(args[7] + 8).unwrap(), BASE + 0x750);
        assert_eq!(p.space.u64(args[7] + 16).unwrap(), 0x348);
        assert_eq!(p.space.u64(args[7] + 24).unwrap(), 0);
        assert_eq!(p.space.u64(args[7] + 32).unwrap(), 1);
        assert_eq!(p.space.u64(args[7] + 40).unwrap(), 0x1234_5678_9ABC_DEF0);
        let Some(Object::LpcPort(port)) = p.objects.get(handle) else {
            panic!("typed endpoint")
        };
        let peer = port.peer().unwrap();
        assert_eq!(peer.base, remote);
        assert!(!peer.vm.space().same_space(&p.space));
        p.space.w32(local, 0x9669).unwrap();
        assert_eq!(peer.vm.space().u32(remote).unwrap(), 0x9669);
        peer.vm.space().w32(remote + 4094, 0xAABB_CCDD).unwrap();
        assert_eq!(p.space.u32(local + 4094).unwrap(), 0xAABB_CCDD);
        assert_eq!(peer.vm.space().u64(BASE + 40).unwrap(), BASE);
        assert!(peer.vm.space().w8(BASE, 1).is_err());
        let duplicate = p.objects.duplicate(handle, false).unwrap();
        p.objects.close(handle).unwrap();
        p.reclaim_scheduler_views().unwrap();
        assert!(p.vm.is_shared_view(local));
        p.objects.close(duplicate.into()).unwrap();
        p.reclaim_scheduler_views().unwrap();
        assert!(p.vm.allocation(local).is_none());
        assert_eq!(p.vm.committed_bytes(), initial);
    }
}

#[test]
fn native_secure_connect_csr_refuses_unmeasured_profiles_without_outputs_or_leaks() {
    for variant in 0..12 {
        let (mut process, mut thread) = fixture(WinArch::Arm64, "NtSecureConnectPort", SERVICE);
        let p = process.state_mut();
        let b = scratch(p, 65536);
        let mut args = setup(p, b);
        match variant {
            0 => Arc::make_mut(&mut p.cfg).version.build = 26100,
            1 => p.space.w32(p.peb + 0x2C0, 1).unwrap(),
            2 => p.space.w8(args[2] + 8, 0).unwrap(),
            3 => p.space.w32(args[4] + 8, 19).unwrap(),
            4 => p.space.w64(args[3] + 24, 4096).unwrap(),
            5 => p.space.w64(args[7], 1).unwrap(),
            6 => args[6] = args[0],
            7 => {
                p.vm.protect(b + 12288, 4096, prot::READONLY).unwrap();
            }
            8 => Arc::make_mut(&mut p.cfg).version.major = 11,
            9 => Arc::make_mut(&mut p.cfg).version.minor = 1,
            10 => Arc::make_mut(&mut p.cfg).version.build = 29694,
            11 => Arc::make_mut(&mut p.cfg).version.build = 29696,
            _ => unreachable!(),
        }
        let before = p.space.bytes(b, 65536).unwrap();
        let counts = (
            p.objects.handle_count(),
            p.objects.iter().count(),
            p.vm.committed_bytes(),
        );
        assert!(
            matches!(invoke(p, &mut thread, &args), Outcome::Fail(_)),
            "variant{variant}"
        );
        assert_eq!(p.space.bytes(b, 65536).unwrap(), before, "variant{variant}");
        assert_eq!(
            (
                p.objects.handle_count(),
                p.objects.iter().count(),
                p.vm.committed_bytes()
            ),
            counts
        );
    }
}

#[test]
fn native_secure_connect_csr_requires_exact_section_identity_and_bounds_server_leases() {
    let (section, server) = server();
    let mut namespace = selected_namespace();
    namespace.select_data_section(section).unwrap();
    let (_, other) = self::server();
    assert!(namespace.select_csr_server(other).is_err());
    namespace.select_csr_server(server.clone()).unwrap();
    assert!(namespace.select_csr_server(server.clone()).is_err());
    let backing = Arc::new(SharedObject::anonymous(65536).unwrap());
    let mut peers = Vec::new();
    for _ in 0..32 {
        peers.push(server.peer(backing.clone(), 65536).unwrap());
    }
    assert!(server.peer(backing.clone(), 65536).is_err());
    drop(peers.pop());
    let replacement = server.peer(backing, 65536).unwrap();
    drop(peers);
    drop(replacement);
}

#[test]
fn native_secure_connect_csr_leaves_unmeasured_compatibility_abis_explicitly_unsupported() {
    for arch in [WinArch::X86, WinArch::X64] {
        let (mut process, mut thread) = fixture(arch, "NtSecureConnectPort", SERVICE);
        let p = process.state_mut();
        let b = scratch(p, 65536);
        let args = setup(p, b);
        let before = p.space.bytes(b, 65536).unwrap();
        let counts = (
            p.objects.handle_count(),
            p.objects.iter().count(),
            p.vm.committed_bytes(),
        );
        assert!(matches!(invoke(p, &mut thread, &args), Outcome::Fail(_)));
        assert_eq!(p.space.bytes(b, 65536).unwrap(), before);
        assert_eq!(
            (
                p.objects.handle_count(),
                p.objects.iter().count(),
                p.vm.committed_bytes()
            ),
            counts
        );
    }
}
