use super::*;
use crate::user::windows::memory::Mem;

fn metadata() -> CacheMetadata {
    CacheMetadata {
        kernel: (10, 0, 29704),
        native_machine: 0xAA64,
        server_pid: 0x898,
    }
}

#[test]
fn translation_cache_profile_rejects_unknown_native_identity() {
    for wrong in [
        CacheMetadata {
            kernel: (10, 0, 29695),
            ..metadata()
        },
        CacheMetadata {
            native_machine: 0x8664,
            ..metadata()
        },
        CacheMetadata {
            server_pid: 0,
            ..metadata()
        },
        CacheMetadata {
            server_pid: 1,
            ..metadata()
        },
    ] {
        assert!(CacheServer::selected(wrong).is_err());
    }
}

#[test]
fn translation_cache_peer_backing_survives_last_endpoint_handle_and_internal_pins() {
    let server = CacheServer::selected(metadata()).unwrap();
    let peer = server.peer().unwrap();
    let space = AddressSpace::new(SpaceConfig {
        va_limit: 1 << 47,
        arena_bytes: 1 << 20,
        reserved_phys: vec![],
    })
    .unwrap();
    let mut client = VirtualMemory::new(space, 65536, 1 << 47);
    let view = client
        .map_shared_view(peer.backing.clone(), None, 0, SECTION_BYTES)
        .unwrap();
    let alias = client
        .map_shared_view(peer.backing.clone(), None, 0, SECTION_BYTES)
        .unwrap();
    assert_eq!(
        client
            .space()
            .bytes(view.base, SECTION_BYTES as usize)
            .unwrap(),
        vec![0; SECTION_BYTES as usize]
    );
    assert!(!client.space().same_space(peer.vm.space()));
    client.space().w32(view.base + 4094, 0xAABB_CCDD).unwrap();
    assert_eq!(peer.vm.space().u32(peer.base + 4094).unwrap(), 0xAABB_CCDD);
    peer.vm
        .space()
        .w32(peer.base + SECTION_BYTES - 4, 0x1234_5678)
        .unwrap();
    assert_eq!(
        client.space().u32(alias.base + SECTION_BYTES - 4).unwrap(),
        0x1234_5678
    );
    let mut objects = Objects::default();
    let id = objects.create(Object::LpcPort(LpcPort::cache(peer)));
    objects.retain_many(&[id]).unwrap();
    let handle = objects.open_access(id, false, 0x1F0001).unwrap();
    let duplicate = objects.duplicate(handle.into(), false).unwrap();
    objects.close(handle.into()).unwrap();
    assert_eq!(server.connections.load(Ordering::Relaxed), 1);
    objects.close(duplicate.into()).unwrap();
    assert_eq!(server.connections.load(Ordering::Relaxed), 0);
    let Some(Object::LpcPort(port)) = objects.obj(id) else {
        panic!("retained endpoint")
    };
    assert!(port.cache_peer().is_none());
    assert_eq!(client.space().u32(view.base + 4094).unwrap(), 0xAABB_CCDD);
    assert_eq!(
        client.space().u32(alias.base + SECTION_BYTES - 4).unwrap(),
        0x1234_5678
    );
    objects.release(id);
    client.retire_shared_view(&view).unwrap();
    assert_eq!(client.committed_bytes(), SECTION_BYTES);
    client.retire_shared_view(&alias).unwrap();
    assert_eq!(client.committed_bytes(), 0);
}

#[test]
fn translation_cache_peer_limit_and_failed_admission_release_leases() {
    let server = CacheServer::selected(metadata()).unwrap();
    let mut peers: Vec<_> = (0..32).map(|_| server.peer().unwrap()).collect();
    assert!(matches!(server.peer(), Err(VmError::NoMemory)));
    assert_eq!(server.connections.load(Ordering::Relaxed), 32);
    peers.pop();
    let replacement = server.peer().unwrap();
    assert_eq!(server.connections.load(Ordering::Relaxed), 32);
    drop(replacement);
    drop(peers);
    assert_eq!(server.connections.load(Ordering::Relaxed), 0);
}

#[test]
fn translation_cache_message_identity_never_reuses_an_acknowledgement_cookie() {
    let server = CacheServer::selected(metadata()).unwrap();
    let first = server.peer().unwrap();
    let second = server.peer().unwrap();
    assert_ne!(first.connection_message, second.connection_message);
    drop(first);
    drop(second);
    server.next_message.store(u32::MAX, Ordering::Relaxed);
    assert!(matches!(server.peer(), Err(VmError::NoMemory)));
    assert_eq!(server.connections.load(Ordering::Relaxed), 0);
}
