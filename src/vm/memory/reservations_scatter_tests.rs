//! Whole-packet admission and shared monitor publication for debugger writes.
use super::*;
#[test]
fn rejected_late_span_preserves_prefix_and_live_reservations() {
    let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap();
    memory.write_slice(&[7; 8], GuestAddress(128)).unwrap();
    let domain = MemoryDomain::for_memory(&memory);
    let monitor = domain.register();
    monitor.read_exclusive(&memory, 128, 8).unwrap();
    assert!(write_scatter(&memory, &[(128, &[9; 8]), (4095, &[1, 2])]).is_err());
    let mut bytes = [0; 8];
    memory.read_slice(&mut bytes, GuestAddress(128)).unwrap();
    assert_eq!(bytes, [7; 8]);
    assert!(monitor.write_exclusive(&memory, 128, &[3; 8]).unwrap());
}
#[test]
fn identical_scatter_invalidates_every_touched_granule_only() {
    let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap();
    let domain = MemoryDomain::for_memory(&memory);
    let first = domain.register();
    let second = domain.register();
    let unrelated = domain.register();
    for (monitor, address) in [(&first, 128), (&second, 256), (&unrelated, 512)] {
        monitor.read_exclusive(&memory, address, 8).unwrap();
    }
    write_scatter(&memory.clone(), &[(128, &[0; 8]), (256, &[0; 8])]).unwrap();
    assert!(!first.write_exclusive(&memory, 128, &[1; 8]).unwrap());
    assert!(!second.write_exclusive(&memory, 256, &[1; 8]).unwrap());
    assert!(unrelated.write_exclusive(&memory, 512, &[1; 8]).unwrap());
}
#[test]
fn crossing_adjacent_host_regions_and_repeated_physical_aliases_are_ordered() {
    let memory =
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096), (GuestAddress(4096), 4096)])
            .unwrap();
    write_scatter(&memory, &[(4094, &[1, 2, 3, 4]), (4096, &[5, 6])]).unwrap();
    let mut bytes = [0; 4];
    memory.read_slice(&mut bytes, GuestAddress(4094)).unwrap();
    assert_eq!(bytes, [1, 2, 5, 6]);
}
#[test]
fn exclusive_readers_cannot_observe_a_half_published_scatter() {
    use std::sync::Arc;
    let memory = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap());
    let domain = MemoryDomain::for_memory(&memory);
    let monitor = domain.register();
    let writer = {
        let memory = memory.clone();
        std::thread::spawn(move || {
            for value in 1..=100u8 {
                write_scatter(&memory, &[(128, &[value; 8]), (136, &[value; 8])]).unwrap();
            }
        })
    };
    for _ in 0..100 {
        let bytes = monitor.read_exclusive(&memory, 128, 16).unwrap();
        assert_eq!(bytes[..8], bytes[8..]);
    }
    writer.join().unwrap();
}
