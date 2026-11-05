use rax::vm::snapshot::PhysicalMemorySnapshot;
use std::time::Instant;
use vm_memory::{GuestAddress, GuestMemoryMmap};
fn main() {
    let memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 64 * 1024 * 1024)]).unwrap();
    let start = Instant::now();
    let saved = PhysicalMemorySnapshot::capture(&memory).unwrap();
    let capture = start.elapsed().as_secs_f64();
    let mut samples = Vec::new();
    for _ in 0..4 {
        let start = Instant::now();
        saved.verify().unwrap();
        samples.push(start.elapsed().as_secs_f64());
    }
    println!("{{\"bytes\":67108864,\"capture_seconds\":{capture},\"verify_seconds\":{samples:?}}}");
}
