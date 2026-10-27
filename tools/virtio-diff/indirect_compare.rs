//! Replay independent records through the owning transport and block sources.
#[allow(dead_code, unused_imports)]
#[path = "../../tests/suites/devices/virtio_indirect.rs"]
mod owning;
mod devices {
    pub use crate::owning::{bus, virtio};
}
fn main() {
    let mut args = std::env::args_os().skip(1);
    let folder = std::path::PathBuf::from(args.next().expect("reference directory"));
    assert!(args.next().is_none());
    let r = owning::compare_reference(&folder);
    println!(
        "{{\"cases\":{},\"requests\":{},\"frame_bytes\":{},\"payload_bytes\":{},\"media_bytes\":{},\"capability_differences\":{},\"reference_difference_cases\":{},\"shared_exact_cases\":{},\"shared_requests\":{},\"shared_payload_bytes\":{},\"shared_media_bytes\":{},\"failed\":{}}}",
        r.cases,
        r.requests,
        r.frame_bytes,
        r.payload_bytes,
        r.media_bytes,
        r.capability_differences,
        r.reference_difference_cases,
        r.shared_exact_cases,
        r.shared_requests,
        r.shared_payload_bytes,
        r.shared_media_bytes,
        r.failed
    );
    if r.failed != 0 {
        std::process::exit(1);
    }
}
