//! Replay retained independent range requests against the owning implementation.
#[allow(dead_code, unused_imports)]
#[path = "../../tests/suites/devices/virtio_ranges.rs"]
mod owning;
#[allow(unused_imports)]
mod devices {
    pub use crate::owning::support::{bus, virtio};
}
fn main() {
    let mut args = std::env::args_os().skip(1);
    let folder = std::path::PathBuf::from(args.next().expect("reference directory"));
    assert!(args.next().is_none());
    let r = owning::compare_ranges(&folder);
    println!(
        "{{\"cases\":{},\"requests\":{},\"frame_bytes\":{},\"payload_bytes\":{},\"primary_media_bytes\":{},\"capability_profile_differences\":{},\"status_profile_differences\":{},\"advisory_media_difference_cases\":{},\"reference_exact_cases\":{},\"reference_fatal_cases\":{},\"reference_completed_requests\":{},\"failed\":{}}}",
        r.cases,
        r.requests,
        r.frame_bytes,
        r.payload_bytes,
        r.primary_media_bytes,
        r.capability_profile_differences,
        r.status_profile_differences,
        r.advisory_media_difference_cases,
        r.reference_exact_cases,
        r.reference_fatal_cases,
        r.reference_completed_requests,
        r.failed
    );
    if r.failed != 0 {
        std::process::exit(1);
    }
}
