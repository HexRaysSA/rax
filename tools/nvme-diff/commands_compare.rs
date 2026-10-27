//! Replay retained independent command/media records through the product driver.
#[allow(dead_code, unused_imports)]
#[path = "../../tests/suites/devices/nvme_commands.rs"]
mod owning;
#[allow(unused_imports)]
mod devices {
    pub use rax::devices::{bus, virtio};
}
fn main() {
    let mut args = std::env::args_os().skip(1);
    let folder = std::path::PathBuf::from(args.next().expect("reference directory"));
    assert!(args.next().is_none());
    let r = owning::compare_reference(&folder);
    println!(
        "{{\"cases\":{},\"io_commands\":{},\"reference_frame_bytes\":{},\"media_bytes_compared\":{},\"payload_bytes_compared\":{},\"dnr_differences\":{},\"namespace_profile_differences\":{},\"capability_profile_differences\":{},\"completion_failure_cases\":{},\"media_failure_cases\":{},\"output_failure_cases\":{},\"capability_failure_cases\":{},\"advisory_media_difference_cases\":{},\"advisory_output_difference_cases\":{},\"reference_contract_failure_cases\":{},\"failed\":{}}}",
        r.cases,
        r.commands,
        r.frame_bytes,
        r.media_bytes,
        r.payload_bytes,
        r.dnr_differences,
        r.namespace_differences,
        r.capability_differences,
        r.completion_failures,
        r.media_failures,
        r.output_failures,
        r.capability_failures,
        r.advisory_media_differences,
        r.advisory_output_differences,
        r.reference_contract_failures,
        r.failed
    );
    if r.failed != 0 {
        std::process::exit(1);
    }
}
