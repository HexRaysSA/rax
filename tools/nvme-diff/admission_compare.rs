//! Compare independent admin CQEs, reporting DNR policy differences explicitly.
#[allow(dead_code, unused_imports)]
#[path = "../../tests/suites/devices/nvme_admission.rs"]
mod owning;
#[allow(unused_imports)]
mod devices {
    pub use rax::devices::{bus, virtio};
}
fn main() {
    let mut args = std::env::args_os().skip(1);
    let directory = std::path::PathBuf::from(args.next().expect("reference directory"));
    assert!(args.next().is_none());
    let (cases, bytes, failed, dnr, policy) = owning::compare_reference(&directory);
    println!(
        "{{\"cases\":{cases},\"bytes_compared\":{bytes},\"failed\":{failed},\"dnr_differences\":{dnr},\"primary_policy_differences\":{policy}}}"
    );
    if failed != 0 {
        std::process::exit(1);
    }
}
