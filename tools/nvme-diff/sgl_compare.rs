//! Replay independent SGL records through the production device's owning driver.
#[allow(dead_code, unused_imports)]
#[path = "../../tests/suites/devices/nvme_sgl.rs"]
mod owning;
#[allow(unused_imports)]
mod devices {
    pub use rax::devices::{bus, virtio};
}
fn main() {
    let mut arguments = std::env::args_os().skip(1);
    let directory = std::path::PathBuf::from(arguments.next().expect("reference directory"));
    assert!(arguments.next().is_none());
    let (cases, bytes, failed) = owning::compare_reference(&directory);
    println!("{{\"cases\":{cases},\"bytes_compared\":{bytes},\"failed\":{failed}}}");
    if failed != 0 {
        std::process::exit(1);
    }
}
