//! Compare independent queue/PCI records with the exact production device.
#[allow(dead_code, unused_imports)]
#[path = "../../tests/suites/devices/nvme_queues.rs"]
mod owning;
#[allow(unused_imports)]
mod devices {
    pub use rax::devices::{bus, virtio};
}
fn main() {
    let mut args = std::env::args_os().skip(1);
    let path = std::path::PathBuf::from(args.next().expect("reference directory"));
    assert!(args.next().is_none());
    let (cases, bytes, failed) = owning::compare_reference(&path);
    println!("{{\"cases\":{cases},\"bytes_compared\":{bytes},\"failed\":{failed}}}");
    if failed != 0 {
        std::process::exit(1);
    }
}
