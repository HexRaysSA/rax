//! Publish the product's scalar MMIO completion policy without a hypervisor.
#[path = "../../tests/suites/backend/hvf_arm64_mmio.rs"]
mod cases;
fn main() {
    let output = std::path::PathBuf::from(std::env::args_os().nth(1).unwrap());
    std::fs::write(
        output,
        cases::observations()
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>(),
    )
    .unwrap();
}
