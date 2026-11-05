//! Execute the production planner and scalar bus transform against native data.
//! The linked engine supplies metadata and arithmetic helpers. The current
//! production RMW source is included so the oracle can qualify a new bus variant
//! before an entire engine rebuild. Owning Cargo targets remain separate gates.
use rax::{error, isa};

#[path = "../../src/devices/bus/rmw.rs"]
mod operations;
mod devices {
    pub mod bus {
        pub use crate::operations::{MmioRmwOp, MmioShift};
    }
}
#[path = "mmio_rmw_compare.rs"]
mod reference;

fn main() {
    let arguments: Vec<_> = std::env::args().collect();
    assert_eq!(arguments.len(), 3);
    let cases = std::fs::read(&arguments[1]).unwrap();
    let records = std::fs::read(&arguments[2]).unwrap();
    let (count, mismatches) = reference::compare(&cases, &records);
    println!(
        "{{\"cases\":{count},\"plans\":{},\"mismatches\":{mismatches}}}",
        count * 2
    );
    assert_eq!(mismatches, 0);
}
