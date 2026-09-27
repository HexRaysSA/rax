//! CSR and vector state transfer. Expected values follow the RISC-V
//! privileged specification's WARL rules as the hart implements them.

use super::super::*;
use crate::isa::riscv::FlatMemory;

fn cpu(isa: Isa) -> RiscVCpu {
    RiscVCpu::new(
        RiscVConfig {
            xlen: Xlen::Rv64,
            isa,
        },
        Box::new(FlatMemory::new(0, 0x2000)),
    )
}

fn csr(csrs: &[(u16, u64)], n: u16) -> Option<u64> {
    csrs.iter().find(|(m, _)| *m == n).map(|(_, v)| *v)
}

#[test]
fn csrs_round_trip_through_their_warl_rules() {
    let mut a = cpu(Isa::rv64gc());
    a.import_csrs(&[
        (0x305, 0x8000_0003), // mtvec: mode 3 is reserved
        (0x340, 0x1234),      // mscratch
        (0x341, 0x2003),      // mepc: IALIGN 16 clears bit 0
        (0xC02, 77),          // instret
        (0xF14, 5),           // mhartid is read-only
        (0x7C0, 1),           // not implemented
    ]);
    let csrs = a.export_csrs();
    assert_eq!(csr(&csrs, 0x340), Some(0x1234));
    assert_eq!(csr(&csrs, 0x341), Some(0x2002));
    assert_eq!(csr(&csrs, 0xC02), Some(77));
    assert_eq!(csr(&csrs, 0xF14), Some(0));
    assert_eq!(csr(&csrs, 0x7C0), None);
    let mtvec = csr(&csrs, 0x305).unwrap();
    assert_ne!(mtvec & 3, 3, "WARL mtvec never reads back a reserved mode");

    // Installing the export on another hart reproduces it exactly.
    let mut b = cpu(Isa::rv64gc());
    b.import_csrs(&csrs);
    assert_eq!(b.export_csrs(), csrs);
}

#[test]
fn vector_state_round_trips_and_checks_its_size() {
    let mut a = cpu(Isa::rv64gc());
    let mut state = a.export_vector().expect("RV64GC here includes V");
    assert_eq!(state.v.len(), 32 * VLENB as usize);
    state.vl = 4;
    state.vtype = 0x10; // e32, m1
    state.vxrm = 0xFF;
    state.v[VLENB as usize] = 0xAB; // v1 byte 0
    a.import_vector(&state).unwrap();
    let back = a.export_vector().unwrap();
    assert_eq!((back.vl, back.vtype, back.vxrm), (4, 0x10, 3));
    assert_eq!(back.v[VLENB as usize], 0xAB);
    state.v.pop();
    assert!(a.import_vector(&state).is_err());

    let mut no_v = Isa::rv64gc();
    no_v.v = false;
    assert!(cpu(no_v).export_vector().is_none());
}
