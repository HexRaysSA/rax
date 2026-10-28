use super::*;
use std::sync::Arc;
use vm_memory::{GuestAddress, GuestMemoryMmap};
#[test]
fn actual_legacy_platform_context_and_new_profile_roundtrip() {
    let bytes = include_bytes!("../../../docs/development/arm-fhm/legacy-s3c-v1.bin");
    let mem =
        Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0x50000000), 0x4000)]).unwrap());
    let mut cpu = Armv6Vcpu::new(0, mem);
    let old = Context::decode(bytes, 0).unwrap();
    assert_eq!(old.cpu.regs[0], 0x123);
    assert_eq!(old.cpu.regs[15], 0x50000000);
    assert_eq!(old.instruction_count, 0);
    assert_eq!(old.cpu.cp15.id_isar6, 1 << 8);
    let state = public_state(&old.cpu);
    cpu.apply_context_record(
        &state,
        &BackendContext {
            kind: S3C64XX_CONTEXT,
            data: bytes.to_vec(),
        },
    )
    .unwrap();
    cpu.cpu.cp15.id_isar6 = 0;
    let raw = cpu.capture_context_record().unwrap();
    assert!(raw.data.starts_with(b"RAXS3C02"));
    let state = cpu.get_state().unwrap();
    cpu.cpu.cp15.id_isar6 = 1 << 8;
    cpu.apply_context_record(&state, &raw).unwrap();
    assert_eq!(cpu.cpu.cp15.id_isar6, 0);
    let before = cpu.capture_context_record().unwrap();
    let mut malformed = raw.clone();
    malformed.data.push(0);
    assert!(cpu.apply_context_record(&state, &malformed).is_err());
    assert_eq!(cpu.capture_context_record().unwrap(), before);
}
