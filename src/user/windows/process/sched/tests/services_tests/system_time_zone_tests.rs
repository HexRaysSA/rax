use super::*;
use crate::user::windows::native::{
    CURRENT_TIME_ZONE_INFORMATION_BYTES, SYSTEM_CURRENT_TIME_ZONE_INFORMATION,
};
use crate::user::windows::nt::status::{
    STATUS_ACCESS_VIOLATION, STATUS_DATATYPE_MISALIGNMENT, STATUS_INFO_LENGTH_MISMATCH,
    STATUS_SUCCESS,
};

#[test]
fn current_time_zone_information_replays_fixed_record_and_native_probe_order() {
    const BYTES: u32 = CURRENT_TIME_ZONE_INFORMATION_BYTES as u32;
    const SENTINEL: u8 = 0xa5;
    const RECORD: [u8; BYTES as usize] = [0x59; BYTES as usize];
    for arch in WinArch::ALL {
        let (mut process, mut thread, base) = query_fixture(arch);
        let state = process.state_mut();
        state.current_time_zone = Ok(RECORD);
        let sp = thread.cpu.sp();
        for (length, offset, return_address, status, write_record, return_length) in [
            (0, 0, base + 264, STATUS_INFO_LENGTH_MISMATCH, false, true),
            (
                BYTES - 1,
                0,
                base + 264,
                STATUS_INFO_LENGTH_MISMATCH,
                false,
                true,
            ),
            (BYTES, 0, 0, STATUS_SUCCESS, true, false),
            (BYTES + 1, 4, base + 265, STATUS_SUCCESS, true, true),
            (BYTES, 0, base + 8, STATUS_SUCCESS, true, true),
            (BYTES, 0, 1, STATUS_ACCESS_VIOLATION, false, false),
            (BYTES - 1, 0, 1, STATUS_ACCESS_VIOLATION, false, false),
            (BYTES, 1, 1, STATUS_DATATYPE_MISALIGNMENT, false, false),
        ] {
            state.space.wr(base, &[SENTINEL; 272]).unwrap();
            thread.cpu.set_sp(sp);
            query_arguments(
                state,
                &mut thread,
                SYSTEM_CURRENT_TIME_ZONE_INFORMATION,
                base + offset,
                length,
                return_address,
            );
            assert_eq!(dispatch_query(state, &mut thread), Outcome::Continue);
            assert_eq!(thread.cpu.gpr(0) as u32, status, "{arch}, length {length}");
            let mut expected = [SENTINEL; 272];
            if write_record {
                let start = offset as usize;
                expected[start..start + RECORD.len()].copy_from_slice(&RECORD);
            }
            if return_length {
                let start = (return_address - base) as usize;
                expected[start..start + 4].copy_from_slice(&BYTES.to_le_bytes());
            }
            assert_eq!(state.space.bytes(base, expected.len()).unwrap(), expected);
        }
    }
}
