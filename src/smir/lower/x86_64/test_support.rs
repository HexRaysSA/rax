//! Independent byte references for the platform C callback boundary.
//!
//! Existing lowering tests assert callback-table membership, call counts, and
//! ordering. Native callback tests separately execute the scalar and pair ABIs.

pub(crate) fn host_c_helper_reference_opcode() -> &'static [u8] {
    if cfg!(windows) {
        &[0x4C, 0x8B, 0x98] // MOV R11, qword [RAX+disp32]
    } else {
        &[0xFF, 0x90] // CALL qword [RAX+disp32]
    }
}

pub(crate) fn host_c_helper_reference(offset: i32) -> Vec<u8> {
    let mut reference = host_c_helper_reference_opcode().to_vec();
    reference.extend_from_slice(&offset.to_le_bytes());
    reference
}

pub(crate) fn host_c_call_opcode() -> &'static [u8] {
    if cfg!(windows) {
        &[0x41, 0xFF, 0xD3] // CALL R11 after the Windows argument adapter
    } else {
        &[0xFF, 0x90] // CALL qword [RAX+disp32]
    }
}
