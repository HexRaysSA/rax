//! Instruction-embedding regressions: sparse memory is equivalent to preloaded memory.
use super::*;
use crate::arch::RAX_MODE_32;
use crate::engine::rax_engine_errmsg;
use crate::fault::*;

struct Sparse(*mut Engine);
impl Sparse {
    fn new(mode: u32) -> Self {
        let cfg = RaxEngineConfig {
            size: std::mem::size_of::<RaxEngineConfig>() as u32,
            arch: RaxArch::X86 as i32,
            mode,
            backend: crate::arch::RAX_BACKEND_EMULATOR,
            mem_base: 0x1000,
            mem_size: 0x1000,
            mem_perms: RAX_PROT_ALL,
            flags: 0,
            riscv_ext: 0,
        };
        let mut engine = ptr::null_mut();
        assert_eq!(rax_engine_open_config(&cfg, &mut engine), RaxStatus::Ok);
        Self(engine)
    }
    fn bytes(&self, address: u64, bytes: &[u8]) {
        assert_eq!(
            rax_mem_write(self.0, address, bytes.as_ptr(), bytes.len()),
            RaxStatus::Ok
        );
    }
    fn reg(&self, id: i32, value: u64) {
        assert_eq!(rax_reg_write_u64(self.0, id, value), RaxStatus::Ok);
    }
    fn message(&self) -> String {
        let mut text = [0 as std::ffi::c_char; 512];
        rax_engine_errmsg(self.0, text.as_mut_ptr(), text.len());
        // SAFETY: errmsg NUL-terminates the nonempty caller-owned buffer.
        unsafe { std::ffi::CStr::from_ptr(text.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    }
}
impl Drop for Sparse {
    fn drop(&mut self) {
        rax_engine_close(self.0);
    }
}

#[test]
fn crossing_fetch_reports_missing_continuation_and_retries_exact_pc() {
    for mode in [RAX_MODE_32, RAX_MODE_64] {
        for tail in 1..5 {
            let e = Sparse::new(mode);
            let pc = 0x2000 - tail as u64;
            // JMP rel32 +0 consumes five bytes and lands immediately after itself.
            let code = [0xe9, 0, 0, 0, 0];
            e.bytes(pc, &code[..tail]);
            let before = rax_emu_icount(e.0);
            assert_ne!(rax_emu_start(e.0, pc, pc + 5, 1_000_000, 8), RaxStatus::Ok);
            let error = e.message();
            assert!(
                error.contains("0x2000"),
                "missing continuation address: {error}"
            );
            assert_eq!(unsafe { rd_u64(e.0, RIP) }, pc, "fetch fault changed PC");
            assert_eq!(
                rax_emu_icount(e.0),
                before,
                "failed fetch retired an instruction"
            );
            assert_eq!(
                rax_mem_map(e.0, 0x2000, 0x1000, RAX_PROT_ALL),
                RaxStatus::Ok
            );
            e.bytes(0x2000, &code[tail..]);
            assert_eq!(rax_emu_start(e.0, pc, pc + 5, 1_000_000, 8), RaxStatus::Ok);
            assert_eq!(unsafe { rd_u64(e.0, RIP) }, pc + 5);
            assert_eq!(rax_emu_icount(e.0), before + 1);
        }
    }
}

#[test]
fn short_instruction_does_not_require_speculative_next_page() {
    for mode in [RAX_MODE_32, RAX_MODE_64] {
        let e = Sparse::new(mode);
        e.bytes(0x1fff, &[0x90]);
        assert_eq!(
            rax_emu_start(e.0, 0x1fff, 0x2000, 1_000_000, 1),
            RaxStatus::Ok
        );
        assert_eq!(unsafe { rd_u64(e.0, RIP) }, 0x2000);
    }
}

#[test]
fn failed_stack_store_preserves_registers_and_retires_nothing() {
    for mode in [RAX_MODE_32, RAX_MODE_64] {
        let e = Sparse::new(mode);
        e.bytes(0x1000, &[0x50]); // PUSH (E/R)AX
        e.reg(0x0104, 0x4000); // RSP; inaccessible stack page below.
        e.reg(RAX, 0x11223344);
        assert_ne!(
            rax_emu_start(e.0, 0x1000, 0x1001, 1_000_000, 1),
            RaxStatus::Ok
        );
        assert_eq!(unsafe { rd_u64(e.0, RIP) }, 0x1000);
        assert_eq!(unsafe { rd_u64(e.0, 0x0104) }, 0x4000);
        assert_eq!(rax_emu_icount(e.0), 0);
    }
}

fn fault(e: &Sparse) -> RaxFaultInfo {
    let mut out = RaxFaultInfo::default();
    assert_eq!(rax_emu_last_fault(e.0, &mut out), RaxStatus::Ok);
    out
}

#[test]
fn fetch_prefix_boundary_matrix_and_query_lifecycle() {
    for mode in [RAX_MODE_32, RAX_MODE_64] {
        // 1..15 byte NOPs, using redundant operand-size prefixes. None changes
        // GPRs or flags; every partial prefix stream must request its next byte.
        for len in 1..=15 {
            for available in 1..=len {
                let e = Sparse::new(mode);
                let pc = 0x2000 - available as u64;
                let mut bytes = vec![0x66; len];
                bytes[len - 1] = 0x90;
                e.bytes(pc, &bytes[..available]);
                e.reg(RAX, 0x2345);
                let status = rax_emu_start(e.0, pc, pc + len as u64, 1_000_000, 1);
                let f = fault(&e);
                if available == len {
                    assert_eq!(status, RaxStatus::Ok);
                    assert_eq!(f.kind, RAX_FAULT_NONE);
                    assert_eq!(f.retired_instructions, 1);
                } else {
                    assert_ne!(status, RaxStatus::Ok);
                    assert_eq!(
                        f.kind,
                        RAX_FAULT_UNMAPPED,
                        "mode={mode} length={len} available={available}: {}",
                        e.message()
                    );
                    assert_eq!(f.access, RAX_FAULT_ACCESS_FETCH);
                    assert_eq!(f.flags, RAX_FAULT_ADDRESS_VALID);
                    assert_eq!((f.pc, f.address, f.retired_instructions), (pc, 0x2000, 0));
                    assert_eq!(
                        rax_mem_map(e.0, 0x2000, 0x1000, RAX_PROT_ALL),
                        RaxStatus::Ok
                    );
                    e.bytes(0x2000, &bytes[available..]);
                    assert_eq!(
                        fault(&e).kind,
                        RAX_FAULT_UNMAPPED,
                        "host writes retain execution fault"
                    );
                    assert_eq!(
                        rax_emu_start(e.0, pc, pc + len as u64, 1_000_000, 1),
                        RaxStatus::Ok
                    );
                    assert_eq!(fault(&e).kind, RAX_FAULT_NONE);
                }
                assert_eq!(unsafe { rd_u64(e.0, RAX) }, 0x2345);
                assert_eq!(unsafe { rd_u64(e.0, RIP) }, pc + len as u64);
            }
        }
    }
}

#[test]
fn typed_data_faults_preserve_state_and_survive_mapping() {
    for mode in [RAX_MODE_32, RAX_MODE_64] {
        for write_access in [false, true] {
            let e = Sparse::new(mode);
            e.bytes(
                0x1000,
                if write_access {
                    &[0x89, 0x03]
                } else {
                    &[0x8b, 0x03]
                },
            ); // MOV [EBX],EAX / EAX,[EBX]
            e.reg(0x0103, 0x3ffe);
            e.reg(RAX, 0x12345678);
            assert_eq!(
                rax_mem_map(e.0, 0x3000, 0x1000, RAX_PROT_ALL),
                RaxStatus::Ok
            );
            e.bytes(0x3ffe, &[0xa5, 0x5a]);
            assert_ne!(
                rax_emu_start(e.0, 0x1000, 0x1002, 1_000_000, 1),
                RaxStatus::Ok
            );
            let f = fault(&e);
            assert_eq!(
                (f.kind, f.address, f.pc),
                (RAX_FAULT_UNMAPPED, 0x4000, 0x1000)
            );
            assert_eq!(
                f.access,
                if write_access {
                    RAX_FAULT_ACCESS_WRITE
                } else {
                    RAX_FAULT_ACCESS_READ
                }
            );
            assert_eq!(f.retired_instructions, 0);
            assert_eq!(unsafe { rd_u64(e.0, RAX) }, 0x12345678);
            let mut unchanged = [0; 2];
            assert_eq!(
                rax_mem_read(e.0, 0x3ffe, unchanged.as_mut_ptr(), 2),
                RaxStatus::Ok
            );
            assert_eq!(
                unchanged,
                [0xa5, 0x5a],
                "failed crossing store partially committed"
            );
            assert_eq!(
                rax_mem_map(e.0, 0x4000, 0x1000, RAX_PROT_ALL),
                RaxStatus::Ok
            );
            if !write_access {
                e.bytes(0x3ffe, &0x76543210_u32.to_le_bytes());
            }
            assert_eq!(
                rax_emu_start(e.0, 0x1000, 0x1002, 1_000_000, 1),
                RaxStatus::Ok
            );
            assert_eq!(fault(&e).retired_instructions, 1);
            assert_eq!(rax_emu_icount(e.0), 1);
            assert_eq!(
                rax_mem_map(e.0, 0x9000, 0x1000, RAX_PROT_ALL),
                RaxStatus::Ok
            );
            assert_eq!(rax_emu_icount(e.0), 1, "mapping reset retirement count");
        }
    }
}

#[test]
fn partial_rep_retries_only_uncompleted_elements() {
    let e = Sparse::new(RAX_MODE_64);
    e.bytes(0x1000, &[0xf3, 0xa4]); // REP MOVSB
    e.bytes(0x1800, &[0x11, 0x22, 0x33, 0x44]);
    assert_eq!(
        rax_mem_map(e.0, 0x3000, 0x1000, RAX_PROT_ALL),
        RaxStatus::Ok
    );
    e.reg(0x0106, 0x1800);
    e.reg(0x0107, 0x3ffe);
    e.reg(RCX, 4);
    assert_ne!(
        rax_emu_start(e.0, 0x1000, 0x1002, 1_000_000, 1),
        RaxStatus::Ok
    );
    assert_eq!(unsafe { rd_u64(e.0, RCX) }, 2);
    assert_eq!(unsafe { rd_u64(e.0, 0x0106) }, 0x1802);
    assert_eq!(unsafe { rd_u64(e.0, 0x0107) }, 0x4000);
    assert_eq!(unsafe { rd_u64(e.0, RIP) }, 0x1000);
    assert_eq!(fault(&e).retired_instructions, 0);
    assert_eq!(
        rax_mem_map(e.0, 0x4000, 0x1000, RAX_PROT_ALL),
        RaxStatus::Ok
    );
    // If replay erroneously starts at the original RSI this will corrupt output.
    e.bytes(0x1800, &[0xaa, 0xbb]);
    assert_eq!(
        rax_emu_start(e.0, 0x1000, 0x1002, 1_000_000, 1),
        RaxStatus::Ok
    );
    let mut bytes = [0; 4];
    assert_eq!(
        rax_mem_read(e.0, 0x3ffe, bytes.as_mut_ptr(), 4),
        RaxStatus::Ok
    );
    assert_eq!(bytes, [0x11, 0x22, 0x33, 0x44]);
    assert_eq!(rax_emu_icount(e.0), 1);
}

#[test]
fn fault_query_validates_header_and_preserves_extension_tail() {
    let e = Sparse::new(RAX_MODE_64);
    let mut info = RaxFaultInfo::default();
    assert_eq!(
        rax_emu_last_fault(ptr::null(), &mut info),
        RaxStatus::Handle
    );
    assert_eq!(rax_emu_last_fault(e.0, ptr::null_mut()), RaxStatus::Arg);
    info.struct_size = 8;
    assert_eq!(rax_emu_last_fault(e.0, &mut info), RaxStatus::Arg);
    assert_eq!(info.struct_size, 8);
    info = RaxFaultInfo::default();
    info.version = 99;
    assert_eq!(rax_emu_last_fault(e.0, &mut info), RaxStatus::Unsupported);
    assert_eq!(info.version, 99);
    #[repr(C)]
    struct Extended {
        info: RaxFaultInfo,
        tail: [u64; 2],
    }
    let mut ext = Extended {
        info: RaxFaultInfo::default(),
        tail: [u64::MAX; 2],
    };
    ext.info.struct_size = std::mem::size_of::<Extended>() as u32;
    assert_eq!(rax_emu_last_fault(e.0, &mut ext.info), RaxStatus::Ok);
    assert_eq!(ext.tail, [u64::MAX; 2]);
    assert_eq!(ext.info.struct_size, 48);
    assert_eq!(std::mem::offset_of!(RaxFaultInfo, retired_instructions), 40);
}

#[test]
fn query_does_not_erase_error_and_reset_clears_fault() {
    let e = Sparse::new(RAX_MODE_64);
    assert_ne!(
        rax_emu_start(e.0, 0x5000, RAX_NO_ADDR, 1_000_000, 1),
        RaxStatus::Ok
    );
    let before = e.message();
    assert_eq!(fault(&e).address, 0x5000);
    assert_eq!(e.message(), before);
    assert_eq!(rax_engine_reset(e.0), RaxStatus::Ok);
    assert_eq!(fault(&e).kind, RAX_FAULT_NONE);
}

#[test]
fn invalid_instruction_is_not_reported_as_a_recoverable_idt_read() {
    let e = Sparse::new(RAX_MODE_64);
    e.bytes(0x1000, &[0x0f, 0x0b]); // UD2; this embedding has no exception table.
    assert_ne!(
        rax_emu_start(e.0, 0x1000, RAX_NO_ADDR, 1_000_000, 1),
        RaxStatus::Ok
    );
    assert_eq!(fault(&e).kind, RAX_FAULT_INVALID_INSTRUCTION);
    assert_eq!(fault(&e).pc, 0x1000);
    assert_eq!(fault(&e).flags, 0);
}

#[test]
fn free_run_fault_reports_actual_pc_and_retirements() {
    let e = Sparse::new(RAX_MODE_32);
    // NOP then JMP rel32 across the missing page. No hooks/count/deadline:
    // deliberately selects the run-to-exit C API branch.
    e.bytes(0x1ffc, &[0x90, 0xe9, 0, 0]);
    assert_ne!(rax_emu_start(e.0, 0x1ffc, RAX_NO_ADDR, 0, 0), RaxStatus::Ok);
    let f = fault(&e);
    assert_eq!(f.pc, 0x1ffd);
    assert_eq!(f.address, 0x2000);
    assert_eq!(f.kind, RAX_FAULT_UNMAPPED);
    assert_eq!(f.access, RAX_FAULT_ACCESS_FETCH);
    assert_eq!(f.retired_instructions, 1);
    assert_eq!(rax_emu_icount(e.0), 1);
}

#[test]
fn already_halted_step_does_not_retire_again() {
    let e = Sparse::new(RAX_MODE_32);
    e.bytes(0x1000, &[0x90, 0xf4]);
    assert_eq!(
        rax_emu_start(e.0, 0x1000, RAX_NO_ADDR, 1_000_000, 8),
        RaxStatus::Ok
    );
    assert_eq!(fault(&e).retired_instructions, 2);
    let mut retired = u64::MAX;
    assert_eq!(rax_emu_step(e.0, 1, &mut retired), RaxStatus::Ok);
    assert_eq!(retired, 0);
    assert_eq!(fault(&e).retired_instructions, 0);
    assert_eq!(rax_emu_icount(e.0), 2);
}

#[test]
fn noncanonical_fetch_is_protection_even_when_exception_backing_is_missing() {
    for count in [0, 1] {
        let e = Sparse::new(RAX_MODE_64);
        e.reg(0x0900, 0x8000_0001); // CR0.PG | CR0.PE
        e.reg(0x0904, 0x20); // CR4.PAE
        e.reg(0x1000, 0x500); // EFER.LMA | EFER.LME
        assert_ne!(
            rax_emu_start(e.0, 0x0000_8000_0000_0000, RAX_NO_ADDR, 0, count),
            RaxStatus::Ok
        );
        let f = fault(&e);
        assert_eq!(f.kind, RAX_FAULT_PERMISSION);
        assert_eq!(f.pc, 0x0000_8000_0000_0000);
        assert_eq!(
            f.flags, 0,
            "a failed IDT access is not the originating fault"
        );
        assert_eq!(f.retired_instructions, 0);
    }
}

#[test]
fn virtual_page_fault_never_names_missing_physical_backing() {
    use rax_engine::error::Error;
    for (code, kind, access) in [
        (0, RAX_FAULT_OTHER, RAX_FAULT_ACCESS_READ),
        (3, RAX_FAULT_PERMISSION, RAX_FAULT_ACCESS_WRITE),
        (0x11, RAX_FAULT_PERMISSION, RAX_FAULT_ACCESS_FETCH),
    ] {
        let error = Error::FaultDelivery {
            fault: Box::new(Error::PageFault {
                vaddr: 0xabc000,
                error_code: code,
            }),
            diagnosis: "missing IDT".into(),
        };
        let info = RaxFaultInfo::from_error(0x1000, &error);
        assert_eq!(info.kind, kind);
        assert_eq!(info.access, access);
        assert_eq!(info.address, 0xabc000);
        assert_eq!(info.flags, RAX_FAULT_ADDRESS_VALID);
    }
}
