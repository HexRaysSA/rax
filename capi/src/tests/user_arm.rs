//! AArch32 runs the shared user executor through the actual C ABI.
use super::*;
use crate::arch::RAX_MODE_THUMB;

const R0: i32 = 0x0100;
const R1: i32 = 0x0101;
const R2: i32 = 0x0102;
const CPSR: i32 = 0x0012;
const TPIDRURW: i32 = 0x1000;
const TPIDRURO: i32 = 0x1001;

fn syscall(e: &User) -> RaxSyscallInfo {
    let mut call = RaxSyscallInfo::default();
    assert_eq!(rax_emu_last_syscall(e.0, &mut call), RaxStatus::Ok);
    call
}

#[test]
fn arm_and_thumb_syscalls_have_typed_resume_and_breakpoint_records() {
    for (mode, bytes, size, immediate) in [
        (
            RAX_MODE_ARM,
            [0xef00_1234u32, 0xe121_2374]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect::<Vec<_>>(),
            4,
            0x1234,
        ),
        (
            RAX_MODE_THUMB,
            [0xdfabu16, 0xbe07]
                .into_iter()
                .flat_map(u16::to_le_bytes)
                .collect(),
            2,
            0xab,
        ),
    ] {
        let e = User::open(RaxArch::Arm, mode);
        e.code(&bytes);
        assert_eq!(e.reg(CPSR), if mode == RAX_MODE_ARM { 0x10 } else { 0x30 });
        assert_eq!(e.start(BASE), RaxStatus::Ok);
        assert_eq!(e.exit().reason, RAX_STOP_SYSCALL);
        let call = syscall(&e);
        assert_eq!(
            (call.pc, call.resume_pc, call.size, call.immediate),
            (BASE, BASE + size, size as u32, immediate)
        );
        assert_eq!(crate::run::rax_emu_icount(e.0), 1);
        assert_eq!(e.start(e.pc()), RaxStatus::Ok);
        let trap = e.exception();
        assert_eq!(
            (trap.vector, trap.pc, trap.return_pc),
            (0x38, BASE + size, BASE + size)
        );
        assert_ne!(trap.flags & RAX_EXCEPTION_SOFTWARE, 0);
        assert_eq!(trap.syndrome, if size == 4 { 0x1234 } else { 7 });
        assert_eq!(crate::run::rax_emu_icount(e.0), 1);
    }
}

#[test]
fn arm_user_privilege_and_little_endian_policy_cannot_be_changed_by_cpsr() {
    let e = User::open(RaxArch::Arm, RAX_MODE_ARM);
    e.set(CPSR, 0x6000_03d3); // Request Supervisor, BE and interrupt masks.
    assert_eq!(e.reg(CPSR), 0x6000_0010);
    for word in [0xee0d_0f70, 0xee07_0fba, 0xe101_2092, 0xf101_0200] {
        // Write read-only TLS, CP15 barrier, removed SWP, SETEND BE.
        e.words(&[word]);
        assert_eq!(e.start(BASE), RaxStatus::Ok);
        assert_eq!(e.exit().reason, RAX_STOP_EXCEPTION);
        assert_eq!(e.exception().vector, 0);
        assert_eq!(e.fault().kind, RAX_FAULT_INVALID_INSTRUCTION);
        assert_eq!(e.pc(), BASE);
    }
}

#[test]
fn arm_permissions_fault_before_cross_page_store_and_retry_after_protect() {
    let e = User::open(RaxArch::Arm, RAX_MODE_ARM);
    e.words(&[0xe581_0000, 0xef00_0000]); // str r0,[r1]; svc 0.
    e.set(R0, 0x1234_5678);
    e.set(R1, RODATA);
    assert_eq!(e.start(BASE), RaxStatus::Fault);
    assert_eq!(e.fault().kind, RAX_FAULT_PERMISSION);
    assert_eq!(e.fault().address, RODATA);
    assert_eq!(crate::run::rax_emu_icount(e.0), 0);
    assert_eq!(
        rax_mem_protect(e.0, RODATA, 0x1000, RAX_PROT_ALL),
        RaxStatus::Ok
    );
    // A 4-byte unaligned store straddles an RW page and a no-write page.
    assert_eq!(
        rax_mem_protect(e.0, NOEXEC, 0x1000, RAX_PROT_READ),
        RaxStatus::Ok
    );
    e.set(R1, NOEXEC - 2);
    assert_eq!(e.start(BASE), RaxStatus::Fault);
    assert_eq!(e.fault().address, NOEXEC);
    let mut bytes = [0xff; 4];
    assert_eq!(
        crate::mem::rax_mem_read(e.0, NOEXEC - 2, bytes.as_mut_ptr(), 4),
        RaxStatus::Ok
    );
    assert_eq!(bytes, [0; 4]);
    assert_eq!(
        rax_mem_protect(e.0, NOEXEC, 0x1000, RAX_PROT_ALL),
        RaxStatus::Ok
    );
    assert_eq!(e.start(BASE), RaxStatus::Ok);
    assert_eq!(e.exit().reason, RAX_STOP_SYSCALL);
}

#[test]
fn arm_tls_exclusives_and_context_survive_mapping_rebuilds() {
    let e = User::open(RaxArch::Arm, RAX_MODE_ARM);
    // mcr TLS,r0; ldrex r0,[r1]; strex r2,r0,[r1]; svc 0.
    e.words(&[0xee0d_0f50, 0xe191_0f9f, 0xe181_2f90, 0xef00_0000]);
    e.set(R0, 0x3456_0000);
    e.set(R1, NOEXEC);
    e.set(TPIDRURO, 0x7788_0000);
    assert_eq!(rax_emu_start(e.0, BASE, RAX_NO_ADDR, 0, 2), RaxStatus::Ok);
    assert_eq!(e.reg(TPIDRURW), 0x3456_0000);
    let blob = save_context(e.0);
    assert_eq!(u32::from_le_bytes(blob[4..8].try_into().unwrap()), 3);
    assert_eq!(
        rax_mem_map(e.0, 0x60000, 0x1000, RAX_PROT_ALL),
        RaxStatus::Ok
    );
    assert_eq!(
        (e.reg(TPIDRURW), e.reg(TPIDRURO)),
        (0x3456_0000, 0x7788_0000)
    );
    assert_eq!(e.start(e.pc()), RaxStatus::Ok);
    assert_eq!(e.reg(R2), 0, "monitor survives backing-map reconstruction");
    e.set(TPIDRURW, 0);
    e.set(TPIDRURO, 0);
    assert_eq!(
        rax_context_restore(e.0, blob.as_ptr(), blob.len()),
        RaxStatus::Ok
    );
    assert_eq!(
        (e.reg(TPIDRURW), e.reg(TPIDRURO)),
        (0x3456_0000, 0x7788_0000)
    );
    assert_eq!(e.start(e.pc()), RaxStatus::Ok);
    assert_eq!(e.reg(R2), 0, "monitor survives context restore");
    assert_eq!(crate::engine::rax_engine_reset(e.0), RaxStatus::Ok);
    assert_eq!((e.reg(TPIDRURW), e.reg(TPIDRURO)), (0, 0));
    assert_eq!(e.reg(CPSR), 0x10);
}

#[test]
fn arm_interworking_it_and_thumb_entry_use_current_state() {
    let e = User::open(RaxArch::Arm, RAX_MODE_ARM);
    let mut bytes: Vec<u8> = [0xe28f_0001u32, 0xe12f_ff10]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    bytes.extend(
        [0x2105u16, 0x2905, 0xbf0c, 0x2201, 0x2202, 0xdf12]
            .into_iter()
            .flat_map(u16::to_le_bytes),
    );
    e.code(&bytes);
    assert_eq!(e.start(BASE), RaxStatus::Ok);
    assert_eq!(e.reg(R2), 1);
    let call = syscall(&e);
    assert_eq!(
        (call.pc, call.resume_pc, call.size),
        (BASE + 18, BASE + 20, 2)
    );
    let blob = save_context(e.0);
    assert_eq!(
        rax_context_restore(e.0, blob.as_ptr(), blob.len()),
        RaxStatus::Ok
    );
    assert_eq!(e.reg(CPSR) & 0x20, 0x20);
    assert_eq!(e.start(BASE + 18 + 1), RaxStatus::Ok);
    assert_eq!(syscall(&e).pc, BASE + 18);
}

#[test]
fn arm_user_context_rejects_bad_extra_state_without_mutation() {
    let e = User::open(RaxArch::Arm, RAX_MODE_ARM);
    e.set(TPIDRURW, 0x1234);
    let blob = save_context(e.0);
    let cpu_len = u64::from_le_bytes(blob[20..28].try_into().unwrap()) as usize;
    let extra_len = 28 + cpu_len + 8; // no generic emulator image.
    for (offset, value) in [
        (4, 2u8),
        (16, 1),
        (28 + cpu_len, 1),
        (extra_len, 19),
        (extra_len + 8 + 16, 2),
    ] {
        let mut bad = blob.clone();
        bad[offset] = value;
        assert_eq!(
            rax_context_restore(e.0, bad.as_ptr(), bad.len()),
            RaxStatus::Format
        );
        assert_eq!(e.reg(TPIDRURW), 0x1234);
    }
}

#[test]
fn arm_user_context_can_restore_into_system_engine_and_traps_clear_exclusives() {
    let e = User::open(RaxArch::Arm, RAX_MODE_ARM);
    e.words(&[0xe191_0f9f, 0xef00_0000, 0xe181_2f90, 0xef00_0000]);
    e.set(R1, NOEXEC);
    assert_eq!(e.start(BASE), RaxStatus::Ok);
    let blob = save_context(e.0);
    let mut other = ptr::null_mut();
    assert_eq!(
        rax_engine_open(RaxArch::Arm as i32, RAX_MODE_ARM, &mut other),
        RaxStatus::Ok
    );
    let other = User(other);
    let old = save_context(other.0);
    assert_eq!(u32::from_le_bytes(old[4..8].try_into().unwrap()), 2);
    assert_eq!(
        rax_context_restore(other.0, blob.as_ptr(), blob.len()),
        RaxStatus::Ok
    );
    assert_ne!(rax_engine_mode(other.0) & RAX_MODE_USER, 0);
    assert_eq!(other.start(other.pc()), RaxStatus::Ok);
    assert_eq!(
        other.reg(R2),
        1,
        "SVC cleared the exclusive monitor before the snapshot"
    );
}

#[test]
fn arm_memory_hooks_observe_only_committed_accesses() {
    let e = User::open(RaxArch::Arm, RAX_MODE_ARM);
    e.words(&[0xe581_0000, 0xef00_0000]);
    e.set(R0, 0x1234_5678);
    e.set(R1, RODATA);
    let mut seen: Vec<(i32, u64, u32, u64)> = Vec::new();
    assert_eq!(
        rax_hook_add_mem(
            e.0,
            RAX_HOOK_MEM_WRITE,
            1,
            0,
            Some(count_writes),
            &mut seen as *mut _ as *mut c_void,
            ptr::null_mut()
        ),
        RaxStatus::Ok
    );
    assert_eq!(e.start(BASE), RaxStatus::Fault);
    assert!(seen.is_empty());
    e.set(R1, NOEXEC);
    assert_eq!(e.start(BASE), RaxStatus::Ok);
    assert_eq!(seen, [(crate::hook::RAX_MEM_WRITE, NOEXEC, 4, 0x1234_5678)]);
}
