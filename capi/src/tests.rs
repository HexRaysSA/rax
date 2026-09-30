//! In-crate ABI tests. These exercise the `extern "C"` entry points directly
//! (with the same raw-pointer discipline a C caller uses), validating the
//! whole surface without requiring a C toolchain.

#![allow(clippy::missing_safety_doc)]

use std::os::raw::c_void;
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::arch::{RAX_MODE_64, RAX_RISCV_EXT_XIDA_SLTW, RaxArch};
use crate::engine::{
    Engine, RaxEngineConfig, rax_engine_close, rax_engine_open, rax_engine_open_config,
    rax_engine_reset,
};
use crate::hook::rax_hook_add_code;
use crate::mem::{
    RAX_PROT_ALL, RAX_PROT_READ, RaxMemRegion, rax_mem_map, rax_mem_protect, rax_mem_read,
    rax_mem_regions, rax_mem_unmap, rax_mem_write,
};
use crate::reg::{rax_reg_read, rax_reg_read_u64, rax_reg_size, rax_reg_write, rax_reg_write_u64};
use crate::run::{
    ExitInfo, RAX_NO_ADDR, RAX_STOP_COUNT, RAX_STOP_HLT, RAX_STOP_UNTIL, rax_can_interrupt,
    rax_emu_icount, rax_emu_last_exit, rax_emu_start, rax_emu_step, rax_interrupt,
};
use crate::status::RaxStatus;

// x86 register ids (mirror rax.h).
const RIP: i32 = 0x0010;
const RAX: i32 = 0x0100;
const RCX: i32 = 0x0101;
const EAX: i32 = 0x0200;
const AH: i32 = 0x0500;
const XMM0: i32 = 0x0B00;
const ARM64_X0: i32 = 0x0100;
const ARM64_V0: i32 = 0x0200;
const ARM64_FPCR: i32 = 0x0020;
const ARM64_FPSR: i32 = 0x0021;
const RISCV_PC: i32 = 0x0011;
const RISCV_X0: i32 = 0x0100;

fn open_x86() -> *mut Engine {
    let mut e: *mut Engine = ptr::null_mut();
    let st = rax_engine_open(RaxArch::X86 as i32, RAX_MODE_64, &mut e);
    assert_eq!(st, RaxStatus::Ok);
    assert!(!e.is_null());
    e
}

fn open_riscv_with_ext(ext: u64) -> *mut Engine {
    let cfg = RaxEngineConfig {
        size: std::mem::size_of::<RaxEngineConfig>() as u32,
        arch: RaxArch::Riscv64 as i32,
        mode: 0,
        backend: crate::arch::RAX_BACKEND_DEFAULT,
        mem_base: 0,
        mem_size: 0,
        mem_perms: RAX_PROT_ALL,
        flags: 0,
        riscv_ext: ext,
    };
    let mut e: *mut Engine = ptr::null_mut();
    let st = rax_engine_open_config(&cfg, &mut e);
    assert_eq!(st, RaxStatus::Ok);
    assert!(!e.is_null());
    e
}

/// mov rax,0x1337 ; mov rcx,1 ; add rax,rcx ; hlt
const HLT_PROG: &[u8] = &[
    0x48, 0xC7, 0xC0, 0x37, 0x13, 0x00, 0x00, // mov rax, 0x1337
    0x48, 0xC7, 0xC1, 0x01, 0x00, 0x00, 0x00, // mov rcx, 1
    0x48, 0x01, 0xC8, // add rax, rcx
    0xF4, // hlt
];

unsafe fn write(e: *mut Engine, addr: u64, bytes: &[u8]) {
    let st = rax_mem_write(e, addr, bytes.as_ptr(), bytes.len());
    assert_eq!(st, RaxStatus::Ok);
}

unsafe fn set_rip(e: *mut Engine, v: u64) {
    assert_eq!(rax_reg_write_u64(e, RIP, v), RaxStatus::Ok);
}

unsafe fn rd_u64(e: *mut Engine, id: i32) -> u64 {
    let mut v = 0u64;
    assert_eq!(rax_reg_read_u64(e, id, &mut v), RaxStatus::Ok);
    v
}

#[test]
fn version_and_strerror() {
    let (mut a, mut b, mut c) = (0u32, 0u32, 0u32);
    let v = crate::rax_version(&mut a, &mut b, &mut c);
    assert_eq!(v, (a << 16) | (b << 8) | c);
    assert_eq!((a, b, c), (1, 7, 0));
    let s = crate::rax_strerror(0);
    assert!(!s.is_null());
    let version_string = unsafe { std::ffi::CStr::from_ptr(crate::rax_version_string()) };
    assert!(
        version_string
            .to_bytes()
            .windows(5)
            .any(|part| part == b"1.7.0")
    );
}

#[test]
fn panic_guards_remain_effective_in_optimized_profile() {
    assert_eq!(
        crate::guard(|| panic!("ffi panic sentinel")),
        RaxStatus::Internal
    );
    assert_eq!(
        crate::guard_val(0x55u32, || panic!("ffi value panic sentinel")),
        0x55
    );
}

#[test]
fn open_query_close() {
    let e = open_x86();
    assert_eq!(crate::engine::rax_engine_arch(e), RaxArch::X86 as i32);
    assert_eq!(crate::engine::rax_engine_mode(e), RAX_MODE_64);
    assert_eq!(crate::engine::rax_engine_supports_stepping(e), 1);
    rax_engine_close(e);
}

#[test]
fn null_handle_rejected() {
    assert_eq!(
        rax_mem_write(ptr::null_mut(), 0, [0u8].as_ptr(), 1),
        RaxStatus::Handle
    );
    assert_eq!(
        rax_reg_write_u64(ptr::null_mut(), RAX, 0),
        RaxStatus::Handle
    );
}

#[test]
fn mem_roundtrip_and_unmapped() {
    unsafe {
        let e = open_x86();
        let data = [1u8, 2, 3, 4, 5, 6, 7, 8];
        write(e, 0x2000, &data);
        let mut back = [0u8; 8];
        assert_eq!(rax_mem_read(e, 0x2000, back.as_mut_ptr(), 8), RaxStatus::Ok);
        assert_eq!(back, data);

        // Above the 256 MiB default region → unmapped.
        let st = rax_mem_read(e, 0x4000_0000_0000, back.as_mut_ptr(), 8);
        assert_eq!(st, RaxStatus::Map);
        rax_engine_close(e);
    }
}

#[test]
fn sparse_map_unmap_protect_regions() {
    unsafe {
        let e = open_x86();
        // Map a high region and use it.
        assert_eq!(
            rax_mem_map(e, 0x4000_0000, 0x2000, RAX_PROT_ALL),
            RaxStatus::Ok
        );
        let payload = [0xDEu8, 0xAD, 0xBE, 0xEF];
        write(e, 0x4000_0000, &payload);
        let mut back = [0u8; 4];
        assert_eq!(
            rax_mem_read(e, 0x4000_0000, back.as_mut_ptr(), 4),
            RaxStatus::Ok
        );
        assert_eq!(back, payload);

        // Region count is now 2 (default + new).
        let mut n: usize = 0;
        assert_eq!(rax_mem_regions(e, ptr::null_mut(), &mut n), RaxStatus::Ok);
        assert_eq!(n, 2);
        let mut regs = [RaxMemRegion {
            base: 0,
            size: 0,
            perms: 0,
            _reserved: 0,
        }; 8];
        let mut cap = regs.len();
        assert_eq!(
            rax_mem_regions(e, regs.as_mut_ptr(), &mut cap),
            RaxStatus::Ok
        );
        assert_eq!(cap, 2);

        // Protect the first page of the high region read-only (splits it → 3 regions).
        assert_eq!(
            rax_mem_protect(e, 0x4000_0000, 0x1000, RAX_PROT_READ),
            RaxStatus::Ok
        );
        let mut n2: usize = 0;
        rax_mem_regions(e, ptr::null_mut(), &mut n2);
        assert_eq!(n2, 3);
        // Contents preserved across the split.
        assert_eq!(
            rax_mem_read(e, 0x4000_0000, back.as_mut_ptr(), 4),
            RaxStatus::Ok
        );
        assert_eq!(back, payload);

        // Unmap the high region entirely.
        assert_eq!(rax_mem_unmap(e, 0x4000_0000, 0x2000), RaxStatus::Ok);
        let mut n3: usize = 0;
        rax_mem_regions(e, ptr::null_mut(), &mut n3);
        assert_eq!(n3, 1);
        rax_engine_close(e);
    }
}

#[test]
fn cannot_unmap_last_region() {
    let e = open_x86();
    // Default region is [0, 256MiB); unmapping all of it must be refused.
    let st = rax_mem_unmap(e, 0, 256 * 1024 * 1024);
    assert_eq!(st, RaxStatus::Map);
    rax_engine_close(e);
}

#[test]
fn register_widths_and_subregisters() {
    unsafe {
        let e = open_x86();
        assert_eq!(rax_reg_size(RaxArch::X86 as i32, RAX), 8);
        assert_eq!(rax_reg_size(RaxArch::X86 as i32, EAX), 4);
        assert_eq!(rax_reg_size(RaxArch::X86 as i32, XMM0), 16);
        assert_eq!(rax_reg_size(RaxArch::X86 as i32, 0x7FFF), 0); // invalid

        // EAX write zero-extends RAX.
        assert_eq!(
            rax_reg_write_u64(e, RAX, 0xAAAA_BBBB_CCCC_DDDD),
            RaxStatus::Ok
        );
        // Raw register buffers follow the C ABI's little-endian contract,
        // independently of the host's integer representation.
        let eax = 0x1122_3344u32.to_le_bytes();
        assert_eq!(rax_reg_write(e, EAX, eax.as_ptr()), RaxStatus::Ok);
        assert_eq!(rd_u64(e, RAX), 0x1122_3344);

        // AH writes bits 15:8.
        assert_eq!(rax_reg_write_u64(e, RAX, 0), RaxStatus::Ok);
        let ah: u8 = 0x77;
        assert_eq!(rax_reg_write(e, AH, &ah as *const u8), RaxStatus::Ok);
        assert_eq!(rd_u64(e, RAX), 0x7700);

        // XMM0 16-byte roundtrip.
        let xin = [0x11u8; 16];
        assert_eq!(rax_reg_write(e, XMM0, xin.as_ptr()), RaxStatus::Ok);
        let mut xout = [0u8; 16];
        let mut sz: usize = 0;
        assert_eq!(
            rax_reg_read(e, XMM0, xout.as_mut_ptr(), &mut sz),
            RaxStatus::Ok
        );
        assert_eq!(sz, 16);
        assert_eq!(xout, xin);

        // Invalid register id.
        let mut v = 0u64;
        assert_eq!(rax_reg_read_u64(e, 0x7FFF, &mut v), RaxStatus::Reg);
        rax_engine_close(e);
    }
}

#[test]
fn run_to_hlt() {
    unsafe {
        let e = open_x86();
        write(e, 0x1000, HLT_PROG);
        set_rip(e, 0x1000);
        assert_eq!(rax_emu_start(e, 0x1000, RAX_NO_ADDR, 0, 0), RaxStatus::Ok);
        let mut ex = ExitInfo::none();
        rax_emu_last_exit(e, &mut ex);
        assert_eq!(ex.reason, RAX_STOP_HLT);
        assert_eq!(rd_u64(e, RAX), 0x1338);
        assert_eq!(rd_u64(e, RCX), 1);
        assert_eq!(rax_emu_icount(e), 4);
        rax_engine_close(e);
    }
}

#[test]
fn step_one_instruction() {
    unsafe {
        let e = open_x86();
        // nop ; nop ; hlt
        write(e, 0x1000, &[0x90, 0x90, 0xF4]);
        set_rip(e, 0x1000);
        let mut executed = 0u64;
        assert_eq!(rax_emu_step(e, 1, &mut executed), RaxStatus::Ok);
        assert_eq!(executed, 1);
        assert_eq!(rd_u64(e, RIP), 0x1001);
        rax_engine_close(e);
    }
}

#[test]
fn count_and_until_stops() {
    unsafe {
        let e = open_x86();
        write(e, 0x1000, &[0x90, 0x90, 0x90, 0xF4]); // nop;nop;nop;hlt
        // count = 2
        set_rip(e, 0x1000);
        assert_eq!(rax_emu_start(e, 0x1000, RAX_NO_ADDR, 0, 2), RaxStatus::Ok);
        let mut ex = ExitInfo::none();
        rax_emu_last_exit(e, &mut ex);
        assert_eq!(ex.reason, RAX_STOP_COUNT);
        assert_eq!(ex.value, 2, "COUNT exit must expose attempted steps");
        assert_eq!(rd_u64(e, RIP), 0x1002);

        // until = 0x1003
        set_rip(e, 0x1000);
        assert_eq!(rax_emu_start(e, 0x1000, 0x1003, 0, 0), RaxStatus::Ok);
        rax_emu_last_exit(e, &mut ex);
        assert_eq!(ex.reason, RAX_STOP_UNTIL);
        assert_eq!(ex.address, 0x1003);
        rax_engine_close(e);
    }
}

extern "C" fn count_cb(_e: *mut Engine, _addr: u64, _size: u32, user: *mut c_void) {
    let c = unsafe { &*(user as *const AtomicU64) };
    c.fetch_add(1, Ordering::Relaxed);
}

#[test]
fn code_hook_counts_instructions() {
    unsafe {
        let e = open_x86();
        write(e, 0x1000, HLT_PROG);
        let counter = AtomicU64::new(0);
        let mut id = 0u32;
        // begin > end => match all addresses.
        assert_eq!(
            rax_hook_add_code(
                e,
                1,
                0,
                Some(count_cb),
                &counter as *const _ as *mut c_void,
                &mut id
            ),
            RaxStatus::Ok
        );
        assert!(id > 0);
        set_rip(e, 0x1000);
        assert_eq!(rax_emu_start(e, 0x1000, RAX_NO_ADDR, 0, 0), RaxStatus::Ok);
        // 3 instructions + the HLT all hit the code hook.
        assert_eq!(counter.load(Ordering::Relaxed), 4);
        rax_engine_close(e);
    }
}

#[test]
fn interrupt_masked_by_default() {
    let e = open_x86();
    // Default rflags has IF clear → cannot inject.
    assert_eq!(rax_can_interrupt(e), 0);
    assert_eq!(rax_interrupt(e, 0x20), RaxStatus::State);
    rax_engine_close(e);
}

#[test]
fn context_save_restore_roundtrip() {
    unsafe {
        let e = open_x86();
        write(e, 0x1000, HLT_PROG);
        assert_eq!(rax_reg_write_u64(e, RAX, 0xCAFE_F00D), RaxStatus::Ok);

        let mut need: usize = 0;
        assert_eq!(
            crate::context::rax_context_save(e, ptr::null_mut(), 0, &mut need),
            RaxStatus::Ok
        );
        assert!(need > 0);
        let mut blob = vec![0u8; need];
        let mut got: usize = 0;
        assert_eq!(
            crate::context::rax_context_save(e, blob.as_mut_ptr(), blob.len(), &mut got),
            RaxStatus::Ok
        );

        // Mutate, then restore.
        assert_eq!(rax_reg_write_u64(e, RAX, 0), RaxStatus::Ok);
        write(e, 0x1000, &[0; 4]); // clobber memory too
        assert_eq!(
            crate::context::rax_context_restore(e, blob.as_ptr(), blob.len()),
            RaxStatus::Ok
        );
        assert_eq!(rd_u64(e, RAX), 0xCAFE_F00D);
        // Memory was restored.
        let mut mb = [0u8; 4];
        rax_mem_read(e, 0x1000, mb.as_mut_ptr(), 4);
        assert_eq!(&mb, &HLT_PROG[..4]);
        rax_engine_close(e);
    }
}

#[test]
fn reset_restores_default_state() {
    unsafe {
        let e = open_x86();
        assert_eq!(rax_reg_write_u64(e, RAX, 0x1234), RaxStatus::Ok);
        assert_eq!(rax_engine_reset(e), RaxStatus::Ok);
        assert_eq!(rd_u64(e, RAX), 0);
        // Flat 64-bit default leaves CS.l set; just ensure mode preserved.
        assert_eq!(crate::engine::rax_engine_mode(e), RAX_MODE_64);
        rax_engine_close(e);
    }
}

#[test]
fn arm64_registers() {
    unsafe {
        let mut e: *mut Engine = ptr::null_mut();
        assert_eq!(
            rax_engine_open(RaxArch::Arm64 as i32, 0, &mut e),
            RaxStatus::Ok
        );
        // X0 id = 0x0100, PC = 0x0011.
        assert_eq!(rax_reg_write_u64(e, 0x0100, 0xABCD), RaxStatus::Ok);
        assert_eq!(rd_u64(e, 0x0100), 0xABCD);
        assert_eq!(rax_reg_write_u64(e, 0x0011, 0x8000), RaxStatus::Ok);
        assert_eq!(rd_u64(e, 0x0011), 0x8000);
        // V0 is 16 bytes.
        assert_eq!(rax_reg_size(RaxArch::Arm64 as i32, 0x0200), 16);
        rax_engine_close(e);
    }
}

#[test]
fn arm64_step_advances_pc() {
    unsafe {
        let mut e: *mut Engine = ptr::null_mut();
        assert_eq!(
            rax_engine_open(RaxArch::Arm64 as i32, 0, &mut e),
            RaxStatus::Ok
        );
        assert_eq!(crate::engine::rax_engine_supports_stepping(e), 1);
        // Two AArch64 NOPs (0xD503201F, little-endian).
        write(e, 0x1000, &[0x1F, 0x20, 0x03, 0xD5, 0x1F, 0x20, 0x03, 0xD5]);
        assert_eq!(rax_reg_write_u64(e, 0x0011, 0x1000), RaxStatus::Ok); // PC
        let mut executed = 0u64;
        assert_eq!(rax_emu_step(e, 1, &mut executed), RaxStatus::Ok);
        assert_eq!(executed, 1);
        assert_eq!(rd_u64(e, 0x0011), 0x1004);
        assert!(rax_emu_icount(e) >= 1);
        rax_engine_close(e);
    }
}

#[test]
fn arm64_mem_hook_observes_load_store_fetch() {
    use crate::hook::{
        RAX_HOOK_MEM_FETCH, RAX_HOOK_MEM_READ, RAX_HOOK_MEM_WRITE, rax_hook_add_mem,
    };
    unsafe {
        let mut e: *mut Engine = ptr::null_mut();
        assert_eq!(
            rax_engine_open(RaxArch::Arm64 as i32, 0, &mut e),
            RaxStatus::Ok
        );
        // mov x0,#0x1122 ; str x0,[sp] ; ldr x1,[sp] ; ret
        write(
            e,
            0x1000,
            &[
                0x40, 0x24, 0x82, 0xD2, 0xE0, 0x03, 0x00, 0xF9, 0xE1, 0x03, 0x40, 0xF9, 0xC0, 0x03,
                0x5F, 0xD6,
            ],
        );
        assert_eq!(rax_reg_write_u64(e, 0x0010, 0x3000), RaxStatus::Ok); // SP

        let mut obs = MemObs::default();
        let mut id = 0u32;
        assert_eq!(
            rax_hook_add_mem(
                e,
                RAX_HOOK_MEM_READ | RAX_HOOK_MEM_WRITE | RAX_HOOK_MEM_FETCH,
                1,
                0,
                Some(mem_cb),
                &mut obs as *mut _ as *mut c_void,
                &mut id,
            ),
            RaxStatus::Ok
        );
        assert_eq!(rax_emu_start(e, 0x1000, 0x100C, 0, 10), RaxStatus::Ok);
        assert_eq!(obs.writes, 1);
        assert_eq!(obs.last_write_addr, 0x3000);
        assert_eq!(obs.last_write_val, 0x1122);
        assert_eq!(obs.reads, 1);
        assert_eq!(obs.last_read_addr, 0x3000);
        assert_eq!(obs.last_read_val, 0x1122);
        assert_eq!(obs.fetches, 3);
        assert_eq!(rd_u64(e, 0x0101), 0x1122); // X1
        rax_engine_close(e);
    }
}

#[test]
fn arm64_emu_start_begin_preserves_monotonic_instruction_count() {
    unsafe {
        let mut e: *mut Engine = ptr::null_mut();
        assert_eq!(
            rax_engine_open(RaxArch::Arm64 as i32, 0, &mut e),
            RaxStatus::Ok
        );
        let code = [
            0x1F, 0x20, 0x03, 0xD5, // nop
            0x1F, 0x20, 0x03, 0xD5, // nop
        ];
        write(e, 0x1000, &code);
        assert_eq!(rax_emu_start(e, 0x1000, RAX_NO_ADDR, 0, 1), RaxStatus::Ok);
        assert_eq!(rax_emu_icount(e), 1);
        assert_eq!(rax_emu_start(e, 0x1004, RAX_NO_ADDR, 0, 1), RaxStatus::Ok);
        assert_eq!(rax_emu_icount(e), 2);
        rax_engine_close(e);
    }
}

#[test]
fn arm64_register_updates_preserve_runtime_and_simd_fp_state() {
    unsafe {
        let mut e: *mut Engine = ptr::null_mut();
        assert_eq!(
            rax_engine_open(RaxArch::Arm64 as i32, 0, &mut e),
            RaxStatus::Ok
        );
        let code = [
            0x1F, 0x20, 0x03, 0xD5, // nop
            0x1F, 0x20, 0x03, 0xD5, // nop
        ];
        write(e, 0x1000, &code);

        let vector = [
            0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba,
            0xdc, 0xfe,
        ];
        assert_eq!(rax_reg_write(e, ARM64_V0, vector.as_ptr()), RaxStatus::Ok);
        assert_eq!(rax_reg_write_u64(e, ARM64_FPCR, 1 << 24), RaxStatus::Ok);
        assert_eq!(rax_reg_write_u64(e, ARM64_FPSR, 1 << 27), RaxStatus::Ok);

        assert_eq!(rax_emu_start(e, 0x1000, RAX_NO_ADDR, 0, 1), RaxStatus::Ok);
        assert_eq!(rax_emu_icount(e), 1);

        // A scalar summary-style write must not reset execution counters or
        // discard unrelated SIMD/FP architectural state.
        assert_eq!(
            rax_reg_write_u64(e, ARM64_X0, 0xfeed_face_cafe_beef),
            RaxStatus::Ok
        );
        assert_eq!(rax_emu_icount(e), 1);
        let mut observed = [0u8; 16];
        assert_eq!(
            rax_reg_read(e, ARM64_V0, observed.as_mut_ptr(), ptr::null_mut()),
            RaxStatus::Ok
        );
        assert_eq!(observed, vector);
        assert_eq!(rd_u64(e, ARM64_FPCR), 1 << 24);
        assert_eq!(rd_u64(e, ARM64_FPSR), 1 << 27);

        assert_eq!(rax_emu_start(e, 0x1004, RAX_NO_ADDR, 0, 1), RaxStatus::Ok);
        assert_eq!(rax_emu_icount(e), 2);
        rax_engine_close(e);
    }
}

#[repr(C)]
#[derive(Default)]
struct MemObs {
    reads: u64,
    writes: u64,
    fetches: u64,
    last_write_addr: u64,
    last_write_val: u64,
    last_read_addr: u64,
    last_read_val: u64,
}

extern "C" fn mem_cb(
    _e: *mut Engine,
    kind: i32,
    addr: u64,
    _size: u32,
    value: u64,
    user: *mut c_void,
) {
    let o = unsafe { &mut *(user as *mut MemObs) };
    match kind {
        0 => {
            o.reads += 1;
            o.last_read_addr = addr;
            o.last_read_val = value;
        }
        1 => {
            o.writes += 1;
            o.last_write_addr = addr;
            o.last_write_val = value;
        }
        2 => o.fetches += 1,
        _ => {}
    }
}

#[test]
fn mem_hook_observes_load_store_fetch() {
    use crate::hook::{
        RAX_HOOK_MEM_FETCH, RAX_HOOK_MEM_READ, RAX_HOOK_MEM_WRITE, rax_hook_add_mem,
    };
    unsafe {
        let e = open_x86();
        // mov rax,0x11223344 ; mov [0x2000],rax ; mov rbx,[0x2000] ; hlt
        let prog = &[
            0x48, 0xC7, 0xC0, 0x44, 0x33, 0x22, 0x11, // mov rax, 0x11223344
            0x48, 0x89, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // mov [0x2000], rax
            0x48, 0x8B, 0x1C, 0x25, 0x00, 0x20, 0x00, 0x00, // mov rbx, [0x2000]
            0xF4, // hlt
        ];
        write(e, 0x1000, prog);

        let mut obs = MemObs::default();
        let mut id = 0u32;
        assert_eq!(
            rax_hook_add_mem(
                e,
                RAX_HOOK_MEM_READ | RAX_HOOK_MEM_WRITE | RAX_HOOK_MEM_FETCH,
                1,
                0, // begin>end => all addresses
                Some(mem_cb),
                &mut obs as *mut _ as *mut c_void,
                &mut id,
            ),
            RaxStatus::Ok
        );
        assert!(id > 0);

        set_rip(e, 0x1000);
        assert_eq!(rax_emu_start(e, 0x1000, RAX_NO_ADDR, 0, 0), RaxStatus::Ok);

        // Observed exactly one 8-byte store and one 8-byte load at 0x2000.
        assert_eq!(obs.writes, 1, "expected one store");
        assert_eq!(obs.last_write_addr, 0x2000);
        assert_eq!(obs.last_write_val, 0x1122_3344);
        assert_eq!(obs.reads, 1, "expected one load");
        assert_eq!(obs.last_read_addr, 0x2000);
        assert_eq!(obs.last_read_val, 0x1122_3344);
        // One fetch per executed instruction (4: two movs, one mov, hlt).
        assert_eq!(obs.fetches, 4);
        // RBX received the loaded value.
        assert_eq!(rd_u64(e, 0x0103), 0x1122_3344);

        rax_engine_close(e);
    }
}

#[test]
fn riscv_step_advances_pc() {
    unsafe {
        let mut e: *mut Engine = ptr::null_mut();
        assert_eq!(
            rax_engine_open(RaxArch::Riscv64 as i32, 0, &mut e),
            RaxStatus::Ok
        );
        assert_eq!(crate::engine::rax_engine_supports_stepping(e), 1);
        // Two RISC-V NOPs (addi x0,x0,0 = 0x00000013, little-endian).
        write(e, 0x1000, &[0x13, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00]);
        assert_eq!(rax_reg_write_u64(e, RISCV_PC, 0x1000), RaxStatus::Ok);
        let mut executed = 0u64;
        assert_eq!(rax_emu_step(e, 1, &mut executed), RaxStatus::Ok);
        assert_eq!(executed, 1);
        assert_eq!(rd_u64(e, RISCV_PC), 0x1004);
        rax_engine_close(e);
    }
}

#[path = "tests/decode.rs"]
mod decode;

#[path = "tests/analyze.rs"]
mod analyze;

#[test]
fn riscv_open_config_ext_survives_reset() {
    unsafe {
        let e = open_riscv_with_ext(RAX_RISCV_EXT_XIDA_SLTW);

        // sltw x5, x6, x7: signed compare of the low 32-bit words.
        let sltw = ((7u32 << 20) | (6u32 << 15) | (2u32 << 12) | (5u32 << 7) | 0x3b).to_le_bytes();
        write(e, 0x1000, &sltw);

        for _ in 0..2 {
            assert_eq!(rax_reg_write_u64(e, RISCV_PC, 0x1000), RaxStatus::Ok);
            assert_eq!(rax_reg_write_u64(e, RISCV_X0 + 5, 0), RaxStatus::Ok);
            assert_eq!(
                rax_reg_write_u64(e, RISCV_X0 + 6, 0xffff_ffff),
                RaxStatus::Ok
            );
            assert_eq!(rax_reg_write_u64(e, RISCV_X0 + 7, 0), RaxStatus::Ok);

            let mut executed = 0u64;
            assert_eq!(rax_emu_step(e, 1, &mut executed), RaxStatus::Ok);
            assert_eq!(executed, 1);
            assert_eq!(rd_u64(e, RISCV_X0 + 5), 1);
            assert_eq!(rd_u64(e, RISCV_PC), 0x1004);

            assert_eq!(rax_engine_reset(e), RaxStatus::Ok);
        }

        rax_engine_close(e);
    }
}

#[path = "tests/arm64_faultin.rs"]
mod arm64_faultin;

#[path = "tests/x86_faultin.rs"]
mod x86_faultin;

#[path = "tests/user_mode.rs"]
mod user_mode;

#[path = "tests/registers_ext.rs"]
mod registers_ext;

#[path = "tests/run_loop.rs"]
mod run_loop;

#[path = "tests/context_compat.rs"]
mod context_compat;

#[path = "tests/header_sync.rs"]
mod header_sync;

#[path = "tests/arm_engines.rs"]
mod arm_engines;

#[path = "tests/riscv_state.rs"]
mod riscv_state;
