//! Machine thread state in the layouts of `mach/arm/_structs.h` and
//! `mach/i386/_structs.h`: the flavors signal frames carry
//! (`ARM_THREAD_STATE64`, `ARM_EXCEPTION_STATE64`, `ARM_NEON_STATE64`;
//! `x86_THREAD_STATE64`, `x86_EXCEPTION_STATE64`, `x86_AVX_STATE64`), read
//! and written as `thread_getstatus` and `thread_setstatus` do
//! (`osfmk/arm64/status.c`; `osfmk/i386/pcb.c` and `fpu.c`).

use super::signal::EntryState;
use crate::isa::arm::common::cpu::ArmCpu;
use crate::user::cpu::aarch64::A64UserCpu;
use crate::user::cpu::x86_64::X86UserCpu;

/// `sizeof(arm_thread_state64_t)`: `x[29]`, `fp`, `lr`, `sp`, `pc`,
/// `cpsr`, `flags`.
pub const ARM_THREAD_STATE64_SIZE: usize = 272;
/// `sizeof(arm_exception_state64_t)`: `far`, `esr`, `exception`.
pub const ARM_EXCEPTION_STATE64_SIZE: usize = 16;
/// `sizeof(arm_neon_state64_t)`: `q[32]`, `fpsr`, `fpcr`, padded to 16.
pub const ARM_NEON_STATE64_SIZE: usize = 528;

/// `sizeof(x86_thread_state64_t)`: 21 registers.
pub const X86_THREAD_STATE64_SIZE: usize = 168;
/// `sizeof(x86_exception_state64_t)`: `trapno`, `cpu`, `err`,
/// `faultvaddr`.
pub const X86_EXCEPTION_STATE64_SIZE: usize = 16;
/// `sizeof(x86_avx_state64_t)`.
pub const X86_AVX_STATE64_SIZE: usize = 844;

/// `PSR64_NZCV_MASK`: the `cpsr` bits user state may set.
const PSR64_NZCV_MASK: u32 = 0xf000_0000;

/// `USER64_CS`.
pub const USER64_CS: u64 = 0x2b;

/// `EFL_USER_SET`: `IF`.
const EFL_USER_SET: u64 = 0x200;
/// `EFL_USER_CLEAR`: `IOPL`, `NT`, `RF`.
const EFL_USER_CLEAR: u64 = 0x3000 | 0x4000 | 0x1_0000;

/// `VM_MAX_USER_PAGE_ADDRESS` on x86-64: `IS_USERADDR64_CANONICAL` accepts
/// addresses below it.
const X86_MAX_USER_PAGE_ADDRESS: u64 = 0x0000_7fff_ffff_f000;

/// `fp_save_layout` `XSAVE64`, which the kernel's copy of the legacy
/// region carries after `fp_valid` (`osfmk/i386/fpu.h`).
const XSAVE64: u32 = 4;

/// Offset of the legacy region (`__fpu_fcw`) in `x86_avx_state64_t`.
const AVX_FCW: usize = 8;
/// Offset of `__fpu_ymmh0` in `x86_avx_state64_t`.
const AVX_YMMH: usize = 588;
/// Offset of the AVX component in the standard XSAVE layout.
const XSAVE_YMM_HI: usize = 576;
/// Offset of the XSAVE header.
const XSAVE_HEADER: usize = 512;

fn put64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn get64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().expect("8 bytes"))
}

fn get32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().expect("4 bytes"))
}

/// `ARM_THREAD_STATE64` with `flags`.
pub fn arm64_thread_state(cpu: &A64UserCpu, flags: u32) -> [u8; ARM_THREAD_STATE64_SIZE] {
    let core = cpu.core();
    let mut b = [0u8; ARM_THREAD_STATE64_SIZE];
    for i in 0..29u8 {
        put64(&mut b, usize::from(i) * 8, core.get_x(i));
    }
    put64(&mut b, 232, core.get_x(29));
    put64(&mut b, 240, core.get_x(30));
    put64(&mut b, 248, cpu.sp());
    put64(&mut b, 256, cpu.pc());
    put32(&mut b, 264, core.el0_spsr() as u32);
    put32(&mut b, 268, flags);
    b
}

/// Installs an `ARM_THREAD_STATE64` (`thread_state64_to_saved_state`):
/// the registers, and of `cpsr` only NZCV.
pub fn set_arm64_thread_state(cpu: &mut A64UserCpu, b: &[u8]) {
    let core = cpu.core_mut();
    for i in 0..29u8 {
        core.set_x(i, get64(b, usize::from(i) * 8));
    }
    core.set_x(29, get64(b, 232));
    core.set_x(30, get64(b, 240));
    core.set_pc(get64(b, 256));
    core.set_nzcv_bits(((get32(b, 264) & PSR64_NZCV_MASK) >> 28) as u8);
    cpu.set_sp(get64(b, 248));
}

/// `ARM_EXCEPTION_STATE64` (`exception` is always 0).
pub fn arm64_exception_state(e: &EntryState) -> [u8; ARM_EXCEPTION_STATE64_SIZE] {
    let mut b = [0u8; ARM_EXCEPTION_STATE64_SIZE];
    put64(&mut b, 0, e.far);
    put32(&mut b, 8, e.esr);
    b
}

/// `ARM_NEON_STATE64`.
pub fn arm64_neon_state(cpu: &A64UserCpu) -> [u8; ARM_NEON_STATE64_SIZE] {
    let core = cpu.core();
    let mut b = [0u8; ARM_NEON_STATE64_SIZE];
    for i in 0..32u8 {
        let off = usize::from(i) * 16;
        b[off..off + 16].copy_from_slice(&core.get_simd(i).to_le_bytes());
    }
    put32(&mut b, 512, core.fpsr_value());
    put32(&mut b, 516, core.fpcr_value());
    b
}

/// Installs an `ARM_NEON_STATE64`.
pub fn set_arm64_neon_state(cpu: &mut A64UserCpu, b: &[u8]) {
    let core = cpu.core_mut();
    for i in 0..32u8 {
        let off = usize::from(i) * 16;
        core.set_simd(
            i,
            u128::from_le_bytes(b[off..off + 16].try_into().expect("16 bytes")),
        );
    }
    core.set_fpsr_value(get32(b, 512));
    core.set_fpcr_value(get32(b, 516));
}

/// `x86_THREAD_STATE64`: `rax rbx rcx rdx rdi rsi rbp rsp r8-r15 rip
/// rflags cs fs gs`.
pub fn x86_thread_state(cpu: &X86UserCpu) -> [u8; X86_THREAD_STATE64_SIZE] {
    let v = cpu.vcpu();
    let r = v.user_regs();
    let regs = [
        r.rax,
        r.rbx,
        r.rcx,
        r.rdx,
        r.rdi,
        r.rsi,
        r.rbp,
        r.rsp,
        r.r8,
        r.r9,
        r.r10,
        r.r11,
        r.r12,
        r.r13,
        r.r14,
        r.r15,
        r.rip,
        v.user_rflags(),
        USER64_CS,
        0,
        0,
    ];
    let mut b = [0u8; X86_THREAD_STATE64_SIZE];
    for (i, v) in regs.iter().enumerate() {
        put64(&mut b, i * 8, *v);
    }
    b
}

/// Installs an `x86_THREAD_STATE64` (`set_thread_state64`): `Err` when
/// `rsp` or `rip` is not a user address. The flags are limited to those
/// user code may set; `cs` is always the user code segment.
pub fn set_x86_thread_state(cpu: &mut X86UserCpu, b: &[u8]) -> Result<(), ()> {
    let rsp = get64(b, 56);
    let rip = get64(b, 128);
    if rsp >= X86_MAX_USER_PAGE_ADDRESS || rip >= X86_MAX_USER_PAGE_ADDRESS {
        return Err(());
    }
    let v = cpu.vcpu_mut();
    let r = v.user_regs_mut();
    r.rax = get64(b, 0);
    r.rbx = get64(b, 8);
    r.rcx = get64(b, 16);
    r.rdx = get64(b, 24);
    r.rdi = get64(b, 32);
    r.rsi = get64(b, 40);
    r.rbp = get64(b, 48);
    r.rsp = rsp;
    r.r8 = get64(b, 64);
    r.r9 = get64(b, 72);
    r.r10 = get64(b, 80);
    r.r11 = get64(b, 88);
    r.r12 = get64(b, 96);
    r.r13 = get64(b, 104);
    r.r14 = get64(b, 112);
    r.r15 = get64(b, 120);
    r.rip = rip;
    v.set_user_rflags((get64(b, 136) & !EFL_USER_CLEAR) | EFL_USER_SET);
    Ok(())
}

/// `x86_EXCEPTION_STATE64` (`cpu` is always 0).
pub fn x86_exception_state(e: &EntryState) -> [u8; X86_EXCEPTION_STATE64_SIZE] {
    let mut b = [0u8; X86_EXCEPTION_STATE64_SIZE];
    b[0..2].copy_from_slice(&(e.trapno as u16).to_le_bytes());
    put32(&mut b, 4, e.err);
    put64(&mut b, 8, e.far);
    b
}

/// `x86_AVX_STATE64` (`fpu_get_fxstate`): the kernel's 512-byte legacy
/// region (the `FXSAVE` image, with its `fp_valid` and `fp_save_layout`
/// words in the reserved bytes) and the upper halves of `YMM0`-`YMM15`.
pub fn x86_avx_state(cpu: &X86UserCpu) -> [u8; X86_AVX_STATE64_SIZE] {
    let image = cpu.vcpu().xsave_image(0b111);
    let mut b = [0u8; X86_AVX_STATE64_SIZE];
    b[AVX_FCW..AVX_FCW + 464].copy_from_slice(&image.bytes[..464]);
    put32(&mut b, AVX_FCW + 496, 1);
    put32(&mut b, AVX_FCW + 500, XSAVE64);
    if image.bytes.len() >= XSAVE_YMM_HI + 256 {
        b[AVX_YMMH..AVX_YMMH + 256].copy_from_slice(&image.bytes[XSAVE_YMM_HI..XSAVE_YMM_HI + 256]);
    }
    b
}

/// Installs an `x86_AVX_STATE64` (`fpu_set_fxstate`): `MXCSR` is limited
/// to the bits the processor supports, and the AVX component is marked
/// in its initial state when every upper half is zero.
pub fn set_x86_avx_state(cpu: &mut X86UserCpu, b: &[u8]) -> Result<(), ()> {
    let v = cpu.vcpu_mut();
    let current = v.xsave_image(0b111);
    let mask = match get32(&current.bytes, 28) {
        0 => 0xffbf,
        m => m,
    };
    let mut image = vec![0u8; current.bytes.len().max(XSAVE_YMM_HI + 256)];
    image[..512].copy_from_slice(&b[AVX_FCW..AVX_FCW + 512]);
    let mxcsr = get32(&image, 24) & mask;
    put32(&mut image, 24, mxcsr);
    let ymmh = &b[AVX_YMMH..AVX_YMMH + 256];
    image[XSAVE_YMM_HI..XSAVE_YMM_HI + 256].copy_from_slice(ymmh);
    let xstate_bv: u64 = if ymmh.iter().all(|&x| x == 0) {
        0b011
    } else {
        0b111
    };
    put64(&mut image, XSAVE_HEADER, xstate_bv);
    v.xrstor_image(&image, 0b111).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::cpu::x86_64::RESERVED_PHYS;
    use crate::user::mm::{AddressSpace, PAGE_SIZE, SpaceConfig};

    fn space() -> AddressSpace {
        AddressSpace::new(SpaceConfig {
            va_limit: 1 << 47,
            arena_bytes: 64 * PAGE_SIZE,
            reserved_phys: RESERVED_PHYS.to_vec(),
        })
        .expect("space")
    }

    #[test]
    fn arm64_thread_state_round_trips_the_registers_and_nzcv() {
        let s = space();
        let mut cpu = A64UserCpu::new(&s);
        for i in 0..31u8 {
            cpu.core_mut().set_x(i, 0x1000 + u64::from(i));
        }
        cpu.set_sp(0x7000);
        cpu.core_mut().set_pc(0x4000);
        cpu.core_mut().set_nzcv_bits(0b1010);
        let b = arm64_thread_state(&cpu, 1);
        assert_eq!(get64(&b, 0), 0x1000);
        assert_eq!(get64(&b, 28 * 8), 0x1000 + 28);
        assert_eq!(get64(&b, 232), 0x1000 + 29);
        assert_eq!(get64(&b, 240), 0x1000 + 30);
        assert_eq!(get64(&b, 248), 0x7000);
        assert_eq!(get64(&b, 256), 0x4000);
        assert_eq!(get32(&b, 264) >> 28, 0b1010);
        assert_eq!(get32(&b, 268), 1);

        let mut other = A64UserCpu::new(&s);
        let mut changed = b;
        put32(&mut changed, 264, 0x6000_001f);
        set_arm64_thread_state(&mut other, &changed);
        assert_eq!(other.core().get_x(17), 0x1000 + 17);
        assert_eq!(other.core().get_x(30), 0x1000 + 30);
        assert_eq!(other.sp(), 0x7000);
        assert_eq!(other.pc(), 0x4000);
        // Only NZCV travels; the mode bits cannot leave EL0t.
        assert_eq!(other.core().nzcv_bits(), 0b0110);
        assert_eq!(other.core().el0_spsr() & 0x1f, 0);
    }

    #[test]
    fn arm64_neon_state_layout() {
        let s = space();
        let mut cpu = A64UserCpu::new(&s);
        cpu.core_mut()
            .set_simd(0, 0x0011_2233_4455_6677_8899_aabb_ccdd_eeff);
        cpu.core_mut().set_simd(31, 1);
        cpu.core_mut().set_fpcr_value(0x0040_0000);
        let b = arm64_neon_state(&cpu);
        assert_eq!(b[0], 0xff);
        assert_eq!(b[15], 0x00);
        assert_eq!(b[31 * 16], 1);
        assert_eq!(get32(&b, 516), 0x0040_0000);
        let mut other = A64UserCpu::new(&s);
        set_arm64_neon_state(&mut other, &b);
        assert_eq!(other.core().get_simd(0), cpu.core().get_simd(0));
        assert_eq!(other.core().fpcr_value(), 0x0040_0000);
    }

    #[test]
    fn x86_thread_state_checks_addresses_and_flags() {
        let s = space();
        let mut cpu = X86UserCpu::new(&s);
        cpu.vcpu_mut().user_regs_mut().rdi = 7;
        cpu.vcpu_mut().user_regs_mut().rip = 0x1000;
        cpu.vcpu_mut().user_regs_mut().rsp = 0x2000;
        let mut b = x86_thread_state(&cpu);
        assert_eq!(get64(&b, 32), 7);
        assert_eq!(get64(&b, 144), USER64_CS);
        // IOPL, NT, and RF are dropped and IF forced on.
        put64(&mut b, 136, 0x1_7001);
        set_x86_thread_state(&mut cpu, &b).expect("user addresses");
        assert_eq!(cpu.vcpu().user_rflags(), 0x203);
        put64(&mut b, 128, X86_MAX_USER_PAGE_ADDRESS);
        assert!(set_x86_thread_state(&mut cpu, &b).is_err());
        assert_eq!(cpu.vcpu().user_regs().rip, 0x1000);
    }

    #[test]
    fn x86_avx_state_round_trips_xmm_and_ymm() {
        let s = space();
        let mut cpu = X86UserCpu::new(&s);
        cpu.vcpu_mut().set_xcr0(0b111).expect("x87, SSE, AVX");
        let mut image = cpu.vcpu().xsave_image(0b111).bytes;
        image[160] = 0x5a; // XMM0 byte 0
        image[XSAVE_YMM_HI + 16] = 0xa5; // YMM1 upper half byte 0
        put64(&mut image, XSAVE_HEADER, 0b111);
        cpu.vcpu_mut().xrstor_image(&image, 0b111).expect("restore");
        let b = x86_avx_state(&cpu);
        assert_eq!(b[AVX_FCW + 160], 0x5a);
        assert_eq!(b[AVX_YMMH + 16], 0xa5);
        assert_eq!(get32(&b, AVX_FCW + 24), 0x1f80);
        assert_eq!(get32(&b, AVX_FCW + 496), 1);
        let mut other = X86UserCpu::new(&s);
        other.vcpu_mut().set_xcr0(0b111).expect("x87, SSE, AVX");
        let mut changed = b;
        // Reserved MXCSR bits are dropped rather than faulting.
        put32(&mut changed, AVX_FCW + 24, 0xffff_1f80);
        set_x86_avx_state(&mut other, &changed).expect("valid state");
        let got = other.vcpu().xsave_image(0b111).bytes;
        assert_eq!(got[160], 0x5a);
        assert_eq!(got[XSAVE_YMM_HI + 16], 0xa5);
        assert_eq!(get32(&got, 24) & 0xffff_0000, 0);
    }
}
