//! Architecture layer: entry point, serial `putc`, power-off, heap window, and
//! per-ISA instruction-coverage tests.
//!
//! Three bare-metal targets plus an x86_64 "usermode" build (for Intel SDE):
//!
//! | arch    | entry @        | serial            | power-off                       |
//! |---------|----------------|-------------------|---------------------------------|
//! | x86_64  | 0x100_0000     | `out 0xE9, al`    | `out 0x604, 0x2000` (ACPI S5)   |
//! | aarch64 | 0x4000_0000    | MMIO 0x0900_0000  | PSCI `SYSTEM_OFF` via `hvc`      |
//! | armv6   | 0x5000_8000    | MMIO 0x7F00_5020  | magic store to 0x7E00_E000      |

use crate::harness::Harness;

// ===========================================================================
// Bare-metal linker symbols (shared by all no_std targets)
// ===========================================================================

#[cfg(not(feature = "usermode"))]
unsafe extern "C" {
    static __bss_start: u8;
    static __bss_end: u8;
    static __heap_start: u8;
    static __heap_end: u8;
    #[allow(dead_code)]
    static __stack_top: u8;
}

#[cfg(not(feature = "usermode"))]
pub fn early_init() {
    // Zero BSS. Guest RAM is already zero-filled by the host mmap, so this is
    // belt-and-suspenders, but it keeps the kernel correct on any loader.
    unsafe {
        let start = core::ptr::addr_of!(__bss_start) as usize;
        let end = core::ptr::addr_of!(__bss_end) as usize;
        let mut p = start;
        while p < end {
            (p as *mut u8).write_volatile(0);
            p += 1;
        }
    }
}

#[cfg(not(feature = "usermode"))]
pub fn heap_range() -> (*mut u8, *mut u8) {
    (
        core::ptr::addr_of!(__heap_start) as *mut u8,
        core::ptr::addr_of!(__heap_end) as *mut u8,
    )
}

// ===========================================================================
// x86_64 (bare metal)
// ===========================================================================
#[cfg(all(not(feature = "usermode"), target_arch = "x86_64"))]
mod imp {
    use core::arch::asm;

    pub const ARCH_NAME: &str = "x86_64";

    #[unsafe(naked)]
    #[unsafe(no_mangle)]
    #[unsafe(link_section = ".text._start")]
    extern "C" fn _start() -> ! {
        core::arch::naked_asm!(
            "lea rsp, [rip + __stack_top]",
            "call {main}",
            "hlt",
            main = sym crate::kmain,
        )
    }

    #[inline]
    pub fn putc(b: u8) {
        unsafe {
            asm!("out dx, al", in("dx") 0xE9u16, in("al") b, options(nostack, preserves_flags));
        }
    }

    pub fn poweroff() -> ! {
        unsafe {
            asm!("out dx, ax", in("dx") 0x604u16, in("ax") 0x2000u16, options(nostack, preserves_flags));
            loop {
                asm!("hlt", options(nostack, nomem));
            }
        }
    }
}

// ===========================================================================
// AArch64 (bare metal)
// ===========================================================================
#[cfg(target_arch = "aarch64")]
mod imp {
    use core::arch::asm;

    pub const ARCH_NAME: &str = "aarch64";
    const UART_DR: *mut u32 = 0x0900_0000 as *mut u32;

    #[unsafe(naked)]
    #[unsafe(no_mangle)]
    #[unsafe(link_section = ".text._start")]
    extern "C" fn _start() -> ! {
        // Establish our own stack inside guest RAM. The VMM's default SP sits at
        // the top of the (large, padded) backing mmap, which is fine here, but
        // we set it explicitly so the kernel never depends on the loader.
        core::arch::naked_asm!(
            "ldr x9, =__stack_top",
            "mov sp, x9",
            "b {main}",
            main = sym crate::kmain,
        )
    }

    #[inline]
    pub fn putc(b: u8) {
        unsafe { core::ptr::write_volatile(UART_DR, b as u32) }
    }

    pub fn poweroff() -> ! {
        unsafe {
            // PSCI SYSTEM_OFF (0x8400_0008) over HVC.
            asm!("mov x0, {off:x}", "hvc #0", off = in(reg) 0x8400_0008u64, options(nostack, nomem));
            loop {
                asm!("wfi", options(nostack, nomem));
            }
        }
    }
}

// ===========================================================================
// ARMv6 / ARM1176 (bare metal, A32)
// ===========================================================================
#[cfg(target_arch = "arm")]
mod imp {
    pub const ARCH_NAME: &str = "armv6";
    const UART_UTXH: *mut u32 = 0x7F00_5020 as *mut u32;
    const POWEROFF: *mut u32 = 0x7E00_E000 as *mut u32;

    #[unsafe(naked)]
    #[unsafe(no_mangle)]
    #[unsafe(link_section = ".text._start")]
    extern "C" fn _start() -> ! {
        // The VMM's default SP points at the top of the padded backing mmap,
        // which is *outside* the S3C64xx RAM window the memory bridge maps — so
        // stack pushes/pops would hit open bus and a `pop {pc}` would load 0.
        // Set SP to the linker-provided top of RAM before entering Rust.
        core::arch::naked_asm!(
            "ldr sp, =__stack_top",
            "b {main}",
            main = sym crate::kmain,
        )
    }

    #[inline]
    pub fn putc(b: u8) {
        unsafe { core::ptr::write_volatile(UART_UTXH, b as u32) }
    }

    pub fn poweroff() -> ! {
        unsafe {
            core::ptr::write_volatile(POWEROFF, 0xDEAD_0FF0u32);
            loop {
                core::arch::asm!("wfi", options(nostack, nomem));
            }
        }
    }
}

// ===========================================================================
// x86_64 usermode (Intel SDE / host) — std build
// ===========================================================================
#[cfg(feature = "usermode")]
mod imp {
    use core::arch::asm;

    pub const ARCH_NAME: &str = "x86_64-usermode";

    const HEAP_SIZE: usize = 8 * 1024 * 1024;
    static mut HEAP: [u8; HEAP_SIZE] = [0u8; HEAP_SIZE];

    pub fn heap_range() -> (*mut u8, *mut u8) {
        unsafe {
            let p = core::ptr::addr_of_mut!(HEAP) as *mut u8;
            (p, p.add(HEAP_SIZE))
        }
    }

    pub fn early_init() {}

    #[inline]
    pub fn putc(b: u8) {
        let buf = [b];
        unsafe {
            asm!("syscall",
                in("rax") 1u64, in("rdi") 1u64, in("rsi") buf.as_ptr(), in("rdx") 1u64,
                lateout("rax") _, lateout("rcx") _, lateout("r11") _);
        }
    }

    pub fn poweroff() -> ! {
        unsafe {
            asm!("syscall", in("rax") 60u64, in("rdi") 0u64, options(noreturn));
        }
    }
}

pub use imp::{ARCH_NAME, poweroff, putc};
#[cfg(feature = "usermode")]
pub use imp::{early_init, heap_range};

// ===========================================================================
// Per-arch ISA coverage. Each check cross-validates an asm result against an
// independent scalar computation, so no magic constants are needed and the same
// source is meaningful on hardware and under the emulator.
// ===========================================================================

pub fn isa_tests(h: &mut Harness) {
    h.group("isa");
    isa_impl(h);
}

#[cfg(all(not(feature = "usermode"), target_arch = "x86_64"))]
fn isa_impl(h: &mut Harness) {
    use core::arch::asm;

    // ALU chain: r = ((a + b) << 3) - (a * 5), computed in asm vs scalar.
    let (a, b) = (12345u64, 6789u64);
    let mut r = a;
    unsafe {
        asm!(
            "add {r}, {b}",
            "shl {r}, 3",
            "mov {t}, {a}",
            "imul {t}, {t}, 5",
            "sub {r}, {t}",
            r = inout(reg) r,
            a = in(reg) a, b = in(reg) b, t = out(reg) _,
            options(nostack),
        );
    }
    h.eq_u64("alu_chain", r, ((a + b) << 3) - a.wrapping_mul(5));

    // rep movsb copy.
    let src: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3));
    let mut dst = [0u8; 32];
    unsafe {
        asm!("cld", "rep movsb",
            in("rsi") src.as_ptr(), in("rdi") dst.as_mut_ptr(), in("rcx") 32usize,
            options(nostack));
    }
    h.check("rep_movsb", dst == src);

    // popcnt / lzcnt / tzcnt vs core.
    let v = 0x0F0F_1234_ABCD_8000u64;
    let (mut pc, mut lz, mut tz): (u64, u64, u64);
    unsafe {
        asm!("popcnt {o}, {i}", o = out(reg) pc, i = in(reg) v, options(nostack, pure, nomem));
        asm!("lzcnt {o}, {i}", o = out(reg) lz, i = in(reg) v, options(nostack, pure, nomem));
        asm!("tzcnt {o}, {i}", o = out(reg) tz, i = in(reg) v, options(nostack, pure, nomem));
    }
    h.eq_u64("popcnt", pc, v.count_ones() as u64);
    h.eq_u64("lzcnt", lz, v.leading_zeros() as u64);
    h.eq_u64("tzcnt", tz, v.trailing_zeros() as u64);

    // BMI: andn, and bextr (start=8, len=16).
    let (x, y) = (0xFFFF_0000_FF00_F0F0u64, 0x0F0F_0F0F_0F0F_0F0Fu64);
    let mut andn: u64;
    unsafe {
        asm!("andn {o}, {a}, {b}", o = out(reg) andn, a = in(reg) x, b = in(reg) y, options(nostack, pure, nomem));
    }
    h.eq_u64("bmi_andn", andn, !x & y);
    let ctrl = (8u64) | (16u64 << 8);
    let mut bextr: u64;
    unsafe {
        asm!("bextr {o}, {s}, {c}", o = out(reg) bextr, s = in(reg) y, c = in(reg) ctrl, options(nostack, pure, nomem));
    }
    h.eq_u64("bmi_bextr", bextr, (y >> 8) & 0xFFFF);

    // SSE2 integer: paddd / pmulld (SSE4.1) vs scalar.
    let pa = [10i32, -20, 30, -40];
    let pb = [1i32, 2, 3, 4];
    let mut pr = [0i32; 4];
    // SAFETY: The x86 test guest provides SSE4.1. Each unaligned access is
    // within a live 16-byte local array; pr is separate and exclusively held.
    // Both vector scratch registers are declared, and the asm cannot unwind.
    unsafe {
        asm!(
            "movdqu xmm0, [{a}]",
            "movdqu xmm1, [{b}]",
            "paddd xmm0, xmm1",
            "pmulld xmm0, xmm1",
            "movdqu [{r}], xmm0",
            a = in(reg) pa.as_ptr(), b = in(reg) pb.as_ptr(), r = in(reg) pr.as_mut_ptr(),
            out("xmm0") _, out("xmm1") _,
            options(nostack, preserves_flags),
        );
    }
    let exp: [i32; 4] = core::array::from_fn(|i| (pa[i] + pb[i]) * pb[i]);
    h.check("sse_paddd_pmulld", pr == exp);

    // AVX (128) float add/mul vs scalar f32.
    // SAFETY: These are unconditional ISA probes for the x86 test guest, which
    // must provide AVX, AVX2 and AVX-512F with the corresponding vector state.
    unsafe { avx_check(h) };
    // AVX2 (256) integer vs scalar.
    // SAFETY: The same test-guest feature contract applies here.
    unsafe { avx2_check(h) };
    // AVX-512 (512) float vs scalar.
    // SAFETY: The same test-guest feature contract applies here.
    unsafe { avx512_check(h) };

    // CPUID leaf 0: max leaf and a non-empty vendor string.
    let (max_leaf, vendor_nonzero) = cpuid0();
    h.check("cpuid_maxleaf", max_leaf >= 1);
    h.check("cpuid_vendor", vendor_nonzero);
}

// Keep compiler-generated code on x86_64-unknown-none's soft-float baseline:
// target_feature enabling AVX also enables SSE, which LLVM cannot combine with
// soft-float. Explicit asm performs the vector probes with memory operands and
// discarded register outputs, so no SIMD value crosses the Rust/asm boundary.
// See docs/development/microkernel.md for the compiler/reference provenance.
#[cfg(all(not(feature = "usermode"), target_arch = "x86_64"))]
unsafe fn avx_check(h: &mut Harness) {
    use core::arch::asm;
    let a = [1.0f32, 2.0, 3.0, 4.0];
    let b = [5.0f32, 6.0, 7.0, 8.0];
    let mut r = [0f32; 4];
    // SAFETY: The caller supplies an AVX-capable guest with vector state
    // enabled. The unaligned accesses cover three distinct, live 16-byte
    // arrays; r is exclusive. Scratch registers are declared; no calls unwind.
    unsafe {
        asm!(
            "vmovups xmm0, [{a}]",
            "vmovups xmm1, [{b}]",
            "vaddps xmm0, xmm0, xmm1",
            "vmulps xmm0, xmm0, xmm1",
            "vmovups [{r}], xmm0",
            a = in(reg) a.as_ptr(), b = in(reg) b.as_ptr(), r = in(reg) r.as_mut_ptr(),
            out("xmm0") _, out("xmm1") _,
            options(nostack),
        );
    }
    let ok = (0..4).all(|i| r[i].to_bits() == ((a[i] + b[i]) * b[i]).to_bits());
    h.check("avx_vaddps_vmulps", ok);
}

#[cfg(all(not(feature = "usermode"), target_arch = "x86_64"))]
unsafe fn avx2_check(h: &mut Harness) {
    use core::arch::asm;
    let a: [i32; 8] = core::array::from_fn(|i| i as i32 + 1);
    let b: [i32; 8] = core::array::from_fn(|i| (i as i32 + 1) * 2);
    let mut r = [0i32; 8];
    // SAFETY: The caller supplies an AVX2-capable guest with vector state
    // enabled. The unaligned accesses cover three distinct, live 32-byte
    // arrays; r is exclusive. Scratch registers are declared; no calls unwind.
    unsafe {
        asm!(
            "vmovdqu ymm0, [{a}]",
            "vmovdqu ymm1, [{b}]",
            "vpaddd ymm0, ymm0, ymm1",
            "vpslld ymm0, ymm0, 1",
            "vmovdqu [{r}], ymm0",
            a = in(reg) a.as_ptr(), b = in(reg) b.as_ptr(), r = in(reg) r.as_mut_ptr(),
            out("ymm0") _, out("ymm1") _,
            options(nostack, preserves_flags),
        );
    }
    let ok = (0..8).all(|i| r[i] == (a[i] + b[i]) << 1);
    h.check("avx2_vpaddd_vpslld", ok);
}

#[cfg(all(not(feature = "usermode"), target_arch = "x86_64"))]
unsafe fn avx512_check(h: &mut Harness) {
    use core::arch::asm;
    let a: [f32; 16] = core::array::from_fn(|i| i as f32 + 1.0);
    let b: [f32; 16] = core::array::from_fn(|i| 16.0 - i as f32);
    let mut r = [0f32; 16];
    // SAFETY: The caller supplies an AVX-512F-capable guest with vector state
    // enabled. The unaligned accesses cover three distinct, live 64-byte
    // arrays; r is exclusive. Scratch registers are declared; no calls unwind.
    unsafe {
        asm!(
            "vmovups zmm0, [{a}]",
            "vmovups zmm1, [{b}]",
            "vaddps zmm0, zmm0, zmm1",
            "vmulps zmm0, zmm0, zmm1",
            "vmovups [{r}], zmm0",
            a = in(reg) a.as_ptr(), b = in(reg) b.as_ptr(), r = in(reg) r.as_mut_ptr(),
            out("zmm0") _, out("zmm1") _,
            options(nostack),
        );
    }
    let ok = (0..16).all(|i| r[i].to_bits() == ((a[i] + b[i]) * b[i]).to_bits());
    h.check("avx512_vaddps_vmulps", ok);
}

#[cfg(all(not(feature = "usermode"), target_arch = "x86_64"))]
fn cpuid0() -> (u32, bool) {
    use core::arch::asm;
    let max_leaf: u32;
    let (ebx, ecx, edx): (u32, u32, u32);
    unsafe {
        asm!(
            "mov {tmp:r}, rbx",
            "cpuid",
            "xchg {tmp:r}, rbx",
            tmp = out(reg) ebx,
            inout("eax") 0u32 => max_leaf,
            out("ecx") ecx, out("edx") edx,
            options(nostack),
        );
    }
    (max_leaf, ebx != 0 || ecx != 0 || edx != 0)
}

#[cfg(target_arch = "aarch64")]
fn isa_impl(h: &mut Harness) {
    use core::arch::asm;

    // madd / msub: r = a*b + c, s = c - a*b.
    let (a, b, c) = (7u64, 9u64, 100u64);
    let (mut r, mut s): (u64, u64);
    unsafe {
        asm!("madd {r}, {a}, {b}, {c}", r = out(reg) r, a = in(reg) a, b = in(reg) b, c = in(reg) c, options(nostack, pure, nomem));
        asm!("msub {s}, {a}, {b}, {c}", s = out(reg) s, a = in(reg) a, b = in(reg) b, c = in(reg) c, options(nostack, pure, nomem));
    }
    h.eq_u64("madd", r, a * b + c);
    h.eq_u64("msub", s, c.wrapping_sub(a * b));

    // udiv / sdiv.
    let (n, d) = (1_000_000_007u64, 998u64);
    let mut q: u64;
    unsafe {
        asm!("udiv {q}, {n}, {d}", q = out(reg) q, n = in(reg) n, d = in(reg) d, options(nostack, pure, nomem));
    }
    h.eq_u64("udiv", q, n / d);
    let (ni, di) = (-1_000_000_007i64, 998i64);
    let mut qi: i64;
    unsafe {
        asm!("sdiv {q}, {n}, {d}", q = out(reg) qi, n = in(reg) ni, d = in(reg) di, options(nostack, pure, nomem));
    }
    h.eq_i64("sdiv", qi, ni / di);

    // clz / rbit / rev.
    let v = 0x0000_1234_ABCD_EF00u64;
    let (mut clz, mut rbit, mut rev): (u64, u64, u64);
    unsafe {
        asm!("clz {o}, {i}", o = out(reg) clz, i = in(reg) v, options(nostack, pure, nomem));
        asm!("rbit {o}, {i}", o = out(reg) rbit, i = in(reg) v, options(nostack, pure, nomem));
        asm!("rev {o}, {i}", o = out(reg) rev, i = in(reg) v, options(nostack, pure, nomem));
    }
    h.eq_u64("clz", clz, v.leading_zeros() as u64);
    h.eq_u64("rbit", rbit, v.reverse_bits());
    h.eq_u64("rev", rev, v.swap_bytes());

    // umulh: high 64 bits of 64x64 product.
    let (x, y) = (0xDEAD_BEEF_CAFE_BABEu64, 0x0123_4567_89AB_CDEFu64);
    let mut hi: u64;
    unsafe {
        asm!("umulh {o}, {a}, {b}", o = out(reg) hi, a = in(reg) x, b = in(reg) y, options(nostack, pure, nomem));
    }
    h.eq_u64("umulh", hi, ((x as u128 * y as u128) >> 64) as u64);

    // ubfx: extract bits [8, 8+16).
    let mut bf: u64;
    unsafe {
        asm!("ubfx {o}, {i}, #8, #16", o = out(reg) bf, i = in(reg) v, options(nostack, pure, nomem));
    }
    h.eq_u64("ubfx", bf, (v >> 8) & 0xFFFF);

    // csel under EQ: select a if x==x else y.
    let mut sel: u64;
    unsafe {
        asm!(
            "cmp {a}, {a}",
            "csel {o}, {a}, {b}, eq",
            o = out(reg) sel, a = in(reg) x, b = in(reg) y,
            options(nostack),
        );
    }
    h.eq_u64("csel_eq", sel, x);

    // ldp/stp round trip through a stack buffer.
    let mut buf = [0u64; 2];
    let mut o0: u64;
    let mut o1: u64;
    unsafe {
        asm!(
            "stp {a}, {b}, [{p}]",
            "ldp {x}, {y}, [{p}]",
            a = in(reg) x, b = in(reg) y, p = in(reg) buf.as_mut_ptr(),
            x = out(reg) o0, y = out(reg) o1,
            options(nostack),
        );
    }
    h.check("ldp_stp", o0 == x && o1 == y && buf == [x, y]);
}

#[cfg(target_arch = "arm")]
fn isa_impl(h: &mut Harness) {
    use core::arch::asm;

    // Exercise every address residue modulo 4. Regardless of the stack
    // allocation's base alignment, these four offsets cover every possible
    // alignment accepted by the Arm Run-time ABI helper.
    let unaligned_bytes = [0x78u8, 0x56, 0x34, 0x12, 0xEF, 0xCD, 0xAB];
    for (name, offset, expected) in [
        ("aeabi_uread4_0", 0, 0x1234_5678),
        ("aeabi_uread4_1", 1, 0xEF12_3456),
        ("aeabi_uread4_2", 2, 0xCDEF_1234),
        ("aeabi_uread4_3", 3, 0xABCD_EF12),
    ] {
        // SAFETY: `offset` is in 0..=3 and `unaligned_bytes` has 7 initialized
        // bytes, so the helper can read exactly bytes offset..offset+4. The
        // shared immutable array outlives the call, the helper creates no
        // reference or mutable alias, follows the AAPCS C ABI, and cannot
        // unwind because it is a leaf assembly routine.
        let value =
            unsafe { crate::arm_eabi::__aeabi_uread4(unaligned_bytes.as_ptr().add(offset)) };
        h.eq_u32(name, value, expected);
    }

    // Data processing with barrel shifter: r = a + (b << 4).
    let (a, b) = (0x1000u32, 0x23u32);
    let mut r: u32;
    unsafe {
        asm!("add {r}, {a}, {b}, lsl #4", r = out(reg) r, a = in(reg) a, b = in(reg) b, options(nostack, pure, nomem));
    }
    h.eq_u32("add_lsl", r, a + (b << 4));

    // mla: r = x*y + acc.
    let (x, y, acc) = (1234u32, 567u32, 89u32);
    let mut mla: u32;
    unsafe {
        asm!("mla {o}, {a}, {b}, {c}", o = out(reg) mla, a = in(reg) x, b = in(reg) y, c = in(reg) acc, options(nostack, pure, nomem));
    }
    h.eq_u32("mla", mla, x.wrapping_mul(y).wrapping_add(acc));

    // umull: 32x32 -> 64.
    let (lo, hi): (u32, u32);
    unsafe {
        asm!("umull {lo}, {hi}, {a}, {b}", lo = out(reg) lo, hi = out(reg) hi, a = in(reg) x, b = in(reg) y, options(nostack, pure, nomem));
    }
    let prod = x as u64 * y as u64;
    h.check("umull", lo as u64 | ((hi as u64) << 32) == prod);

    // clz / rev / rev16.
    let v = 0x0012_34ABu32;
    let (mut clz, mut rev): (u32, u32);
    unsafe {
        asm!("clz {o}, {i}", o = out(reg) clz, i = in(reg) v, options(nostack, pure, nomem));
        asm!("rev {o}, {i}", o = out(reg) rev, i = in(reg) v, options(nostack, pure, nomem));
    }
    h.eq_u32("clz", clz, v.leading_zeros());
    h.eq_u32("rev", rev, v.swap_bytes());

    // Conditional execution: addeq taken when Z set.
    let mut cond = 10u32;
    unsafe {
        asm!(
            "cmp {z}, {z}",
            "addeq {o}, {o}, #5",
            z = in(reg) 1u32, o = inout(reg) cond,
            options(nostack),
        );
    }
    h.eq_u32("addeq", cond, 15);

    // uxtb / sxtb sign/zero extension of a byte.
    let byteval = 0xF3u32;
    let (mut ux, mut sx): (u32, u32);
    unsafe {
        asm!("uxtb {o}, {i}", o = out(reg) ux, i = in(reg) byteval, options(nostack, pure, nomem));
        asm!("sxtb {o}, {i}", o = out(reg) sx, i = in(reg) byteval, options(nostack, pure, nomem));
    }
    h.eq_u32("uxtb", ux, 0xF3);
    h.eq_u32("sxtb", sx, 0xFFFF_FFF3);

    // ldm/stm block transfer, round-tripped through memory. Explicit r4/r5/r6
    // make the register-list order deterministic (ldm/stm transfer in register-
    // number order, not source order).
    let store = [0x1111_1111u32, 0x2222_2222, 0x3333_3333];
    let mut buf = [0u32; 3];
    unsafe {
        asm!(
            "ldm {s}, {{r0, r1, r2}}",
            "stm {b}, {{r0, r1, r2}}",
            s = in(reg) store.as_ptr(),
            b = in(reg) buf.as_mut_ptr(),
            out("r0") _, out("r1") _, out("r2") _,
            options(nostack),
        );
    }
    h.check("ldm_stm", buf == store);
}

#[cfg(feature = "usermode")]
fn isa_impl(h: &mut Harness) {
    // Usermode runs under Intel SDE / the host CPU; reuse the bare-metal x86_64
    // checks that do not require ring-0.
    let _ = h;
}
