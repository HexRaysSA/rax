//! Host control for x86 estimates, independent of guest and ambient MXCSR.
//!
//! Intel SDM Vol. 2B, RCPPS/RCPSS/RSQRTPS/RSQRTSS, specifies no SIMD
//! exceptions, rounding-control independence, signed-zero treatment of
//! denormals, and flushing of tiny reciprocal results. Translated x86 hosts
//! may implement these operations through arithmetic affected by MXCSR.

fn control_for_mask(mask: u32) -> u32 {
    // Intel SDM Vol. 1, FXSAVE: a zero MXCSR_MASK means 0x0000_FFBF.
    // Mask exceptions and use round-to-nearest. Enable FTZ/DAZ only where
    // the host advertises them; native x86 estimates already define these
    // special cases independently of either control bit.
    let mask = if mask == 0 { 0xFFBF } else { mask };
    0x1F80 | (mask & 0x8040)
}

/// O(1) time/space after one nondestructive, aligned FXSAVE query.
pub(crate) fn control() -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        static CONTROL: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
        *CONTROL.get_or_init(|| {
            #[repr(align(16))]
            struct Image([u8; 512]);
            let mut image = Image([0; 512]);
            // SAFETY: x86-64 provides FXSAVE; the output has the required
            // alignment and extent. FXSAVE leaves live FP state unchanged.
            unsafe {
                core::arch::asm!(
                    "fxsave64 [{image}]",
                    image = in(reg) image.0.as_mut_ptr(),
                    options(nostack, preserves_flags),
                );
            }
            let mask = u32::from_le_bytes(image.0[28..32].try_into().unwrap());
            control_for_mask(mask)
        })
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        // Offline x86 lowering cannot query the eventual host. Select the
        // architectural default mask, which does not assume optional DAZ.
        control_for_mask(0)
    }
}

#[cfg(target_arch = "x86_64")]
macro_rules! estimate {
    ($name:ident, $instruction:literal) => {
        pub(crate) fn $name(bits: u64) -> u64 {
            let selected = control();
            let mut saved = 0u32;
            let result: u64;
            // Keep control switching and the estimate in one asm block so
            // LLVM cannot move a nominally control-independent intrinsic
            // outside the scope. Only XMM0 is clobbered. All pointers remain
            // live until the final output, so lateout may reuse an input GPR.
            unsafe {
                core::arch::asm!(
                    "stmxcsr [{saved}]",
                    "ldmxcsr [{selected}]",
                    "movq xmm0, {bits}",
                    $instruction,
                    "ldmxcsr [{saved}]",
                    "movq {result}, xmm0",
                    saved = in(reg) &mut saved,
                    selected = in(reg) &selected,
                    bits = in(reg) bits,
                    result = lateout(reg) result,
                    out("xmm0") _,
                    options(nostack, preserves_flags),
                );
            }
            result
        }
    };
}

#[cfg(target_arch = "x86_64")]
estimate!(reciprocal_scalar, "rcpss xmm0, xmm0");
#[cfg(target_arch = "x86_64")]
estimate!(reciprocal_packed, "rcpps xmm0, xmm0");
#[cfg(target_arch = "x86_64")]
estimate!(rsqrt_scalar, "rsqrtss xmm0, xmm0");
#[cfg(target_arch = "x86_64")]
estimate!(rsqrt_packed, "rsqrtps xmm0, xmm0");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_control_respects_default_and_optional_host_mask_bits() {
        assert_eq!(control_for_mask(0), 0x9F80);
        assert_eq!(control_for_mask(0xFFBF), 0x9F80);
        assert_eq!(control_for_mask(0xFFFF), 0x9FC0);
        assert_eq!(control_for_mask(0x7FBF), 0x1F80);
        assert_eq!(control_for_mask(0xFFFF_0000), 0x1F80);
    }

    #[cfg(target_arch = "x86_64")]
    fn read_control() -> u32 {
        let mut value = 0;
        unsafe {
            core::arch::asm!("stmxcsr [{value}]", value = in(reg) &mut value,
                             options(nostack, preserves_flags));
        }
        value
    }

    #[cfg(target_arch = "x86_64")]
    fn write_control(value: u32) {
        unsafe {
            core::arch::asm!("ldmxcsr [{value}]", value = in(reg) &value,
                             options(nostack, preserves_flags));
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn native_estimates_ignore_ambient_control_and_restore_it_exactly() {
        let selected = control();
        let before = read_control();
        let variants: [fn(u64) -> u64; 4] = [
            reciprocal_scalar,
            reciprocal_packed,
            rsqrt_scalar,
            rsqrt_packed,
        ];
        let inputs: [u32; 10] = [
            0,
            0x8000_0000,
            1,
            0x8000_0001,
            0x4040_0000,
            0x4080_0000,
            0x7F80_0000,
            0xFF80_0000,
            0x7FC1_2345,
            0xFF81_2345,
        ];
        let mut observations = 0;
        for (index, input) in inputs.into_iter().enumerate() {
            let pair = u64::from(input) | (u64::from(inputs[(index + 1) % inputs.len()]) << 32);
            let baseline = variants.map(|function| function(pair));
            for ambient in [
                0x1F80, 0x3FA1, 0x5FA1, 0x7FA1, 0x9F80, 0xBFA1, 0xDFA1, 0xFFA1,
            ] {
                for (variant, function) in variants.into_iter().enumerate() {
                    write_control(ambient);
                    let actual = function(pair);
                    let after = read_control();
                    write_control(before);
                    assert_eq!(after, ambient, "variant={variant}, input={input:#x}");
                    assert_eq!(
                        actual, baseline[variant],
                        "variant={variant}, ambient={ambient:#x}"
                    );
                    observations += 1;
                }
            }
        }
        assert_eq!(observations, 320);
        assert_eq!(read_control(), before);
        println!("host_estimate_control={selected:#06x}; observations={observations}");
    }
}
