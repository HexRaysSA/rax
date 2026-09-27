//! A thread's state by flavor, as `thread_get_state` and
//! `thread_set_state` see it (`machine_thread_get_state` and
//! `machine_thread_set_state`, `osfmk/arm64/status.c` and
//! `osfmk/i386/pcb.c`; the floating-point flavors through
//! `fpu_get_fxstate`/`fpu_set_fxstate`, `osfmk/i386/fpu.c`): the flavors
//! a 64-bit thread has, the counts each takes, and the state in 32-bit
//! words. The layouts are [`thread_state`](super::thread_state)'s.
//!
//! Hardware debug registers (`ARM_DEBUG_STATE64`, `x86_DEBUG_STATE64`)
//! are kept and reported but not applied: the emulated CPUs have no
//! breakpoint or watchpoint registers. `x86_SAVED_STATE64`,
//! `x86_THREAD_FULL_STATE64` (which needs a custom LDT), and the SME and
//! SVE flavors are refused as on a machine without them.

use super::abi::DarwinAbi;
use super::arch::DarwinCpu;
use super::signal::EntryState;
use super::thread_state as ts;
use crate::user::darwin::mach::kr::{self, KernReturn};

/// `THREAD_STATE_FLAVOR_LIST`.
const FLAVOR_LIST: i32 = 0;
/// `THREAD_STATE_FLAVOR_LIST_NEW`.
const FLAVOR_LIST_NEW: i32 = 128;
/// `THREAD_STATE_FLAVOR_LIST_10_9`.
const FLAVOR_LIST_10_9: i32 = 129;
/// `THREAD_STATE_FLAVOR_LIST_10_13`.
const FLAVOR_LIST_10_13: i32 = 130;
/// `THREAD_STATE_FLAVOR_LIST_10_15`.
const FLAVOR_LIST_10_15: i32 = 131;

/// arm64 flavors and their counts (`mach/arm/thread_status.h`).
pub mod arm {
    /// `ARM_THREAD_STATE`: the unified state.
    pub const THREAD_STATE: i32 = 1;
    /// `ARM_VFP_STATE`.
    pub const VFP_STATE: i32 = 2;
    /// `ARM_EXCEPTION_STATE`.
    pub const EXCEPTION_STATE: i32 = 3;
    /// `ARM_DEBUG_STATE`.
    pub const DEBUG_STATE: i32 = 4;
    /// `ARM_THREAD_STATE64`.
    pub const THREAD_STATE64: i32 = 6;
    /// `ARM_EXCEPTION_STATE64`.
    pub const EXCEPTION_STATE64: i32 = 7;
    /// `ARM_EXCEPTION_STATE64_V2`.
    pub const EXCEPTION_STATE64_V2: i32 = 10;
    /// `ARM_DEBUG_STATE64`.
    pub const DEBUG_STATE64: i32 = 15;
    /// `ARM_NEON_STATE64`.
    pub const NEON_STATE64: i32 = 17;
    /// `ARM_PAGEIN_STATE`.
    pub const PAGEIN_STATE: i32 = 27;

    /// `ARM_THREAD_STATE64_COUNT`.
    pub const THREAD_STATE64_COUNT: u32 = 68;
    /// `ARM_UNIFIED_THREAD_STATE_COUNT`.
    pub const UNIFIED_THREAD_STATE_COUNT: u32 = 70;
    /// `ARM_EXCEPTION_STATE64_COUNT` (and `_V2_COUNT`).
    pub const EXCEPTION_STATE64_COUNT: u32 = 4;
    /// `ARM_DEBUG_STATE64_COUNT`.
    pub const DEBUG_STATE64_COUNT: u32 = 130;
    /// `ARM_NEON_STATE64_COUNT`.
    pub const NEON_STATE64_COUNT: u32 = 132;
    /// `ARM_VFP_STATE_COUNT`.
    pub const VFP_STATE_COUNT: u32 = 65;
    /// `ARM_VFPV2_STATE_COUNT`.
    pub const VFPV2_STATE_COUNT: u32 = 33;
}

/// x86-64 flavors and their counts (`mach/i386/thread_status.h`).
pub mod x86 {
    /// `x86_THREAD_STATE32` (`i386_THREAD_STATE`).
    pub const THREAD_STATE32: i32 = 1;
    /// `x86_FLOAT_STATE32` (`i386_FLOAT_STATE`).
    pub const FLOAT_STATE32: i32 = 2;
    /// `x86_EXCEPTION_STATE32` (`i386_EXCEPTION_STATE`).
    pub const EXCEPTION_STATE32: i32 = 3;
    /// `x86_THREAD_STATE64`.
    pub const THREAD_STATE64: i32 = 4;
    /// `x86_FLOAT_STATE64`.
    pub const FLOAT_STATE64: i32 = 5;
    /// `x86_EXCEPTION_STATE64`.
    pub const EXCEPTION_STATE64: i32 = 6;
    /// `x86_THREAD_STATE`.
    pub const THREAD_STATE: i32 = 7;
    /// `x86_FLOAT_STATE`.
    pub const FLOAT_STATE: i32 = 8;
    /// `x86_EXCEPTION_STATE`.
    pub const EXCEPTION_STATE: i32 = 9;
    /// `x86_DEBUG_STATE32`.
    pub const DEBUG_STATE32: i32 = 10;
    /// `x86_DEBUG_STATE64`.
    pub const DEBUG_STATE64: i32 = 11;
    /// `x86_DEBUG_STATE`.
    pub const DEBUG_STATE: i32 = 12;
    /// `x86_AVX_STATE32`.
    pub const AVX_STATE32: i32 = 16;
    /// `x86_AVX_STATE64`.
    pub const AVX_STATE64: i32 = 17;
    /// `x86_AVX_STATE`.
    pub const AVX_STATE: i32 = 18;
    /// `x86_AVX512_STATE32`.
    pub const AVX512_STATE32: i32 = 19;
    /// `x86_AVX512_STATE64`.
    pub const AVX512_STATE64: i32 = 20;
    /// `x86_AVX512_STATE`.
    pub const AVX512_STATE: i32 = 21;
    /// `x86_PAGEIN_STATE`.
    pub const PAGEIN_STATE: i32 = 22;
    /// `x86_INSTRUCTION_STATE`.
    pub const INSTRUCTION_STATE: i32 = 24;

    /// `x86_THREAD_STATE64_COUNT`.
    pub const THREAD_STATE64_COUNT: u32 = 42;
    /// `x86_THREAD_STATE_COUNT`.
    pub const THREAD_STATE_COUNT: u32 = 44;
    /// `x86_FLOAT_STATE64_COUNT` (and `32_COUNT`).
    pub const FLOAT_STATE64_COUNT: u32 = 131;
    /// `x86_FLOAT_STATE_COUNT`.
    pub const FLOAT_STATE_COUNT: u32 = 133;
    /// `x86_EXCEPTION_STATE64_COUNT`.
    pub const EXCEPTION_STATE64_COUNT: u32 = 4;
    /// `x86_EXCEPTION_STATE_COUNT`.
    pub const EXCEPTION_STATE_COUNT: u32 = 6;
    /// `x86_DEBUG_STATE64_COUNT`.
    pub const DEBUG_STATE64_COUNT: u32 = 16;
    /// `x86_DEBUG_STATE_COUNT`.
    pub const DEBUG_STATE_COUNT: u32 = 18;
    /// `x86_AVX_STATE32_COUNT`.
    pub const AVX_STATE32_COUNT: u32 = 179;
    /// `x86_AVX_STATE64_COUNT`.
    pub const AVX_STATE64_COUNT: u32 = 211;
    /// `x86_AVX_STATE_COUNT`.
    pub const AVX_STATE_COUNT: u32 = 213;
    /// `x86_AVX512_STATE32_COUNT`.
    pub const AVX512_STATE32_COUNT: u32 = 259;
    /// `x86_AVX512_STATE64_COUNT`.
    pub const AVX512_STATE64_COUNT: u32 = 611;
    /// `x86_AVX512_STATE_COUNT`.
    pub const AVX512_STATE_COUNT: u32 = 613;
    /// `x86_INSTRUCTION_STATE_COUNT`.
    pub const INSTRUCTION_STATE_COUNT: u32 = 614;
}

/// `VM_MAX_PAGE_ADDRESS` on x86-64: debug addresses must lie below it.
const X86_VM_MAX_PAGE_ADDRESS: u64 = 0x0000_7fff_ffe0_0000;

/// `__DARWIN_ARM_THREAD_STATE64_FLAGS_NO_PTRAUTH`.
const FLAGS_NO_PTRAUTH: u32 = 0x1;
/// `__DARWIN_ARM_THREAD_STATE64_FLAGS_KERNEL_SIGNED_PC` and `_LR`.
const FLAGS_KERNEL_SIGNED: u32 = 0x4 | 0x8;

fn words(b: &[u8]) -> Vec<u32> {
    b.chunks(4)
        .map(|c| {
            let mut w = [0u8; 4];
            w[..c.len()].copy_from_slice(c);
            u32::from_le_bytes(w)
        })
        .collect()
}

fn bytes(w: &[u32]) -> Vec<u8> {
    w.iter().flat_map(|v| v.to_le_bytes()).collect()
}

/// A thread's state outside its CPU.
pub struct View<'a> {
    /// The CPU.
    pub cpu: &'a DarwinCpu,
    /// The last exception entry.
    pub entry: &'a EntryState,
    /// The debug registers set with `thread_set_state` (empty: none).
    pub debug: &'a [u32],
    /// Whether the process authenticates pointers (arm64e).
    pub ptrauth: bool,
}

/// `thread_get_state`: the state of `flavor` in at most `count` words.
pub fn get(v: &View<'_>, flavor: i32, count: u32) -> Result<Vec<u32>, KernReturn> {
    match v.cpu {
        DarwinCpu::Arm64(cpu) => get_arm64(v, cpu, flavor, count),
        DarwinCpu::X86_64(cpu) => get_x86(v, cpu, flavor, count),
    }
}

/// `_MachineStateCount` (`osfmk/arm64/status.c`, `osfmk/i386/pcb.c`):
/// the words of `flavor`'s state, the room the kernel gives a state it
/// sends with an exception; 0 for a flavor it has no size for.
pub fn machine_state_count(abi: DarwinAbi, flavor: i32) -> u32 {
    match abi {
        DarwinAbi::Arm64 => match flavor {
            arm::THREAD_STATE => arm::UNIFIED_THREAD_STATE_COUNT,
            arm::VFP_STATE => arm::VFP_STATE_COUNT,
            arm::EXCEPTION_STATE => 3,
            arm::DEBUG_STATE => 64,
            arm::THREAD_STATE64 => arm::THREAD_STATE64_COUNT,
            arm::EXCEPTION_STATE64 | arm::EXCEPTION_STATE64_V2 => arm::EXCEPTION_STATE64_COUNT,
            // ARM_THREAD_STATE32, ARM_DEBUG_STATE32, ARM_NEON_STATE.
            9 => 17,
            14 => 66,
            16 => 68,
            arm::DEBUG_STATE64 => arm::DEBUG_STATE64_COUNT,
            arm::NEON_STATE64 => arm::NEON_STATE64_COUNT,
            arm::PAGEIN_STATE => 1,
            _ => 0,
        },
        DarwinAbi::X86_64 => match flavor {
            x86::THREAD_STATE32 => 16,
            x86::FLOAT_STATE32 => 131,
            x86::EXCEPTION_STATE32 => 3,
            x86::THREAD_STATE64 => x86::THREAD_STATE64_COUNT,
            x86::FLOAT_STATE64 => x86::FLOAT_STATE64_COUNT,
            x86::EXCEPTION_STATE64 => x86::EXCEPTION_STATE64_COUNT,
            x86::THREAD_STATE => x86::THREAD_STATE_COUNT,
            x86::FLOAT_STATE => x86::FLOAT_STATE_COUNT,
            x86::EXCEPTION_STATE => x86::EXCEPTION_STATE_COUNT,
            x86::DEBUG_STATE32 => 8,
            x86::DEBUG_STATE64 => x86::DEBUG_STATE64_COUNT,
            x86::DEBUG_STATE => x86::DEBUG_STATE_COUNT,
            x86::AVX_STATE32 => x86::AVX_STATE32_COUNT,
            x86::AVX_STATE64 => x86::AVX_STATE64_COUNT,
            x86::AVX_STATE => x86::AVX_STATE_COUNT,
            x86::AVX512_STATE32 => x86::AVX512_STATE32_COUNT,
            x86::AVX512_STATE64 => x86::AVX512_STATE64_COUNT,
            x86::AVX512_STATE => x86::AVX512_STATE_COUNT,
            x86::PAGEIN_STATE => 1,
            // x86_THREAD_FULL_STATE64, x86_LAST_BRANCH_STATE.
            23 => 50,
            x86::INSTRUCTION_STATE => x86::INSTRUCTION_STATE_COUNT,
            25 => 194,
            _ => 0,
        },
    }
}

fn need(count: u32, n: u32) -> Result<(), KernReturn> {
    if count < n {
        Err(kr::KERN_INVALID_ARGUMENT)
    } else {
        Ok(())
    }
}

fn get_arm64(
    v: &View<'_>,
    cpu: &crate::user::cpu::aarch64::A64UserCpu,
    flavor: i32,
    count: u32,
) -> Result<Vec<u32>, KernReturn> {
    let thread64 = || {
        let flags = if v.ptrauth {
            FLAGS_KERNEL_SIGNED
        } else {
            FLAGS_NO_PTRAUTH
        };
        words(&ts::arm64_thread_state(cpu, flags))
    };
    Ok(match flavor {
        FLAVOR_LIST => {
            need(count, 4)?;
            vec![1, 2, 3, 4]
        }
        FLAVOR_LIST_NEW => {
            need(count, 4)?;
            vec![1, 2, 7, 15]
        }
        FLAVOR_LIST_10_15 => {
            need(count, 5)?;
            vec![1, 2, 7, 15, 27]
        }
        arm::THREAD_STATE => {
            // A smaller buffer asks for the 32-bit state, which a 64-bit
            // thread does not have.
            need(count, arm::UNIFIED_THREAD_STATE_COUNT)?;
            let mut s = vec![arm::THREAD_STATE64 as u32, arm::THREAD_STATE64_COUNT];
            s.extend(thread64());
            s
        }
        arm::THREAD_STATE64 => {
            need(count, arm::THREAD_STATE64_COUNT)?;
            thread64()
        }
        arm::EXCEPTION_STATE64 => {
            need(count, arm::EXCEPTION_STATE64_COUNT)?;
            words(&ts::arm64_exception_state(v.entry))
        }
        arm::EXCEPTION_STATE64_V2 => {
            // far and a 64-bit esr.
            need(count, arm::EXCEPTION_STATE64_COUNT)?;
            let e = v.entry;
            vec![e.far as u32, (e.far >> 32) as u32, e.esr, 0]
        }
        arm::DEBUG_STATE64 => {
            need(count, arm::DEBUG_STATE64_COUNT)?;
            debug_or_zero(v.debug, arm::DEBUG_STATE64_COUNT)
        }
        arm::VFP_STATE => {
            // The 32-bit view of the saved NEON registers: s0-s63 (q0-q15)
            // and fpscr, or s0-s31 and fpscr for a VFPv2-sized buffer.
            if count < arm::VFPV2_STATE_COUNT {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            let n = if count < arm::VFP_STATE_COUNT {
                arm::VFPV2_STATE_COUNT
            } else {
                arm::VFP_STATE_COUNT
            };
            words(&ts::arm64_neon_state(cpu)[..n as usize * 4])
        }
        arm::NEON_STATE64 => {
            need(count, arm::NEON_STATE64_COUNT)?;
            words(&ts::arm64_neon_state(cpu))
        }
        arm::PAGEIN_STATE => {
            need(count, 1)?;
            vec![0]
        }
        // The 32-bit flavors, the SME and SVE state, and anything else.
        _ => return Err(kr::KERN_INVALID_ARGUMENT),
    })
}

fn debug_or_zero(debug: &[u32], n: u32) -> Vec<u32> {
    if debug.is_empty() {
        vec![0; n as usize]
    } else {
        debug.to_vec()
    }
}

fn get_x86(
    v: &View<'_>,
    cpu: &crate::user::cpu::x86_64::X86UserCpu,
    flavor: i32,
    count: u32,
) -> Result<Vec<u32>, KernReturn> {
    let float64 = || words(&ts::x86_avx_state(cpu)[..x86::FLOAT_STATE64_COUNT as usize * 4]);
    let with_header = |f: i32, n: u32, body: Vec<u32>| {
        let mut s = vec![f as u32, n];
        s.extend(body);
        s
    };
    Ok(match flavor {
        FLAVOR_LIST => {
            need(count, 3)?;
            vec![1, 2, 3]
        }
        FLAVOR_LIST_NEW => {
            need(count, 4)?;
            vec![7, 8, 9, 12]
        }
        FLAVOR_LIST_10_9 => {
            need(count, 5)?;
            vec![7, 8, 9, 12, 18]
        }
        FLAVOR_LIST_10_13 => {
            need(count, 6)?;
            vec![7, 8, 9, 12, 18, 21]
        }
        FLAVOR_LIST_10_15 => {
            need(count, 7)?;
            vec![7, 8, 9, 12, 18, 21, 22]
        }
        x86::THREAD_STATE64 => {
            need(count, x86::THREAD_STATE64_COUNT)?;
            words(&ts::x86_thread_state(cpu))
        }
        x86::THREAD_STATE => {
            need(count, x86::THREAD_STATE_COUNT)?;
            with_header(
                x86::THREAD_STATE64,
                x86::THREAD_STATE64_COUNT,
                words(&ts::x86_thread_state(cpu)),
            )
        }
        x86::FLOAT_STATE64 => {
            need(count, x86::FLOAT_STATE64_COUNT)?;
            float64()
        }
        x86::FLOAT_STATE => {
            need(count, x86::FLOAT_STATE_COUNT)?;
            with_header(x86::FLOAT_STATE64, x86::FLOAT_STATE64_COUNT, float64())
        }
        x86::AVX_STATE64 => {
            if count != x86::AVX_STATE64_COUNT {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            words(&ts::x86_avx_state(cpu))
        }
        x86::AVX_STATE => {
            need(count, x86::AVX_STATE_COUNT)?;
            with_header(
                x86::AVX_STATE64,
                x86::AVX_STATE64_COUNT,
                words(&ts::x86_avx_state(cpu)),
            )
        }
        // The thread's state has no AVX-512 components on the emulated
        // Haswell (fpu_get_fxstate).
        x86::AVX512_STATE64 => {
            if count != x86::AVX512_STATE64_COUNT {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            return Err(kr::KERN_FAILURE);
        }
        x86::AVX512_STATE => {
            need(count, x86::AVX512_STATE_COUNT)?;
            return Err(kr::KERN_FAILURE);
        }
        x86::EXCEPTION_STATE64 => {
            need(count, x86::EXCEPTION_STATE64_COUNT)?;
            words(&ts::x86_exception_state(v.entry))
        }
        x86::EXCEPTION_STATE => {
            need(count, x86::EXCEPTION_STATE_COUNT)?;
            with_header(
                x86::EXCEPTION_STATE64,
                x86::EXCEPTION_STATE64_COUNT,
                words(&ts::x86_exception_state(v.entry)),
            )
        }
        x86::DEBUG_STATE64 => {
            need(count, x86::DEBUG_STATE64_COUNT)?;
            debug_or_zero(v.debug, x86::DEBUG_STATE64_COUNT)
        }
        x86::DEBUG_STATE => {
            need(count, x86::DEBUG_STATE_COUNT)?;
            with_header(
                x86::DEBUG_STATE64,
                x86::DEBUG_STATE64_COUNT,
                debug_or_zero(v.debug, x86::DEBUG_STATE64_COUNT),
            )
        }
        x86::PAGEIN_STATE => {
            need(count, 1)?;
            vec![0]
        }
        // No instruction stream is kept for the thread: nothing to report.
        x86::INSTRUCTION_STATE => {
            need(count, x86::INSTRUCTION_STATE_COUNT)?;
            Vec::new()
        }
        // The 32-bit flavors (a 64-bit thread has none of them), the full
        // and saved states, last-branch records, and anything else.
        _ => return Err(kr::KERN_INVALID_ARGUMENT),
    })
}

/// `thread_set_state`: installs `state` (its count the slice's length)
/// as `flavor`; `debug` keeps the debug registers.
pub fn set(
    cpu: &mut DarwinCpu,
    debug: &mut Vec<u32>,
    flavor: i32,
    state: &[u32],
) -> Result<(), KernReturn> {
    let count = state.len() as u32;
    match cpu {
        DarwinCpu::Arm64(cpu) => set_arm64(cpu, debug, flavor, state, count),
        DarwinCpu::X86_64(cpu) => set_x86(cpu, debug, flavor, state, count),
    }
}

fn exactly(count: u32, n: u32) -> Result<(), KernReturn> {
    if count != n {
        Err(kr::KERN_INVALID_ARGUMENT)
    } else {
        Ok(())
    }
}

fn set_arm64(
    cpu: &mut crate::user::cpu::aarch64::A64UserCpu,
    debug: &mut Vec<u32>,
    flavor: i32,
    state: &[u32],
    count: u32,
) -> Result<(), KernReturn> {
    match flavor {
        arm::THREAD_STATE => {
            // The unified state must carry the 64-bit state: a thread's
            // saved state is 64-bit.
            if count < arm::UNIFIED_THREAD_STATE_COUNT
                || state[0] != arm::THREAD_STATE64 as u32
                || state[1] != arm::THREAD_STATE64_COUNT
            {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            ts::set_arm64_thread_state(cpu, &bytes(&state[2..70]));
        }
        arm::THREAD_STATE64 => {
            exactly(count, arm::THREAD_STATE64_COUNT)?;
            ts::set_arm64_thread_state(cpu, &bytes(state));
        }
        // The exception state is not the thread's to change.
        arm::EXCEPTION_STATE64 | arm::EXCEPTION_STATE64_V2 => {
            exactly(count, arm::EXCEPTION_STATE64_COUNT)?;
        }
        arm::DEBUG_STATE64 => {
            exactly(count, arm::DEBUG_STATE64_COUNT)?;
            set_arm_debug(debug, state)?;
        }
        arm::VFP_STATE => {
            if count != arm::VFP_STATE_COUNT && count != arm::VFPV2_STATE_COUNT {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            // Into the saved NEON registers' 32-bit view.
            let mut neon = ts::arm64_neon_state(cpu);
            let b = bytes(state);
            neon[..b.len()].copy_from_slice(&b);
            ts::set_arm64_neon_state(cpu, &neon);
        }
        arm::NEON_STATE64 => {
            exactly(count, arm::NEON_STATE64_COUNT)?;
            ts::set_arm64_neon_state(cpu, &bytes(state));
        }
        _ => return Err(kr::KERN_INVALID_ARGUMENT),
    }
    Ok(())
}

fn set_x86(
    cpu: &mut crate::user::cpu::x86_64::X86UserCpu,
    debug: &mut Vec<u32>,
    flavor: i32,
    state: &[u32],
    count: u32,
) -> Result<(), KernReturn> {
    let thread64 = |cpu: &mut crate::user::cpu::x86_64::X86UserCpu, s: &[u32]| {
        ts::set_x86_thread_state(cpu, &bytes(s)).map_err(|_| kr::KERN_INVALID_ARGUMENT)
    };
    // fpu_set_fxstate: a float state leaves the upper halves of the YMM
    // registers in their initial (zero) state.
    let float64 = |cpu: &mut crate::user::cpu::x86_64::X86UserCpu, s: &[u32]| {
        let mut avx = vec![0u8; ts::X86_AVX_STATE64_SIZE];
        let b = bytes(s);
        avx[..b.len()].copy_from_slice(&b);
        ts::set_x86_avx_state(cpu, &avx).map_err(|_| kr::KERN_INVALID_ARGUMENT)
    };
    let avx64 = |cpu: &mut crate::user::cpu::x86_64::X86UserCpu, s: &[u32]| {
        ts::set_x86_avx_state(cpu, &bytes(s)).map_err(|_| kr::KERN_INVALID_ARGUMENT)
    };
    let header = |f: i32, n: u32| state.len() >= 2 && state[0] == f as u32 && state[1] == n;
    match flavor {
        x86::THREAD_STATE64 => {
            exactly(count, x86::THREAD_STATE64_COUNT)?;
            thread64(cpu, state)
        }
        x86::THREAD_STATE => {
            exactly(count, x86::THREAD_STATE_COUNT)?;
            if !header(x86::THREAD_STATE64, x86::THREAD_STATE64_COUNT) {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            thread64(cpu, &state[2..])
        }
        x86::FLOAT_STATE64 => {
            exactly(count, x86::FLOAT_STATE64_COUNT)?;
            float64(cpu, state)
        }
        x86::FLOAT_STATE => {
            exactly(count, x86::FLOAT_STATE_COUNT)?;
            if !header(x86::FLOAT_STATE64, x86::FLOAT_STATE64_COUNT) {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            float64(cpu, &state[2..])
        }
        x86::AVX_STATE64 => {
            exactly(count, x86::AVX_STATE64_COUNT)?;
            avx64(cpu, state)
        }
        x86::AVX_STATE => {
            exactly(count, x86::AVX_STATE_COUNT)?;
            if !header(x86::AVX_STATE64, x86::AVX_STATE64_COUNT) {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            avx64(cpu, &state[2..2 + x86::AVX_STATE64_COUNT as usize])
        }
        x86::AVX512_STATE64 => {
            exactly(count, x86::AVX512_STATE64_COUNT)?;
            Err(kr::KERN_FAILURE)
        }
        x86::AVX512_STATE => {
            exactly(count, x86::AVX512_STATE_COUNT)?;
            if !header(x86::AVX512_STATE64, x86::AVX512_STATE64_COUNT) {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            Err(kr::KERN_FAILURE)
        }
        x86::FLOAT_STATE32 | x86::AVX_STATE32 | x86::AVX512_STATE32 => {
            let n = match flavor {
                x86::FLOAT_STATE32 => x86::FLOAT_STATE64_COUNT,
                x86::AVX_STATE32 => x86::AVX_STATE32_COUNT,
                _ => x86::AVX512_STATE32_COUNT,
            };
            exactly(count, n)?;
            Err(kr::KERN_INVALID_ARGUMENT)
        }
        // set_debug_state64 reads the state without a count check.
        x86::DEBUG_STATE64 => set_x86_debug(debug, state),
        x86::DEBUG_STATE => {
            exactly(count, x86::DEBUG_STATE_COUNT)?;
            if !header(x86::DEBUG_STATE64, x86::DEBUG_STATE64_COUNT) {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            set_x86_debug(debug, &state[2..])
        }
        _ => Err(kr::KERN_INVALID_ARGUMENT),
    }
}

/// Bits of the arm64 debug control registers (`osfmk/arm64/proc_reg.h`).
mod dbg {
    /// `ARM_DBGBCR_TYPE_MASK` (`ARM_DBGBCR_TYPE_IVA` is 0).
    pub const BCR_TYPE_MASK: u64 = 1 << 21;
    /// `ARM_DBG_CR_LINKED_MASK` (`ARM_DBG_CR_LINKED_UNLINKED` is 0).
    pub const CR_LINKED_MASK: u64 = 1 << 20;
    /// `ARM_DBG_CR_ENABLE_MASK`.
    pub const CR_ENABLE: u64 = 1;
    /// `ARM_DBG_CR_BYTE_ADDRESS_SELECT_MASK`.
    pub const CR_BYTE_ADDRESS_SELECT_MASK: u64 = 0x1e0;
    /// `ARM_DBGWCR_BYTE_ADDRESS_SELECT_MASK`.
    pub const WCR_BYTE_ADDRESS_SELECT_MASK: u64 = 0x1fe0;
    /// `ARM_DBGWCR_ACCESS_CONTROL_MASK`.
    pub const WCR_ACCESS_CONTROL_MASK: u64 = 3 << 3;
    /// `ARM_DBG_CR_ADDRESS_MASK_MASK`.
    pub const CR_ADDRESS_MASK_MASK: u64 = 0x1f00_0000;
    /// `ARM_DBG_CR_MODE_CONTROL_USER` (the security-state field is 0).
    pub const CR_MODE_CONTROL_USER: u64 = 2 << 1;
    /// `ARM_DBG_VR_ADDRESS_MASK64`.
    pub const VR_ADDRESS_MASK: u64 = !3;
    /// `MDSCR_SS`: single step.
    pub const MDSCR_SS: u64 = 1;
}

/// `ARM_DEBUG_STATE64` for `thread_set_state`: no context-ID or linked
/// breakpoints (`KERN_PROTECTION_FAILURE`); a state enabling nothing
/// removes the thread's; otherwise the registers are masked to what a
/// user may set, each for user mode.
fn set_arm_debug(debug: &mut Vec<u32>, state: &[u32]) -> Result<(), KernReturn> {
    let r = |s: &[u32], i: usize| u64::from(s[2 * i]) | u64::from(s[2 * i + 1]) << 32;
    // bvr[16], bcr[16], wvr[16], wcr[16], mdscr_el1.
    let (bvr, bcr, wvr, wcr, mdscr) = (0, 16, 32, 48, 64);
    let mut enabled = r(state, mdscr) & dbg::MDSCR_SS != 0;
    for i in 0..16 {
        let (b, w) = (r(state, bcr + i), r(state, wcr + i));
        if b & dbg::BCR_TYPE_MASK != 0
            || b & dbg::CR_LINKED_MASK != 0
            || w & dbg::CR_LINKED_MASK != 0
        {
            return Err(kr::KERN_PROTECTION_FAILURE);
        }
        if b & dbg::CR_ENABLE != 0 || w & dbg::CR_ENABLE != 0 {
            enabled = true;
        }
    }
    if !enabled {
        debug.clear();
        return Ok(());
    }
    let mut out = if debug.is_empty() {
        vec![0u32; arm::DEBUG_STATE64_COUNT as usize]
    } else {
        std::mem::take(debug)
    };
    let mut put = |i: usize, v: u64| {
        out[2 * i] = v as u32;
        out[2 * i + 1] = (v >> 32) as u32;
    };
    for i in 0..16 {
        let b = r(state, bcr + i) & (dbg::CR_BYTE_ADDRESS_SELECT_MASK | dbg::CR_ENABLE);
        put(bcr + i, b | dbg::CR_MODE_CONTROL_USER);
        put(bvr + i, r(state, bvr + i) & dbg::VR_ADDRESS_MASK);
        let w = r(state, wcr + i)
            & (dbg::CR_ADDRESS_MASK_MASK
                | dbg::WCR_BYTE_ADDRESS_SELECT_MASK
                | dbg::WCR_ACCESS_CONTROL_MASK
                | dbg::CR_ENABLE);
        put(wcr + i, w | dbg::CR_MODE_CONTROL_USER);
        put(wvr + i, r(state, wvr + i) & dbg::VR_ADDRESS_MASK);
    }
    drop(put);
    // Only the single-step bit of the thread's MDSCR_EL1 changes.
    let cur = u64::from(out[2 * mdscr]) | u64::from(out[2 * mdscr + 1]) << 32;
    let new = if r(state, mdscr) & dbg::MDSCR_SS != 0 {
        cur | dbg::MDSCR_SS
    } else {
        cur & !dbg::MDSCR_SS
    };
    out[2 * mdscr] = new as u32;
    out[2 * mdscr + 1] = (new >> 32) as u32;
    *debug = out;
    Ok(())
}

/// `set_debug_state64`: `debug_state_is_valid64` and its fix-ups of DR7.
fn set_x86_debug(debug: &mut Vec<u32>, state: &[u32]) -> Result<(), KernReturn> {
    let mut s = state.to_vec();
    s.resize(x86::DEBUG_STATE64_COUNT as usize, 0);
    let reg = |s: &[u32], i: usize| u64::from(s[2 * i]) | u64::from(s[2 * i + 1]) << 32;
    // dr0-dr3, dr4, dr5, dr6, dr7.
    let mut dr7 = s[14];
    // dr7d_is_valid: no I/O breakpoints (CR4.DE is clear), execution
    // breakpoints of length 1, and no global enables.
    for i in 0..4 {
        let rw = (dr7 >> (16 + i * 4)) & 3;
        let len = (dr7 >> (18 + i * 4)) & 3;
        if rw == 2 || (rw == 0 && len != 0) {
            return Err(kr::KERN_INVALID_ARGUMENT);
        }
    }
    dr7 = (dr7 | 1 << 10) & !(1 << 11 | 1 << 12 | 1 << 14 | 1 << 15);
    if dr7 & (0x2 | 0x8 | 0x20 | 0x80) != 0 {
        return Err(kr::KERN_INVALID_ARGUMENT);
    }
    for i in 0..4 {
        if dr7 & (1 << (2 * i)) != 0 && reg(&s, i) >= X86_VM_MAX_PAGE_ADDRESS {
            return Err(kr::KERN_INVALID_ARGUMENT);
        }
    }
    s[14] = dr7;
    s[15] = 0;
    *debug = s;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_debug_state_follows_dr7_rules() {
        let mut d = Vec::new();
        let mut s = vec![0u32; 16];
        // DR0 enabled locally at a user address: accepted, DR7 fixed up.
        s[0] = 0x1000;
        s[14] = 0x1;
        assert_eq!(set_x86_debug(&mut d, &s), Ok(()));
        assert_eq!(d[14], 0x401);
        // Global enable, an I/O breakpoint, a long execution breakpoint.
        for dr7 in [0x2, 0x1 | 2 << 16, 0x1 | 1 << 18] {
            s[14] = dr7;
            assert_eq!(set_x86_debug(&mut d, &s), Err(kr::KERN_INVALID_ARGUMENT));
        }
        // An address at or above VM_MAX_PAGE_ADDRESS.
        s[14] = 0x1;
        s[0] = 0xffe0_0000;
        s[1] = 0x7fff;
        assert_eq!(set_x86_debug(&mut d, &s), Err(kr::KERN_INVALID_ARGUMENT));
    }

    /// The SDK's `*_COUNT` of every flavor with a size (printed from
    /// `mach/thread_status.h` for each architecture).
    #[test]
    fn machine_state_counts_follow_the_headers() {
        let arm: Vec<(i32, u32)> = (0..40)
            .map(|f| (f, machine_state_count(DarwinAbi::Arm64, f)))
            .filter(|&(_, n)| n != 0)
            .collect();
        assert_eq!(
            arm,
            [
                (1, 70),
                (2, 65),
                (3, 3),
                (4, 64),
                (6, 68),
                (7, 4),
                (9, 17),
                (10, 4),
                (14, 66),
                (15, 130),
                (16, 68),
                (17, 132),
                (27, 1)
            ]
        );
        let x86: Vec<(i32, u32)> = (0..40)
            .map(|f| (f, machine_state_count(DarwinAbi::X86_64, f)))
            .filter(|&(_, n)| n != 0)
            .collect();
        assert_eq!(
            x86,
            [
                (1, 16),
                (2, 131),
                (3, 3),
                (4, 42),
                (5, 131),
                (6, 4),
                (7, 44),
                (8, 133),
                (9, 6),
                (10, 8),
                (11, 16),
                (12, 18),
                (16, 179),
                (17, 211),
                (18, 213),
                (19, 259),
                (20, 611),
                (21, 613),
                (22, 1),
                (23, 50),
                (24, 614),
                (25, 194)
            ]
        );
    }
}
