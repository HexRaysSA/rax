//! `strace` call sites: where a traced call came from (`strace_pc`,
//! `strace_stack`).
//!
//! The PC is the calling thread's in the call: the address after the trap
//! instruction, where a debugger shows a thread in a system call. The
//! backtrace follows the frame records both Darwin ABIs keep: the frame
//! pointer (`RBP`, `X29`) points at the caller's frame pointer, with the
//! return address in the next word. The system-call stubs of
//! `libsystem_kernel` are leaves without a frame record, so the stub's own
//! return address comes first: the word at `RSP` on x86-64 and `LR` on
//! arm64, kept only when it points into executable memory (in a function
//! with a frame record, either may be something else). Every address is
//! named by the mapping holding it (an image path, `[shared region]`), as
//! looked up at the byte before it (the call instruction's last).
//!
//! The site is captured before the call runs, so a call that replaces the
//! registers or the stack (`sigreturn`, `execve`, a receive into a stack
//! buffer) reports where it was called from.

use std::fmt::Write as _;
use std::sync::Arc;

use crate::isa::arm::aarch64::pauth::PauthKeyKind;
use crate::user::darwin::abi::DarwinAbi;
use crate::user::darwin::arch::DarwinCpu;
use crate::user::darwin::pauth::UserPauth;
use crate::user::darwin::process::{Proc, Thread};
use crate::user::mm::{AddressSpace, Perms};

/// `RBP` in [`DarwinCpu::reg`] order.
const X86_RBP: usize = 5;
/// The arm64 frame pointer.
const ARM64_FP: usize = 29;
/// The arm64 link register.
const ARM64_LR: usize = 30;

/// One frame of a backtrace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// The PC, or a return address.
    pub addr: u64,
    /// The name of the mapping holding the address, if it has one.
    pub image: Option<Arc<str>>,
}

/// Where a traced call came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallSite {
    /// The caller's ABI (names the PC register).
    pub abi: DarwinAbi,
    /// The PC after the trap instruction.
    pub pc: u64,
    /// Whether the call's line shows the PC.
    pub show_pc: bool,
    /// The backtrace, innermost first: the PC, then return addresses.
    /// Empty when the trace prints none.
    pub frames: Vec<Frame>,
}

impl CallSite {
    /// The site of `thread`'s call at `pc`; `None` unless the trace
    /// shows the PC or a backtrace.
    pub fn capture(proc: &Proc, thread: &Thread, pc: u64) -> Option<CallSite> {
        let config = &proc.config;
        if !config.strace || (!config.strace_pc && config.strace_stack == 0) {
            return None;
        }
        let frames = if config.strace_stack == 0 {
            Vec::new()
        } else {
            backtrace(&proc.space, &thread.cpu, pc, config.strace_stack)
        };
        Some(CallSite {
            abi: proc.abi,
            pc,
            show_pc: config.strace_pc,
            frames,
        })
    }
}

/// Formats a traced call's report: `[tid] text`, with the PC before
/// `text` and the backtrace on the lines after when `site` asks for them.
pub fn report(tid: u64, site: Option<&CallSite>, text: &str) -> String {
    let mut out = format!("[{tid:#x}] ");
    if let Some(site) = site.filter(|s| s.show_pc) {
        let register = match site.abi {
            DarwinAbi::X86_64 => "rip",
            DarwinAbi::Arm64 => "pc",
        };
        let _ = write!(out, "{register}={:#x} ", site.pc);
    }
    out.push_str(text);
    out.push('\n');
    for frame in site.map_or(&[][..], |s| &s.frames) {
        let _ = write!(out, "[{tid:#x}]  > {:#x}", frame.addr);
        if let Some(image) = &frame.image {
            let _ = write!(out, " {image}");
        }
        out.push('\n');
    }
    out
}

/// Prints [`report`] on standard error in one write.
pub fn print(tid: u64, site: Option<&CallSite>, text: &str) {
    eprint!("{}", report(tid, site, text));
}

/// The backtrace of a thread stopped in a call at `pc` with `cpu`'s
/// registers: at most `depth` frames, the PC first.
pub fn backtrace(space: &AddressSpace, cpu: &DarwinCpu, pc: u64, depth: usize) -> Vec<Frame> {
    match cpu {
        DarwinCpu::X86_64(_) => {
            let start = Start {
                pc,
                leaf: read_u64(space, cpu.sp()),
                fp: cpu.reg(X86_RBP),
            };
            walk(space, start, depth, |addr| addr)
        }
        DarwinCpu::Arm64(core) => {
            // arm64e signs the return addresses it saves; the instruction
            // key's layout says which bits hold the code.
            let pauth = UserPauth::from_cpu(core);
            let start = Start {
                pc,
                leaf: Some(cpu.reg(ARM64_LR)),
                fp: cpu.reg(ARM64_FP),
            };
            walk(space, start, depth, |addr| {
                pauth.strip(addr, PauthKeyKind::Ia)
            })
        }
    }
}

/// The registers a backtrace starts from.
#[derive(Clone, Copy, Debug)]
struct Start {
    /// The PC.
    pc: u64,
    /// A leaf function's return address (`None`: unreadable).
    leaf: Option<u64>,
    /// The frame pointer.
    fp: u64,
}

/// Walks the frame records from `start`. The walk stops at a null or
/// misaligned frame pointer, an unreadable record, a return address
/// outside executable memory, or a caller's record that is not above the
/// callee's (so it ends on a corrupt or cyclic chain).
fn walk(
    space: &AddressSpace,
    start: Start,
    depth: usize,
    strip: impl Fn(u64) -> u64,
) -> Vec<Frame> {
    let mut frames = Vec::new();
    if depth == 0 {
        return frames;
    }
    frames.push(Frame {
        addr: start.pc,
        image: image_of(space, start.pc),
    });
    let leaf = start
        .leaf
        .map(&strip)
        .and_then(|addr| code_frame(space, addr));
    let leaf_addr = leaf.as_ref().map(|f| f.addr);
    frames.extend(leaf);
    let mut fp = start.fp;
    let mut first_record = true;
    while frames.len() < depth {
        if fp == 0 || fp % 8 != 0 {
            break;
        }
        let Some(ret_slot) = fp.checked_add(8) else {
            break;
        };
        let (Some(caller_fp), Some(ret)) = (read_u64(space, fp), read_u64(space, ret_slot)) else {
            break;
        };
        let Some(frame) = code_frame(space, strip(ret)) else {
            break;
        };
        // A function that made the call itself, with its record set up,
        // has its return address in both the leaf position and the record.
        let repeats_leaf = first_record && leaf_addr == Some(frame.addr);
        if !repeats_leaf {
            frames.push(frame);
        }
        first_record = false;
        if caller_fp <= fp {
            break;
        }
        fp = caller_fp;
    }
    frames.truncate(depth);
    frames
}

/// A frame for return address `addr` if it follows executable code.
fn code_frame(space: &AddressSpace, addr: u64) -> Option<Frame> {
    let vma = space.vma_at(addr.wrapping_sub(1))?;
    vma.perms.contains(Perms::EXEC).then(|| Frame {
        addr,
        image: vma.name,
    })
}

/// The name of the mapping holding the byte before `addr`.
fn image_of(space: &AddressSpace, addr: u64) -> Option<Arc<str>> {
    space.vma_at(addr.wrapping_sub(1)).and_then(|vma| vma.name)
}

fn read_u64(space: &AddressSpace, addr: u64) -> Option<u64> {
    let mut bytes = [0u8; 8];
    space.read(addr, &mut bytes).ok()?;
    Some(u64::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests;
