//! The host subsystem (`mach_host.defs`, `osfmk/kern/host.c`) for the
//! emulated machine: one CPU of the process's architecture and
//! [`process::MEMSIZE`](crate::user::darwin::process::MEMSIZE) of memory.

use super::{Buf, MigResult, Out, Req, ids, info_reply};
use crate::user::darwin::abi::DarwinAbi;
use crate::user::darwin::commpage::NCPUS;
use crate::user::darwin::mach::ipc::{KObject, Port};
use crate::user::darwin::mach::kr::{self, KernReturn};
use crate::user::darwin::mach::voucher;
use crate::user::darwin::process::{MEMSIZE, memsize_usable};
use crate::user::darwin::syscall::Ctx;

/// `host_info` flavors.
mod flavor {
    pub const BASIC_INFO: i32 = 1;
    pub const SCHED_INFO: i32 = 3;
    pub const RESOURCE_SIZES: i32 = 4;
    pub const PRIORITY_INFO: i32 = 5;
    pub const SEMAPHORE_TRAPS: i32 = 7;
    pub const MACH_MSG_TRAP: i32 = 8;
    pub const VM_PURGABLE: i32 = 9;
    pub const DEBUG_INFO_INTERNAL: i32 = 10;
    pub const CAN_HAS_DEBUGGER: i32 = 11;
    pub const PREFERRED_USER_ARCH: i32 = 12;
}

/// `host_statistics` flavors.
mod stat {
    pub const LOAD_INFO: i32 = 1;
    pub const VM_INFO: i32 = 2;
    pub const CPU_LOAD_INFO: i32 = 3;
    pub const VM_INFO64: i32 = 4;
    pub const EXTMOD_INFO64: i32 = 5;
    pub const EXPIRED_TASK_INFO: i32 = 6;
}

/// The `cpu_type` and `cpu_subtype` the kernel reports for its CPUs
/// (`slot_type`/`slot_subtype`): an Intel Haswell-class Mac reports
/// `CPU_TYPE_X86` with `CPU_SUBTYPE_X86_64_H` (`osfmk/i386/cpuid.c`), an
/// Apple-silicon Mac `CPU_TYPE_ARM64` with `CPU_SUBTYPE_ARM64E`.
pub fn slot_type(abi: DarwinAbi) -> (i32, i32) {
    match abi {
        DarwinAbi::X86_64 => (7, 8),
        DarwinAbi::Arm64 => (0x0100_000c, 2),
    }
}

/// `machine_info.memory_size`: the usable memory truncated to 32 bits on
/// arm64 (`machine_conf`), capped at 2 GiB on x86-64 (`i386_vm_init`).
pub fn memory_size(abi: DarwinAbi) -> u32 {
    match abi {
        DarwinAbi::X86_64 => MEMSIZE.min(1 << 31) as u32,
        DarwinAbi::Arm64 => memsize_usable(abi) as u32,
    }
}

/// `host_page_size`: the kernel's page size.
pub fn kernel_page_size(abi: DarwinAbi) -> u64 {
    abi.page_size()
}

fn is_host(req: &Req) -> bool {
    matches!(req.port.kobject, KObject::Host | KObject::HostPriv)
}

/// Serves the host subsystem.
pub fn serve(ctx: &mut Ctx<'_>, req: &mut Req) -> MigResult {
    use ids::host as h;
    match req.id {
        h::HOST_INFO => {
            req.simple(40)?;
            if !is_host(req) {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            let count = req.u32(36).min(68);
            let words = host_info(ctx.proc.abi, req.i32(32), count)?;
            Ok(info_reply(&words))
        }
        h::HOST_GET_IO_MAIN => {
            req.simple(24)?;
            if !is_host(req) {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            // IOKit's main port is the host's: its calls go to the host
            // kernel through the proxy.
            let port = crate::user::darwin::bridge::io_main(ctx.proc).ok_or(kr::KERN_FAILURE)?;
            Ok(Out::Complex(
                vec![super::OutDesc::Port(
                    Some(crate::user::darwin::mach::ipc::Right::Send(port)),
                    crate::user::darwin::mach::ipc::disp::MOVE_SEND,
                )],
                Vec::new(),
            ))
        }
        h::HOST_KERNEL_VERSION => {
            req.simple(24)?;
            if !is_host(req) {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            let mut v = kernel_version(ctx.proc.config.host_services);
            v.truncate(511);
            v.push(0);
            let cnt = v.len() as u32;
            v.resize(v.len().div_ceil(4) * 4, 0);
            Ok(Out::Simple(Buf::new().u32(0).u32(cnt).bytes(&v).done()))
        }
        h::HOST_PAGE_SIZE => {
            req.simple(24)?;
            if !is_host(req) {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            Ok(Out::Simple(
                Buf::new().u64(kernel_page_size(ctx.proc.abi)).done(),
            ))
        }
        h::HOST_GET_CLOCK_SERVICE => {
            req.simple(36)?;
            if !is_host(req) {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            // SYSTEM_CLOCK (0) and CALENDAR_CLOCK (1).
            let id = req.i32(32);
            if !(0..=1).contains(&id) {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            let port = clock_port(ctx, id as u32);
            Ok(Out::Complex(vec![super::make_send(&port)], Vec::new()))
        }
        h::HOST_STATISTICS | h::HOST_STATISTICS64 => {
            req.simple(40)?;
            if !is_host(req) {
                return Err(kr::KERN_INVALID_HOST);
            }
            let max = if req.id == h::HOST_STATISTICS {
                68
            } else {
                256
            };
            let count = req.u32(36).min(max);
            let words = host_statistics(req.id == h::HOST_STATISTICS64, req.i32(32), count)?;
            Ok(info_reply(&words))
        }
        // host_priv's exception ports: the guest holds only the host name
        // port, which does not convert (convert_port_to_host_priv).
        ids::host_priv::HOST_SET_EXCEPTION_PORTS | ids::host_priv::HOST_SWAP_EXCEPTION_PORTS => {
            req.complex_of(1, 60)?;
            let handler = super::exception::take_handler(req)?;
            super::exception::release(ctx.proc, &handler);
            Err(kr::KERN_INVALID_ARGUMENT)
        }
        ids::host_priv::HOST_GET_EXCEPTION_PORTS => {
            req.simple(36)?;
            Err(kr::KERN_INVALID_ARGUMENT)
        }
        // host_get_special_port and host_set_special_port refuse the host
        // name port the same way (host_priv NULL).
        ids::host_priv::HOST_GET_SPECIAL_PORT => {
            req.simple(40)?;
            Err(kr::KERN_INVALID_ARGUMENT)
        }
        ids::host_priv::HOST_SET_SPECIAL_PORT => {
            req.complex_of(1, 52)?;
            let right = req.take_port(28, &[crate::user::darwin::mach::ipc::disp::MOVE_SEND])?;
            crate::user::darwin::syscall::mach::kmsg::release(ctx.proc, right);
            Err(kr::KERN_INVALID_ARGUMENT)
        }
        h::KERNELRPC_HOST_CREATE_MACH_VOUCHER => {
            // recipes[recipesCnt] (at most 5120 bytes, padded to 4).
            let max = voucher::MAX_RECIPE_ARRAY;
            if req.complex() || req.size() < 36 || req.size() > 36 + max {
                return Err(kr::MIG_BAD_ARGUMENTS);
            }
            let n = req.u32(32) as usize;
            if n > max || req.size() != 36 + n.next_multiple_of(4) {
                return Err(kr::MIG_BAD_ARGUMENTS);
            }
            if !is_host(req) {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            let recipes = req.bytes(36, n).to_vec();
            let port =
                match crate::user::darwin::syscall::mach::voucher::create(ctx.proc, &recipes)? {
                    None => return Ok(Out::Complex(vec![super::null_port()], Vec::new())),
                    Some(a) => ctx.proc.vouchers.canonical(a),
                };
            Ok(Out::Complex(vec![super::make_send(&port)], Vec::new()))
        }
        h::HOST_REQUEST_NOTIFICATION => {
            // host_request_notification(host, notify_type, notify_port):
            // calendar-change notifications, which the emulated clock never
            // sends; the send-once right is kept until the task exits.
            req.complex_of(1, 52)?;
            if !is_host(req) {
                return Err(kr::KERN_INVALID_HOST);
            }
            let notify_type = req.i32(48);
            if !(0..=1).contains(&notify_type) {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            let right =
                req.take_port(28, &[crate::user::darwin::mach::ipc::disp::MOVE_SEND_ONCE])?;
            if let Some(r) = right {
                ctx.proc.task.host_notify.push(r);
            }
            Ok(Out::Simple(Vec::new()))
        }
        _ => {
            warn(ctx, req.id);
            Err(kr::MIG_BAD_ID)
        }
    }
}

fn warn(ctx: &Ctx<'_>, id: i32) {
    if ctx.proc.config.warn_unhandled() {
        eprintln!(
            "rax-user: unimplemented MIG routine {id} ({})",
            ids::name(id).unwrap_or("?")
        );
    }
}

/// The clock port for clock `id` (one per process, made on first use).
pub fn clock_port(ctx: &mut Ctx<'_>, id: u32) -> std::sync::Arc<Port> {
    let slot = &mut ctx.proc.task.clock_ports[id as usize];
    slot.get_or_insert_with(|| Port::new(KObject::Clock(id)))
        .clone()
}

/// The host's `kern.version` string (the userland the process runs is the
/// host's; on a host without one, a Darwin identity built from the
/// vendored kernel).
fn kernel_version(_host_services: bool) -> Vec<u8> {
    #[cfg(target_os = "macos")]
    if _host_services {
        let mut buf = vec![0u8; 512];
        let mut len = buf.len();
        let mut mib = [libc::CTL_KERN, libc::KERN_VERSION];
        // SAFETY: `mib` and `buf` are live buffers of the sizes passed.
        let r = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                2,
                buf.as_mut_ptr().cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if r == 0 {
            buf.truncate(len.saturating_sub(1));
            if let Some(n) = buf.iter().position(|&b| b == 0) {
                buf.truncate(n);
            }
            return buf;
        }
    }
    b"Darwin Kernel Version 25.0.0: root:xnu-12377.121.6/RELEASE".to_vec()
}

/// `host_info(flavor)` with the caller's `count` (`osfmk/kern/host.c`).
pub fn host_info(abi: DarwinAbi, f: i32, count: u32) -> Result<Vec<u32>, KernReturn> {
    let (cpu_type, cpu_subtype) = slot_type(abi);
    let ncpu = u32::from(NCPUS);
    match f {
        flavor::BASIC_INFO => {
            // host_basic_info: HOST_BASIC_INFO_OLD_COUNT 5, _COUNT 12.
            if count < 5 {
                return Err(kr::KERN_FAILURE);
            }
            let mut w = vec![
                ncpu,
                ncpu,
                memory_size(abi),
                cpu_type as u32,
                cpu_subtype as u32,
            ];
            if count >= 12 {
                w.extend_from_slice(&[0, ncpu, ncpu, ncpu, ncpu]);
                w.extend_from_slice(&[MEMSIZE as u32, (MEMSIZE >> 32) as u32]);
            }
            Ok(w)
        }
        flavor::SCHED_INFO => {
            if count < 2 {
                return Err(kr::KERN_FAILURE);
            }
            // The initial quantum: 10 ms.
            Ok(vec![10, 10])
        }
        flavor::RESOURCE_SIZES => {
            if count < 5 {
                return Err(kr::KERN_FAILURE);
            }
            Err(kr::KERN_INVALID_ARGUMENT)
        }
        flavor::PRIORITY_INFO => {
            if count < 8 {
                return Err(kr::KERN_FAILURE);
            }
            // MINPRI_KERNEL, MINPRI_KERNEL, MINPRI_RESERVED,
            // BASEPRI_DEFAULT, DEPRESSPRI, IDLEPRI, MINPRI_USER,
            // MAXPRI_RESERVED.
            Ok(vec![80, 80, 64, 31, 0, 0, 0, 79])
        }
        flavor::SEMAPHORE_TRAPS | flavor::MACH_MSG_TRAP => Ok(Vec::new()),
        flavor::CAN_HAS_DEBUGGER => {
            if count < 1 {
                return Err(kr::KERN_FAILURE);
            }
            Ok(vec![0])
        }
        flavor::VM_PURGABLE => {
            // vm_purgeable_info: 8 fifo queues, 1 obsolete, 1 lifo queue
            // of (count, size) pairs, all empty.
            if count < 68 {
                return Err(kr::KERN_FAILURE);
            }
            Ok(vec![0; 68])
        }
        flavor::DEBUG_INFO_INTERNAL => Err(kr::KERN_NOT_SUPPORTED),
        flavor::PREFERRED_USER_ARCH => {
            if count < 2 {
                return Err(kr::KERN_FAILURE);
            }
            Ok(vec![cpu_type as u32, cpu_subtype as u32])
        }
        _ => Err(kr::KERN_INVALID_ARGUMENT),
    }
}

/// `host_statistics(64)(flavor)` for an idle machine: no load, no paging.
fn host_statistics(is64: bool, f: i32, count: u32) -> Result<Vec<u32>, KernReturn> {
    let page = |n: u64| n as u32;
    match f {
        stat::LOAD_INFO => {
            // avenrun[3], mach_factor[3] (fixed point, LOAD_SCALE 1000).
            if count < 6 {
                return Err(kr::KERN_FAILURE);
            }
            Ok(vec![0, 0, 0, 1000, 1000, 1000])
        }
        stat::VM_INFO => {
            // vm_statistics (REV0 12 .. REV2 15 words).
            if count < 12 {
                return Err(kr::KERN_FAILURE);
            }
            let free = page(MEMSIZE / 16384);
            let mut w = vec![free, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            w.truncate(count.min(15) as usize);
            Ok(w)
        }
        stat::CPU_LOAD_INFO => {
            // cpu_ticks[CPU_STATE_MAX]: user, system, idle, nice.
            if count < 4 {
                return Err(kr::KERN_FAILURE);
            }
            Ok(vec![0, 0, 0, 0])
        }
        stat::VM_INFO64 if is64 => {
            // vm_statistics64: REV0 .. REV3 (HOST_VM_INFO64_COUNT 40).
            if count < 38 {
                return Err(kr::KERN_FAILURE);
            }
            let mut w = vec![0u32; 40];
            w[0] = page(MEMSIZE / 16384);
            w.truncate(count.min(40) as usize);
            Ok(w)
        }
        stat::EXTMOD_INFO64 if is64 => {
            if count < 12 {
                return Err(kr::KERN_FAILURE);
            }
            Ok(vec![0; 12])
        }
        stat::EXPIRED_TASK_INFO => {
            // task_power_info: 26 words (TASK_POWER_INFO_COUNT with v2).
            if count < 10 {
                return Err(kr::KERN_FAILURE);
            }
            let mut w = vec![0u32; 26];
            w.truncate(count.min(26) as usize);
            Ok(w)
        }
        _ => Err(kr::KERN_INVALID_ARGUMENT),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_info_counts_follow_xnu() {
        // A count below HOST_BASIC_INFO_OLD_COUNT fails; 5..11 gets the old
        // structure; 12 or more the full one.
        assert_eq!(
            host_info(DarwinAbi::Arm64, flavor::BASIC_INFO, 4),
            Err(kr::KERN_FAILURE)
        );
        assert_eq!(
            host_info(DarwinAbi::Arm64, flavor::BASIC_INFO, 5)
                .unwrap()
                .len(),
            5
        );
        let w = host_info(DarwinAbi::Arm64, flavor::BASIC_INFO, 68).unwrap();
        assert_eq!(w.len(), 12);
        assert_eq!((w[3], w[4]), (0x0100_000c, 2));
        assert_eq!(u64::from(w[10]) | (u64::from(w[11]) << 32), MEMSIZE);
        let x = host_info(DarwinAbi::X86_64, flavor::BASIC_INFO, 12).unwrap();
        assert_eq!((x[2], x[3], x[4]), (1 << 31, 7, 8));
        assert_eq!(
            host_info(DarwinAbi::X86_64, flavor::MACH_MSG_TRAP, 0),
            Ok(vec![])
        );
        assert_eq!(
            host_info(DarwinAbi::X86_64, 0, 68),
            Err(kr::KERN_INVALID_ARGUMENT)
        );
    }
}
