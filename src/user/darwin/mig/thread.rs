//! The thread subsystem (`thread_act.defs`, `osfmk/kern/thread.c`,
//! `thread_act.c`, `thread_policy.c`) for threads of the calling task.

use super::exception;
use super::{Buf, MigResult, Out, Req, copy_send, ids, info_reply, make_send, null_port};
use crate::user::darwin::mach::exception::EXC_MASK_VALID;
use crate::user::darwin::mach::ipc::{KObject, Right, disp};
use crate::user::darwin::mach::kr::{self, KernReturn};
use crate::user::darwin::mach::task::{EXC_TYPES_COUNT, ExcAction};
use crate::user::darwin::process::Thread;
use crate::user::darwin::thread_status;

/// `THREAD_STATE_MAX`: the most words of state a message carries.
const THREAD_STATE_MAX: u32 = 1296;
use crate::user::darwin::syscall::Ctx;
use crate::user::darwin::syscall::mach::kmsg;

/// `thread_info` flavors (`osfmk/mach/thread_info.h`).
mod flavor {
    pub const BASIC_INFO: i32 = 3;
    pub const IDENTIFIER_INFO: i32 = 4;
    pub const EXTENDED_INFO: i32 = 5;
    pub const DEBUG_INFO_INTERNAL: i32 = 6;
    pub const SCHED_TIMESHARE_INFO: i32 = 10;
    pub const SCHED_RR_INFO: i32 = 11;
    pub const SCHED_FIFO_INFO: i32 = 12;
}

/// `TH_STATE_*`.
const TH_STATE_RUNNING: u32 = 1;
const TH_STATE_STOPPED: u32 = 2;
const TH_STATE_WAITING: u32 = 3;
/// `POLICY_TIMESHARE`.
const POLICY_TIMESHARE: u32 = 1;
/// `BASEPRI_DEFAULT` and `MAXPRI_USER`.
pub(crate) const BASEPRI_DEFAULT: u32 = 31;
pub(crate) const MAXPRI_USER: u32 = 63;
/// `KERN_INVALID_POLICY`.
const KERN_INVALID_POLICY: KernReturn = 16;

/// Runs `f` on the thread `req`'s port names (`convert_port_to_thread`).
fn with_thread<R>(
    ctx: &mut Ctx<'_>,
    req: &Req,
    f: impl FnOnce(&mut Thread, bool) -> R,
) -> Result<R, KernReturn> {
    let KObject::Thread(tid) = req.port.kobject else {
        return Err(kr::KERN_INVALID_ARGUMENT);
    };
    if tid == ctx.thread.tid {
        return Ok(f(ctx.thread, true));
    }
    match ctx.proc.threads.get_mut(&tid) {
        Some(t) if !t.exited => Ok(f(t, false)),
        // A terminated thread's port no longer converts.
        _ => Err(kr::KERN_TERMINATED),
    }
}

fn time_value(ns: u64) -> [u32; 2] {
    [
        (ns / 1_000_000_000) as u32,
        ((ns % 1_000_000_000) / 1000) as u32,
    ]
}

/// `retrieve_thread_basic_info`.
pub(crate) fn basic_info(t: &Thread, running: bool) -> [u32; 10] {
    let run_state = if running || t.runnable() {
        TH_STATE_RUNNING
    } else if t.mach.suspend_count > 0 {
        TH_STATE_STOPPED
    } else {
        TH_STATE_WAITING
    };
    let u = time_value(t.mach.user_ns);
    let s = time_value(t.mach.system_ns);
    [
        u[0],
        u[1],
        s[0],
        s[1],
        0,
        POLICY_TIMESHARE,
        run_state,
        0,
        t.mach.suspend_count,
        0,
    ]
}

/// Serves the thread subsystem.
pub fn serve(ctx: &mut Ctx<'_>, req: &mut Req) -> MigResult {
    use ids::thread_act as t;
    match req.id {
        t::THREAD_INFO => {
            req.simple(40)?;
            let fl = req.i32(32);
            let count = req.u32(36).min(32);
            let dispatch_offset = ctx.proc.pthread_dispatch_offset();
            let words = with_thread(ctx, req, |th, running| -> Result<Vec<u32>, KernReturn> {
                let need = |n: u32| {
                    if count < n {
                        Err(kr::KERN_INVALID_ARGUMENT)
                    } else {
                        Ok(())
                    }
                };
                let mut w: Vec<u32> = match fl {
                    flavor::BASIC_INFO => {
                        need(10)?;
                        basic_info(th, running).to_vec()
                    }
                    flavor::IDENTIFIER_INFO => {
                        need(6)?;
                        let handle = th.cpu.tsd_base();
                        let qaddr = if handle != 0 {
                            handle + dispatch_offset
                        } else {
                            0
                        };
                        let mut v = Vec::with_capacity(6);
                        for x in [th.tid, handle, qaddr] {
                            v.extend_from_slice(&[x as u32, (x >> 32) as u32]);
                        }
                        v
                    }
                    flavor::EXTENDED_INFO => {
                        // pth_user_time, pth_system_time (ns), cpu_usage,
                        // policy, run_state, flags, sleep_time, curpri,
                        // priority, maxpriority, pth_name[64].
                        need(28)?;
                        let b = basic_info(th, running);
                        let mut v = Vec::with_capacity(28);
                        for x in [th.mach.user_ns, th.mach.system_ns] {
                            v.extend_from_slice(&[x as u32, (x >> 32) as u32]);
                        }
                        v.extend_from_slice(&[
                            b[4],
                            b[5],
                            b[6],
                            b[7],
                            b[9],
                            BASEPRI_DEFAULT,
                            BASEPRI_DEFAULT,
                            MAXPRI_USER,
                        ]);
                        let mut name = [0u8; 64];
                        let n = th.name.len().min(63);
                        name[..n].copy_from_slice(&th.name[..n]);
                        for c in name.chunks(4) {
                            v.push(u32::from_le_bytes(c.try_into().expect("4 bytes")));
                        }
                        v
                    }
                    flavor::SCHED_TIMESHARE_INFO => {
                        // policy_timeshare_info: max_priority, base_priority,
                        // cur_priority, depressed, depress_priority.
                        need(5)?;
                        vec![MAXPRI_USER, BASEPRI_DEFAULT, BASEPRI_DEFAULT, 0, u32::MAX]
                    }
                    flavor::SCHED_RR_INFO => {
                        need(5)?;
                        return Err(KERN_INVALID_POLICY);
                    }
                    flavor::SCHED_FIFO_INFO => {
                        need(4)?;
                        return Err(KERN_INVALID_POLICY);
                    }
                    flavor::DEBUG_INFO_INTERNAL => return Err(kr::KERN_NOT_SUPPORTED),
                    _ => return Err(kr::KERN_INVALID_ARGUMENT),
                };
                // THREAD_IDENTIFIER_INFO leaves the count as the caller
                // passed it (the rest of the array is zero); the other
                // flavors report their own size.
                if fl == flavor::IDENTIFIER_INFO {
                    w.resize(count as usize, 0);
                }
                Ok(w)
            })??;
            Ok(info_reply(&words))
        }
        t::THREAD_GET_SPECIAL_PORT => {
            req.simple(36)?;
            let which = req.i32(32);
            let port = req.port.clone();
            with_thread(ctx, req, |_, _| ())?;
            // THREAD_KERNEL_PORT (1): the control port; THREAD_INSPECT_PORT
            // (2) and THREAD_READ_PORT (3): flavored ports.
            match which {
                1 => Ok(Out::Complex(vec![copy_send(&port)], Vec::new())),
                2 | 3 => {
                    let p = crate::user::darwin::mach::ipc::Port::new(port.kobject.clone());
                    Ok(Out::Complex(vec![make_send(&p)], Vec::new()))
                }
                _ => Err(kr::KERN_INVALID_ARGUMENT),
            }
        }
        t::THREAD_SET_SPECIAL_PORT => {
            req.complex_of(1, 52)?;
            let right = req.take_port(28, &[disp::MOVE_SEND, disp::MOVE_SEND_ONCE])?;
            kmsg::release(ctx.proc, right);
            with_thread(ctx, req, |_, _| ())?;
            // Only THREAD_KERNEL_PORT exists, and it is not settable.
            Err(if req.i32(48) == 1 {
                kr::KERN_NO_ACCESS
            } else {
                kr::KERN_INVALID_ARGUMENT
            })
        }
        t::THREAD_SET_EXCEPTION_PORTS | t::THREAD_SWAP_EXCEPTION_PORTS => {
            req.complex_of(1, 60)?;
            let handler = exception::take_handler(req)?;
            let (mask, behavior, flv) = (req.u32(48), req.i32(52), req.i32(56));
            let abi = ctx.proc.abi;
            let result = with_thread(ctx, req, |th, _| {
                exception::validate(abi, mask, &handler, behavior, flv)?;
                // The thread's actions exist from its first set or swap.
                if th.mach.exc.is_empty() {
                    th.mach.exc = vec![ExcAction::default(); EXC_TYPES_COUNT];
                }
                let old_view = exception::view(&th.mach.exc, mask);
                let old = exception::install(&mut th.mach.exc, mask, &handler, behavior, flv);
                Ok((old_view, old))
            })
            .and_then(|r| r);
            exception::release(ctx.proc, &handler);
            let (old_view, old) = result?;
            for p in old {
                kmsg::release_send(ctx.proc, &p);
            }
            if req.id == t::THREAD_SWAP_EXCEPTION_PORTS {
                Ok(exception::ports_reply(&old_view))
            } else {
                Ok(Out::Simple(Vec::new()))
            }
        }
        t::THREAD_GET_EXCEPTION_PORTS | t::THREAD_GET_EXCEPTION_PORTS_INFO => {
            req.simple(36)?;
            let mask = req.u32(32);
            let o = with_thread(ctx, req, |th, _| {
                if mask & !EXC_MASK_VALID != 0 {
                    return Err(kr::KERN_INVALID_ARGUMENT);
                }
                Ok(exception::view(&th.mach.exc, mask))
            })??;
            Ok(if req.id == t::THREAD_GET_EXCEPTION_PORTS_INFO {
                exception::info_reply(&o, ctx.proc.pid as u32 | 1)
            } else {
                exception::ports_reply(&o)
            })
        }
        t::KERNELRPC_THREAD_POLICY_SET => {
            let n = req.simple_array(40, 4, 16, 36)?;
            with_thread(ctx, req, |_, _| ())?;
            // THREAD_EXTENDED_POLICY 1, TIME_CONSTRAINT 2, PRECEDENCE 3,
            // AFFINITY 4, BACKGROUND 5, LATENCY_QOS 7, THROUGHPUT_QOS 8,
            // QOS 9, then the private flavors: accepted, with no effect on
            // one-CPU scheduling.
            let fl = req.i32(32);
            let min = match fl {
                1 | 3 | 4 | 5 | 7 | 8 => 1,
                2 => 4,
                9 => 2,
                10..=12 => 0,
                _ => return Err(kr::KERN_INVALID_ARGUMENT),
            };
            if n < min {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            Ok(Out::Simple(Vec::new()))
        }
        t::THREAD_POLICY_GET => {
            req.simple(44)?;
            with_thread(ctx, req, |_, _| ())?;
            let fl = req.i32(32);
            let count = req.u32(36).min(16);
            let default = req.u32(40) != 0;
            // Defaults: timeshare, no time constraint, importance 0, no
            // affinity tag, not background, unspecified QoS tiers.
            let words: Vec<u32> = match fl {
                1 => vec![1],
                2 => vec![0, 0, 0, 0],
                3 => vec![0],
                4 => vec![0],
                5 => vec![0],
                7 | 8 => vec![0],
                9 => vec![0, 0],
                _ => return Err(kr::KERN_INVALID_ARGUMENT),
            };
            if (count as usize) < words.len() {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            let mut b = Buf::new().u32(words.len() as u32);
            for w in &words {
                b = b.u32(*w);
            }
            // A default query of THREAD_TIME_CONSTRAINT_POLICY reports it.
            let _ = default;
            Ok(Out::Simple(b.u32(u32::from(default || fl == 2)).done()))
        }
        t::THREAD_SUSPEND => {
            req.simple(24)?;
            with_thread(ctx, req, |th, _| {
                th.mach.suspend_count += 1;
            })?;
            Ok(Out::Simple(Vec::new()))
        }
        t::THREAD_RESUME => {
            req.simple(24)?;
            with_thread(ctx, req, |th, _| {
                if th.mach.suspend_count == 0 {
                    Err(kr::KERN_FAILURE)
                } else {
                    th.mach.suspend_count -= 1;
                    Ok(())
                }
            })??;
            Ok(Out::Simple(Vec::new()))
        }
        t::THREAD_ABORT | t::THREAD_ABORT_SAFELY => {
            req.simple(24)?;
            // Interrupts the thread's wait: its call restarts and sees an
            // interruption.
            with_thread(ctx, req, |th, running| {
                if !running && th.wait.as_ref().is_some_and(|w| w.interruptible) {
                    th.woken = true;
                }
            })?;
            Ok(Out::Simple(Vec::new()))
        }
        t::THREAD_TERMINATE => {
            req.simple(24)?;
            with_thread(ctx, req, |th, _| {
                th.exited = true;
            })?;
            Ok(Out::Simple(Vec::new()))
        }
        t::THREAD_GET_STATE => {
            // flavor, old_stateCnt (bounded by THREAD_STATE_MAX).
            req.simple(40)?;
            let (flavor, count) = (req.i32(32), req.u32(36).min(THREAD_STATE_MAX));
            let ptrauth = crate::user::darwin::signal::frame::uses_ptrauth(ctx.proc);
            let state = with_thread(ctx, req, |th, _| {
                let view = thread_status::View {
                    cpu: &th.cpu,
                    entry: &th.sig.entry,
                    debug: &th.mach.debug_state,
                    ptrauth,
                };
                thread_status::get(&view, flavor, count)
            })??;
            let mut b = Buf::new().u32(state.len() as u32);
            for w in state {
                b = b.u32(w);
            }
            Ok(Out::Simple(b.done()))
        }
        t::THREAD_SET_STATE => {
            // flavor, new_state[new_stateCnt].
            let n = req.simple_array(40, 4, THREAD_STATE_MAX as usize, 36)?;
            let flavor = req.i32(32);
            let state: Vec<u32> = (0..n).map(|i| req.u32(40 + 4 * i)).collect();
            with_thread(ctx, req, |th, _| {
                thread_status::set(&mut th.cpu, &mut th.mach.debug_state, flavor, &state)
            })??;
            Ok(Out::Simple(Vec::new()))
        }
        t::THREAD_GET_MACH_VOUCHER => {
            // `which` does not matter.
            req.simple(36)?;
            let v = with_thread(ctx, req, |th, _| th.mach.voucher.clone())?;
            Ok(Out::Complex(
                vec![v.as_ref().map_or_else(null_port, make_send)],
                Vec::new(),
            ))
        }
        t::THREAD_SET_MACH_VOUCHER => {
            // Anything but a voucher clears the thread's voucher; a thread
            // other than the caller has started, so only the caller's own
            // voucher can be set.
            req.complex_of(1, 40)?;
            let right = req.take_port(28, &[disp::MOVE_SEND])?;
            let v = right
                .as_ref()
                .and_then(|r| r.port())
                .filter(|p| matches!(p.kobject, KObject::Voucher(_)))
                .cloned();
            kmsg::release(ctx.proc, right);
            with_thread(ctx, req, |th, running| {
                if running {
                    th.mach.voucher = v;
                    Ok(())
                } else {
                    Err(kr::KERN_INVALID_ARGUMENT)
                }
            })??;
            Ok(Out::Simple(Vec::new()))
        }
        t::THREAD_SWAP_MACH_VOUCHER => {
            req.complex_of(2, 52)?;
            let new = req.take_port(28, &[disp::MOVE_SEND])?;
            let old = req.take_port(40, &[disp::MOVE_SEND])?;
            kmsg::release(ctx.proc, new.into_iter().chain(old));
            Err(kr::KERN_NOT_SUPPORTED)
        }
        _ => {
            if ctx.proc.config.warn_unhandled() {
                eprintln!(
                    "rax-user: unimplemented MIG routine {} ({})",
                    req.id,
                    ids::name(req.id).unwrap_or("?")
                );
            }
            Err(kr::MIG_BAD_ID)
        }
    }
}
