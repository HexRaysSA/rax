//! `mach_msg2_trap` and the legacy `mach_msg_trap` /
//! `mach_msg_overwrite_trap` (`osfmk/ipc/mach_msg.c`).
//!
//! A combined send/receive that must wait for its reply parks the thread
//! after the send; the restarted trap skips the send (its [`Resume`]
//! records the stage) and only receives. A send to a full queue waits
//! before anything is copied in.

use std::time::{Duration, Instant};

use super::RESTART;
use super::kmsg::{self, UserHeader};
use crate::user::darwin::mach::ipc::{KObject, MACH_PORT_NULL, Object, PortName, disp};
use crate::user::darwin::mach::kr::{self, KernReturn};
use crate::user::darwin::mach::msg::{self, HEADER_SIZE, Message, Sender, bits, opt};
use crate::user::darwin::signal;
use crate::user::darwin::syscall::Ctx;
use crate::user::darwin::wait::{Resume, Wait, WaitKey};

/// `IPC_KMSG_MAX_BODY_SPACE`: 48 MiB less the largest trailer.
const MAX_BODY_SPACE: u32 = (64 * 1024 * 1024 * 3) / 4 - 68;
/// `IPC_KMSG_MAX_AUX_DATA_SPACE`.
const MAX_AUX_DATA_SPACE: u32 = 1024;
/// `IPC_KOBJECT_DESC_MAX`.
const KOBJECT_DESC_MAX: u32 = 3;
/// `sizeof(mach_msg_vector_t)`.
const VECTOR_SIZE: usize = 24;
/// `sizeof(mach_msg_aux_header_t)`.
const AUX_HEADER_SIZE: u32 = 8;

/// What to send.
struct Send {
    addr: u64,
    size: u32,
    header: UserHeader,
    dsc_count: u32,
    aux_addr: u64,
    aux_size: u32,
}

/// Where to receive.
struct Recv {
    addr: u64,
    size: u32,
    aux_addr: u64,
    aux_size: u32,
    name: PortName,
    /// `MACH64_RCV_LINEAR_VECTOR` (kevent receives): the auxiliary data
    /// follows the trailer in the one buffer, and a message whose data
    /// does not fit there is too large.
    linear: bool,
    /// `MACH64_RCV_STACK`: a linear receive ends at the buffer's end.
    stack: bool,
}

fn lo(v: u64) -> u32 {
    v as u32
}

fn hi(v: u64) -> u32 {
    (v >> 32) as u32
}

/// The sender identity of the calling task (`ipc_kmsg_init_trailer`).
fn sender(ctx: &Ctx<'_>) -> Sender {
    let (_, euid, _, egid) = ctx.proc.creds;
    Sender {
        sec: [euid, egid],
        audit: ctx.proc.audit,
    }
}

/// `mach_msg2_trap(data, options, msgh_bits_and_send_size,
/// msgh_remote_and_local_port, msgh_voucher_and_id,
/// desc_count_and_rcv_name, rcv_size_and_priority, timeout)`.
pub fn msg2(ctx: &mut Ctx<'_>, a: &[u64; 9]) -> KernReturn {
    let options = a[1];
    // ipc_preflight_msg_option64
    if options & opt::SEND_MSG != 0 {
        let cfi = options & opt::CFI_MASK;
        if cfi == 0 || cfi & (cfi - 1) != 0 {
            return kr::MACH_SEND_INVALID_OPTIONS;
        }
        if options & (opt::SEND_MQ_CALL | opt::SEND_ANY) == 0 && options & opt::MSG_VECTOR != 0 {
            return kr::MACH_SEND_INVALID_OPTIONS;
        }
    }
    let (mb_ss, mr_lp, mv_id, dc_rn, rs_pr) = (a[2], a[3], a[4], a[5], a[6]);
    let timeout = a[7] as u32;
    let header = UserHeader {
        bits: lo(mb_ss),
        remote: lo(mr_lp),
        local: hi(mr_lp),
        voucher: lo(mv_id),
        id: hi(mv_id) as i32,
    };
    let (send, recv) = if options & opt::MSG_VECTOR != 0 {
        let snd = hi(mb_ss);
        let rcv = lo(rs_pr);
        let count = snd.max(rcv) as usize;
        let sending = options & opt::SEND_MSG != 0;
        if count == 0 || count > 2 {
            return if sending {
                if count == 0 {
                    kr::MACH_SEND_MSG_TOO_SMALL
                } else {
                    kr::MACH_SEND_INVALID_DATA
                }
            } else {
                kr::MACH_RCV_INVALID_ARGUMENTS
            };
        }
        let Ok(raw) = ctx.read(a[0], count * VECTOR_SIZE) else {
            return if sending {
                kr::MACH_SEND_INVALID_DATA
            } else {
                kr::MACH_RCV_INVALID_ARGUMENTS
            };
        };
        let vec = |i: usize| -> (u64, u64, u32, u32) {
            if i >= count {
                return (0, 0, 0, 0);
            }
            let v = &raw[i * VECTOR_SIZE..(i + 1) * VECTOR_SIZE];
            (
                u64::from_le_bytes(v[0..8].try_into().expect("8 bytes")),
                u64::from_le_bytes(v[8..16].try_into().expect("8 bytes")),
                u32::from_le_bytes(v[16..20].try_into().expect("4 bytes")),
                u32::from_le_bytes(v[20..24].try_into().expect("4 bytes")),
            )
        };
        let (m_data, m_rcv, m_send_size, m_rcv_size) = vec(0);
        let (x_data, x_rcv, x_send_size, x_rcv_size) = vec(1);
        let send = if sending {
            // mach_msg_validate_data_vectors(sending)
            if snd == 0 {
                return kr::MACH_SEND_MSG_TOO_SMALL;
            }
            if m_data == 0 {
                return kr::MACH_SEND_INVALID_DATA;
            }
            let aux_size = if snd == 2 { x_send_size } else { 0 };
            if aux_size != 0 && x_data == 0 {
                return kr::MACH_SEND_INVALID_DATA;
            }
            if aux_size != 0 && aux_size < AUX_HEADER_SIZE {
                return kr::MACH_SEND_AUX_TOO_SMALL;
            }
            if aux_size > MAX_AUX_DATA_SPACE {
                return kr::MACH_SEND_AUX_TOO_LARGE;
            }
            Some(Send {
                addr: m_data,
                size: m_send_size,
                header,
                dsc_count: lo(dc_rn),
                aux_addr: if aux_size != 0 { x_data } else { 0 },
                aux_size,
            })
        } else {
            None
        };
        // The receive vectors are validated after the send
        // (mach_msg_validate_data_vectors(receiving)).
        let recv = (options & opt::RCV_MSG != 0).then(|| {
            if rcv == 0 {
                return Err(kr::MACH_RCV_INVALID_ARGUMENTS);
            }
            let (aux_addr, aux_size) = if rcv == 2 {
                let addr = if x_rcv != 0 { x_rcv } else { x_data };
                if addr == 0 || x_rcv_size < AUX_HEADER_SIZE {
                    return Err(kr::MACH_RCV_INVALID_ARGUMENTS);
                }
                (addr, x_rcv_size)
            } else {
                (0, 0)
            };
            Ok(Recv {
                addr: if m_rcv != 0 { m_rcv } else { m_data },
                size: m_rcv_size,
                aux_addr,
                aux_size,
                name: hi(dc_rn),
                linear: false,
                stack: false,
            })
        });
        (send, recv)
    } else {
        let send = (options & opt::SEND_MSG != 0).then(|| Send {
            addr: a[0],
            size: hi(mb_ss),
            header,
            dsc_count: lo(dc_rn),
            aux_addr: 0,
            aux_size: 0,
        });
        let recv = (options & opt::RCV_MSG != 0).then(|| {
            Ok(Recv {
                addr: a[0],
                size: lo(rs_pr),
                aux_addr: 0,
                aux_size: 0,
                name: hi(dc_rn),
                linear: false,
                stack: false,
            })
        });
        (send, recv)
    };
    run(ctx, options, send, recv, timeout, true)
}

/// `mach_msg_overwrite_trap(msg, option, send_size, rcv_size, rcv_name,
/// timeout, priority, rcv_msg)` (and `mach_msg_trap` with `rcv_msg` 0).
pub fn overwrite(ctx: &mut Ctx<'_>, a: &[u64; 9], has_rcv_msg: bool) -> KernReturn {
    let options = u64::from(a[1] as u32);
    let (addr, send_size, rcv_size, rcv_name, timeout) = (
        a[0],
        a[2] as u32,
        a[3] as u32,
        a[4] as PortName,
        a[5] as u32,
    );
    let rcv_msg = if has_rcv_msg { a[7] } else { 0 };
    let mut send = None;
    if options & opt::SEND_MSG != 0 {
        // mach_msg_copyin_user_header
        if send_size < HEADER_SIZE as u32 || send_size & 3 != 0 {
            return kr::MACH_SEND_MSG_TOO_SMALL;
        }
        if send_size > MAX_BODY_SPACE {
            return kr::MACH_SEND_TOO_LARGE;
        }
        let n = if send_size >= 28 { 28 } else { HEADER_SIZE };
        let Ok(h) = ctx.read(addr, n) else {
            return kr::MACH_SEND_INVALID_DATA;
        };
        let w = |o: usize| u32::from_le_bytes(h[o..o + 4].try_into().expect("4 bytes"));
        let header = UserHeader {
            bits: w(0),
            remote: w(8),
            local: w(12),
            voucher: w(16),
            id: w(20) as i32,
        };
        let dsc_count = if header.bits & bits::COMPLEX != 0 {
            if send_size < 28 {
                return kr::MACH_SEND_MSG_TOO_SMALL;
            }
            w(24)
        } else {
            0
        };
        // ipc_policy_allow_legacy_send_trap: only a hardcoded set of
        // kernel calls from binaries built with an SDK before macOS 13.
        if !legacy_send_allowed(ctx, header.id) {
            return kr::KERN_NOT_SUPPORTED;
        }
        send = Some(Send {
            addr,
            size: send_size,
            header,
            dsc_count,
            aux_addr: 0,
            aux_size: 0,
        });
    }
    let recv = (options & opt::RCV_MSG != 0).then_some(Ok(Recv {
        addr: if rcv_msg != 0 { rcv_msg } else { addr },
        size: rcv_size,
        aux_addr: 0,
        aux_size: 0,
        name: rcv_name,
        linear: false,
        stack: false,
    }));
    run(ctx, options, send, recv, timeout, false)
}

/// `ipc_policy_allow_legacy_mach_msg_trap_for_platform`.
fn legacy_send_allowed(ctx: &Ctx<'_>, id: i32) -> bool {
    const PLATFORM_MACOS: u32 = 1;
    let Some(b) = ctx.proc.program.main.build else {
        return false;
    };
    if b.platform != PLATFORM_MACOS || b.sdk == 0 || b.sdk >> 16 > 12 {
        return false;
    }
    matches!(id, 0xd4a | 0xd4d | 0xe13 | 0x12c4 | 0x12c8)
}

/// Runs the send and receive halves, parking the thread when either must
/// wait.
fn run(
    ctx: &mut Ctx<'_>,
    options: u64,
    send: Option<Send>,
    recv: Option<Result<Recv, KernReturn>>,
    timeout: u32,
    msg2: bool,
) -> KernReturn {
    let resume = ctx
        .thread
        .resume
        .filter(|r| r.pc == ctx.pc && r.call == ctx.nr);
    let step = resume.map_or(0, |r| r.step);
    if let Some(s) = send.as_ref().filter(|_| step == 0) {
        match do_send(
            ctx,
            options,
            s,
            timeout,
            resume.and_then(|r| r.deadline),
            msg2,
        ) {
            Sent::Done => {}
            Sent::Failed(mr) => return mr,
            Sent::Wait(w) => return park(ctx, w, 0),
        }
    }
    let r = match recv {
        None => return kr::MACH_MSG_SUCCESS,
        Some(Err(mr)) => return mr,
        Some(Ok(r)) => r,
    };
    // The receive's deadline starts when it does.
    let deadline = if step == 1 {
        resume.and_then(|r| r.deadline)
    } else {
        None
    };
    match do_receive(ctx, options, &r, timeout, deadline, step == 1) {
        Ok(mr) => mr,
        Err(w) => park(ctx, w, 1),
    }
}

/// Parks the thread on `wait`, recording `step`; a deliverable signal
/// interrupts the receive instead (`MACH_RCV_INTERRUPTED`).
fn park(ctx: &mut Ctx<'_>, mut wait: Wait, step: u32) -> KernReturn {
    if step == 1 && wait.interruptible && signal::cursig(ctx.proc, ctx.thread).is_some() {
        return kr::MACH_RCV_INTERRUPTED;
    }
    wait.seq = crate::user::darwin::wait::next_seq();
    ctx.thread.resume = Some(Resume {
        pc: ctx.pc,
        call: ctx.nr,
        deadline: wait.deadline,
        step,
    });
    ctx.thread.wait = Some(wait);
    RESTART
}

enum Sent {
    Done,
    Failed(KernReturn),
    Wait(Wait),
}

fn timeout_deadline(
    options: u64,
    flag: u64,
    timeout: u32,
    kept: Option<Instant>,
) -> Option<Instant> {
    if options & flag == 0 {
        return None;
    }
    Some(kept.unwrap_or_else(|| Instant::now() + Duration::from_millis(u64::from(timeout))))
}

/// The send half (`mach_msg_trap_send`).
fn do_send(
    ctx: &mut Ctx<'_>,
    options: u64,
    s: &Send,
    timeout: u32,
    kept: Option<Instant>,
    msg2: bool,
) -> Sent {
    if s.size < HEADER_SIZE as u32 || s.size & 3 != 0 {
        return Sent::Failed(kr::MACH_SEND_MSG_TOO_SMALL);
    }
    if s.size > MAX_BODY_SPACE {
        return Sent::Failed(kr::MACH_SEND_TOO_LARGE);
    }
    if s.header.bits & bits::COMPLEX != 0 {
        if s.size < 28 {
            return Sent::Failed(kr::MACH_SEND_MSG_TOO_SMALL);
        }
        if s.dsc_count > (s.size - 28) / 12 {
            return Sent::Failed(kr::MACH_SEND_MSG_TOO_SMALL);
        }
    } else if s.dsc_count != 0 {
        return Sent::Failed(kr::MACH_SEND_TOO_LARGE);
    }
    if options & opt::SEND_KOBJECT_CALL != 0 && s.dsc_count > KOBJECT_DESC_MAX {
        return Sent::Failed(kr::MACH_SEND_TOO_LARGE);
    }
    // The body as the sender laid it out; mach_msg2 takes the header from
    // the trap arguments.
    let mut raw = vec![0u8; s.size as usize];
    if ctx.read_into(s.addr, &mut raw).is_err() {
        return Sent::Failed(kr::MACH_SEND_INVALID_DATA);
    }
    let h = s.header;
    raw[0..4].copy_from_slice(&h.bits.to_le_bytes());
    raw[4..8].copy_from_slice(&s.size.to_le_bytes());
    raw[8..12].copy_from_slice(&h.remote.to_le_bytes());
    raw[12..16].copy_from_slice(&h.local.to_le_bytes());
    raw[16..20].copy_from_slice(&h.voucher.to_le_bytes());
    raw[20..24].copy_from_slice(&h.id.to_le_bytes());
    let aux = if s.aux_size != 0 {
        let mut a = vec![0u8; s.aux_size as usize];
        if ctx.read_into(s.aux_addr, &mut a).is_err() {
            return Sent::Failed(kr::MACH_SEND_INVALID_DATA);
        }
        a[0..4].copy_from_slice(&s.aux_size.to_le_bytes());
        a[4..8].fill(0);
        a
    } else {
        Vec::new()
    };

    // A full queue: wait before copying anything in. When the send times
    // out, the message is copied in and handed back to the sender
    // (mach_msg_receive_pseudo), so moved rights return under their names
    // and copied or made ones add references.
    let dest_port = ctx
        .proc
        .ipc
        .lookup(h.remote)
        .ok()
        .and_then(|e| e.port().cloned());
    // A send that cannot wait: its timeout expired, or a signal
    // interrupts the wait (MACH_SEND_INTERRUPTED).
    let mut failed = None;
    if let Some(port) = &dest_port
        && kmsg::queue_full(port, disp::copyin_type(bits::remote(h.bits)))
    {
        let deadline = timeout_deadline(options, opt::SEND_TIMEOUT, timeout, kept);
        failed = if deadline.is_some_and(|d| d <= Instant::now()) {
            Some(kr::MACH_SEND_TIMED_OUT)
        } else if signal::cursig(ctx.proc, ctx.thread).is_some() {
            Some(kr::MACH_SEND_INTERRUPTED)
        } else {
            return Sent::Wait(Wait::key(WaitKey::PortSpace(port.id), deadline));
        };
    }

    let sender = sender(ctx);
    let mut m = match kmsg::copyin(ctx, &h, &raw, s.dsc_count, options, sender) {
        Ok(m) => m,
        Err(mr) => return Sent::Failed(mr),
    };
    if let Some(why) = failed {
        let (bytes, status) = kmsg::copyout_pseudo(ctx.proc, m, s.addr);
        let n = bytes.len().min(s.size as usize);
        let mr = if ctx.write(s.addr, &bytes[..n]).is_err() {
            kr::MACH_RCV_INVALID_DATA
        } else {
            why | status
        };
        return Sent::Failed(mr);
    }
    m.aux = aux;
    if msg2 {
        // ipc_validate_kmsg_dest_from_user: the call class must match the
        // destination (kernel object or message queue).
        if let Err(mr) = check_call_class(&m, options) {
            kmsg::destroy(ctx.proc, m);
            return Sent::Failed(mr);
        }
    }
    ctx.proc.task.messages.0 += 1;
    if m.dest.port().is_some_and(|p| {
        matches!(p.kobject, KObject::Proxy(_)) || p.state.lock().unwrap().host.is_some()
    }) {
        // A host port's: the host's send decides.
        let wait = (options & opt::SEND_TIMEOUT != 0).then_some(timeout);
        let class = options & opt::CFI_MASK;
        return match crate::user::darwin::bridge::send(ctx.proc, m, wait, class) {
            Ok(()) => Sent::Done,
            Err(mr) => Sent::Failed(mr),
        };
    }
    kmsg::deliver(ctx, m);
    Sent::Done
}

fn check_call_class(m: &Message, options: u64) -> Result<(), KernReturn> {
    if options & opt::SEND_ANY != 0 {
        return Ok(());
    }
    let port = m.dest.port().expect("a message's destination is a port");
    if matches!(port.kobject, KObject::Proxy(_)) {
        // The host checks its own port's class.
        return Ok(());
    }
    if port.is_kernel() {
        if options & opt::SEND_KOBJECT_CALL == 0 {
            return Err(kr::MACH_SEND_INVALID_OPTIONS);
        }
    } else if options & opt::SEND_MQ_CALL == 0 {
        return Err(kr::MACH_SEND_INVALID_OPTIONS);
    }
    Ok(())
}

/// The receive half (`mach_msg_trap_receive`): `Err` when the thread must
/// wait.
fn do_receive(
    ctx: &mut Ctx<'_>,
    options: u64,
    r: &Recv,
    timeout: u32,
    kept: Option<Instant>,
    restarted: bool,
) -> Result<KernReturn, Wait> {
    // ipc_mqueue_copyin: a receive right or a port set.
    let (ports, key) = match ctx.proc.ipc.lookup(r.name) {
        Ok(e) => match &e.object {
            Some(Object::Port(p)) if e.receive => (vec![p.clone()], WaitKey::Port(p.id)),
            Some(Object::Set(s)) => (s.members.lock().unwrap().clone(), WaitKey::Port(s.id)),
            _ => return Ok(kr::MACH_RCV_INVALID_NAME),
        },
        Err(_) => {
            return Ok(if restarted {
                kr::MACH_RCV_PORT_DIED
            } else {
                kr::MACH_RCV_INVALID_NAME
            });
        }
    };
    match receive_from(ctx, &ports, options, r) {
        Some(got) => Ok(got.kr),
        None => {
            let deadline = timeout_deadline(options, opt::RCV_TIMEOUT, timeout, kept);
            if deadline.is_some_and(|d| d <= Instant::now()) {
                return Ok(kr::MACH_RCV_TIMED_OUT);
            }
            Err(Wait::key(key, deadline))
        }
    }
}

/// The outcome of a receive (`mach_msg_recv_result_t`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Received {
    /// The receive's result.
    pub kr: KernReturn,
    /// The message size (without trailer).
    pub msg_size: u32,
    /// The trailer size.
    pub trailer_size: u32,
    /// The auxiliary data size.
    pub aux_size: u32,
    /// The name of the port the message was queued on.
    pub name: PortName,
}

/// Receives the first queued message of `ports` into `r`
/// (`ipc_mqueue_select_on_thread_locked`, `mach_msg_receive_results`);
/// `None` when nothing is queued.
fn receive_from(
    ctx: &mut Ctx<'_>,
    ports: &[std::sync::Arc<crate::user::darwin::mach::ipc::Port>],
    options: u64,
    r: &Recv,
) -> Option<Received> {
    let port = ports
        .iter()
        .find(|p| !p.state.lock().unwrap().queue.is_empty())
        .cloned()?;
    let name = ctx.proc.ipc.name_of(&port).unwrap_or(MACH_PORT_NULL);
    let done = |kr: KernReturn, msg_size: usize, trailer_size: usize, aux_size: usize| {
        Some(Received {
            kr,
            msg_size: msg_size as u32,
            trailer_size: trailer_size as u32,
            aux_size: aux_size as u32,
            name,
        })
    };

    // ipc_mqueue_select_on_thread_locked: the size check.
    let tsize = msg::trailer_size(options);
    let (msize, asize, seqno, context) = {
        let st = port.state.lock().unwrap();
        let m = st.queue.front().expect("the queue has a message");
        (m.size(), m.aux.len(), st.seqno, st.context)
    };
    // ipc_mqueue_msg_too_large: a linear receive needs room for the
    // auxiliary data too.
    let too_large = msize + tsize + if r.linear { asize } else { 0 } > r.size as usize;
    // A message left queued reports its size without a trailer.
    if too_large && options & opt::RCV_LARGE != 0 && r.linear {
        // The knote reports the sizes; nothing is written.
        return done(kr::MACH_RCV_TOO_LARGE, msize, 0, asize);
    }
    if too_large && options & opt::RCV_LARGE != 0 {
        // mach_msg_receive_too_large: report the size, keep the message.
        let mut mr = kr::MACH_RCV_TOO_LARGE;
        if options & opt::RCV_LARGE_IDENTITY != 0 && r.size >= 16 {
            if ctx.write_u32(r.addr + 12, name).is_err() {
                mr = kr::MACH_RCV_INVALID_DATA;
            }
        }
        if r.size >= 8 && ctx.write_u32(r.addr + 4, msize as u32).is_err() {
            mr = kr::MACH_RCV_INVALID_DATA;
        }
        return done(mr, msize, 0, 0);
    }
    let m = {
        let mut st = port.state.lock().unwrap();
        st.seqno = st.seqno.wrapping_add(1);
        st.queue.pop_front().expect("the queue has a message")
    };
    ctx.proc.post(WaitKey::PortSpace(port.id));
    kmsg::fire_send_possible(ctx.proc, &port);
    ctx.proc.task.messages.1 += 1;
    let sender = m.sender;
    let aux = m.aux.clone();
    // ipc_kmsg_put_to_user: where the message goes. A linear receive on a
    // stack ends at the buffer's end.
    let msg_addr = if r.linear && r.stack && !too_large {
        r.addr + u64::from(r.size) - (msize + tsize + asize) as u64
    } else {
        r.addr
    };
    let (bytes, mut mr) = if too_large {
        // mach_msg_receive_error: only the header survives.
        (kmsg::copyout_dest_only(ctx.proc, m), kr::MACH_RCV_TOO_LARGE)
    } else {
        let (b, status) = kmsg::copyout(ctx.proc, m, options, msg_addr);
        (
            b,
            if status != 0 {
                kr::MACH_RCV_BODY_ERROR | status
            } else {
                kr::MACH_MSG_SUCCESS
            },
        )
    };

    // ipc_kmsg_put_to_user (a failed copy-out reports no sizes).
    if bytes.len() > r.size as usize {
        return done(kr::MACH_RCV_INVALID_DATA, 0, 0, 0);
    }
    let mut out = bytes;
    let trailer = msg::trailer(options, seqno, &sender, context);
    let room = r.size as usize - out.len();
    out.extend_from_slice(&trailer[..trailer.len().min(room)]);
    if ctx.proc.config.strace {
        let w = |o: usize| u32::from_le_bytes(out[o..o + 4].try_into().expect("header"));
        eprintln!(
            "[{:#x}]   received bits={:#x} size={} remote={:#x} local={:#x} voucher={:#x} id={} ({} bytes with trailer)",
            ctx.thread.tid,
            w(0),
            w(4),
            w(8),
            w(12),
            w(16),
            w(20) as i32,
            out.len()
        );
    }
    let trailer_len = out.len() - msize.min(out.len());
    if ctx.write(msg_addr, &out).is_err() {
        return done(kr::MACH_RCV_INVALID_DATA, 0, 0, 0);
    }
    if r.linear {
        // The auxiliary data follows the trailer; none leaves no header.
        if !aux.is_empty() && ctx.write(msg_addr + out.len() as u64, &aux).is_err() {
            return done(kr::MACH_RCV_INVALID_DATA, 0, 0, 0);
        }
    } else if r.aux_addr != 0 {
        if aux.is_empty() {
            if ctx.write(r.aux_addr, &[0u8; 8]).is_err() {
                mr = kr::MACH_RCV_INVALID_DATA;
            }
        } else if aux.len() <= r.aux_size as usize && ctx.write(r.aux_addr, &aux).is_err() {
            mr = kr::MACH_RCV_INVALID_DATA;
        }
    }
    done(mr, msize, trailer_len, aux.len())
}

/// A port or port set a knote watches.
#[derive(Clone, Debug)]
pub enum Watched {
    /// A receive right's port.
    Port(std::sync::Arc<crate::user::darwin::mach::ipc::Port>),
    /// A port set.
    Set(std::sync::Arc<crate::user::darwin::mach::ipc::PortSet>),
}

impl Watched {
    /// The port or set's identity (its knote list key).
    pub fn id(&self) -> u64 {
        match self {
            Watched::Port(p) => p.id,
            Watched::Set(s) => s.id,
        }
    }

    fn ports(&self) -> Vec<std::sync::Arc<crate::user::darwin::mach::ipc::Port>> {
        match self {
            Watched::Port(p) => vec![p.clone()],
            Watched::Set(s) => s.members.lock().unwrap().clone(),
        }
    }

    /// Whether a message is queued.
    pub fn has_message(&self) -> bool {
        self.ports()
            .iter()
            .any(|p| !p.state.lock().unwrap().queue.is_empty())
    }
}

/// Receives without waiting from `w` into `addr` (`size` bytes) with
/// `options` (`filt_machportprocess`): a linear vector receive, the
/// message, its trailer, and its auxiliary data in one buffer, at the
/// buffer's end when `stack`. `None` when nothing is queued.
pub fn receive_object(
    ctx: &mut Ctx<'_>,
    w: &Watched,
    options: u64,
    addr: u64,
    size: u32,
    stack: bool,
) -> Option<Received> {
    let r = Recv {
        addr,
        size,
        aux_addr: 0,
        aux_size: 0,
        name: MACH_PORT_NULL,
        linear: true,
        stack,
    };
    receive_from(ctx, &w.ports(), options, &r)
}
