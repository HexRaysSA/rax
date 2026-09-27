//! Mach exception delivery (`exception_triage`, `exception_deliver`,
//! `osfmk/kern/exception.c`).
//!
//! A machine exception or an invalid Mach trap goes as a message to the
//! handler of the faulting thread, then to the task's, then to the
//! host's, whose handler (`ux_handler`, `osfmk/kern/ux_handler.c`) turns
//! it into a signal. Each handler gets the request its behavior selects
//! (`exc.defs`, `mach_exc.defs`) and the thread waits, without running,
//! for the reply on a port of its own (`mach_msg_rpc_from_kernel`,
//! `osfmk/kern/ipc_mig.c`). A reply that takes the exception resumes the
//! thread, with the thread state a state behavior's reply returns; any
//! other outcome passes the exception to the next level.
//!
//! The kernel sends the thread's and task's control ports (developer mode
//! is on, as on the machines the fixtures compare with). The host level's
//! handler is the only one there is: `host_set_exception_ports` needs the
//! privileged host port, which no guest holds.

use std::sync::Arc;

use super::abi::DarwinAbi;
use super::arch::Exception;
use super::mach::exception::{EXC_MASK_UX, behavior, exc};
use super::mach::ipc::{KObject, Port, Right, disp};
use super::mach::kr::{self, KernReturn};
use super::mach::msg::{self, Item, Message, Sender, bits, desc};
use super::process::{Proc, Thread};
use super::signal;
use super::syscall::mach::{guard, kmsg};
use super::thread_status;
use super::wait::{self, Wait, WaitKey};

/// `THREAD_STATE_MAX`: the most words a request or reply state holds.
const THREAD_STATE_MAX: usize = 1296;

/// `SIGKILL`.
const SIGKILL: i32 = 9;

/// The request IDs (`exc` subsystem 2401, `mach_exc` 2405).
mod id {
    /// `exception_raise`.
    pub const RAISE: i32 = 2401;
    /// `exception_raise_state`.
    pub const RAISE_STATE: i32 = 2402;
    /// `exception_raise_state_identity`.
    pub const RAISE_STATE_IDENTITY: i32 = 2403;
    /// The `mach_exc` routines' offset: 64-bit codes.
    pub const CODES64: i32 = 4;
    /// `mach_exception_raise_identity_protected`.
    pub const RAISE_IDENTITY_PROTECTED: i32 = 2408;
    /// `mach_exception_raise_state_identity_protected`.
    pub const RAISE_STATE_IDENTITY_PROTECTED: i32 = 2410;
}

/// Who a request says raised the exception.
enum Identity {
    /// Nobody (`EXCEPTION_STATE`).
    None,
    /// The thread's and task's ports.
    Ports([Arc<Port>; 2]),
    /// The thread's ID and a task identity token (the protected
    /// behaviors).
    Token {
        /// `thread_id`.
        thread_id: u64,
        /// The token's port.
        token: Arc<Port>,
    },
}

/// An exception as the kernel raises it: its type and codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Raised {
    /// `EXC_*`.
    pub exception: i32,
    /// The codes.
    pub codes: [i64; 2],
    /// How many codes there are (1 or 2).
    pub ncodes: u32,
    /// The task dies of `SIGKILL` once the exception is delivered (a
    /// fatal guard violation).
    pub fatal: bool,
}

/// A guard violation the thread handles on its way back to user mode
/// (`thread_ast_mach_exception`): `EXC_GUARD`'s code and subcode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuardAst {
    /// Type, flavor, and target.
    pub code: u64,
    /// The payload.
    pub subcode: u64,
    /// Another violation cannot replace it.
    pub sticky: bool,
}

/// Notes violation `g` in `slot` unless a pending one stays: a sticky one,
/// or any when `g` is not sticky.
pub fn post_guard(slot: &mut Option<GuardAst>, g: GuardAst) {
    if slot.is_some_and(|p| p.sticky || !g.sticky) {
        return;
    }
    *slot = Some(g);
}

/// `guard_ast`: raises the thread's pending guard violation, if its kind
/// is delivered (`mach_port_guard_ast`; a virtual-memory violation is
/// always fatal), with `thread_interrupt_level(THREAD_UNINT)` as for any
/// exception here.
pub fn guard_ast(proc: &mut Proc, thread: &mut Thread) {
    let Some(g) = thread.mach.guard_ast.take() else {
        return;
    };
    if proc.exit.is_some() || thread.exited {
        return;
    }
    let fatal = match g.code >> 61 {
        guard::GUARD_TYPE_MACH_PORT => guard::ast(proc, g.code),
        _ => Some(true),
    };
    let Some(fatal) = fatal else {
        return;
    };
    // task_exception_notify: delivered synchronously (developer mode).
    triage(
        proc,
        thread,
        Raised {
            exception: exc::GUARD,
            codes: [g.code as i64, g.subcode as i64],
            ncodes: 2,
            fatal,
        },
    );
}

/// The levels an exception tries, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// The thread's handlers.
    Thread,
    /// The task's.
    Task,
    /// The host's.
    Host,
}

impl Level {
    fn next(self) -> Level {
        match self {
            Level::Thread => Level::Task,
            Level::Task | Level::Host => Level::Host,
        }
    }
}

/// An exception whose request a handler has: the thread waits for the
/// reply.
#[derive(Clone, Debug)]
pub struct InFlight {
    /// The exception.
    pub raised: Raised,
    /// The level whose handler has it.
    pub level: Level,
    /// The request's `msgh_id`.
    pub id: i32,
    /// The reply carries a thread state (`EXCEPTION_STATE`,
    /// `EXCEPTION_STATE_IDENTITY`).
    pub stateful: bool,
    /// The port the reply comes to (the thread's kernel reply port).
    pub reply: Arc<Port>,
}

/// The codes of machine exception `e` (`sleh.c` on arm64, `user_trap` on
/// x86-64); `insn` is the instruction word at an arm64 undefined
/// instruction.
fn fault_codes(e: &Exception, insn: u32) -> Raised {
    let (exception, code, subcode) = signal::mach_exception(e, insn);
    Raised {
        exception,
        codes: [code, subcode],
        ncodes: 2,
        fatal: false,
    }
}

/// Raises machine exception `e` on `thread` (the kernel entry that
/// reports it).
pub fn raise_fault(proc: &mut Proc, thread: &mut Thread, e: &Exception) {
    thread.sig.entry = signal::entry_state(e);
    let arm64 = proc.abi == DarwinAbi::Arm64;
    if let Exception::Breakpoint {
        imm: 0xb000..=0xbfff,
        pc,
    } = *e
        && arm64
    {
        // A breakpoint of the range system libraries use to stop on a
        // disallowed condition (`user_brk_descriptors`): unrecoverable
        // for a process no debugger traces, which is killed without an
        // exception message or a signal handler
        // (`maybe_unrecoverable_exception_triage`).
        proc.exit_with(super::process::ExitStatus::Signaled {
            signo: SIGKILL,
            core: false,
            pc,
        });
        return;
    }
    // handle_uncategorized: the instruction word as the subcode (0 when
    // it cannot be read).
    let mut insn = 0;
    if let Exception::Undefined { pc, .. } = *e
        && arm64
    {
        let mut b = [0u8; 4];
        if proc.space.read(pc, &mut b).is_ok() {
            insn = u32::from_le_bytes(b);
        }
    }
    triage(proc, thread, fault_codes(e, insn));
}

/// Raises `EXC_SYSCALL` for invalid Mach trap `number` (`X16` on arm64,
/// `RAX` on x86-64): the trap number alone on arm64 (`mach_syscall`),
/// `RAX` and 1 on x86-64 (`mach_call_munger64`).
pub fn raise_syscall(proc: &mut Proc, thread: &mut Thread, number: u64) {
    let raised = syscall_codes(proc.abi, number);
    triage(proc, thread, raised);
}

fn syscall_codes(abi: DarwinAbi, number: u64) -> Raised {
    match abi {
        DarwinAbi::Arm64 => Raised {
            exception: exc::SYSCALL,
            codes: [i64::from((number as i32).wrapping_neg()), 0],
            ncodes: 1,
            fatal: false,
        },
        DarwinAbi::X86_64 => Raised {
            exception: exc::SYSCALL,
            codes: [number as i64, 1],
            ncodes: 2,
            fatal: false,
        },
    }
}

/// `exception_triage`: offers the exception to the thread's handler,
/// then the task's, then the host's.
pub fn triage(proc: &mut Proc, thread: &mut Thread, raised: Raised) {
    walk(proc, thread, raised, Level::Thread);
}

/// Tries the levels from `from` on until a handler has the request (the
/// thread then waits) or a level takes the exception.
fn walk(proc: &mut Proc, thread: &mut Thread, raised: Raised, from: Level) {
    let mut level = from;
    loop {
        // A terminating thread sends nothing (exception_deliver).
        if proc.exit.is_some() || thread.exited {
            return;
        }
        if level == Level::Host {
            host(proc, thread, &raised);
            break;
        }
        if send(proc, thread, &raised, level).is_ok() {
            return;
        }
        level = level.next();
    }
    finish(proc, &raised);
}

/// The end of an exception's delivery: a fatal one kills the task
/// (`exit_with_mach_exception`).
fn finish(proc: &mut Proc, raised: &Raised) {
    if raised.fatal && proc.exit.is_none() {
        proc.exit_with(super::process::ExitStatus::Signaled {
            signo: SIGKILL,
            core: false,
            pc: 0,
        });
    }
}

/// The host level: `ux_handler` holds the exceptions of
/// [`EXC_MASK_UX`] and posts their signals; no handler takes the others.
fn host(proc: &mut Proc, thread: &mut Thread, raised: &Raised) {
    if EXC_MASK_UX & (1 << raised.exception) != 0 {
        signal::raise_mach(
            proc,
            thread,
            raised.exception,
            raised.codes[0],
            raised.codes[1],
        );
    }
}

/// `exception_deliver` at `level` up to the wait: sends the request of
/// the level's action and parks the thread; `Err` when the level has no
/// handler that can get it.
fn send(
    proc: &mut Proc,
    thread: &mut Thread,
    raised: &Raised,
    level: Level,
) -> Result<(), KernReturn> {
    let i = raised.exception as usize;
    let action = match level {
        Level::Thread => thread.mach.exc.get(i).cloned(),
        Level::Task => proc.task.exc.get(i).cloned(),
        Level::Host => None,
    }
    .ok_or(kr::KERN_FAILURE)?;
    // A dead handler is not valid (exception_port_copy_send).
    let port = action
        .port
        .filter(|p| !p.is_dead() && !p.is_kernel())
        .ok_or(kr::KERN_FAILURE)?;
    let codes64 = action.behavior as u32 & behavior::CODES != 0;
    let offset = if codes64 { id::CODES64 } else { 0 };
    // (request ID, identity ports or token, a state travels).
    let (request_id, ports, token, stateful) = match behavior::base(action.behavior) {
        behavior::DEFAULT => (id::RAISE + offset, true, false, false),
        behavior::STATE => (id::RAISE_STATE + offset, false, false, true),
        behavior::STATE_IDENTITY => (id::RAISE_STATE_IDENTITY + offset, true, false, true),
        // The protected behaviors exist with 64-bit codes only (the
        // handler checks refuse the others).
        behavior::IDENTITY_PROTECTED if codes64 => {
            (id::RAISE_IDENTITY_PROTECTED, false, true, false)
        }
        behavior::STATE_IDENTITY_PROTECTED if codes64 => {
            (id::RAISE_STATE_IDENTITY_PROTECTED, false, true, true)
        }
        _ => return Err(kr::KERN_FAILURE),
    };
    // The state the handler sees: the flavor's full size
    // (`_MachineStateCount`); a flavor the thread cannot report fails
    // the level.
    let state = if stateful {
        let view = thread_status::View {
            cpu: &thread.cpu,
            entry: &thread.sig.entry,
            debug: &thread.mach.debug_state,
            ptrauth: signal::frame::uses_ptrauth(proc),
        };
        let count = thread_status::machine_state_count(proc.abi, action.flavor);
        Some(thread_status::get(&view, action.flavor, count)?)
    } else {
        None
    };
    let identity = if ports {
        Identity::Ports([thread.kport.clone(), proc.task_port.clone()])
    } else if token {
        Identity::Token {
            thread_id: thread.tid,
            token: crate::user::darwin::mig::task::identity_token(proc),
        }
    } else {
        Identity::None
    };
    let complex = !matches!(identity, Identity::None);
    let (body, items) = request(
        raised,
        codes64,
        identity,
        state.as_deref().map(|s| (action.flavor, s)),
    );
    port.state.lock().unwrap().srights += 1;
    let reply = Port::new(KObject::None);
    reply.state.lock().unwrap().sorights += 1;
    let m = Message {
        bits: bits::set(
            disp::MOVE_SEND,
            disp::MOVE_SEND_ONCE,
            0,
            if complex { bits::COMPLEX } else { 0 },
        ),
        dest: Right::Send(port),
        reply: Some(Right::SendOnce(reply.clone())),
        voucher: None,
        voucher_name: 0,
        id: request_id,
        body,
        items,
        sender: Sender::KERNEL,
        aux: Vec::new(),
    };
    // MACH_SEND_KERNEL_DEFAULT: the queue limit does not apply.
    kmsg::enqueue(proc, m);
    park(
        thread,
        InFlight {
            raised: *raised,
            level,
            id: request_id,
            stateful,
            reply,
        },
    );
    Ok(())
}

/// The request's body (after the header, in the 64-bit layout) and its
/// descriptors' rights: the thread's and task's ports (made send rights)
/// for the identity behaviors or a task identity token for the protected
/// ones, the NDR record, the protected behaviors' thread ID, the
/// exception, the codes (truncated to 32 bits without
/// `MACH_EXCEPTION_CODES`), and the flavor and state for the state
/// behaviors.
fn request(
    raised: &Raised,
    codes64: bool,
    identity: Identity,
    state: Option<(i32, &[u32])>,
) -> (Vec<u8>, Vec<(usize, Item)>) {
    let mut body = Vec::new();
    let mut items = Vec::new();
    let (ports, thread_id) = match identity {
        Identity::None => (Vec::new(), None),
        Identity::Ports(p) => (p.to_vec(), None),
        Identity::Token { thread_id, token } => (vec![token], Some(thread_id)),
    };
    if !ports.is_empty() {
        body.extend_from_slice(&(ports.len() as u32).to_le_bytes());
        for port in ports {
            {
                let mut st = port.state.lock().unwrap();
                st.srights += 1;
                st.mscount += 1;
            }
            let pos = body.len();
            body.extend_from_slice(&[0u8; 12]);
            body[pos + 10] = disp::MOVE_SEND as u8;
            body[pos + 11] = desc::PORT;
            items.push((
                pos,
                Item::Port {
                    right: Some(Right::Send(port)),
                    disp: disp::MOVE_SEND,
                },
            ));
        }
    }
    body.extend_from_slice(&msg::NDR_RECORD);
    if let Some(t) = thread_id {
        body.extend_from_slice(&t.to_le_bytes());
    }
    body.extend_from_slice(&raised.exception.to_le_bytes());
    body.extend_from_slice(&raised.ncodes.to_le_bytes());
    for &c in &raised.codes[..raised.ncodes as usize] {
        if codes64 {
            body.extend_from_slice(&c.to_le_bytes());
        } else {
            body.extend_from_slice(&(c as i32).to_le_bytes());
        }
    }
    if let Some((flavor, s)) = state {
        body.extend_from_slice(&flavor.to_le_bytes());
        body.extend_from_slice(&(s.len() as u32).to_le_bytes());
        for w in s {
            body.extend_from_slice(&w.to_le_bytes());
        }
    }
    (body, items)
}

/// Makes `thread` wait for the reply to `f`; neither a signal nor
/// `thread_abort_safely` ends the wait.
fn park(thread: &mut Thread, f: InFlight) {
    thread.wait = Some(Wait {
        fds: Vec::new(),
        deadline: None,
        keys: vec![WaitKey::Port(f.reply.id)],
        interruptible: false,
        seq: wait::next_seq(),
    });
    thread.woken = false;
    thread.mach.exception = Some(f);
}

/// Continues `thread`'s exception once its wait ends: takes the
/// handler's reply (the exception is handled, the thread's state the
/// reply's) or passes the exception to the next level. A thread woken
/// without a reply waits on; a terminating one drops the exception.
pub fn resume(proc: &mut Proc, thread: &mut Thread) {
    let Some(f) = thread.mach.exception.take() else {
        return;
    };
    if proc.exit.is_some() || thread.exited {
        kmsg::destroy_receive(proc, &f.reply);
        return;
    }
    let m = f.reply.state.lock().unwrap().queue.pop_front();
    let Some(m) = m else {
        park(thread, f);
        return;
    };
    let kr = take_reply(proc, thread, &f, m);
    // The reply port goes with the request (a late reply is destroyed).
    kmsg::destroy_receive(proc, &f.reply);
    if proc.config.strace {
        let name = kr::name(kr).map_or_else(|| format!("{kr:#x}"), str::to_string);
        eprintln!(
            "[{:#x}] exception {} at the {:?} level: {name}",
            thread.tid, f.raised.exception, f.level
        );
    }
    if kr != kr::KERN_SUCCESS && kr != kr::MACH_RCV_PORT_DIED {
        walk(proc, thread, f.raised, f.level.next());
    } else {
        finish(proc, &f.raised);
    }
}

/// Drops the exception a terminated thread waited on: its reply port
/// dies with the thread (a late reply is destroyed).
pub fn abandon(proc: &mut Proc, thread: &mut Thread) {
    if let Some(f) = thread.mach.exception.take() {
        kmsg::destroy_receive(proc, &f.reply);
    }
}

/// The reply's outcome as the MIG user stub checks it
/// (`__MIG_check__Reply__mach_exception_raise*_t`), with a state
/// behavior's state installed (`thread_setstatus_from_user`); the reply
/// is consumed.
fn take_reply(proc: &mut Proc, thread: &mut Thread, f: &InFlight, mut m: Message) -> KernReturn {
    let dest = std::mem::replace(&mut m.dest, Right::Dead);
    kmsg::consume_dest(proc, dest);
    let kr = match check_reply(&m, f) {
        Ok(Some((flavor, state))) => thread_status::set(
            &mut thread.cpu,
            &mut thread.mach.debug_state,
            flavor,
            &state,
        )
        .err()
        .unwrap_or(kr::KERN_SUCCESS),
        Ok(None) => kr::KERN_SUCCESS,
        Err(kr) => kr,
    };
    kmsg::destroy(proc, m);
    kr
}

/// The reply's result: `Ok` with the returned flavor and state for a
/// state behavior when it takes the exception, `Err` with the reply's
/// code or the MIG error otherwise.
fn check_reply(m: &Message, f: &InFlight) -> Result<Option<(i32, Vec<u32>)>, KernReturn> {
    if m.id != f.id + 100 {
        return Err(if m.id == kmsg::MACH_NOTIFY_SEND_ONCE {
            kr::MIG_SERVER_DIED
        } else {
            kr::MIG_REPLY_MISMATCH
        });
    }
    let word = |off: usize| {
        m.body
            .get(off..off + 4)
            .map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()))
    };
    // After the header: the NDR record, RetCode, then the flavor, the
    // count, and the state.
    let size = m.size();
    let ret = word(8) as i32;
    let complex = m.bits & bits::COMPLEX != 0;
    // An error reply is a bare mig_reply_error_t.
    let error_size = size == 36 && ret != kr::KERN_SUCCESS;
    let min = msg::HEADER_SIZE + 20;
    let bad_size = if f.stateful {
        !(min..=min + 4 * THREAD_STATE_MAX).contains(&size) && !error_size
    } else {
        size != 36
    };
    if complex || bad_size || m.reply.is_some() {
        return Err(kr::MIG_TYPE_ERROR);
    }
    if ret != kr::KERN_SUCCESS {
        return Err(ret);
    }
    if !f.stateful {
        return Ok(None);
    }
    let (flavor, count) = (word(12) as i32, word(16) as usize);
    if count > THREAD_STATE_MAX || size != min + 4 * count {
        return Err(kr::MIG_TYPE_ERROR);
    }
    let state = (0..count).map(|i| word(20 + 4 * i)).collect();
    Ok(Some((flavor, state)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raised(exception: i32, codes: [i64; 2], ncodes: u32) -> Raised {
        Raised {
            exception,
            codes,
            ncodes,
            fatal: false,
        }
    }

    #[test]
    fn sticky_guards_stay_pending() {
        let g = |code, sticky| GuardAst {
            code,
            subcode: 0,
            sticky,
        };
        let mut slot = None;
        post_guard(&mut slot, g(1, false));
        post_guard(&mut slot, g(2, false));
        assert_eq!(slot, Some(g(1, false)));
        // A sticky violation replaces a non-sticky one, not another sticky.
        post_guard(&mut slot, g(3, true));
        post_guard(&mut slot, g(4, true));
        post_guard(&mut slot, g(5, false));
        assert_eq!(slot, Some(g(3, true)));
    }

    /// The request sizes and offsets `mach_excUser.c` and `excUser.c`
    /// lay out (msgh_size = 24 + the body).
    #[test]
    fn requests_follow_the_mig_layouts() {
        let r = raised(exc::BAD_ACCESS, [2, 0x1_2345_6789], 2);
        let ports = || Identity::Ports([Port::new(KObject::None), Port::new(KObject::None)]);
        // mach_exception_raise: 2 descriptors, NDR at 52, the exception
        // at 60, the count at 64, the 64-bit codes at 68.
        let (b, items) = request(&r, true, ports(), None);
        assert_eq!(24 + b.len(), 84);
        assert_eq!(items.iter().map(|(p, _)| *p).collect::<Vec<_>>(), [4, 16]);
        assert_eq!(b[4 + 10], 17);
        assert_eq!(&b[52 - 24..60 - 24], &msg::NDR_RECORD);
        assert_eq!(&b[60 - 24..64 - 24], &1i32.to_le_bytes());
        assert_eq!(&b[64 - 24..68 - 24], &2u32.to_le_bytes());
        assert_eq!(&b[76 - 24..84 - 24], &0x1_2345_6789i64.to_le_bytes());
        // exception_raise: the codes truncated to 32 bits.
        let (b, _) = request(&r, false, ports(), None);
        assert_eq!(24 + b.len(), 76);
        assert_eq!(&b[72 - 24..76 - 24], &0x2345_6789i32.to_le_bytes());
        // mach_exception_raise_state with 68 words: NDR at 24, the
        // flavor at 56, the count at 60, the state at 64.
        let s = vec![7u32; 68];
        let (b, items) = request(&r, true, Identity::None, Some((6, &s)));
        assert!(items.is_empty());
        assert_eq!(24 + b.len(), 336);
        assert_eq!(&b[56 - 24..60 - 24], &6i32.to_le_bytes());
        assert_eq!(&b[60 - 24..64 - 24], &68u32.to_le_bytes());
        // exception_raise_state (x86_THREAD_STATE64) and the identity
        // variants.
        let s42 = vec![0u32; 42];
        assert_eq!(
            24 + request(&r, false, Identity::None, Some((4, &s42))).0.len(),
            224
        );
        assert_eq!(24 + request(&r, true, ports(), Some((6, &s))).0.len(), 364);
        assert_eq!(24 + request(&r, false, ports(), Some((6, &s))).0.len(), 356);
        // One code (EXC_SYSCALL on arm64).
        let one = raised(exc::SYSCALL, [200, 0], 1);
        assert_eq!(
            24 + request(&one, true, Identity::None, Some((6, &s))).0.len(),
            328
        );
        assert_eq!(24 + request(&one, true, ports(), None).0.len(), 76);
        // mach_exception_raise_identity_protected: the token descriptor,
        // NDR at 40, the thread ID at 48, the exception at 56, the
        // codes at 64; the state variant's flavor at 80.
        let token = || Identity::Token {
            thread_id: 0x1234,
            token: Port::new(KObject::TaskIdToken(1)),
        };
        let (b, items) = request(&r, true, token(), None);
        assert_eq!(24 + b.len(), 80);
        assert_eq!(items.len(), 1);
        assert_eq!(&b[0..4], &1u32.to_le_bytes());
        assert_eq!(&b[48 - 24..56 - 24], &0x1234u64.to_le_bytes());
        assert_eq!(&b[56 - 24..60 - 24], &1i32.to_le_bytes());
        let (b, _) = request(&r, true, token(), Some((6, &s)));
        assert_eq!(24 + b.len(), 360);
        assert_eq!(&b[80 - 24..84 - 24], &6i32.to_le_bytes());
    }

    fn reply(id: i32, ret: i32, state: Option<(i32, &[u32])>) -> Message {
        let mut body = msg::NDR_RECORD.to_vec();
        body.extend_from_slice(&ret.to_le_bytes());
        if let Some((flavor, s)) = state {
            body.extend_from_slice(&flavor.to_le_bytes());
            body.extend_from_slice(&(s.len() as u32).to_le_bytes());
            for w in s {
                body.extend_from_slice(&w.to_le_bytes());
            }
        }
        Message {
            bits: bits::set(disp::MOVE_SEND_ONCE, 0, 0, 0),
            dest: Right::Dead,
            reply: None,
            voucher: None,
            voucher_name: 0,
            id,
            body,
            items: Vec::new(),
            sender: Sender::KERNEL,
            aux: Vec::new(),
        }
    }

    fn in_flight(id: i32, stateful: bool) -> InFlight {
        InFlight {
            raised: raised(exc::BAD_ACCESS, [1, 0], 2),
            level: Level::Task,
            id,
            stateful,
            reply: Port::new(KObject::None),
        }
    }

    #[test]
    fn replies_are_checked_as_mig_checks_them() {
        let plain = in_flight(2405, false);
        assert_eq!(check_reply(&reply(2505, 0, None), &plain), Ok(None));
        assert_eq!(check_reply(&reply(2505, 5, None), &plain), Err(5));
        assert_eq!(
            check_reply(&reply(2505, -305, None), &plain),
            Err(kr::MIG_NO_REPLY)
        );
        assert_eq!(
            check_reply(&reply(2506, 0, None), &plain),
            Err(kr::MIG_REPLY_MISMATCH)
        );
        assert_eq!(
            check_reply(&reply(kmsg::MACH_NOTIFY_SEND_ONCE, 0, None), &plain),
            Err(kr::MIG_SERVER_DIED)
        );
        // A state where none belongs, a complex reply, a reply port.
        assert_eq!(
            check_reply(&reply(2505, 0, Some((6, &[]))), &plain),
            Err(kr::MIG_TYPE_ERROR)
        );
        let mut c = reply(2505, 0, None);
        c.bits |= bits::COMPLEX;
        assert_eq!(check_reply(&c, &plain), Err(kr::MIG_TYPE_ERROR));
        let mut r = reply(2505, 0, None);
        r.reply = Some(Right::Dead);
        assert_eq!(check_reply(&r, &plain), Err(kr::MIG_TYPE_ERROR));

        let state = in_flight(2406, true);
        let s = [1u32, 2, 3];
        assert_eq!(
            check_reply(&reply(2506, 0, Some((6, &s))), &state),
            Ok(Some((6, s.to_vec())))
        );
        // An error reply is 36 bytes; a successful one needs its state.
        assert_eq!(check_reply(&reply(2506, 5, None), &state), Err(5));
        assert_eq!(
            check_reply(&reply(2506, 0, None), &state),
            Err(kr::MIG_TYPE_ERROR)
        );
        // The count must match the size and stay within THREAD_STATE_MAX.
        let mut short = reply(2506, 0, Some((6, &s)));
        short.body.truncate(short.body.len() - 4);
        assert_eq!(check_reply(&short, &state), Err(kr::MIG_TYPE_ERROR));
        assert_eq!(
            check_reply(&reply(2506, 0, Some((6, &[]))), &state),
            Ok(Some((6, Vec::new())))
        );
    }

    #[test]
    fn syscall_codes_follow_each_architecture() {
        // x16 = -200 on arm64: one code, the trap number.
        assert_eq!(
            syscall_codes(DarwinAbi::Arm64, (-200i64) as u64),
            raised(exc::SYSCALL, [200, 0], 1)
        );
        // RAX = 0x10000c8 on x86-64: RAX and 1.
        assert_eq!(
            syscall_codes(DarwinAbi::X86_64, 0x100_00c8),
            raised(exc::SYSCALL, [0x100_00c8, 1], 2)
        );
    }

    #[test]
    fn fault_codes_carry_the_pc_and_the_instruction() {
        // BRK: EXC_ARM_BREAKPOINT and the PC; an undefined instruction:
        // EXC_ARM_UNDEFINED and its word.
        let brk = Exception::Breakpoint {
            pc: 0x1_0000_4000,
            imm: 1,
        };
        assert_eq!(
            fault_codes(&brk, 0),
            raised(exc::BREAKPOINT, [1, 0x1_0000_4000], 2)
        );
        let udf = Exception::Undefined {
            pc: 0x1_0000_4000,
            reason: String::new(),
        };
        assert_eq!(
            fault_codes(&udf, 0xdead),
            raised(exc::BAD_INSTRUCTION, [1, 0xdead], 2)
        );
    }
}
