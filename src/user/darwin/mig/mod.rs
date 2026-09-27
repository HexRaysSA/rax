//! The kernel's MIG servers (`ipc_kobject_server` and the `*_server`
//! routines generated from `osfmk/mach/*.defs`).
//!
//! A message sent to a kernel object's port arrives here as a
//! [`Message`]. The routine for its `msgh_id` checks the request's layout
//! as MIG's generated server does (`MIG_BAD_ARGUMENTS` on a size or
//! complexity mismatch), runs, and produces the reply MIG would build: a
//! simple reply (`NDR`, `RetCode`, out-arguments), a complex one
//! (descriptors, then `NDR` and the remaining out-arguments), or on
//! failure a `mig_reply_error_t`. The reply goes to the request's reply
//! right with `msgh_id + 100`.
//!
//! Request layouts follow the MIG-generated headers for the vendored
//! definitions (`mig -header` over the `.defs` files listed in
//! `tools/darwin/gen_mig.py`); offsets below count from the start of the
//! message, header included.

pub mod clock;
pub mod host;
pub mod ids;
pub mod port;
pub mod task;
pub mod thread;
pub mod vm;

use std::sync::Arc;

use crate::user::darwin::mach::ipc::{KObject, Port, Right, disp};
use crate::user::darwin::mach::kr::{self, KernReturn};
use crate::user::darwin::mach::msg::{HEADER_SIZE, Item, Message, NDR_RECORD, Sender, bits, desc};
use crate::user::darwin::syscall::Ctx;
use crate::user::darwin::syscall::mach::kmsg;

/// A request being served.
pub struct Req {
    /// `msgh_id`.
    pub id: i32,
    /// `msgh_bits` (kernel form).
    pub bits: u32,
    /// The whole message: header (zeroed ports) and body.
    pub raw: Vec<u8>,
    /// Descriptor payloads by descriptor offset in `raw`.
    pub items: Vec<(usize, Item)>,
    /// The kernel object's port.
    pub port: Arc<Port>,
}

impl Req {
    /// `msgh_size`.
    pub fn size(&self) -> usize {
        self.raw.len()
    }

    /// Whether the request is complex.
    pub fn complex(&self) -> bool {
        self.bits & bits::COMPLEX != 0
    }

    /// A 32-bit field at message offset `off`.
    pub fn u32(&self, off: usize) -> u32 {
        u32::from_le_bytes(self.raw[off..off + 4].try_into().expect("in-bounds field"))
    }

    /// A signed 32-bit field.
    pub fn i32(&self, off: usize) -> i32 {
        self.u32(off) as i32
    }

    /// A 64-bit field.
    pub fn u64(&self, off: usize) -> u64 {
        u64::from_le_bytes(self.raw[off..off + 8].try_into().expect("in-bounds field"))
    }

    /// Bytes `off..off + len`.
    pub fn bytes(&self, off: usize, len: usize) -> &[u8] {
        &self.raw[off..off + len]
    }

    /// MIG's check for a simple request of exactly `size` bytes.
    pub fn simple(&self, size: usize) -> Result<(), KernReturn> {
        if self.complex() || self.size() != size {
            return Err(kr::MIG_BAD_ARGUMENTS);
        }
        Ok(())
    }

    /// MIG's check for a simple request with a trailing variable array:
    /// `fixed` bytes before the array, elements of `elem` bytes, at most
    /// `max` of them, the count at `count_off`. Returns the count.
    pub fn simple_array(
        &self,
        fixed: usize,
        elem: usize,
        max: usize,
        count_off: usize,
    ) -> Result<usize, KernReturn> {
        if self.complex() || self.size() < fixed || self.size() > fixed + elem * max {
            return Err(kr::MIG_BAD_ARGUMENTS);
        }
        let n = self.u32(count_off) as usize;
        if n > max || self.size() != fixed + elem * n {
            return Err(kr::MIG_BAD_ARGUMENTS);
        }
        Ok(n)
    }

    /// MIG's check for a complex request of exactly `size` bytes carrying
    /// `count` descriptors.
    pub fn complex_of(&self, count: u32, size: usize) -> Result<(), KernReturn> {
        if !self.complex() || self.size() != size || self.u32(HEADER_SIZE) != count {
            return Err(kr::MIG_BAD_ARGUMENTS);
        }
        Ok(())
    }

    /// Takes the port right of the descriptor at `off`, checking it is a
    /// port descriptor carrying a right of type `want` (`MIG_TYPE_ERROR`
    /// otherwise).
    pub fn take_port(&mut self, off: usize, want: &[u32]) -> Result<Option<Right>, KernReturn> {
        let i = self
            .items
            .iter()
            .position(|(p, _)| *p == off)
            .ok_or(kr::MIG_TYPE_ERROR)?;
        match &self.items[i].1 {
            Item::Port { disp: d, .. } if want.contains(d) => {}
            _ => return Err(kr::MIG_TYPE_ERROR),
        }
        match self.items.remove(i).1 {
            Item::Port { right, .. } => Ok(right),
            _ => unreachable!("checked above"),
        }
    }
}

/// A descriptor of a complex reply.
pub enum OutDesc {
    /// A port right (`MACH_MSG_PORT_DESCRIPTOR`) of type `disp`.
    Port(Option<Right>, u32),
    /// An out-of-line port array.
    OolPorts(Vec<Option<Right>>, u32),
    /// Out-of-line memory.
    Ool(Vec<u8>),
}

/// What a routine produced.
pub enum Out {
    /// A simple reply: `RetCode` is `KERN_SUCCESS`, `data` follows it.
    Simple(Vec<u8>),
    /// A complex reply: descriptors, then (when `data` is not empty) the
    /// NDR record and `data`.
    Complex(Vec<OutDesc>, Vec<u8>),
    /// No reply (`MIG_NO_REPLY`).
    NoReply,
}

/// A routine's result: `Err` becomes a `mig_reply_error_t`.
pub type MigResult = Result<Out, KernReturn>;

/// Little-endian byte building for replies.
#[derive(Default)]
pub struct Buf(pub Vec<u8>);

impl Buf {
    /// An empty buffer.
    pub fn new() -> Self {
        Buf(Vec::new())
    }

    /// Appends a `u32`.
    pub fn u32(mut self, v: u32) -> Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Appends an `i32`.
    pub fn i32(self, v: i32) -> Self {
        self.u32(v as u32)
    }

    /// Appends a `u64`.
    pub fn u64(mut self, v: u64) -> Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Appends bytes.
    pub fn bytes(mut self, b: &[u8]) -> Self {
        self.0.extend_from_slice(b);
        self
    }

    /// The bytes.
    pub fn done(self) -> Vec<u8> {
        self.0
    }
}

/// An info reply: `count` words out of `words`, trimmed to the caller's
/// count (`*_info_outCnt` then the array, sized to the count).
pub fn info_reply(words: &[u32]) -> Out {
    let mut b = Buf::new().u32(words.len() as u32);
    for w in words {
        b = b.u32(*w);
    }
    Out::Simple(b.done())
}

/// Runs the kernel server for a message sent to kernel object `port` and
/// builds its reply (`ipc_kobject_server`). Every right the request
/// carried that the routine did not keep is destroyed.
pub fn serve(ctx: &mut Ctx<'_>, port: &Arc<Port>, mut m: Message) -> Option<Message> {
    let reply_right = m.reply.take();
    let reply_type = bits::local(m.bits);
    let mut raw = Vec::with_capacity(m.size());
    raw.extend_from_slice(&m.bits.to_le_bytes());
    raw.extend_from_slice(&(m.size() as u32).to_le_bytes());
    raw.extend_from_slice(&[0u8; 12]);
    raw.extend_from_slice(&m.id.to_le_bytes());
    raw.extend_from_slice(&m.body);
    let mut req = Req {
        id: m.id,
        bits: m.bits,
        raw,
        items: std::mem::take(&mut m.items)
            .into_iter()
            .map(|(p, i)| (p + HEADER_SIZE, i))
            .collect(),
        port: port.clone(),
    };
    let result = dispatch(ctx, &mut req);
    if ctx.proc.config.strace {
        let name = ids::name(req.id).unwrap_or("?");
        let r = match &result {
            Ok(_) => "KERN_SUCCESS".to_string(),
            Err(k) => kr::name(*k).map_or_else(|| format!("{k:#x}"), str::to_string),
        };
        eprintln!("[{:#x}] mig {}({}) = {r}", ctx.thread.tid, name, req.id);
    }
    // The request's leftovers: its destination right, voucher, and any
    // descriptor rights the routine did not take.
    let leftovers: Vec<Item> = req.items.into_iter().map(|(_, i)| i).collect();
    m.items = leftovers.into_iter().map(|i| (0, i)).collect();
    kmsg::destroy(ctx.proc, m);

    let result = match result {
        Ok(Out::NoReply) | Err(kr::MIG_NO_REPLY) => {
            kmsg::release(ctx.proc, reply_right);
            return None;
        }
        r => r,
    };
    let dest = match reply_right {
        Some(r @ (Right::Send(_) | Right::SendOnce(_))) => r,
        other => {
            // No reply port: the reply is discarded with what it carries.
            if let Ok(Out::Complex(descs, _)) = result {
                release_descs(ctx, descs);
            }
            kmsg::release(ctx.proc, other);
            return None;
        }
    };
    let rbits_remote = reply_type;
    let (body, items, complex) = match result {
        Err(k) => (
            Buf::new().bytes(&NDR_RECORD).i32(k).done(),
            Vec::new(),
            false,
        ),
        Ok(Out::Simple(data)) => (
            Buf::new()
                .bytes(&NDR_RECORD)
                .i32(kr::KERN_SUCCESS)
                .bytes(&data)
                .done(),
            Vec::new(),
            false,
        ),
        Ok(Out::Complex(descs, data)) => {
            let mut body = Buf::new().u32(descs.len() as u32).done();
            let mut items = Vec::with_capacity(descs.len());
            for d in descs {
                let pos = body.len();
                match d {
                    OutDesc::Port(right, t) => {
                        body.extend_from_slice(&[0u8; 12]);
                        body[pos + 10] = t as u8;
                        body[pos + 11] = desc::PORT;
                        items.push((pos, Item::Port { right, disp: t }));
                    }
                    OutDesc::OolPorts(rights, t) => {
                        body.extend_from_slice(&[0u8; 16]);
                        body[pos + 10] = t as u8;
                        body[pos + 11] = desc::OOL_PORTS;
                        body[pos + 12..pos + 16]
                            .copy_from_slice(&(rights.len() as u32).to_le_bytes());
                        items.push((pos, Item::OolPorts { rights, disp: t }));
                    }
                    OutDesc::Ool(data) => {
                        body.extend_from_slice(&[0u8; 16]);
                        body[pos + 11] = desc::OOL;
                        body[pos + 12..pos + 16]
                            .copy_from_slice(&(data.len() as u32).to_le_bytes());
                        items.push((
                            pos,
                            Item::Ool {
                                data,
                                copy: desc::VIRTUAL_COPY,
                                page_offset: 0,
                            },
                        ));
                    }
                }
            }
            if !data.is_empty() {
                body.extend_from_slice(&NDR_RECORD);
                body.extend_from_slice(&data);
            }
            (body, items, true)
        }
        Ok(Out::NoReply) => unreachable!("handled above"),
    };
    Some(Message {
        bits: bits::set(rbits_remote, 0, 0, if complex { bits::COMPLEX } else { 0 }),
        dest,
        reply: None,
        voucher: None,
        voucher_name: 0,
        id: req.id + 100,
        body,
        items,
        sender: Sender::KERNEL,
        aux: Vec::new(),
    })
}

fn release_descs(ctx: &mut Ctx<'_>, descs: Vec<OutDesc>) {
    for d in descs {
        match d {
            OutDesc::Port(r, _) => kmsg::release(ctx.proc, r),
            OutDesc::OolPorts(rs, _) => kmsg::release(ctx.proc, rs.into_iter().flatten()),
            OutDesc::Ool(_) => {}
        }
    }
}

/// Routes a request to its subsystem by message ID
/// (`ipc_kobject_server_lookup` over every kernel subsystem).
fn dispatch(ctx: &mut Ctx<'_>, req: &mut Req) -> MigResult {
    let id = req.id;
    let sub = |base: i32, n: i32| (base..base + n).contains(&id);
    if sub(ids::clock::BASE, 3) {
        clock::serve(ctx, req)
    } else if sub(ids::host::BASE, 100) {
        host::serve(ctx, req)
    } else if sub(ids::mach_port::BASE, 100) {
        port::serve(ctx, req)
    } else if sub(ids::task::BASE, 100) || sub(ids::task_restartable::BASE, 2) {
        task::serve(ctx, req)
    } else if sub(ids::thread_act::BASE, 100) {
        thread::serve(ctx, req)
    } else if sub(ids::mach_vm::BASE, 100) || sub(ids::vm_map::BASE, 100) {
        vm::serve(ctx, req)
    } else {
        Err(kr::MIG_BAD_ID)
    }
}

/// Whether the request's port is the caller's own task port
/// (`convert_port_to_task` succeeds only for tasks the emulator runs,
/// which is the calling task).
pub fn is_task(ctx: &Ctx<'_>, req: &Req) -> bool {
    req.port.kobject == KObject::Task && Arc::ptr_eq(&req.port, &ctx.proc.task_port)
}

/// A send right to `port` made by the kernel (`ipc_port_make_send`) for a
/// reply, with its descriptor type.
pub fn make_send(port: &Arc<Port>) -> OutDesc {
    {
        let mut st = port.state.lock().unwrap();
        st.srights += 1;
        st.mscount += 1;
    }
    OutDesc::Port(Some(Right::Send(port.clone())), disp::MOVE_SEND)
}

/// A copy of a send right the kernel holds to `port`
/// (`ipc_port_copy_send`), for a reply.
pub fn copy_send(port: &Arc<Port>) -> OutDesc {
    if port.is_dead() {
        return OutDesc::Port(Some(Right::Dead), disp::MOVE_SEND);
    }
    port.state.lock().unwrap().srights += 1;
    OutDesc::Port(Some(Right::Send(port.clone())), disp::MOVE_SEND)
}

/// A null port for a reply descriptor.
pub fn null_port() -> OutDesc {
    OutDesc::Port(None, disp::MOVE_SEND)
}
