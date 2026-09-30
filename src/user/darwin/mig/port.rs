//! The `mach_port` subsystem (`mach_port.defs`) on the calling task's
//! name space: the MIG forms of the port operations in
//! [`syscall::mach::port`](crate::user::darwin::syscall::mach::port).

use super::{Buf, MigResult, Out, OutDesc, Req, ids, info_reply, is_task};
use crate::user::darwin::mach::ipc::{PortName, Right, disp};
use crate::user::darwin::mach::kr::{self, KernReturn};
use crate::user::darwin::syscall::Ctx;
use crate::user::darwin::syscall::mach::{kmsg, port};

fn nm(req: &Req, off: usize) -> PortName {
    req.u32(off) as PortName
}

fn ok(k: KernReturn) -> MigResult {
    if k == kr::KERN_SUCCESS {
        Ok(Out::Simple(Vec::new()))
    } else {
        Err(k)
    }
}

/// Serves the `mach_port` subsystem.
pub fn serve(ctx: &mut Ctx<'_>, req: &mut Req) -> MigResult {
    use ids::mach_port as m;
    // convert_port_to_space: only the calling task's space is reachable.
    let space = is_task(ctx, req);
    macro_rules! space {
        () => {
            if !space {
                return Err(kr::KERN_INVALID_TASK);
            }
        };
    }
    match req.id {
        m::MACH_PORT_NAMES => {
            req.simple(24)?;
            space!();
            let v = port::names(ctx.proc);
            let names: Vec<u8> = v.iter().flat_map(|n| n.0.to_le_bytes()).collect();
            let types: Vec<u8> = v.iter().flat_map(|n| n.1.to_le_bytes()).collect();
            let n = v.len() as u32;
            Ok(Out::Complex(
                vec![OutDesc::Ool(names), OutDesc::Ool(types)],
                Buf::new().u32(n).u32(n).done(),
            ))
        }
        m::MACH_PORT_TYPE => {
            req.simple(36)?;
            space!();
            let t = port::port_type(ctx.proc, nm(req, 32))?;
            Ok(Out::Simple(Buf::new().u32(t).done()))
        }
        m::MACH_PORT_RENAME => {
            // Renaming was removed from XNU; the routine always fails.
            req.simple(40)?;
            space!();
            Err(kr::KERN_NOT_SUPPORTED)
        }
        m::MACH_PORT_ALLOCATE_NAME => {
            req.simple(40)?;
            space!();
            port::allocate_name(ctx.proc, req.u32(32), nm(req, 36))?;
            Ok(Out::Simple(Vec::new()))
        }
        m::MACH_PORT_ALLOCATE => {
            req.simple(36)?;
            space!();
            let n = port::allocate(ctx.proc, req.u32(32))?;
            Ok(Out::Simple(Buf::new().u32(n).done()))
        }
        m::MACH_PORT_DESTROY => {
            req.simple(36)?;
            space!();
            ok(port::destroy(ctx.proc, nm(req, 32)))
        }
        m::MACH_PORT_DEALLOCATE => {
            req.simple(36)?;
            space!();
            ok(port::deallocate(ctx.proc, nm(req, 32)))
        }
        m::MACH_PORT_GET_REFS => {
            req.simple(40)?;
            space!();
            let r = port::get_refs(ctx.proc, nm(req, 32), req.u32(36))?;
            Ok(Out::Simple(Buf::new().u32(r).done()))
        }
        m::MACH_PORT_MOD_REFS => {
            req.simple(44)?;
            space!();
            ok(port::mod_refs(
                ctx.proc,
                nm(req, 32),
                req.u32(36),
                req.i32(40),
            ))
        }
        m::MACH_PORT_SET_MSCOUNT => {
            req.simple(40)?;
            space!();
            ok(port::set_mscount(ctx.proc, nm(req, 32), req.u32(36)))
        }
        m::MACH_PORT_GET_SET_STATUS => {
            req.simple(36)?;
            space!();
            let names = port::get_set_status(ctx.proc, nm(req, 32))?;
            let n = names.len() as u32;
            let bytes: Vec<u8> = names.iter().flat_map(|n| n.to_le_bytes()).collect();
            Ok(Out::Complex(
                vec![OutDesc::Ool(bytes)],
                Buf::new().u32(n).done(),
            ))
        }
        m::MACH_PORT_MOVE_MEMBER => {
            req.simple(40)?;
            space!();
            ok(port::move_member(ctx.proc, nm(req, 32), nm(req, 36)))
        }
        m::MACH_PORT_REQUEST_NOTIFICATION => {
            // notify: a send-once right (MAKE_SEND_ONCE or MOVE_SEND_ONCE).
            req.complex_of(1, 60)?;
            let notify = req.take_port(28, &[disp::MOVE_SEND_ONCE])?;
            if !space {
                kmsg::release(ctx.proc, notify);
                return Err(kr::KERN_INVALID_TASK);
            }
            let previous = port::request_notification(
                ctx.proc,
                nm(req, 48),
                req.i32(52),
                req.u32(56),
                notify,
            )?;
            Ok(Out::Complex(
                vec![OutDesc::Port(previous, disp::MOVE_SEND_ONCE)],
                Vec::new(),
            ))
        }
        m::MACH_PORT_INSERT_RIGHT => {
            req.complex_of(1, 52)?;
            let (right, d) = take_any(req, 28)?;
            if !space {
                kmsg::release(ctx.proc, right);
                return Err(kr::KERN_INVALID_TASK);
            }
            let Some(right) = right.filter(|r| !matches!(r, Right::Dead)) else {
                return Err(kr::KERN_INVALID_CAPABILITY);
            };
            ok(port::insert_right(ctx.proc, nm(req, 48), d, right))
        }
        m::MACH_PORT_EXTRACT_RIGHT => {
            req.simple(40)?;
            space!();
            let d = req.u32(36);
            let r = port::extract_right(ctx.proc, nm(req, 32), d)?;
            Ok(Out::Complex(
                vec![OutDesc::Port(Some(r), disp::copyin_type(d))],
                Vec::new(),
            ))
        }
        m::MACH_PORT_SET_SEQNO => {
            req.simple(40)?;
            space!();
            ok(port::set_seqno(ctx.proc, nm(req, 32), req.u32(36)))
        }
        m::MACH_PORT_GET_ATTRIBUTES => {
            req.simple(44)?;
            space!();
            let count = req.u32(40).min(17);
            Ok(info_reply(&port::get_attributes(
                ctx.proc,
                nm(req, 32),
                req.i32(36),
                count,
            )?))
        }
        m::MACH_PORT_SET_ATTRIBUTES => {
            let n = req.simple_array(44, 4, 17, 40)?;
            space!();
            let info: Vec<u32> = (0..n).map(|i| req.u32(44 + 4 * i)).collect();
            ok(port::set_attributes(
                ctx.proc,
                nm(req, 32),
                req.i32(36),
                &info,
            ))
        }
        m::MACH_PORT_ALLOCATE_QOS => {
            // mach_port_qos_t: name:1, prealloc:1 bit flags, then len.
            req.simple(44)?;
            space!();
            let (r, flags, len) = (req.u32(32), req.u32(36), req.u32(40));
            if flags & 1 != 0 {
                // qos.name without a name: mach_port_allocate_full wants a
                // valid name.
                return Err(kr::KERN_INVALID_VALUE);
            }
            if flags & 2 != 0 && r != crate::user::darwin::mach::ipc::right::RECEIVE {
                return Err(kr::KERN_INVALID_VALUE);
            }
            let n = port::allocate(ctx.proc, r)?;
            // prealloc is cleared on return.
            Ok(Out::Simple(
                Buf::new().u32(flags & !2).u32(len).u32(n).done(),
            ))
        }
        m::MACH_PORT_ALLOCATE_FULL => {
            req.complex_of(1, 64)?;
            let (proto, _) = take_any(req, 28)?;
            if !space {
                kmsg::release(ctx.proc, proto);
                return Err(kr::KERN_INVALID_TASK);
            }
            if proto.is_some() {
                kmsg::release(ctx.proc, proto);
                return Err(kr::KERN_INVALID_VALUE);
            }
            let (r, flags, len, want) = (req.u32(48), req.u32(52), req.u32(56), nm(req, 60));
            let n = if flags & 1 != 0 {
                port::allocate_name(ctx.proc, r, want)?
            } else {
                port::allocate(ctx.proc, r)?
            };
            Ok(Out::Simple(
                Buf::new().u32(flags & !2).u32(len).u32(n).done(),
            ))
        }
        m::MACH_PORT_GET_SRIGHTS => {
            req.simple(36)?;
            space!();
            let n = port::get_srights(ctx.proc, nm(req, 32))?;
            Ok(Out::Simple(Buf::new().u32(n).done()))
        }
        m::MACH_PORT_INSERT_MEMBER => {
            req.simple(40)?;
            space!();
            ok(port::insert_member(ctx.proc, nm(req, 32), nm(req, 36)))
        }
        m::MACH_PORT_EXTRACT_MEMBER => {
            req.simple(40)?;
            space!();
            ok(port::extract_member(ctx.proc, nm(req, 32), nm(req, 36)))
        }
        m::MACH_PORT_GET_CONTEXT => {
            req.simple(36)?;
            space!();
            let c = port::get_context(ctx.proc, nm(req, 32))?;
            Ok(Out::Simple(Buf::new().u64(c).done()))
        }
        m::MACH_PORT_SET_CONTEXT => {
            req.simple(44)?;
            space!();
            ok(port::set_context(ctx.proc, nm(req, 32), req.u64(36)))
        }
        m::MACH_PORT_KOBJECT => {
            req.simple(36)?;
            space!();
            let t = port::kobject(ctx.proc, nm(req, 32))?;
            Ok(Out::Simple(Buf::new().u32(t).u64(0).done()))
        }
        m::MACH_PORT_CONSTRUCT => {
            req.complex_of(1, 60)?;
            space!();
            let opts = ool_bytes(req, 28)?;
            if opts.len() < port::OPTIONS_SIZE {
                return Err(kr::KERN_INVALID_ARGUMENT);
            }
            let n = port::construct(ctx.proc, &opts, req.u64(52))?;
            Ok(Out::Simple(Buf::new().u32(n).done()))
        }
        m::MACH_PORT_DESTRUCT => {
            req.simple(48)?;
            space!();
            ok(port::destruct(
                ctx.proc,
                nm(req, 32),
                req.i32(36),
                req.u64(40),
            ))
        }
        m::MACH_PORT_GUARD => {
            req.simple(48)?;
            space!();
            ok(port::guard(
                ctx.proc,
                nm(req, 32),
                req.u64(36),
                req.u32(44) != 0,
            ))
        }
        m::MACH_PORT_UNGUARD => {
            req.simple(44)?;
            space!();
            ok(port::unguard(ctx.proc, nm(req, 32), req.u64(36)))
        }
        m::MACH_PORT_SPACE_BASIC_INFO => {
            // ipc_info_space_basic_t: iisb_genno_mask, iisb_table_size,
            // iisb_table_next, iisb_table_inuse, iisb_reserved[2].
            req.simple(24)?;
            space!();
            let inuse = port::names(ctx.proc).len() as u32;
            let size = ctx.proc.ipc.table_size();
            Ok(Out::Simple(
                Buf::new()
                    .u32(0xfc)
                    .u32(size)
                    .u32(size * 2)
                    .u32(inuse)
                    .u32(0)
                    .u32(0)
                    .done(),
            ))
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

/// Takes the port right of the descriptor at `off` with any disposition,
/// with the right's type.
fn take_any(req: &mut Req, off: usize) -> Result<(Option<Right>, u32), KernReturn> {
    use crate::user::darwin::mach::msg::Item;
    let d = match req.items.iter().find(|(p, _)| *p == off) {
        Some((_, Item::Port { disp: d, .. })) => *d,
        _ => return Err(kr::MIG_TYPE_ERROR),
    };
    Ok((req.take_port(off, &[d])?, d))
}

/// The bytes of the out-of-line descriptor at `off`.
fn ool_bytes(req: &mut Req, off: usize) -> Result<Vec<u8>, KernReturn> {
    use crate::user::darwin::mach::msg::Item;
    let i = req
        .items
        .iter()
        .position(|(p, _)| *p == off)
        .ok_or(kr::MIG_TYPE_ERROR)?;
    match req.items.remove(i).1 {
        Item::Ool { data, .. } => Ok(data),
        other => {
            req.items.push((off, other));
            Err(kr::MIG_TYPE_ERROR)
        }
    }
}
