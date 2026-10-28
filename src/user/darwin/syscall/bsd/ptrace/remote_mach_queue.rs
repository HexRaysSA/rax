//! Ordered target-to-parent control and Mach reply queues.

use std::io;

use super::super::{channels::ServerRoute, transport};
use super::{MAX_BACKLOG, MAX_FRAME, MAX_SERVER_FDS, Message, encode_frame, too_large};
use crate::user::darwin::process::Proc;

/// Queues a response without blocking while the tracer is not reading.
/// The additional backlog is bounded separately from the transport queue.
pub(in super::super) fn queue_response(proc: &mut Proc, reply: Message) -> bool {
    queue_response_on(proc, ServerRoute::Parent, reply)
}

pub(in super::super) fn queue_response_on(
    proc: &mut Proc,
    route: ServerRoute,
    reply: Message,
) -> bool {
    let sequence = match &reply {
        Message::Reply { sequence, .. } => Some(*sequence),
        Message::Dead { .. } => None,
        _ => return false,
    };
    let frame = encode_frame(reply).or_else(|_| {
        let Some(sequence) = sequence else {
            return Err(too_large());
        };
        let mut body = crate::user::darwin::mach::msg::NDR_RECORD.to_vec();
        body.extend_from_slice(
            &crate::user::darwin::mach::kr::KERN_RESOURCE_SHORTAGE.to_le_bytes(),
        );
        encode_frame(Message::Reply {
            sequence,
            bits: 0,
            body,
            threads: None,
            memory: None,
        })
    });
    let Ok(frame) = frame else {
        return false;
    };
    let Some(state) = route.server_mut(proc) else {
        return false;
    };
    if sequence.is_none()
        && (!state.notices.is_empty()
            || frame.payload.len() > MAX_BACKLOG.saturating_sub(state.queued_bytes))
    {
        // Stop accepting new requests until these notices have entered
        // the ordered backlog.
        state.notices.push_back(frame.payload);
        return flush_responses_on(proc, route);
    }
    if frame.payload.len() > MAX_BACKLOG.saturating_sub(state.queued_bytes) {
        return false;
    }
    if frame.fd.is_some() && state.queued_fds == MAX_SERVER_FDS {
        return false;
    }
    state.queued_bytes += frame.payload.len();
    state.queued_fds += usize::from(frame.fd.is_some());
    state.replies.push_back(frame);
    let queued = flush_responses_on(proc, route);
    if queued && sequence.is_some() {
        proc.tracing.output_barrier = true;
    }
    queued
}

/// Queues a small local control notification after preceding responses.
pub(in super::super) fn queue_control(proc: &mut Proc, bytes: Vec<u8>) -> bool {
    queue_control_on(proc, ServerRoute::Parent, bytes)
}

pub(in super::super) fn queue_control_on(
    proc: &mut Proc,
    route: ServerRoute,
    bytes: Vec<u8>,
) -> bool {
    try_queue_control_on(proc, route, bytes).is_ok()
}

/// Queues a control frame while preserving the transport error for syscalls.
pub(in super::super) fn try_queue_control(proc: &mut Proc, bytes: Vec<u8>) -> io::Result<()> {
    try_queue_control_on(proc, ServerRoute::Parent, bytes)
}

pub(in super::super) fn try_queue_control_on(
    proc: &mut Proc,
    route: ServerRoute,
    bytes: Vec<u8>,
) -> io::Result<()> {
    if bytes.len() > MAX_FRAME {
        return Err(too_large());
    }
    let state = route.server_mut(proc).ok_or(io::ErrorKind::BrokenPipe)?;
    if !state.notices.is_empty() || bytes.len() > MAX_BACKLOG.saturating_sub(state.queued_bytes) {
        state.notices.push_back(bytes);
    } else {
        state.queued_bytes += bytes.len();
        state.replies.push_back(transport::Frame {
            payload: bytes,
            fd: None,
        });
    }
    try_flush_responses_on(proc, route)
}

/// Transfers queued server responses into the nonblocking link in order.
pub(in super::super) fn flush_responses(proc: &mut Proc) -> bool {
    flush_responses_on(proc, ServerRoute::Parent)
}

pub(in super::super) fn flush_responses_on(proc: &mut Proc, route: ServerRoute) -> bool {
    try_flush_responses_on(proc, route).is_ok()
}

pub(in super::super) fn try_flush_responses(proc: &mut Proc) -> io::Result<()> {
    try_flush_responses_on(proc, ServerRoute::Parent)
}

pub(in super::super) fn try_flush_responses_on(
    proc: &mut Proc,
    route: ServerRoute,
) -> io::Result<()> {
    if route.link(proc).is_none() {
        return if route
            .server(proc)
            .is_some_and(|state| state.replies.is_empty() && state.notices.is_empty())
        {
            Ok(())
        } else {
            Err(io::ErrorKind::BrokenPipe.into())
        };
    }
    let (state, link) = route.parts(proc).ok_or(io::ErrorKind::BrokenPipe)?;
    loop {
        while let Some(bytes) = state.notices.front() {
            if bytes.len() > MAX_BACKLOG.saturating_sub(state.queued_bytes) {
                break;
            }
            let bytes = state.notices.pop_front().expect("front exists");
            state.queued_bytes += bytes.len();
            state.replies.push_back(transport::Frame {
                payload: bytes,
                fd: None,
            });
        }
        while let Some(frame) = state.replies.front() {
            let result = match &frame.fd {
                Some(fd) => link.queue_with_fd(&frame.payload, fd),
                None => link.queue(&frame.payload),
            };
            match result {
                Ok(()) => {
                    state.queued_bytes -= frame.payload.len();
                    state.queued_fds -= usize::from(frame.fd.is_some());
                    state.replies.pop_front();
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        link.flush()?;
        if (state.replies.is_empty() && state.notices.is_empty()) || link.wants_write() {
            return Ok(());
        }
    }
}

pub(in super::super) fn parent_died(proc: &mut Proc) {
    super::token::parent_died(proc);
    super::suspension::parent_died(proc);
    super::callback_runtime::parent_died(proc);
    let state = &mut proc.tracing.family.mach;
    state.parent_server.allowed = false;
    state.parent_server.replies.clear();
    state.parent_server.queued_bytes = 0;
    state.parent_server.queued_fds = 0;
    state.parent_server.notices.clear();
    state.parent_server.failed = false;
    let exports = std::mem::take(&mut state.parent_server.exports);
    crate::user::darwin::syscall::mach::kmsg::release(
        proc,
        exports.into_values().map(|export| export.right),
    );
}
