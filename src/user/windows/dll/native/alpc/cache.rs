//! The translation-cache peer owns every reply until acknowledgement.
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::STATUS_SUCCESS;
use crate::user::windows::objects::Object;

mod lookup;
pub(super) use lookup::lookup;

pub(super) fn release_reply(c: &mut Ctx, port: u64, message: u64, other: [u64; 5]) -> ApiResult {
    if other != [0; 5] {
        return Err(c.unsupported("cache reply release options are not selected"));
    }
    let expected = match c.p.objects.get(port) {
        Some(Object::LpcPort(endpoint)) => endpoint
            .cache_peer()
            .and_then(|peer| peer.pending_reply.clone()),
        _ => None,
    }
    .ok_or_else(|| c.unsupported("cache endpoint has no pending reply"))?;
    if c.mem().bytes(message, expected.len())? != expected {
        return Err(c.unsupported("cache endpoint does not own the supplied connection reply"));
    }
    let Some(Object::LpcPort(endpoint)) = c.p.objects.get_mut(port) else {
        unreachable!("captured owned cache endpoint")
    };
    endpoint
        .cache_peer_mut()
        .expect("captured cache peer")
        .pending_reply = None;
    // Native RELEASE_MESSAGE acknowledges kernel message ownership. It does
    // not send application data, change the caller buffer or retire the Section.
    Flow::ret(STATUS_SUCCESS.into())
}
