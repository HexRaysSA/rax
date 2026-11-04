//! Native volume queries share argument capture and keep provider records exact.
mod attributes;
mod device;
mod host;
use super::named_object::{Checked, finish_with};
use crate::user::windows::hle::{ApiResult, Ctx};

struct Arguments {
    handle: u64,
    io: u64,
    output: u64,
    length: u32,
    class: u32,
}

pub(super) fn query(c: &mut Ctx) -> ApiResult {
    let mut caller_store = false;
    let result: Checked<u32> = (|| {
        // Capture in ABI argument order under the same guard/status boundary
        // used by both classes, including partially accessible WoW64 stacks.
        let args = Arguments {
            handle: c.ptr(0)?,
            io: c.ptr(1)?,
            output: c.ptr(2)?,
            length: c.u32(3)?,
            class: c.u32(4)?,
        };
        match args.class {
            4 => device::checked(c, &mut caller_store, args),
            5 => attributes::checked(c, &mut caller_store, args),
            class => Err(c
                .unsupported(format!("volume information class {class}"))
                .into()),
        }
    })();
    finish_with(c, result, caller_store)
}
