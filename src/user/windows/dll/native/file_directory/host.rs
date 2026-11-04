//! Only retained handles, captured UTF-16 and initialized host storage cross FFI.
#[cfg(windows)]
mod windows;
use super::{Checked, Completion, Ctx, Request};

pub(super) fn query(c: &mut Ctx, request: Request) -> Checked<Completion> {
    #[cfg(windows)]
    {
        windows::query(c, request)
    }
    #[cfg(unix)]
    {
        super::portable::query(c, request)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = request;
        Err(c
            .unsupported("directory enumeration host adapter unavailable")
            .into())
    }
}
