//! UCRT host-backed secure random numbers.

use crate::user::entropy;
use crate::user::windows::hle::{ApiResult, Arg::Ptr, Conv::Cdecl, Ctx, Export, Flow};
use crate::user::windows::memory::Mem;

use super::{RuntimeKind, invalid, state};

pub(crate) static UCRT_RANDOM_EXPORTS: &[Export] = &[Export::func("rand_s", Cdecl, &[Ptr], rand_s)];

fn rand_s(c: &mut Ctx) -> ApiResult {
    const EINVAL: u32 = 22;
    const ENOMEM: u32 = 12;

    let output = c.ptr(0)?;
    let kind = RuntimeKind::Ucrt;
    if output == 0 {
        state::set_errno(c, kind, EINVAL)?;
        return invalid::invoke(c, kind, [0; 5], Box::new(|_, _| Flow::ret(EINVAL.into())));
    }

    c.mem().w32(output, 0)?;
    let mut sample = [0; 4];
    if entropy::fill(&mut sample).is_err() {
        state::set_errno(c, kind, ENOMEM)?;
        return Flow::ret(ENOMEM.into());
    }
    c.mem().wr(output, &sample)?;
    Flow::ret(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::windows::dll::crt::tests::{area, int, invoke, run};

    #[test]
    fn rand_s_preserves_the_adjacent_word_and_reaches_invalid_parameter_handling() {
        run(|c| {
            let kind = RuntimeKind::Ucrt;
            let at = area(c);
            c.mem().w64(at, u64::MAX).unwrap();
            let status = int(invoke(c, kind, "rand_s", &[at]));
            if cfg!(all(
                target_family = "wasm",
                any(target_os = "unknown", target_os = "none")
            )) {
                assert_eq!(status, 12);
                assert_eq!(c.mem().u32(at).unwrap(), 0);
            } else {
                assert_eq!(status, 0);
            }
            assert_eq!(c.mem().u32(at + 4).unwrap(), u32::MAX);
            let handler = 0x12340;
            int(invoke(
                c,
                kind,
                "_set_invalid_parameter_handler",
                &[handler],
            ));
            let Flow::Call { target, then, .. } = invoke(c, kind, "rand_s", &[0]).unwrap() else {
                panic!("invalid parameter callback");
            };
            assert_eq!(target, handler);
            let errno = int(invoke(c, kind, "_errno", &[]));
            assert_eq!(c.mem().u32(errno).unwrap(), 22);
            assert_eq!(int(then(c, 0)), 22);
        });
    }
}
