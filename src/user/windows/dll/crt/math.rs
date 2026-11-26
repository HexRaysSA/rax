//! Floating point helpers used by the built-in Universal CRT.

use crate::user::windows::hle::{ApiResult, Arg::*, Conv::Cdecl, Ctx, Export, Flow};

pub(crate) static UCRT_MATH_EXPORTS: &[Export] = &[Export::func("_o_atan", Cdecl, &[F64], atan)];

pub(crate) static UCRT_SCALAR_MATH_EXPORTS: &[Export] = &[
    Export::func("atan", Cdecl, &[F64], atan),
    Export::func("atanf", Cdecl, &[F32], |c| Flow::f32(c.f32(0)?.atan())),
    Export::func("atan2", Cdecl, &[F64, F64], |c| {
        Flow::f64(c.f64(0)?.atan2(c.f64(1)?))
    }),
    Export::func("atan2f", Cdecl, &[F32, F32], |c| {
        Flow::f32(c.f32(0)?.atan2(c.f32(1)?))
    }),
    Export::func("cos", Cdecl, &[F64], |c| Flow::f64(c.f64(0)?.cos())),
    Export::func("cosf", Cdecl, &[F32], |c| Flow::f32(c.f32(0)?.cos())),
    Export::func("sin", Cdecl, &[F64], |c| Flow::f64(c.f64(0)?.sin())),
    Export::func("sinf", Cdecl, &[F32], |c| Flow::f32(c.f32(0)?.sin())),
    Export::func("tan", Cdecl, &[F64], |c| Flow::f64(c.f64(0)?.tan())),
    Export::func("tanf", Cdecl, &[F32], |c| Flow::f32(c.f32(0)?.tan())),
    Export::func("exp2f", Cdecl, &[F32], |c| Flow::f32(c.f32(0)?.exp2())),
    Export::func("exp2", Cdecl, &[F64], |c| Flow::f64(c.f64(0)?.exp2())),
    Export::func("expf", Cdecl, &[F32], |c| Flow::f32(c.f32(0)?.exp())),
    Export::func("exp", Cdecl, &[F64], |c| Flow::f64(c.f64(0)?.exp())),
    Export::func("log2f", Cdecl, &[F32], |c| Flow::f32(c.f32(0)?.log2())),
    Export::func("log2", Cdecl, &[F64], |c| Flow::f64(c.f64(0)?.log2())),
    Export::func("log10f", Cdecl, &[F32], |c| Flow::f32(c.f32(0)?.log10())),
    Export::func("logf", Cdecl, &[F32], |c| Flow::f32(c.f32(0)?.ln())),
    Export::func("log", Cdecl, &[F64], |c| Flow::f64(c.f64(0)?.ln())),
    Export::func("powf", Cdecl, &[F32, F32], |c| {
        Flow::f32(c.f32(0)?.powf(c.f32(1)?))
    }),
    Export::func("pow", Cdecl, &[F64, F64], |c| {
        Flow::f64(c.f64(0)?.powf(c.f64(1)?))
    }),
];

fn atan(c: &mut Ctx) -> ApiResult {
    Flow::f64(c.f64(0)?.atan())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::windows::arch::{WinArch, WinCpu};
    use crate::user::windows::hle::{Item, Value};
    use crate::user::windows::memory::Mem;

    #[test]
    fn math_reads_and_returns_float_on_all_guest_abis() {
        for (name, samples) in [
            (
                "tanf",
                [(-0.0_f32, -0.0_f32), (std::f32::consts::FRAC_PI_4, 1.0)],
            ),
            ("exp2f", [(-3.0, 0.125), (3.0, 8.0)]),
        ] {
            let Item::Func(api) = &UCRT_SCALAR_MATH_EXPORTS
                .iter()
                .find(|export| export.name == name)
                .unwrap()
                .item
            else {
                panic!("{name} must be a built-in function");
            };
            super::super::tests::run(|c| {
                c.api = api;
                let sp = c.entry_sp;
                for (input, expected) in samples {
                    let raw = input.to_bits();
                    match &mut c.t.cpu {
                        WinCpu::X86(_, WinArch::X86) => c.mem().w32(sp + 4, raw).unwrap(),
                        WinCpu::X86(x, _) => {
                            x.vcpu_mut().user_regs_mut().xmm[0][0] = u64::from(raw)
                        }
                        WinCpu::Arm64(a) => a.core_mut().set_simd(0, u128::from(raw)),
                        WinCpu::Arm64Ec(_) => unreachable!(),
                    }
                    let Flow::Ret(Value::F32(actual)) = (api.imp)(c).unwrap() else {
                        panic!("expected a float return");
                    };
                    if expected == 0.0 {
                        assert_eq!(actual.to_bits(), expected.to_bits());
                    } else {
                        assert!((actual - expected).abs() <= f32::EPSILON);
                    }
                }
            });
        }
    }
}
