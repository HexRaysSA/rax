//! Captured primary-token properties with measured caller-probe ordering.
mod bno_copy;
mod claims;
mod groups;
mod statistics;
mod user;

use super::query::{guard_result, probe_write, write_guard_result};
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;
use crate::user::windows::security::token::claims::{TOKEN_DEVICE_CLAIMS, TOKEN_USER_CLAIMS};
use crate::user::windows::security::token::scalars::{self, CapturedScalar};

const TOKEN_USER: u32 = 1;
const TOKEN_GROUPS: u32 = 2;
const TOKEN_INTEGRITY_LEVEL: u32 = 25;
const SE_GROUP_INTEGRITY: u32 = 0x20;

pub(super) fn information(c: &mut Ctx) -> ApiResult {
    let mut direct_copies = false;
    let result = checked(c, &mut direct_copies);
    if direct_copies {
        write_guard_result(c, result)
    } else {
        guard_result(c, result)
    }
}

fn checked(c: &mut Ctx, direct_copies: &mut bool) -> ApiResult {
    let (token, class, output, length, returned) =
        (c.ptr(0)?, c.u32(1)?, c.ptr(2)?, c.u32(3)?, c.ptr(4)?);
    let token_kind = matches!(class, 8 | 9)
        && c.arch() == WinArch::Arm64
        && c.p.native.as_ref().is_some_and(|runtime| {
            let version = &runtime.version;
            (version.major, version.minor, version.build) == (10, 0, 29708)
                && runtime.object_namespace.native_machine == Some(0xaa64)
        });
    let sid_record = matches!(class, TOKEN_USER | TOKEN_INTEGRITY_LEVEL);
    let claim_record = matches!(class, TOKEN_USER_CLAIMS | TOKEN_DEVICE_CLAIMS);
    if !token_kind
        && !sid_record
        && !claim_record
        && !matches!(class, TOKEN_GROUPS | 10 | 12 | 29 | 44)
        && !scalars::is_class(class)
    {
        return Err(c.unsupported(format!("NtQueryInformationToken class {class}")));
    }
    // These WoW64 wrappers reject the selector without touching either
    // destination, unlike the native64 class checks below.
    if c.arch() == WinArch::X86 && matches!(class, 40 | 45) {
        return Flow::ret(STATUS_INVALID_INFO_CLASS.into());
    }
    // WoW64 token converters use private native results, followed by
    // direct caller stores. They do not align or preflight the caller capacity.
    *direct_copies = c.arch() == WinArch::X86
        && (sid_record || claim_record || matches!(class, TOKEN_GROUPS | 10 | 44));
    if c.arch() == WinArch::X86
        && sid_record
        && let Some(status) = user::preflight(c, output, length, returned)?
    {
        return Flow::ret(status.into());
    }
    if c.arch() == WinArch::X86
        && class == 10
        && let Some(status) = statistics::preflight(c, output, length, returned)?
    {
        return Flow::ret(status.into());
    }
    if !*direct_copies && length != 0 {
        if output % 4 != 0 {
            return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
        }
        probe_write(c, output, length as usize)?;
    }
    if !*direct_copies {
        probe_write(c, returned, 4)?;
    }
    let property = c.p.objects.primary_token_scalar(class);
    // A captured native invalid-class result follows both probes but precedes
    // handle/type/access checks. It never publishes ReturnLength.
    if property == Some(CapturedScalar::InvalidClass) {
        return Flow::ret(STATUS_INVALID_INFO_CLASS.into());
    }
    // TOKEN_ELEVATION publishes its exact required size before validating
    // the handle, and rejects both shorter and longer buffers.
    if class == 20 {
        c.mem().w32(returned, 4)?;
        if length != 4 {
            return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
        }
    }
    let process_token = c.arch().ptr(u64::MAX - 3);
    let thread_token = c.arch().ptr(u64::MAX - 4);
    let effective_token = c.arch().ptr(u64::MAX - 5);
    if token == thread_token {
        return user::handle_error(c, class, returned, STATUS_NO_TOKEN);
    }
    let mut captured_value = None;
    let mut captured_subject = None;
    if token != process_token && token != effective_token {
        if token == c.arch().ptr(u64::MAX) || token == c.arch().ptr(u64::MAX - 1) {
            return user::handle_error(c, class, returned, STATUS_OBJECT_TYPE_MISMATCH);
        }
        match c.p.objects.get(token) {
            None => return user::handle_error(c, class, returned, STATUS_INVALID_HANDLE),
            Some(Object::PrimaryToken) => {
                if c.p.objects.access(token).unwrap_or(0) & 8 == 0 {
                    return user::handle_error(c, class, returned, STATUS_ACCESS_DENIED);
                }
            }
            Some(Object::ImpersonationToken(subject)) => {
                if c.p.objects.access(token).unwrap_or(0) & 8 == 0 {
                    return user::handle_error(c, class, returned, STATUS_ACCESS_DENIED);
                }
                if sid_record || claim_record || matches!(class, TOKEN_GROUPS | 10) {
                    captured_subject = Some(subject.clone());
                } else if class != 29 {
                    return Err(c.unsupported(if class == 12 {
                        "impersonation-token SessionId is not captured".to_owned()
                    } else {
                        format!("impersonation-token class {class} is not captured")
                    }));
                } else {
                    captured_value = Some(u32::from(subject.app_container));
                }
            }
            Some(Object::GuestImpersonationToken { subject, level }) => {
                if c.p.objects.access(token).unwrap_or(0) & 8 == 0 {
                    return user::handle_error(c, class, returned, STATUS_ACCESS_DENIED);
                }
                match class {
                    TOKEN_USER
                    | TOKEN_GROUPS
                    | TOKEN_INTEGRITY_LEVEL
                    | TOKEN_USER_CLAIMS
                    | TOKEN_DEVICE_CLAIMS => {
                        captured_subject = Some(subject.clone());
                    }
                    8 => captured_value = Some(2),
                    9 => captured_value = Some(*level),
                    29 => captured_value = Some(u32::from(subject.app_container)),
                    _ => {
                        return Err(
                            c.unsupported(format!("guest impersonation-token class {class}"))
                        );
                    }
                }
            }
            Some(Object::Opaque("Token")) => {
                return Err(c.unsupported("opaque token has no modeled primary subject"));
            }
            Some(_) => return user::handle_error(c, class, returned, STATUS_OBJECT_TYPE_MISMATCH),
        }
    }
    if claim_record {
        let subject = captured_subject
            .or_else(|| c.p.objects.primary_token_subject())
            .ok_or_else(|| c.unsupported("token claim subject is not captured"))?;
        let empty = if class == TOKEN_USER_CLAIMS {
            subject.empty_claims.user
        } else {
            subject.empty_claims.device
        };
        if !empty {
            return Err(c.unsupported("token claims lack a supported empty capture"));
        }
        return claims::publish_empty(c, output, length, returned);
    }
    if class == TOKEN_GROUPS {
        let subject = captured_subject
            .or_else(|| c.p.objects.primary_token_subject())
            .ok_or_else(|| c.unsupported("token groups are not captured"))?;
        return groups::publish(c, &subject.groups, output, length, returned);
    }
    if sid_record {
        let subject = captured_subject
            .or_else(|| c.p.objects.primary_token_subject())
            .ok_or_else(|| {
                c.unsupported(if class == TOKEN_USER {
                    "primary-token user SID is not captured"
                } else {
                    "token integrity SID is not captured"
                })
            })?;
        let (sid, attributes) = if class == TOKEN_USER {
            (subject.user.as_slice(), subject.user_attributes)
        } else {
            let mut labels = subject
                .groups
                .iter()
                .filter(|group| group.attributes & SE_GROUP_INTEGRITY != 0);
            let Some(label) = labels.next() else {
                return Err(c.unsupported("token integrity SID is not captured"));
            };
            if labels.next().is_some() {
                return Err(c.unsupported("token has multiple integrity SIDs"));
            }
            (label.sid.as_slice(), label.attributes)
        };
        return user::publish(c, sid, attributes, output, length, returned);
    }
    if class == 44 {
        return bno_information(c, output, length, returned);
    }
    if class == 10 {
        let expected_type = if captured_subject.is_some() { 2 } else { 1 };
        let subject = captured_subject
            .or_else(|| c.p.objects.primary_token_subject())
            .ok_or_else(|| c.unsupported("token statistics subject is not captured"))?;
        return statistics::publish(c, &subject, expected_type, output, length, returned);
    }
    let primary = match class {
        // Native TokenType uses the supplied token object's kind. A query of
        // a primary token's impersonation level fails after handle admission.
        8 => Some(1),
        9 if captured_value.is_none() => return Flow::ret(STATUS_INVALID_INFO_CLASS.into()),
        12 if c.p.objects.primary_token_app_container().is_some() => {
            c.p.objects.primary_token_session_id()
        }
        29 => c.p.objects.primary_token_app_container().map(u32::from),
        _ if c.p.objects.primary_token_app_container().is_some() => match property {
            Some(CapturedScalar::Value(value)) => Some(value),
            _ => None,
        },
        _ => None,
    };
    let Some(value) = captured_value.or(primary) else {
        return Err(c.unsupported(if class == 12 {
            "primary-token SessionId is not captured"
        } else if class == 29 {
            "primary-token subject is not captured"
        } else {
            "primary-token scalar property is not captured"
        }));
    };
    // Native writes the required length before either short-buffer return or
    // successful data publication. Overlapping output therefore wins.
    let required = scalars::width(class).unwrap_or(4);
    c.mem().w32(returned, required)?;
    if length < required {
        return Flow::ret(STATUS_BUFFER_TOO_SMALL.into());
    }
    if required == 1 {
        c.mem().w8(output, value as u8)?;
    } else {
        c.mem().w32(output, value)?;
    }
    Flow::ret(STATUS_SUCCESS.into())
}

fn bno_information(c: &mut Ctx, output: u64, length: u32, returned: u64) -> ApiResult {
    if c.p.objects.primary_token_app_container().is_none() {
        return Err(c.unsupported("primary-token subject is not captured"));
    }
    let value =
        c.p.objects
            .primary_token_bno()
            .ok_or_else(|| c.unsupported("primary-token BNO isolation is not captured"))?;
    let width = c.psize() as usize;
    let required = value
        .required_bytes(width)
        .ok_or_else(|| c.unsupported("TokenBnoIsolation pointer width is unsupported"))?;
    c.mem().w32(returned, required)?;
    if length < required {
        return Flow::ret(STATUS_BUFFER_TOO_SMALL.into());
    }
    let header = (2 * width) as u64;
    // The converter clears the pointer before publishing the enabled flag.
    // A later flag fault therefore leaves NULL. Once the flag is stored, the
    // pointer is published before the bounded prefix copy is attempted.
    c.write_ptr(output, 0)?;
    c.mem()
        .w8(output + width as u64, u8::from(value.prefix().is_some()))?;
    if let Some(prefix) = value.prefix() {
        c.write_ptr(output, output + header)?;
        if c.arch() == WinArch::X86 {
            let bytes: Vec<_> = prefix
                .iter()
                .copied()
                .chain(std::iter::once(0))
                .flat_map(u16::to_le_bytes)
                .collect();
            bno_copy::copy(c, output + header, &bytes)?;
        } else {
            c.mem().put_wstr(output + header, prefix)?;
        }
    }
    Flow::ret(STATUS_SUCCESS.into())
}
