//! Captured object-manager names, attributes, output faults and publication status.
pub(super) mod attributes;
use super::query::{guard_result, write_guard_result};
use crate::user::windows::hle::{ApiErr, ApiResult, Ctx, Flow, Value};
use crate::user::windows::memory::{Mem, MemFault};
use crate::user::windows::nt::status::*;
use crate::user::windows::object_namespace::{LookupError, NativeName};
use crate::user::windows::objects::Object;

pub(super) enum Failure {
    Status(u32),
    Api(ApiErr),
}
impl From<MemFault> for Failure {
    fn from(value: MemFault) -> Self {
        Self::Api(value.into())
    }
}
impl From<ApiErr> for Failure {
    fn from(value: ApiErr) -> Self {
        Self::Api(value)
    }
}
pub(super) type Checked<T> = Result<T, Failure>;
pub(super) fn status<T>(value: u32) -> Checked<T> {
    Err(Failure::Status(value))
}
pub(super) fn finish(c: &mut Ctx, result: Checked<u32>) -> ApiResult {
    finish_with(c, result, false)
}
pub(super) fn finish_with(c: &mut Ctx, result: Checked<u32>, caller_write: bool) -> ApiResult {
    finish_flow(c, result.map(nt_return), caller_write)
}

pub(super) fn nt_return(code: u32) -> Flow {
    Flow::Ret(Value::Int(u64::from(code)))
}

pub(super) fn finish_flow(c: &mut Ctx, result: Checked<Flow>, caller_write: bool) -> ApiResult {
    let result = match result {
        Ok(flow) => Ok(flow),
        Err(Failure::Status(s)) => Ok(nt_return(s)),
        Err(Failure::Api(e)) => Err(e),
    };
    let result = if caller_write {
        write_guard_result(c, result)
    } else {
        guard_result(c, result)
    };
    match result {
        Err(ApiErr::Fault(_)) => Flow::ret(STATUS_ACCESS_VIOLATION.into()),
        result => result,
    }
}

pub(super) fn name(
    c: &Ctx,
    attrs: &attributes::Attributes,
    opening: bool,
    kind: &str,
) -> Checked<Option<NativeName>> {
    let Some(units) = &attrs.name else {
        return if attrs.root != 0 {
            status(STATUS_OBJECT_NAME_INVALID)
        } else if opening {
            status(STATUS_OBJECT_PATH_SYNTAX_BAD)
        } else {
            Ok(None)
        };
    };
    if units.is_empty() && !opening {
        return Ok(None);
    }
    let root = if attrs.root == 0 {
        None
    } else {
        let pseudo =
            attrs.root == c.arch().ptr(u64::MAX) || attrs.root == c.arch().ptr(u64::MAX - 1);
        let object = c.p.objects.get(attrs.root);
        if !pseudo && object.is_none() {
            return status(STATUS_INVALID_HANDLE);
        }
        if units.first() == Some(&92) {
            return status(STATUS_OBJECT_PATH_SYNTAX_BAD);
        }
        match object {
            Some(Object::Directory(directory)) => Some(directory.clone()),
            _ => return status(STATUS_OBJECT_TYPE_MISMATCH),
        }
    };
    if units.is_empty() {
        return status(if root.is_some() {
            STATUS_OBJECT_TYPE_MISMATCH
        } else {
            STATUS_OBJECT_PATH_SYNTAX_BAD
        });
    }
    c.p.object_namespace
        .named(root, units, attrs.flags)
        .map(Some)
        .map_err(|error| match error {
            LookupError::Status(code) => Failure::Status(code),
            LookupError::Unselected => c
                .unsupported(format!(
                    "NT {kind} name outside selected guest directory namespace"
                ))
                .into(),
        })
}
