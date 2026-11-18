//! Pointers a program gave out, in the hands of its host:
//! `rax_portable_v1_value_pointer`.
//!
//! A host has no pointer but one a call returned. It cannot read it, and it
//! cannot make one of a number: all it can do is hand the pointer back to
//! the process it came from, as it is or moved along within the object it
//! points into.

use std::sync::Arc;

use rax_smir_portable::interp::Moved;

use super::imports::in_callback;
use super::{
    EBADF, EDEADLK, EINVAL, ERANGE, Object, REGISTRY, RaxPortableHandleV1, Stage, Status, guarded,
    insert, locked,
};

/// A pointer `offset` bytes on from another, within the object that one
/// points into or to one past its end. The new value is of the same
/// process and may access what the old one may; nothing is read or
/// written. A pointer into no object, such as a null pointer, is moved by
/// nothing only.
///
/// `EBADF` if `pointer_value` is no pointer, or the object it points into
/// is no longer there, or its process has ended or was never called;
/// `ERANGE` if that many bytes on is beyond the object. The question is
/// put to the process between two calls, so it waits for one that is
/// running.
///
/// # Safety
///
/// `value` is room for a handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rax_portable_v1_value_pointer(
    pointer_value: RaxPortableHandleV1,
    offset: u64,
    value: *mut RaxPortableHandleV1,
) -> Status {
    guarded(|| {
        let (process, pointer) = match locked(&REGISTRY).object(pointer_value)? {
            Object::Pointer(process, pointer) => (Arc::clone(process), *pointer),
            _ => return Err(EBADF),
        };
        if value.is_null() {
            return Err(EINVAL);
        }
        // The process answers between two calls: a host function it is
        // calling would wait for itself.
        if in_callback() {
            return Err(EDEADLK);
        }
        // Only a library that still lasts has objects.
        let instance = match &*locked(&process.stage) {
            Stage::Library(instance) => Arc::clone(instance),
            _ => return Err(EBADF),
        };
        let moved = match instance.offset(pointer, offset) {
            Moved::To(moved) => moved,
            Moved::Outside => return Err(ERANGE),
            Moved::Gone => return Err(EBADF),
        };
        // The hold on the process ends before the new value shows, so that
        // whoever has it can join the process.
        drop(instance);
        let handle = insert(Object::Pointer(process, moved));
        // SAFETY: room for a handle, by the caller's promise.
        unsafe { value.write(handle) };
        Ok(())
    })
}
