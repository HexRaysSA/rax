//! Functions of the host that a program calls: their registration with a
//! context, and `rax_portable_v1_call_result_bits`,
//! `rax_portable_v1_call_return` and `rax_portable_v1_host_complete`, by
//! which a host answers a call.
//!
//! A host registers a function with the descriptor that says what it takes
//! and returns: integers and floats, nothing of the program's memory. A
//! program that imports the function, quoting that descriptor's identity,
//! calls it; the call arrives at the host's callback with the arguments as
//! values and a handle for the call. The callback answers by making the
//! results of bits (`call_result_bits`) and returning them
//! (`call_return`), either before it returns itself, or later: it then
//! leaves the call `pending`, and whoever has the answer completes the
//! call from any thread (`host_complete`). The program's thread waits for
//! that.

use std::cell::Cell;
use std::ffi::c_void;
use std::sync::{Arc, Condvar, Mutex};

use rax_smir_portable::ir::{HostDescriptor, Module, Value};

use super::{
    EBADF, EBUSY, EINVAL, ERANGE, Object, REGISTRY, RaxPortableBytesV1, RaxPortableHandleV1,
    RaxPortableHostImportV1, RaxPortablePollV1, Scalar, Status, borrowed, guarded, insert, locked,
    observed, poll_structure, rax_portable_v1_release,
};

/// The callback of a host function, as the contract declares it.
type Call = unsafe extern "C" fn(
    user: *mut c_void,
    call: RaxPortableHandleV1,
    arguments: *const RaxPortableHandleV1,
    count: u64,
    result: *mut RaxPortablePollV1,
) -> Status;

/// A function a host registered with a context.
pub(crate) struct Registered {
    descriptor: HostDescriptor,
    call: Call,
    release: Option<unsafe extern "C" fn(user: *mut c_void)>,
    user: *mut c_void,
}

// SAFETY: `user` is the host's, which registered it to be handed to its
// callbacks from whatever thread a program calls on; nothing here reads it.
unsafe impl Send for Registered {}
// SAFETY: as above.
unsafe impl Sync for Registered {}

impl Registered {
    /// The identity of the descriptor the function was registered with.
    pub(crate) fn identity(&self) -> [u8; 32] {
        self.descriptor.identity
    }
}

impl Drop for Registered {
    /// The host is told, once, when the registration is no longer used: its
    /// context is released and no process of the context is left.
    fn drop(&mut self) {
        if let Some(release) = self.release {
            // SAFETY: the callback and its argument are the host's own, as
            // it registered them.
            unsafe { release(self.user) };
        }
    }
}

/// The functions a configuration registers.
///
/// `EINVAL` for a structure of another size or version, a descriptor that
/// is none, a name that is not the descriptor's (`NAMESPACE:NAME`, or
/// empty), no callback, or two registrations of one function.
///
/// # Safety
///
/// `imports` points to `count` structures whose counted fields are what
/// they say.
pub(crate) unsafe fn registered(
    imports: *const RaxPortableHostImportV1,
    count: u64,
) -> Result<Vec<Arc<Registered>>, Status> {
    let count = usize::try_from(count).map_err(|_| EINVAL)?;
    if count != 0 && imports.is_null() {
        return Err(EINVAL);
    }
    // All of them are looked at before any is registered: a configuration
    // that is refused has registered nothing, and nothing is released.
    let mut described: Vec<(HostDescriptor, &RaxPortableHostImportV1)> = Vec::with_capacity(count);
    for index in 0..count {
        // SAFETY: `imports` has `count` elements.
        let import = unsafe { &*imports.add(index) };
        if import.size as usize != size_of::<RaxPortableHostImportV1>() || import.version != 1 {
            return Err(EINVAL);
        }
        // SAFETY: counted bytes of the caller's.
        let (name, record) = unsafe {
            (
                borrowed(import.name)?,
                borrowed(import.admitted_descriptor)?,
            )
        };
        let descriptor = HostDescriptor::decode(record).map_err(|_| EINVAL)?;
        let named = format!("{}:{}", descriptor.namespace, descriptor.name);
        if !(name.is_empty() || name == named.as_bytes())
            || import.call.is_null()
            || described
                .iter()
                .any(|(other, _)| other.identity == descriptor.identity)
        {
            return Err(EINVAL);
        }
        described.push((descriptor, import));
    }
    Ok(described
        .into_iter()
        .map(|(descriptor, import)| {
            Arc::new(Registered {
                descriptor,
                // SAFETY: the contract's callback types; the pointers are
                // the host's functions of those types, and the first is
                // not null.
                call: unsafe { std::mem::transmute::<*const c_void, Call>(import.call) },
                release: unsafe {
                    std::mem::transmute::<*const c_void, Option<unsafe extern "C" fn(*mut c_void)>>(
                        import.release,
                    )
                },
                user: import.user,
            })
        })
        .collect())
}

/// Whether the functions registered are all that `module` imports from its
/// host, each described as the module imports it.
pub(crate) fn has_all(functions: &[Arc<Registered>], module: &Module) -> bool {
    module.host_imports().iter().all(|import| {
        functions
            .iter()
            .any(|function| function.descriptor.describes(module, import))
    })
}

/// One call of a host function, from when the program makes it to when the
/// host has answered.
pub(crate) struct HostCall {
    /// How many bits each result has.
    results: Vec<u32>,
    state: Mutex<Answer>,
    changed: Condvar,
}

#[derive(Default)]
struct Answer {
    /// The results `call_return` took, until the call is completed.
    prepared: Option<Vec<u128>>,
    /// How the call came out: the results, or that the host failed.
    done: Option<Option<Vec<u128>>>,
    /// The program no longer waits: nothing more is taken.
    closed: bool,
}

thread_local! {
    /// Whether this thread is inside a host function's callback.
    static CALLED: Cell<bool> = const { Cell::new(false) };
}

/// Whether the calling thread is inside the callback of a host function,
/// where it must not wait for the program that waits for it.
pub(crate) fn in_callback() -> bool {
    CALLED.with(Cell::get)
}

/// Call a registered function with the bits of its arguments and wait for
/// its answer: the bits of its results, or nothing if the host failed.
pub(crate) fn perform(function: &Registered, arguments: &[u128]) -> Option<Vec<u128>> {
    let (takes, returns) = function.descriptor.widths();
    let call = Arc::new(HostCall {
        results: returns,
        state: Mutex::new(Answer::default()),
        changed: Condvar::new(),
    });
    let handle = insert(Object::HostCall(Arc::clone(&call)));
    // The arguments are values the callback borrows.
    let values: Vec<RaxPortableHandleV1> = arguments
        .iter()
        .zip(&takes)
        .map(|(bits, width)| {
            insert(Object::Value(Scalar {
                value: Value::Int(*bits),
                bits: *width,
            }))
        })
        .collect();
    let mut poll = RaxPortablePollV1 {
        size: size_of::<RaxPortablePollV1>() as u32,
        version: 1,
        state: RaxPortableBytesV1 {
            data: std::ptr::null(),
            length: 0,
        },
        result: RaxPortableHandleV1::default(),
        error: 0,
        reserved0: 0,
    };
    let was = CALLED.with(|called| called.replace(true));
    // SAFETY: the host's callback, with its own argument, as many values as
    // are counted and a poll structure of this version.
    let status = unsafe {
        (function.call)(
            function.user,
            handle,
            values.as_ptr(),
            values.len() as u64,
            &raw mut poll,
        )
    };
    CALLED.with(|called| called.set(was));
    for value in values {
        rax_portable_v1_release(value);
    }
    // What the callback left in the structure: `returned` by `call_return`,
    // or `pending`, its own word for an answer that comes later.
    let said: &[u8] = if poll.state.data.is_null() || poll.state.length > 16 {
        b""
    } else {
        // SAFETY: the callback left counted bytes there, its own or ours.
        unsafe { std::slice::from_raw_parts(poll.state.data, poll.state.length as usize) }
    };
    let mut answer = locked(&call.state);
    let results = match (status, said) {
        (0, b"returned") => answer.prepared.take(),
        (0, b"pending") => {
            while answer.done.is_none() {
                answer = call
                    .changed
                    .wait(answer)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
            answer.done.take().flatten()
        }
        _ => None,
    };
    answer.closed = true;
    drop(answer);
    rax_portable_v1_release(handle);
    results.filter(|results| results.len() == call.results.len())
}

fn call_of(handle: RaxPortableHandleV1) -> Result<Arc<HostCall>, Status> {
    match locked(&REGISTRY).object(handle)? {
        Object::HostCall(call) => Ok(Arc::clone(call)),
        _ => Err(EBADF),
    }
}

/// A result of a call of a host function, from its bits: the value at
/// `result_index` of what the function returns, in as many bytes as its
/// type has, least significant first.
///
/// `EBADF` if `call` is no call of a host function; `ERANGE` for an index
/// beyond the function's results; `EINVAL` for bytes of another length or
/// bits beyond the type's width.
///
/// # Safety
///
/// `bits` is counted bytes of the caller's and `value` room for a handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rax_portable_v1_call_result_bits(
    call: RaxPortableHandleV1,
    result_index: u64,
    bits: RaxPortableBytesV1,
    value: *mut RaxPortableHandleV1,
) -> Status {
    guarded(|| {
        let call = call_of(call)?;
        if value.is_null() {
            return Err(EINVAL);
        }
        let width = usize::try_from(result_index)
            .ok()
            .and_then(|index| call.results.get(index).copied())
            .ok_or(ERANGE)?;
        // SAFETY: the caller's promise.
        let given = unsafe { borrowed(bits)? };
        if given.len() != width.div_ceil(8) as usize {
            return Err(EINVAL);
        }
        let mut wide = [0_u8; 16];
        wide[..given.len()].copy_from_slice(given);
        let number = u128::from_le_bytes(wide);
        if width < 128 && number >> width != 0 {
            return Err(EINVAL);
        }
        let handle = insert(Object::Value(Scalar {
            value: Value::Int(number),
            bits: width,
        }));
        // SAFETY: room for a handle, by the caller's promise.
        unsafe { value.write(handle) };
        Ok(())
    })
}

/// Return from a call of a host function: `values` are its results, as
/// many and as wide as the function returns. `completion` then says
/// `returned`. A callback that hands it the structure it was given, and
/// returns, has answered the call; otherwise the call is answered when
/// `completion` is given to `rax_portable_v1_host_complete`.
///
/// `EBADF` if `call` is no call of a host function, or a value is none;
/// `EINVAL` if the values are not in number and width what the function
/// returns; `EBUSY` if the call has its results already, or the program no
/// longer waits for it.
///
/// # Safety
///
/// `values` points to `count` handles, and `completion` to a
/// `RaxPortablePollV1` with its size and version set.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rax_portable_v1_call_return(
    call: RaxPortableHandleV1,
    values: *const RaxPortableHandleV1,
    count: u64,
    completion: *mut RaxPortablePollV1,
) -> Status {
    guarded(|| {
        let call = call_of(call)?;
        // SAFETY: the caller's promise.
        unsafe { poll_structure(completion)? };
        if usize::try_from(count).ok() != Some(call.results.len())
            || (count != 0 && values.is_null())
        {
            return Err(EINVAL);
        }
        let mut results = Vec::with_capacity(call.results.len());
        for (index, width) in call.results.iter().enumerate() {
            // SAFETY: `values` has `count` handles.
            let handle = unsafe { *values.add(index) };
            match locked(&REGISTRY).object(handle)? {
                Object::Value(Scalar {
                    value: Value::Int(bits),
                    bits: given,
                }) if given == width => results.push(*bits),
                Object::Value(_) => return Err(EINVAL),
                _ => return Err(EBADF),
            }
        }
        let mut answer = locked(&call.state);
        if answer.closed || answer.prepared.is_some() || answer.done.is_some() {
            return Err(EBUSY);
        }
        answer.prepared = Some(results);
        // SAFETY: the structure was checked.
        unsafe { observed(completion, b"returned", RaxPortableHandleV1::default(), 0) };
        Ok(())
    })
}

/// Complete a call of a host function that its callback left `pending`,
/// from any thread: with the results `rax_portable_v1_call_return` took,
/// if `result` says `returned`, or as a failure of the host, which ends the
/// program, if it says `failed`. The program's thread goes on.
///
/// `EBADF` if `call` is no call of a host function; `EINVAL` if `result` is
/// no such structure, says something else, or says `returned` of a call
/// that has no results yet; `EBUSY` if the call was completed already, or
/// the program no longer waits for it.
///
/// # Safety
///
/// `result` points to a `RaxPortablePollV1` whose state is counted bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rax_portable_v1_host_complete(
    call: RaxPortableHandleV1,
    result: *const RaxPortablePollV1,
) -> Status {
    guarded(|| {
        let call = call_of(call)?;
        // SAFETY: the caller's promise; the structure is only read.
        unsafe { poll_structure(result.cast_mut())? };
        // SAFETY: the structure is this one, and its state counted bytes.
        let said = unsafe { borrowed((*result).state)? };
        let mut answer = locked(&call.state);
        if answer.closed || answer.done.is_some() {
            return Err(EBUSY);
        }
        answer.done = Some(match said {
            b"returned" => Some(answer.prepared.take().ok_or(EINVAL)?),
            b"failed" => None,
            _ => return Err(EINVAL),
        });
        call.changed.notify_all();
        Ok(())
    })
}
