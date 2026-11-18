//! Modules linked into one program: `rax_portable_x1_module_link`.

use std::sync::Arc;

use rax_smir_portable::ir::Module;

use super::{
    EBADF, EINVAL, ENOEXEC, Object, REGISTRY, RaxPortableHandleV1, Status, admitted, context_of,
    guarded, locked,
};

/// Link modules of a context into one program, which is a module of the
/// context like any other: a process is made of it, and its functions are
/// looked up in it. See `rax_portable_extensions_v1.h`.
///
/// The first module is the program, whose exported functions and whose
/// types the linked module has; the others are the modules it and they
/// depend on, in any order. The modules given stay what they were.
///
/// `EINVAL` for no modules; `EBADF` for a handle that is no module of this
/// context; `ENOEXEC` if they do not link: a dependency that none or more
/// than one of them answers, a function that is missing or of another
/// type, modules that need one another in a circle, or one nobody needs;
/// `ENOTSUP` if the context wants code for this host and there is none to
/// be had.
///
/// # Safety
///
/// `modules` points to `count` handles and `linked` to room for one.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rax_portable_x1_module_link(
    context: RaxPortableHandleV1,
    modules: *const RaxPortableHandleV1,
    count: u64,
    linked: *mut RaxPortableHandleV1,
) -> Status {
    guarded(|| {
        let context = context_of(context)?;
        let count = usize::try_from(count).map_err(|_| EINVAL)?;
        if count == 0 || modules.is_null() || linked.is_null() {
            return Err(EINVAL);
        }
        let mut parts = Vec::with_capacity(count);
        for index in 0..count {
            // SAFETY: `modules` has `count` elements.
            let handle = unsafe { *modules.add(index) };
            match locked(&REGISTRY).object(handle)? {
                Object::Module(owner, loaded) if Arc::ptr_eq(owner, &context) => {
                    parts.push(Module::clone(&loaded.module));
                }
                _ => return Err(EBADF),
            }
        }
        let program = Module::link(parts).map_err(|_| ENOEXEC)?;
        let handle = admitted(context, program)?;
        // SAFETY: room for a handle, by the caller's promise.
        unsafe { linked.write(handle) };
        Ok(())
    })
}
