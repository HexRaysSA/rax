//! The voucher traps (`osfmk/ipc/mach_kernelrpc.c`, `osfmk/ipc/ipc_voucher.c`):
//! `host_create_mach_voucher_trap`, `mach_voucher_extract_attr_recipe_trap`,
//! and `mach_generate_activity_id`.

use std::sync::Arc;

use crate::user::darwin::mach::ipc::{KObject, MACH_PORT_DEAD, MACH_PORT_NULL, PortName};
use crate::user::darwin::mach::kr::{self, KernReturn};
use crate::user::darwin::mach::voucher::{self, Attrs};
use crate::user::darwin::process::Proc;
use crate::user::darwin::syscall::Ctx;

/// `MACH_ACTIVITY_ID_COUNT_MAX`.
const ACTIVITY_ID_COUNT_MAX: i32 = 16;
/// `EFAULT`: `mach_generate_activity_id` returns its copy-out's errno.
const EFAULT: KernReturn = 14;

/// The voucher values `name` holds a send right to
/// (`convert_port_name_to_voucher`).
pub fn voucher_of(proc: &Proc, name: PortName) -> Option<Arc<Attrs>> {
    if name == MACH_PORT_NULL || name == MACH_PORT_DEAD {
        return None;
    }
    let e = proc.ipc.lookup(name).ok().filter(|e| e.send > 0)?;
    voucher::attrs_of(e.port()?).cloned()
}

/// Runs `recipes` with previous-voucher names from `proc`'s space.
pub fn create(proc: &Proc, recipes: &[u8]) -> Result<Option<Attrs>, KernReturn> {
    voucher::create(recipes, |n| voucher_of(proc, n).map(|a| (*a).clone()))
}

/// `host_create_mach_voucher_trap(host, recipes, recipes_size, voucher)`:
/// the host name, then the size (a negative one invalid, one past
/// `MACH_VOUCHER_ATTR_MAX_RAW_RECIPE_ARRAY_SIZE` too large), then the
/// recipes; the new voucher's send right is named in the caller's space
/// (with the name it already has for the voucher, if any) even when the
/// name cannot be stored. An empty array makes no voucher (name 0).
pub fn host_create(
    ctx: &mut Ctx<'_>,
    host: PortName,
    recipes: u64,
    size: i32,
    out: u64,
) -> KernReturn {
    let is_host = host != MACH_PORT_NULL
        && host != MACH_PORT_DEAD
        && ctx
            .proc
            .ipc
            .lookup(host)
            .ok()
            .filter(|e| e.send > 0)
            .and_then(|e| e.port())
            .is_some_and(|p| matches!(p.kobject, KObject::Host | KObject::HostPriv));
    if !is_host {
        return kr::MACH_SEND_INVALID_DEST;
    }
    if size < 0 {
        return kr::KERN_INVALID_ARGUMENT;
    }
    if size as usize > voucher::MAX_RECIPE_ARRAY {
        return kr::MIG_ARRAY_TOO_LARGE;
    }
    let Ok(bytes) = ctx.read(recipes, size as usize) else {
        return kr::KERN_MEMORY_ERROR;
    };
    let name = match create(ctx.proc, &bytes) {
        Ok(None) => MACH_PORT_NULL,
        Ok(Some(a)) => {
            let port = ctx.proc.vouchers.canonical(a);
            ctx.proc.insert_send(&port)
        }
        Err(k) => return k,
    };
    match ctx.write_u32(out, name) {
        Ok(()) => kr::KERN_SUCCESS,
        Err(_) => kr::KERN_MEMORY_ERROR,
    }
}

/// `mach_voucher_extract_attr_recipe_trap(voucher, key, recipe,
/// recipe_size)`: the size first, then the voucher, then the caller's
/// buffer is read (a fault there fails even when there is nothing to
/// extract), then the recipe and its size are stored. On failure the size
/// is left as it was.
pub fn extract_recipe(
    ctx: &mut Ctx<'_>,
    name: PortName,
    key: u32,
    recipe: u64,
    size_addr: u64,
) -> KernReturn {
    let Ok(size) = ctx.read_u32(size_addr) else {
        return kr::KERN_MEMORY_ERROR;
    };
    let size = size as usize;
    if size > voucher::MAX_RECIPE_ARRAY {
        return kr::MIG_ARRAY_TOO_LARGE;
    }
    let Some(attrs) = voucher_of(ctx.proc, name) else {
        return kr::MACH_SEND_INVALID_DEST;
    };
    if ctx.read(recipe, size).is_err() {
        return kr::KERN_MEMORY_ERROR;
    }
    let r = match voucher::extract_recipe(&attrs, key, size, ctx.proc.pid) {
        Ok(r) => r,
        Err(k) => return k,
    };
    if !r.is_empty() && ctx.write(recipe, &r).is_err() {
        return kr::KERN_MEMORY_ERROR;
    }
    match ctx.write_u32(size_addr, r.len() as u32) {
        Ok(()) => kr::KERN_SUCCESS,
        Err(_) => kr::KERN_MEMORY_ERROR,
    }
}

/// `mach_generate_activity_id(target, count, activity_id)`: reserves
/// `count` (1-16) activity IDs and stores the first; `target` is not
/// looked at. IDs come from one counter for the whole system: on a macOS
/// host the host kernel's, elsewhere the process's own. A failed store
/// returns `EFAULT` with the IDs already taken.
pub fn generate_activity_id(ctx: &mut Ctx<'_>, count: i32, out: u64) -> KernReturn {
    if count <= 0 || count > ACTIVITY_ID_COUNT_MAX {
        return kr::KERN_INVALID_ARGUMENT;
    }
    let id = ctx.proc.vouchers.activity_ids(ctx.proc.pid, count as u64);
    match ctx.write_u64(out, id) {
        Ok(()) => kr::KERN_SUCCESS,
        Err(_) => EFAULT,
    }
}
