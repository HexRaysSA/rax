//! ThreadTebInformation reads a bounded span of an owned guest TEB.
//! Layout and private-kernel boundary observations are retained in
//! docs/specifications/windows/native-thread-teb/.
use super::*;

const THREAD_GET_SET_CONTEXT: u32 = 0x18;
const STATUS_THREAD_IS_TERMINATING: u32 = 0xc000_004b;

pub(super) fn information(
    c: &mut Ctx,
    handle: u64,
    record: u64,
    length: u32,
    returned: u64,
) -> ApiResult {
    let result = query(c, handle, record, length, returned);
    // Both the native entry's probes and the WoW conversion visit read-only
    // guards. This differs from the direct output stores of classes9/12/17.
    guard_result(c, result)
}

fn query(c: &mut Ctx, handle: u64, record: u64, length: u32, returned: u64) -> ApiResult {
    let wow64 = c.arch() == WinArch::X86;
    if !wow64 {
        // Native alignment applies once the supplied span reaches a ULONG,
        // before ReturnLength. Shorter spans still probe ReturnLength before
        // rejecting the descriptor length. Independent combined-fault captures
        // distinguish all three stages, including guard consumption.
        if length >= 4 && record % 4 != 0 {
            return Flow::ret(STATUS_DATATYPE_MISALIGNMENT.into());
        }
        if length != 0
            && record
                .checked_add(u64::from(length))
                .is_none_or(|end| end > c.p.vm.high())
        {
            return Flow::ret(STATUS_ACCESS_VIOLATION.into());
        }
        if returned != 0 {
            probe_write(c, returned, 4)?;
        }
        if length != 16 {
            return Flow::ret(STATUS_INFO_LENGTH_MISMATCH.into());
        }
    }
    // Snapshot the complete descriptor before any aliased destination store.
    // WoW64 converts its12-byte descriptor regardless of supplied length and
    // permits unaligned input; native64 requires an exact16-byte descriptor.
    let width = if wow64 { 4 } else { 8 };
    let output = c.mem().ptr(record, width)?;
    let offset = c.mem().u32(record + width)?;
    let count = c.mem().u32(record + width + 4)?;
    // The selected WoW conversion first adds its native-TEB bias to the
    // ULONG offset. Overflow rejects the request before either destination
    // probe or handle validation, even for a zero-byte request. The copy below
    // still uses the guest's primary32-bit TEB, not its native companion.
    if wow64 && offset.checked_add(0x2000).is_none() {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    if wow64 && returned != 0 {
        probe_write(c, returned, 4)?;
    }
    probe_write(c, output, count as usize)?;
    let id = if handle == c.arch().ptr(CURRENT_THREAD) {
        c.t.obj
    } else {
        if handle == c.arch().ptr(CURRENT_PROCESS) {
            return Flow::ret(STATUS_OBJECT_TYPE_MISMATCH.into());
        }
        let Some(id) = c.p.objects.id(handle) else {
            return Flow::ret(STATUS_INVALID_HANDLE.into());
        };
        if !matches!(c.p.objects.obj(id), Some(Object::Thread { .. })) {
            return Flow::ret(STATUS_OBJECT_TYPE_MISMATCH.into());
        }
        if c.p.objects.access(handle).unwrap_or(0) & THREAD_GET_SET_CONTEXT
            != THREAD_GET_SET_CONTEXT
        {
            return Flow::ret(STATUS_ACCESS_DENIED.into());
        }
        id
    };
    // These are the observed structure extents for the selected native profile,
    // not the page-rounded allocation sizes. WoW64 reads the primary32-bit TEB.
    let extent = if wow64 { 0x1030 } else { 0x1870 };
    if count == 0 || u64::from(offset) + u64::from(count) > extent {
        return Flow::ret(STATUS_INVALID_PARAMETER.into());
    }
    let Some(Object::Thread { tid, exit_code }) = c.p.objects.obj(id) else {
        unreachable!("validated thread");
    };
    if exit_code.is_some() {
        if c.p.objects.thread_start(id).is_none() {
            return Err(c.unsupported("thread TEB belongs to an external process"));
        }
        return Flow::ret(STATUS_THREAD_IS_TERMINATING.into());
    }
    let target = if id == c.t.obj {
        &*c.t
    } else {
        c.p.threads
            .get(tid)
            .filter(|thread| thread.obj == id)
            .ok_or_else(|| c.unsupported("thread TEB owner is outside the guest scheduler"))?
    };
    if target.terminate.is_some() || matches!(target.state, ThreadState::Exited(_)) {
        return Flow::ret(STATUS_THREAD_IS_TERMINATING.into());
    }
    let bytes = c
        .mem()
        .bytes(target.teb + u64::from(offset), count as usize)?;
    c.mem().wr(output, &bytes)?;
    return_length(c, returned, count)?;
    Flow::ret(STATUS_SUCCESS.into())
}
