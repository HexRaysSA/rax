//! Capture default overlapped-window limits and non-client rendering.
use super::{GetProcAddress, Handle, Module};
use crate::user::windows::gui::windows::{OVERLAPPED_STYLE, WCA_NCRENDERING_ENABLED};
use std::cell::Cell;
use std::ffi::{CStr, c_void};
use std::mem::{size_of, transmute};
use std::ptr::null_mut;

type WindowProc = unsafe extern "system" fn(Handle, u32, usize, isize) -> isize;

#[repr(C)]
struct WindowClass {
    size: u32,
    style: u32,
    procedure: WindowProc,
    class_extra: i32,
    window_extra: i32,
    module: Handle,
    icon: Handle,
    cursor: Handle,
    background: Handle,
    menu: *const u16,
    name: *const u16,
    small_icon: Handle,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetModuleHandleW(name: *const u16) -> Handle;
}

#[repr(C)]
struct CompositionAttribute {
    selector: u32,
    output: *mut c_void,
    size: u32,
}

type QueryComposition = unsafe extern "system" fn(Handle, *const CompositionAttribute) -> i32;

thread_local! {
    static LIMITS: Cell<Option<[i32; 10]>> = const { Cell::new(None) };
    static COMPOSITION: Cell<Option<QueryComposition>> = const { Cell::new(None) };
    static RENDERING: Cell<Option<bool>> = const { Cell::new(None) };
}

unsafe extern "system" fn observe(window: Handle, message: u32, _: usize, data: isize) -> isize {
    if message == 0x24 && data != 0 {
        // SAFETY: USER32 passed a live native MINMAXINFO. It contains ten
        // consecutive LONGs, copied before returning to the installed caller.
        let limits = unsafe { (data as *const [i32; 10]).read_unaligned() };
        LIMITS.with(|slot| slot.set(Some(limits)));
        if let Some(query) = COMPOSITION.with(Cell::get) {
            let mut value = u32::MAX;
            let attribute = CompositionAttribute {
                selector: WCA_NCRENDERING_ENABLED,
                output: (&mut value as *mut u32).cast(),
                size: size_of::<u32>() as u32,
            };
            // SAFETY: the handle comes from this fixed native callback. The
            // descriptor and its writable BOOL remain live across the query.
            if unsafe { query(window, &attribute) } != 0 && value <= 1 {
                RENDERING.with(|slot| slot.set(Some(value != 0)));
            }
        }
    }
    // Reject WM_NCCREATE. The helper never creates a visible or live window.
    0
}

pub(super) fn capture(user: &Module, win32u: &Module) -> Result<([i32; 10], Option<bool>), String> {
    let lookup = |name: &CStr| {
        // SAFETY: live selected module and a static, terminated export name.
        let address = unsafe { GetProcAddress(user.0, name.as_ptr()) };
        if address.is_null() {
            Err(format!("selected USER32 has no {}", name.to_string_lossy()))
        } else {
            Ok(address)
        }
    };
    // SAFETY: these named USER32 exports use the documented Windows ABI.
    let register: unsafe extern "system" fn(*const WindowClass) -> u16 =
        unsafe { transmute(lookup(c"RegisterClassExW")?) };
    let unregister: unsafe extern "system" fn(*const u16, Handle) -> i32 =
        unsafe { transmute(lookup(c"UnregisterClassW")?) };
    let create: unsafe extern "system" fn(
        u32,
        *const u16,
        *const u16,
        u32,
        i32,
        i32,
        i32,
        i32,
        Handle,
        Handle,
        Handle,
        Handle,
    ) -> Handle = unsafe { transmute(lookup(c"CreateWindowExW")?) };
    let destroy: unsafe extern "system" fn(Handle) -> i32 =
        unsafe { transmute(lookup(c"DestroyWindow")?) };
    // SAFETY: a null module name selects the current executable.
    let module = unsafe { GetModuleHandleW(std::ptr::null()) };
    if module.is_null() {
        return Err("host executable module unavailable for window-limits query".into());
    }
    let name: Vec<u16> = format!(
        "Rax.NativeOverlappedLimits.{:?}",
        std::thread::current().id()
    )
    .encode_utf16()
    .chain([0])
    .collect();
    let class = WindowClass {
        size: size_of::<WindowClass>() as u32,
        style: 0,
        procedure: observe,
        class_extra: 0,
        window_extra: 0,
        module,
        icon: null_mut(),
        cursor: null_mut(),
        background: null_mut(),
        menu: std::ptr::null(),
        name: name.as_ptr(),
        small_icon: null_mut(),
    };
    // SAFETY: the fixed class and its name remain live across the calls and
    // its native callback executes on this private helper thread.
    if unsafe { register(&class) } == 0 {
        return Err(format!(
            "register native window-limits class: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: selected Win32u stays loaded through the helper callback.
    let query =
        unsafe { GetProcAddress(win32u.0, c"NtUserGetWindowCompositionAttribute".as_ptr()) };
    let query = if query.is_null() {
        None
    } else {
        // SAFETY: this named Win32u export takes HWND and attribute pointer.
        Some(unsafe { transmute::<*mut c_void, QueryComposition>(query) })
    };
    LIMITS.with(|slot| slot.set(None));
    COMPOSITION.with(|slot| slot.set(query));
    RENDERING.with(|slot| slot.set(None));
    // SAFETY: live class, fixed hidden style and dimensions, no foreign HWND
    // or guest data. The callback rejects creation after observing limits.
    let window = unsafe {
        create(
            0,
            name.as_ptr(),
            std::ptr::null(),
            OVERLAPPED_STYLE,
            0,
            0,
            197,
            103,
            null_mut(),
            null_mut(),
            module,
            null_mut(),
        )
    };
    COMPOSITION.with(Cell::take);
    let limits = LIMITS.with(Cell::take);
    let rendering = RENDERING.with(Cell::take);
    let unexpected = !window.is_null();
    if unexpected {
        // SAFETY: only the returned handle owned by this thread is destroyed.
        unsafe { destroy(window) };
    }
    // SAFETY: the class name and module used for registration remain live.
    if unsafe { unregister(name.as_ptr(), module) } == 0 {
        return Err(format!(
            "unregister native window-limits class: {}",
            std::io::Error::last_os_error()
        ));
    }
    if unexpected {
        return Err("native window-limits probe unexpectedly created a window".into());
    }
    limits
        .map(|limits| (limits, rendering))
        .ok_or_else(|| "native overlapped window did not report default limits".into())
}
