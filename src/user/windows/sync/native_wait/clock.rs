//! Awake-time clocks are distinct from UTC and counters that include suspend.
use std::io;

#[cfg(unix)]
pub(super) fn awake_nanoseconds() -> io::Result<u128> {
    #[cfg(target_os = "macos")]
    let id = libc::CLOCK_UPTIME_RAW;
    #[cfg(not(target_os = "macos"))]
    let id = libc::CLOCK_MONOTONIC;
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: a known host clock ID and initialized private timespec storage.
    if unsafe { libc::clock_gettime(id, &mut time) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if time.tv_sec < 0 || !(0..1_000_000_000).contains(&time.tv_nsec) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid awake-time clock sample",
        ));
    }
    Ok(time.tv_sec as u128 * 1_000_000_000 + time.tv_nsec as u128)
}

#[cfg(not(any(unix, windows)))]
pub(super) fn awake_nanoseconds() -> io::Result<u128> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "awake clock is not available on this target",
    ))
}

#[cfg(windows)]
pub(super) fn awake_nanoseconds() -> io::Result<u128> {
    use std::ffi::{c_char, c_void};
    use std::sync::OnceLock;
    type Precise = unsafe extern "system" fn(*mut u64);
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetModuleHandleW(name: *const u16) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const c_char) -> *mut c_void;
        fn QueryUnbiasedInterruptTime(time: *mut u64) -> i32;
    }
    static PRECISE: OnceLock<Option<Precise>> = OnceLock::new();
    let function = PRECISE.get_or_init(|| {
        // Kernel32 is the documented provider. Build 29683 exports this API
        // only from KernelBase in the four captured native/compatibility profiles.
        // Dynamic resolution retains the older unbiased-clock fallback.
        for name in ["kernel32.dll\0", "KernelBase.dll\0"] {
            let name: Vec<u16> = name.encode_utf16().collect();
            // SAFETY: borrowed process-lifetime system module; no guest pointer or
            // argument enters either loader query. The documented ABI is Precise.
            let module = unsafe { GetModuleHandleW(name.as_ptr()) };
            if module.is_null() {
                continue;
            }
            let symbol =
                unsafe { GetProcAddress(module, c"QueryUnbiasedInterruptTimePrecise".as_ptr()) };
            if !symbol.is_null() {
                return Some(unsafe { std::mem::transmute::<*mut c_void, Precise>(symbol) });
            }
        }
        None
    });
    let mut ticks = 0;
    if let Some(function) = function {
        // SAFETY: exact resolved system ABI and initialized private u64 storage.
        unsafe { function(&mut ticks) };
    } else if unsafe { QueryUnbiasedInterruptTime(&mut ticks) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // Both Windows APIs exclude sleep/hibernation and return 100 ns units.
    // The older fallback is clock-tick quantized; units do not imply precision.
    Ok(u128::from(ticks) * 100)
}
