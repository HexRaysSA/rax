//! Fixed current-process BASE NLS query on native 64-bit Windows.
use std::ffi::c_void;
use std::io;
use std::ptr;

const INFORMATION_BYTES: usize = 1660;
const API: u32 = 0x0001_001b;
const NATIVE_MACHINE: u16 = if cfg!(target_arch = "aarch64") {
    0xaa64
} else {
    0x8664
};

#[link(name = "ntdll")]
unsafe extern "system" {
    fn CsrAllocateCaptureBuffer(count: u32, size: u32) -> *mut c_void;
    fn CsrAllocateMessagePointer(capture: *mut c_void, size: u32, field: *mut *mut c_void) -> u32;
    fn CsrClientCallServer(message: *mut c_void, capture: *mut c_void, api: u32, size: u32) -> u32;
    fn CsrFreeCaptureBuffer(capture: *mut c_void);
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcess() -> *mut c_void;
    fn GetCurrentProcessId() -> u32;
    fn IsWow64Process2(process: *mut c_void, guest: *mut u16, native: *mut u16) -> i32;
    fn ProcessIdToSessionId(process: u32, session: *mut u32) -> i32;
    fn GetUserDefaultLocaleName(buffer: *mut u16, units: i32) -> i32;
    fn ReadProcessMemory(
        process: *mut c_void,
        address: *const c_void,
        output: *mut c_void,
        bytes: usize,
        read: *mut usize,
    ) -> i32;
}

#[repr(align(16))]
struct Message([u8; 952]);
struct Capture(*mut c_void);

impl Drop for Capture {
    fn drop(&mut self) {
        // SAFETY: each instance owns one non-null capture from NTDLL.
        unsafe { CsrFreeCaptureBuffer(self.0) }
    }
}

fn read<const N: usize>(address: *const c_void) -> io::Result<[u8; N]> {
    let mut bytes = [0; N];
    let mut count = 0;
    // SAFETY: ReadProcessMemory validates the current-process address. The
    // exclusive output is exactly N bytes and the count is initialized.
    if unsafe {
        ReadProcessMemory(
            GetCurrentProcess(),
            address,
            bytes.as_mut_ptr().cast(),
            N,
            &mut count,
        )
    } == 0
        || count != N
    {
        return Err(io::Error::last_os_error());
    }
    Ok(bytes)
}

fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("fixed field"))
}

fn sample(index: usize, pattern: u8) -> io::Result<()> {
    let mut message = Message([0; 952]);
    let size = INFORMATION_BYTES as u32;
    // SAFETY: the capture has one fixed-size output and no guest input.
    let pointer = unsafe { CsrAllocateCaptureBuffer(1, size) };
    if pointer.is_null() {
        return Err(io::Error::other("allocate native capture"));
    }
    let capture = Capture(pointer);
    let slot = message.0[64..].as_mut_ptr().cast::<*mut c_void>();
    // SAFETY: the pointer field is aligned and remains in this message.
    let allocated = unsafe { CsrAllocateMessagePointer(capture.0, size, slot) };
    let information = unsafe { slot.read() };
    if allocated < size || information.is_null() {
        return Err(io::Error::other("allocate native message pointer"));
    }
    let header = read::<40>(capture.0)?;
    let registered = u64::from_le_bytes(header[32..40].try_into().expect("capture slot"));
    let capture_slot = if registered == slot as u64 {
        "message_field"
    } else if registered == 64 {
        "message_offset"
    } else {
        "other"
    };
    // SAFETY: a non-null output with at least INFORMATION_BYTES capacity was
    // just allocated inside this owned capture.
    unsafe { ptr::write_bytes(information.cast::<u8>(), pattern, INFORMATION_BYTES) };
    message.0[72..76].copy_from_slice(&size.to_le_bytes());
    // SAFETY: fixed BASE selector, initialized 16-byte payload, exact capture
    // allocation and no pointers or other inputs from an emulated process.
    let status = unsafe { CsrClientCallServer(message.0.as_mut_ptr().cast(), capture.0, API, 16) };
    let bytes = read::<INFORMATION_BYTES>(information)?;
    let reply = word(&message.0, 52);
    let header_flags_zero = message.0[4..8] == [0; 4];
    let reserved_zero = message.0[56..64] == [0; 8];
    let size_padding_zero = message.0[76..80] == [0; 4];
    print!(
        "sample={index} input={pattern:02x} status={status:08x} reply={reply:08x} data_bytes={} message_bytes={} api={:x} requested={} allocated={allocated} capture_bytes={} count={} slot={capture_slot} header_flags_zero={header_flags_zero} reserved_zero={reserved_zero} size_padding_zero={size_padding_zero} payload=",
        u16::from_le_bytes(message.0[..2].try_into().expect("header data size")),
        u16::from_le_bytes(message.0[2..4].try_into().expect("header message size")),
        word(&message.0, 48),
        word(&message.0, 72),
        word(&header, 0),
        word(&header, 16),
    );
    for byte in bytes {
        print!("{byte:02x}");
    }
    println!();
    if status != reply || (status == 0xc000_0001 && bytes != [pattern; INFORMATION_BYTES]) {
        return Err(io::Error::other("inconsistent fixed BASE reply"));
    }
    Ok(())
}

fn main() -> io::Result<()> {
    let (mut guest, mut native) = (0, 0);
    let mut session = 0;
    // SAFETY: both calls query the current process and write initialized
    // scalar out parameters. No external process handle is accepted.
    if !cfg!(all(
        windows,
        any(target_arch = "x86_64", target_arch = "aarch64")
    )) || unsafe { IsWow64Process2(GetCurrentProcess(), &mut guest, &mut native) } == 0
        || guest != 0
        || native != NATIVE_MACHINE
        || unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session) } == 0
    {
        return Err(io::Error::other("matching native 64-bit Windows required"));
    }
    println!("machine={native:04x} session={session}");
    let patterns = [0xa5, 0x5a, 0, 0xa5, 0x5a, 0];
    for (index, pattern) in patterns.into_iter().enumerate() {
        if index == 3 {
            let mut locale = [0_u16; 85];
            // SAFETY: the output array is writable for the full unit count.
            let length = unsafe { GetUserDefaultLocaleName(locale.as_mut_ptr(), 85) };
            if length <= 0 || length as usize > locale.len() {
                return Err(io::Error::last_os_error());
            }
            let name = String::from_utf16(&locale[..length as usize - 1])
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            println!("public_locale={name}");
        }
        sample(index, pattern)?;
    }
    println!("complete samples={}", patterns.len());
    Ok(())
}
