// Own-process class-2 queries against two installed, local image mappings.
use std::{ffi::c_void, io, ptr};

type Handle = *mut c_void;
type Query =
    unsafe extern "system" fn(Handle, *const c_void, u32, *mut c_void, usize, *mut usize) -> i32;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcess() -> Handle;
    fn GetModuleHandleW(name: *const u16) -> Handle;
    fn GetProcAddress(module: Handle, name: *const u8) -> *mut c_void;
    fn IsWow64Process2(process: Handle, image: *mut u16, native: *mut u16) -> i32;
    fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
    fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        attrs: *mut c_void,
        disposition: u32,
        flags: u32,
        template_file: Handle,
    ) -> Handle;
    fn CreateFileMappingW(
        file: Handle,
        attrs: *mut c_void,
        protect: u32,
        max_hi: u32,
        max_low: u32,
        name: *const u16,
    ) -> Handle;
    fn MapViewOfFile(section: Handle, access: u32, hi: u32, low: u32, size: usize) -> *mut c_void;
    fn UnmapViewOfFile(view: *const c_void) -> i32;
    fn CloseHandle(handle: Handle) -> i32;
}

struct Owned(Handle);
impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: this wrapper is constructed only for a live owned handle.
        unsafe { CloseHandle(self.0) };
    }
}
struct View(*mut c_void);
impl Drop for View {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns the view base returned by MapViewOfFile.
        unsafe { UnmapViewOfFile(self.0) };
    }
}

fn cmd_view() -> io::Result<View> {
    let mut path = vec![0; 32_768];
    // SAFETY: exclusive wide buffer with its exact capacity.
    let used = unsafe { GetSystemDirectoryW(path.as_mut_ptr(), path.len() as u32) } as usize;
    if used == 0 || used >= path.len() {
        return Err(io::Error::last_os_error());
    }
    path.truncate(used);
    path.extend(r"\cmd.exe".encode_utf16().chain([0]));
    // SAFETY: terminated installed path, OPEN_EXISTING, read-only access.
    let file = unsafe {
        CreateFileW(
            path.as_ptr(),
            0x8000_0000,
            7,
            ptr::null_mut(),
            3,
            0x80,
            ptr::null_mut(),
        )
    };
    if file.is_null() || file.addr() == usize::MAX {
        return Err(io::Error::last_os_error());
    }
    let file = Owned(file);
    // SAFETY: owns the open file. SEC_IMAGE_NO_EXECUTE | PAGE_READONLY
    // creates a read-only image mapping without invoking its loader entry.
    let section =
        unsafe { CreateFileMappingW(file.0, ptr::null_mut(), 0x1100_0002, 0, 0, ptr::null()) };
    if section.is_null() {
        return Err(io::Error::last_os_error());
    }
    let section = Owned(section);
    // SAFETY: owned section, read-only view of the whole installed image.
    let view = unsafe { MapViewOfFile(section.0, 4, 0, 0, 0) };
    if view.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(View(view))
}

const CAPACITY: usize = 1024;
#[repr(align(8))]
struct Aligned([u8; CAPACITY]);

struct Sample {
    status: u32,
    returned: usize,
    bytes: [u8; CAPACITY],
}

#[derive(Clone, Copy)]
enum Output {
    Aligned,
    Unaligned,
    Null,
}

fn sample(
    query: Query,
    process: Handle,
    address: *const c_void,
    length: usize,
    poison: u8,
    output: Output,
    return_length: bool,
) -> Sample {
    assert!(length < CAPACITY);
    let mut data = Aligned([poison; CAPACITY]);
    let mut returned = usize::from_ne_bytes([poison; size_of::<usize>()]);
    let offset = usize::from(matches!(output, Output::Unaligned));
    let bytes = if matches!(output, Output::Null) {
        assert_eq!(length, 0);
        ptr::null_mut()
    } else {
        data.0[offset..].as_mut_ptr()
    };
    let result = if return_length {
        &mut returned
    } else {
        ptr::null_mut()
    };
    // SAFETY: queries the current process using only a fixed installed view
    // or the explicitly invalid address operand. The optional outputs refer
    // to separate private writable storage. Zero length permits a null buffer.
    let status = unsafe { query(process, address, 2, bytes.cast(), length, result) } as u32;
    if !bytes.is_null() {
        let slot = offset + 8..offset + 16;
        let inline = bytes.wrapping_add(16).addr();
        if data.0[slot.clone()] == inline.to_le_bytes() {
            data.0[slot].copy_from_slice(&16usize.to_le_bytes());
        }
    }
    Sample {
        status,
        returned,
        bytes: data.0,
    }
}

fn subject(query: Query, process: Handle, name: &str, address: *const c_void) -> usize {
    let baseline = sample(query, process, address, 1000, 0xA5, Output::Aligned, true);
    assert_eq!(baseline.status, 0);
    let size = baseline.returned;
    assert!((18..CAPACITY - 8).contains(&size));
    assert_eq!(
        u64::from_le_bytes(baseline.bytes[8..16].try_into().unwrap()),
        16
    );
    let local: Vec<_> = r"\Device\HarddiskVolume"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    assert!(baseline.bytes[16..size].starts_with(&local));
    println!("subject={name} required={size}");
    let mut total = 0;
    for poison in [0xA5, 0x5A] {
        let mut emit = |case, length, address, output, result| {
            let value = sample(query, process, address, length, poison, output, result);
            let bytes: String = value.bytes[..size + 8]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            println!(
                "row={name} case={case} length={length} poison={poison:02x} status={:08x} returned={:016x} bytes={bytes}",
                value.status, value.returned,
            );
            total += 1;
        };
        for length in 0..=size + 1 {
            emit("length", length, address, Output::Aligned, true);
        }
        emit("no_result", size, address, Output::Aligned, false);
        emit("null_empty", 0, address, Output::Null, true);
        emit("unaligned", size, address, Output::Unaligned, true);
        emit(
            "address_and_alignment",
            size,
            ptr::without_provenance(usize::MAX),
            Output::Unaligned,
            true,
        );
    }
    total
}

fn main() -> io::Result<()> {
    assert_eq!(size_of::<usize>(), 8);
    // SAFETY: GetCurrentProcess returns the current-process pseudo-handle.
    let process = unsafe { GetCurrentProcess() };
    let (mut image, mut native) = (0, 0);
    // SAFETY: two separate writable USHORT outputs for the current process.
    assert_ne!(
        unsafe { IsWow64Process2(process, &mut image, &mut native) },
        0
    );
    assert_eq!((image, native), (0, 0xAA64));
    println!("machine=aa64");
    let wide = |name: &str| name.encode_utf16().chain([0]).collect::<Vec<_>>();
    // SAFETY: both names are terminated and refer to process-loaded modules.
    let ntdll = unsafe { GetModuleHandleW(wide("ntdll.dll").as_ptr()) };
    let kernel = unsafe { GetModuleHandleW(wide("kernel32.dll").as_ptr()) };
    assert!(!ntdll.is_null() && !kernel.is_null());
    // SAFETY: loaded NTDLL and a terminated exported name of the declared ABI.
    let address = unsafe { GetProcAddress(ntdll, c"NtQueryVirtualMemory".as_ptr().cast()) };
    assert!(!address.is_null());
    let query: Query = unsafe { std::mem::transmute(address) };
    let cmd = cmd_view()?;
    let total = subject(query, process, "kernel32", kernel.cast_const())
        + subject(query, process, "cmd", cmd.0.cast_const());
    println!("complete rows={total}");
    Ok(())
}
