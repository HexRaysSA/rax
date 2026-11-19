//! Fixed current-process GUI queries on an owned, otherwise idle host helper.
//! No guest pointer, service argument or callback is forwarded to the host.
use super::{check, data, invalid};
use crate::user::windows::arch::WinArch;
use crate::user::windows::gui::{Inputs, View};
use crate::user::windows::object_namespace::DataSection;
use std::ffi::{c_char, c_void};
use std::io;
use std::num::NonZeroU32;
use std::path::Path;
use std::sync::Arc;

type Handle = *mut c_void;
mod context;
mod cursor_icons;
mod desktop;
mod system_parameters;
mod window_station;

#[repr(C)]
#[derive(Default)]
struct Region {
    base: usize,
    allocation: usize,
    allocation_protection: u32,
    #[cfg(target_pointer_width = "64")]
    partition: u32,
    size: usize,
    state: u32,
    protection: u32,
    kind: u32,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryExW(name: *const u16, file: Handle, flags: u32) -> Handle;
    fn FreeLibrary(module: Handle) -> i32;
    fn GetProcAddress(module: Handle, name: *const c_char) -> *mut c_void;
    fn VirtualQuery(address: *const c_void, region: *mut Region, bytes: usize) -> usize;
    fn ReadProcessMemory(
        process: Handle,
        address: *const c_void,
        output: *mut c_void,
        bytes: usize,
        got: *mut usize,
    ) -> i32;
}
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryInformationProcess(
        process: Handle,
        class: u32,
        output: *mut c_void,
        bytes: u32,
        got: *mut u32,
    ) -> i32;
    fn NtQueryInformationThread(
        thread: Handle,
        class: u32,
        output: *mut c_void,
        bytes: u32,
        got: *mut u32,
    ) -> i32;
}

struct Module(Handle);
impl Module {
    fn open(path: &Path) -> io::Result<Self> {
        use std::os::windows::ffi::OsStrExt;
        let wide: Vec<_> = path.as_os_str().encode_wide().chain([0]).collect();
        // SAFETY: confined selected full DLL path, terminated live UTF-16 and
        // system-directory dependency search. The owned reference closes below.
        let handle = unsafe { LoadLibraryExW(wide.as_ptr(), std::ptr::null_mut(), 0x800) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(handle))
    }
}
impl Drop for Module {
    fn drop(&mut self) {
        // SAFETY: one uniquely owned successful LoadLibraryEx reference.
        unsafe {
            FreeLibrary(self.0);
        }
    }
}

fn read<const N: usize>(address: usize) -> io::Result<[u8; N]> {
    let mut bytes = [0; N];
    let mut got = 0usize;
    // SAFETY: fixed native query address, initialized exclusive bounded output;
    // RPM rejects stale/unreadable host pages. There are no guest inputs.
    let ok = unsafe {
        ReadProcessMemory(
            (-1isize) as Handle,
            address as *const c_void,
            bytes.as_mut_ptr().cast(),
            N,
            &mut got,
        )
    };
    if ok == 0 || got != N {
        return Err(io::Error::last_os_error());
    }
    Ok(bytes)
}

fn region(address: usize) -> io::Result<Region> {
    let mut region = Region::default();
    // SAFETY: fixed native address is queried, never directly dereferenced;
    // initialized exclusive repr(C) ABI output.
    let got = unsafe {
        VirtualQuery(
            address as *const c_void,
            &mut region,
            std::mem::size_of::<Region>(),
        )
    };
    if got != std::mem::size_of::<Region>() {
        return Err(io::Error::last_os_error());
    }
    Ok(region)
}

fn allocation(base: u64) -> io::Result<View> {
    let base = usize::try_from(base).map_err(|_| invalid("GUI address exceeds host width"))?;
    if base == 0 || base % 65536 != 0 {
        return Err(invalid("GUI allocation base is invalid"));
    }
    let mut size = 0usize;
    loop {
        let at = base
            .checked_add(size)
            .ok_or_else(|| invalid("GUI allocation address overflow"))?;
        let current = region(at)?;
        if current.allocation != base {
            break;
        }
        if current.base != at
            || current.size == 0
            || current.size % 4096 != 0
            || current.size > (64 << 20) - size
        {
            return Err(invalid("GUI allocation extent exceeds bounded profile"));
        }
        size += current.size;
        if size == 64 << 20 {
            return Err(invalid("GUI allocation exceeds 64 MiB"));
        }
    }
    let regions = data::regions(base, size)?;
    Ok(View {
        base: base as u64,
        section: DataSection::private_readonly(size as u64, regions)?,
    })
}

fn word(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("fixed native record"),
    )
}

fn process_dpi(win32u: &Module) -> Option<NonZeroU32> {
    // SAFETY: The selected Win32u module remains live across the fixed
    // zero-argument query on this private, already converted host thread.
    let address = unsafe { GetProcAddress(win32u.0, c"NtUserGetDpiForCurrentProcess".as_ptr()) };
    if address.is_null() {
        return None;
    }
    let query: unsafe extern "system" fn() -> u32 = unsafe { std::mem::transmute(address) };
    NonZeroU32::new(unsafe { query() })
}

pub(crate) fn snapshot(arch: WinArch, user: &Path, win32u: &Path) -> io::Result<Arc<Inputs>> {
    let native = if cfg!(target_arch = "aarch64") {
        WinArch::Arm64
    } else if cfg!(target_arch = "x86_64") {
        WinArch::X64
    } else {
        WinArch::X86
    };
    if arch != native || native == WinArch::X86 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "GUI metadata requires the matching native 64-bit runtime; WoW64 needs paired contexts",
        ));
    }
    let _user = Module::open(user)?;
    let win32u = Module::open(win32u)?;
    // SAFETY: live owned selected Win32u module and a static terminated export
    // name. The fixed zero-argument ABI was measured on native ARM64/x86 views.
    let address = unsafe { GetProcAddress(win32u.0, c"NtGdiInit2".as_ptr()) };
    if address.is_null() {
        return Err(invalid("selected Win32u has no NtGdiInit2"));
    }
    // SAFETY: selected installed export, fixed no-argument native ABI; this
    // private host helper never executes guest code or supplies guest pointers.
    let initialize: unsafe extern "system" fn() -> usize = unsafe { std::mem::transmute(address) };
    if unsafe { initialize() } == 0 {
        return Err(invalid("native GUI initialization returned zero"));
    }
    // SAFETY: fixed no-argument, query-only installed Win32u export. This is
    // acquired once on the owned native helper, never from guest arguments.
    let address = unsafe { GetProcAddress(win32u.0, c"NtUserRemoteConnectState".as_ptr()) };
    if address.is_null() {
        return Err(invalid("selected Win32u has no NtUserRemoteConnectState"));
    }
    let remote_connect_state: unsafe extern "system" fn() -> u32 =
        unsafe { std::mem::transmute(address) };
    let mut process = [0u64; 6];
    let mut thread = [0u64; 6];
    let mut got = 0;
    // SAFETY: current-process/current-thread pseudo handles and initialized,
    // aligned exclusive native BASIC_INFORMATION outputs of exactly 48 bytes.
    check(
        unsafe {
            NtQueryInformationProcess(
                (-1isize) as Handle,
                0,
                process.as_mut_ptr().cast(),
                48,
                &mut got,
            )
        },
        "query native GUI process",
    )?;
    if got != 48 {
        return Err(invalid("GUI process query extent differs"));
    }
    check(
        unsafe {
            NtQueryInformationThread(
                (-2isize) as Handle,
                0,
                thread.as_mut_ptr().cast(),
                48,
                &mut got,
            )
        },
        "query native GUI thread",
    )?;
    if got != 48 {
        return Err(invalid("GUI thread query extent differs"));
    }
    let peb = usize::try_from(process[1]).map_err(|_| invalid("GUI PEB exceeds host width"))?;
    let teb = usize::try_from(thread[1]).map_err(|_| invalid("GUI TEB exceeds host width"))?;
    for _ in 0..3 {
        // SAFETY: fixed installed query on this already converted native helper.
        let remote_before = unsafe { remote_connect_state() };
        let (handle_before, assigned_desktop) = desktop::capture(&_user, &win32u)?;
        let assigned_window_station =
            window_station::capture(&_user, &win32u).map_err(|error| error.to_string());
        let dpi = process_dpi(&win32u);
        let process_ui_context = context::capture(&win32u);
        let system_parameters = system_parameters::capture(&win32u);
        let cursor_icons = cursor_icons::capture_stable(&win32u);
        let process_before = read::<512>(peb)?;
        let client_before = read::<160>(
            teb.checked_add(0x800)
                .ok_or_else(|| invalid("GUI TEB overflow"))?,
        )?;
        let gdi_base = word(&process_before, 0xf8);
        let desktop_base = word(&client_before, 0x28);
        let gdi = allocation(gdi_base)?;
        let desktop = allocation(desktop_base)?;
        let repeated_gdi = allocation(gdi_base)?;
        let repeated_desktop = allocation(desktop_base)?;
        let (handle_after, repeated_identity) = desktop::capture(&_user, &win32u)?;
        if handle_before == handle_after
            && assigned_desktop.name() == repeated_identity.name()
            && assigned_desktop.access == repeated_identity.access
            && assigned_desktop.flags == repeated_identity.flags
            && assigned_window_station == window_station::capture(&_user, &win32u).map_err(|error| error.to_string())
            && dpi == process_dpi(&win32u)
            && process_ui_context == context::capture(&win32u)
            && system_parameters == system_parameters::capture(&win32u)
            && gdi.section.regions == repeated_gdi.section.regions
            && desktop.section.regions == repeated_desktop.section.regions
            && gdi.section.size == repeated_gdi.section.size
            && desktop.section.size == repeated_desktop.section.size
            && read::<512>(peb)? == process_before
            && read::<160>(teb + 0x800)? == client_before
            // SAFETY: same fixed current-session query; changed input retries.
            && unsafe { remote_connect_state() } == remote_before
        {
            let client = std::array::from_fn(|index| word(&client_before, index * 8));
            let mut inputs = Inputs::selected(
                arch,
                gdi,
                desktop,
                client,
                remote_before,
                dpi,
                assigned_desktop,
                process_ui_context,
            )?;
            let selected = Arc::get_mut(&mut inputs).expect("new GUI snapshot");
            selected.system_parameters = system_parameters;
            selected.cursor_icons = cursor_icons;
            selected.window_station = assigned_window_station.map(|(_, station)| station);
            return Ok(inputs);
        }
    }
    Err(invalid("native GUI views changed during bounded capture"))
}
