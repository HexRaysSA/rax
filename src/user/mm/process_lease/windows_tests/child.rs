//! Native, explicitly inherited handles for this test's fresh child only.

use std::ffi::{OsStr, c_void};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::ptr;

use super::ProcessLease;

const ROLE: &str = "RAX_MM_WINDOWS_LEASE_CHILD";
const LIMIT_MS: u32 = 30_000;

#[repr(C)]
struct StartupInfo {
    size: u32,
    reserved: *mut u16,
    desktop: *mut u16,
    title: *mut u16,
    position_and_flags: [u32; 8],
    show_window: u16,
    reserved_bytes: u16,
    reserved_data: *mut u8,
    stdin: *mut c_void,
    stdout: *mut c_void,
    stderr: *mut c_void,
}

#[repr(C)]
struct StartupInfoEx {
    base: StartupInfo,
    attributes: *mut c_void,
}

#[repr(C)]
struct ProcessInformation {
    process: *mut c_void,
    thread: *mut c_void,
    pid: u32,
    tid: u32,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateEventW(
        attributes: *const c_void,
        manual: i32,
        initial: i32,
        name: *const u16,
    ) -> *mut c_void;
    fn SetEvent(handle: *mut c_void) -> i32;
    fn GetCurrentProcess() -> *mut c_void;
    fn DuplicateHandle(
        source: *mut c_void,
        handle: *mut c_void,
        target: *mut c_void,
        result: *mut *mut c_void,
        access: u32,
        inherit: i32,
        options: u32,
    ) -> i32;
    fn GetHandleInformation(handle: *mut c_void, flags: *mut u32) -> i32;
    fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
    fn ReleaseMutex(handle: *mut c_void) -> i32;
    fn GetExitCodeProcess(handle: *mut c_void, code: *mut u32) -> i32;
    fn InitializeProcThreadAttributeList(
        list: *mut c_void,
        count: u32,
        flags: u32,
        bytes: *mut usize,
    ) -> i32;
    fn UpdateProcThreadAttribute(
        list: *mut c_void,
        flags: u32,
        attribute: usize,
        value: *const c_void,
        bytes: usize,
        previous: *mut c_void,
        returned: *mut usize,
    ) -> i32;
    fn DeleteProcThreadAttributeList(list: *mut c_void);
    fn CreateProcessW(
        application: *const u16,
        command: *mut u16,
        process_attributes: *const c_void,
        thread_attributes: *const c_void,
        inherit: i32,
        flags: u32,
        environment: *const c_void,
        directory: *const u16,
        startup: *mut StartupInfo,
        information: *mut ProcessInformation,
    ) -> i32;
}

fn checked(value: i32) {
    assert_ne!(value, 0, "{}", std::io::Error::last_os_error());
}

fn owned(raw: *mut c_void) -> OwnedHandle {
    assert!(!raw.is_null(), "{}", std::io::Error::last_os_error());
    // SAFETY: callers pass one newly created or inherited owned real handle.
    unsafe { OwnedHandle::from_raw_handle(raw) }
}

pub(super) fn event() -> OwnedHandle {
    // SAFETY: a private, initially nonsignaled manual-reset event; no retained
    // caller pointers and no inherited or named object.
    owned(unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) })
}

pub(super) fn inheritable(handle: BorrowedHandle<'_>) -> OwnedHandle {
    let mut duplicate = ptr::null_mut();
    // SAFETY: the source stays live; current-process pseudo handles are used
    // only as process arguments, never in the child handle list. SAME_ACCESS
    // creates one independently owned inheritable duplicate for that list.
    unsafe {
        let process = GetCurrentProcess();
        checked(DuplicateHandle(
            process,
            handle.as_raw_handle(),
            process,
            &mut duplicate,
            0,
            1,
            2,
        ));
    }
    owned(duplicate)
}

pub(super) fn is_inheritable(handle: *mut c_void) -> bool {
    let mut flags = 0;
    // SAFETY: callers keep this owned handle live and flags is writable.
    checked(unsafe { GetHandleInformation(handle, &mut flags) });
    flags & 1 != 0
}

pub(super) fn assert_contended(handle: BorrowedHandle<'_>) {
    // SAFETY: the parent keeps this mutex live; a zero timeout cannot block.
    let result = unsafe { WaitForSingleObject(handle.as_raw_handle(), 0) };
    if matches!(result, 0 | 0x80) {
        // SAFETY: an unexpected successful wait must still be balanced.
        checked(unsafe { ReleaseMutex(handle.as_raw_handle()) });
    }
    assert_eq!(result, 0x102, "another process must retain ownership");
}

pub(super) fn serve_if_requested() {
    let Ok(value) = std::env::var(ROLE) else {
        return;
    };
    let handles: Vec<usize> = value.split(',').map(|v| v.parse().unwrap()).collect();
    assert_eq!(handles.len(), 3);
    let lease = ProcessLease::from_handle(owned(handles[0] as *mut c_void)).unwrap();
    let ready = owned(handles[1] as *mut c_void);
    let release = owned(handles[2] as *mut c_void);
    lease
        .with(|| {
            assert_eq!(lease.holder().unwrap(), Some(std::process::id()));
            // SAFETY: the explicit bootstrap supplied these two live event handles.
            checked(unsafe { SetEvent(ready.as_raw_handle()) });
            assert_eq!(
                unsafe { WaitForSingleObject(release.as_raw_handle(), LIMIT_MS) },
                0
            );
            // Deliberate normal exit of this test-owned process without destructors:
            // the kernel must abandon the mutex while its parent retains a handle.
            std::process::exit(0);
        })
        .unwrap();
    unreachable!();
}

struct Attributes(Vec<usize>);

impl Attributes {
    fn new(handles: &[*mut c_void]) -> Self {
        let mut bytes = 0;
        // SAFETY: the documented sizing call writes only bytes and fails with
        // insufficient-buffer by design. The second call uses aligned storage.
        assert_eq!(
            unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut bytes) },
            0
        );
        assert!(bytes > 0);
        let mut storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
        checked(unsafe {
            InitializeProcThreadAttributeList(storage.as_mut_ptr().cast(), 1, 0, &mut bytes)
        });
        let mut list = Self(storage);
        // SAFETY: PROC_THREAD_ATTRIBUTE_HANDLE_LIST contains only live real,
        // inheritable duplicates. Both list and handle slice survive spawn.
        checked(unsafe {
            UpdateProcThreadAttribute(
                list.pointer(),
                0,
                0x20002,
                handles.as_ptr().cast(),
                size_of_val(handles),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        });
        list
    }

    fn pointer(&mut self) -> *mut c_void {
        self.0.as_mut_ptr().cast()
    }
}

impl Drop for Attributes {
    fn drop(&mut self) {
        // SAFETY: new initialized this list; the backing allocation is live.
        unsafe { DeleteProcThreadAttributeList(self.pointer()) };
    }
}

pub(super) struct Worker {
    process: OwnedHandle,
    ready: OwnedHandle,
    release: OwnedHandle,
    pid: u32,
    finished: bool,
}

impl Worker {
    pub(super) fn spawn(lease: &ProcessLease, name: &str) -> Self {
        use std::os::windows::io::AsHandle;
        let ready = event();
        let release = event();
        let inherited = [
            inheritable(lease.handle()),
            inheritable(ready.as_handle()),
            inheritable(release.as_handle()),
        ];
        let handles = inherited.each_ref().map(AsRawHandle::as_raw_handle);
        let mut attributes = Attributes::new(&handles);
        let image: Vec<u16> = std::env::current_exe()
            .unwrap()
            .as_os_str()
            .encode_wide()
            .collect();
        // A Windows filename cannot contain quotes or NUL. Quoting the complete
        // executable token preserves spaces; all following arguments are fixed
        // libtest tokens with no shell and no user-controlled argument grammar.
        assert!(!image.contains(&0) && !image.contains(&(b'"' as u16)));
        let mut command = vec![b'"' as u16];
        command.extend_from_slice(&image);
        command.extend(format!("\" --exact {name} --test-threads=1 --nocapture\0").encode_utf16());
        let mut application = image;
        application.push(0);
        // This private child needs only its role plus native system/temp roots.
        // Build a sorted Unicode environment without mutating the test process.
        let mut variables = std::collections::BTreeMap::new();
        variables.insert(
            ROLE,
            handles
                .iter()
                .map(|h| (*h as usize).to_string())
                .collect::<Vec<_>>()
                .join(",")
                .into(),
        );
        for key in ["SystemRoot", "TEMP", "TMP"] {
            if let Some(value) = std::env::var_os(key) {
                variables.insert(key, value);
            }
        }
        let mut environment = Vec::new();
        for (key, value) in variables {
            environment.extend(OsStr::new(key).encode_wide());
            environment.push(b'=' as u16);
            environment.extend(value.encode_wide());
            environment.push(0);
        }
        environment.push(0);
        // SAFETY: all zero values are valid for unused STARTUPINFO fields.
        let mut startup: StartupInfoEx = unsafe { std::mem::zeroed() };
        startup.base.size = size_of::<StartupInfoEx>() as u32;
        startup.attributes = attributes.pointer();
        let mut info: ProcessInformation = unsafe { std::mem::zeroed() };
        // SAFETY: application/environment are terminated; command is mutable;
        // structures match the SDK layout. Only the explicit three-handle list
        // is inherited. EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT
        // | CREATE_NO_WINDOW creates exactly this same test image without a shell.
        checked(unsafe {
            CreateProcessW(
                application.as_ptr(),
                command.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                1,
                0x08080400,
                environment.as_ptr().cast(),
                ptr::null(),
                &mut startup.base,
                &mut info,
            )
        });
        drop(owned(info.thread));
        Self {
            process: owned(info.process),
            ready,
            release,
            pid: info.pid,
            finished: false,
        }
    }

    pub(super) fn pid(&self) -> u32 {
        self.pid
    }

    pub(super) fn ready(&self) {
        // SAFETY: both objects stay live; these waits have finite native bounds.
        assert_eq!(
            unsafe { WaitForSingleObject(self.ready.as_raw_handle(), LIMIT_MS) },
            0
        );
        assert_eq!(
            unsafe { WaitForSingleObject(self.process.as_raw_handle(), 0) },
            0x102
        );
    }

    pub(super) fn exit_while_holding(&mut self) {
        // SAFETY: this event releases only this helper's child; the owned
        // process handle supplies its actual wait and terminal exit status.
        checked(unsafe { SetEvent(self.release.as_raw_handle()) });
        assert_eq!(
            unsafe { WaitForSingleObject(self.process.as_raw_handle(), LIMIT_MS) },
            0
        );
        let mut code = 259;
        checked(unsafe { GetExitCodeProcess(self.process.as_raw_handle(), &mut code) });
        assert_eq!(code, 0);
        self.finished = true;
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        if !self.finished {
            // SAFETY: allow the owned child to finish if its parent assertion
            // unwinds. No external process is terminated or otherwise changed.
            unsafe {
                SetEvent(self.release.as_raw_handle());
                WaitForSingleObject(self.process.as_raw_handle(), LIMIT_MS);
            }
        }
    }
}
