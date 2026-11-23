use std::ffi::{CString, c_void};

type Module = *mut c_void;
type IsApiSetImplemented = unsafe extern "system" fn(*const std::ffi::c_char) -> i32;
const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x800;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryExW(name: *const u16, reserved: Module, flags: u32) -> Module;
    fn GetModuleFileNameW(module: Module, path: *mut u16, size: u32) -> u32;
    fn GetLastError() -> u32;
    fn FreeLibrary(module: Module) -> i32;
    fn GetProcAddress(module: Module, name: *const std::ffi::c_char) -> *const c_void;
}

struct Library(Module);

impl Library {
    fn load(name: &str) -> Result<Self, u32> {
        let wide: Vec<_> = name.encode_utf16().chain(Some(0)).collect();
        // SAFETY: wide is terminated and live, reserved is null, and the
        // search is restricted to the installed system directory.
        let module = unsafe {
            LoadLibraryExW(
                wide.as_ptr(),
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if module.is_null() {
            // SAFETY: capture this thread's error immediately after failure.
            return Err(unsafe { GetLastError() });
        }
        Ok(Self(module))
    }

    fn basename(&self) -> String {
        let mut path = vec![0u16; 32_768];
        // SAFETY: self owns a live module and path is writable for its length.
        let count = unsafe { GetModuleFileNameW(self.0, path.as_mut_ptr(), path.len() as u32) };
        assert!(count != 0 && (count as usize) < path.len());
        String::from_utf16(&path[..count as usize])
            .unwrap()
            .rsplit(['\\', '/'])
            .next()
            .unwrap()
            .to_ascii_lowercase()
    }

    fn query(&self, name: &str) -> Option<bool> {
        // SAFETY: the module is the documented API query DLL, self retains
        // its reference, and the export name is NUL terminated.
        let symbol = unsafe { GetProcAddress(self.0, c"IsApiSetImplemented".as_ptr()) };
        if symbol.is_null() {
            return None;
        }
        let name = CString::new(name).unwrap();
        // SAFETY: this export has the BOOL (WINAPI *)(PCSTR) declaration.
        let implementation: IsApiSetImplemented = unsafe { std::mem::transmute(symbol) };
        Some(unsafe { implementation(name.as_ptr()) } != 0)
    }
}

impl Drop for Library {
    fn drop(&mut self) {
        // SAFETY: release the single live reference obtained by load.
        assert_ne!(unsafe { FreeLibrary(self.0) }, 0);
    }
}

fn main() {
    assert_eq!(Library::load("ntdll.dll").unwrap().basename(), "ntdll.dll");
    assert_eq!(
        Library::load("api-ms-win-core-rtlsupport-l1-1-0.dll")
            .unwrap()
            .basename(),
        "ntdll.dll"
    );
    assert!(
        Library::load("api-ms-win-core-rtlsupport-l65535-65535-0.dll").is_err(),
        "uninstalled identity unexpectedly resolved"
    );
    println!("arch\tcontract\tloader-host\tloader-error\tquery");
    let query = Library::load("api-ms-win-core-apiquery-l2-1-0.dll").ok();
    for identity in [
        "api-ms-win-core-rtlsupport-l1-1",
        "api-ms-win-crt-runtime-l1-1",
        "api-ms-win-core-synch-l1-2",
        "api-ms-win-core-rtlsupport-l65535-65535",
    ] {
        for revision in [
            "0",
            "1",
            "65535",
            "4294967296",
            "0000",
            "banana",
            "0abc",
            "b0",
            "_",
            "",
            "0-0",
        ] {
            let contract = format!("{identity}-{revision}");
            let filename = format!("{contract}.dll");
            let (host, error) = match Library::load(&filename) {
                Ok(module) => (module.basename(), 0),
                Err(error) => (String::new(), error),
            };
            let query_result = query.as_ref().and_then(|module| module.query(&contract));
            println!(
                "{}\t{contract}\t{host}\t{error}\t{query_result:?}",
                std::env::consts::ARCH
            );
        }
    }
}
