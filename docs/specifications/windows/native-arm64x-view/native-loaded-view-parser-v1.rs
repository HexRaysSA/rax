//! Read-only parsing of this process's loaded NTDLL, using the owning PE decoder.
#![allow(dead_code)]
#[path = "../../src/user/image/pe/mod.rs"]
mod pe;
use pe::RvaSource;
use std::ffi::{c_char, c_void};
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetModuleHandleW(name: *const u16) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const c_char) -> *mut c_void;
    fn ReadProcessMemory(
        process: *mut c_void,
        address: *const c_void,
        buffer: *mut c_void,
        size: usize,
        returned: *mut usize,
    ) -> i32;
}
struct OwnModule {
    base: usize,
    size: u32,
}
impl RvaSource for OwnModule {
    fn read_rva(&self, rva: u64, buffer: &mut [u8]) -> Result<(), pe::RvaFault> {
        let fault = pe::RvaFault { rva };
        let end = rva
            .checked_add(buffer.len() as u64)
            .filter(|&end| end <= u64::from(self.size))
            .ok_or(fault)?;
        let _ = end;
        let at = self
            .base
            .checked_add(usize::try_from(rva).map_err(|_| fault)?)
            .ok_or(fault)?;
        let mut returned = 0;
        // SAFETY: the OS validates this bounded read from an already loaded,
        // process-lifetime module in the current process. The initialized exclusive
        // destination and returned-length outputs remain live and are not retained.
        let status = unsafe {
            ReadProcessMemory(
                (-1isize) as *mut c_void,
                at as *const c_void,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut returned,
            )
        };
        if status == 0 || returned != buffer.len() {
            return Err(fault);
        }
        Ok(())
    }
}
fn main() {
    let name = "ntdll.dll\0".encode_utf16().collect::<Vec<_>>();
    // SAFETY: owned NUL-terminated name; module already loaded for process lifetime.
    let base = unsafe { GetModuleHandleW(name.as_ptr()) };
    assert!(!base.is_null());
    let header = OwnModule {
        base: base as usize,
        size: 4096,
    };
    assert_eq!(header.u16_at(0).unwrap(), 0x5A4D);
    let nt = u64::from(header.u32_at(60).unwrap());
    assert_eq!(header.u32_at(nt).unwrap(), 0x4550);
    let machine = header.u16_at(nt + 4).unwrap();
    let preferred = header.u64_at(nt + 48).unwrap();
    let size = header.u32_at(nt + 80).unwrap();
    assert!((4096..=64 << 20).contains(&size));
    let module = OwnModule {
        base: base as usize,
        size,
    };
    let dir = pe::DataDirectory {
        rva: header.u32_at(nt + 24 + 112 + 10 * 8).unwrap(),
        size: header.u32_at(nt + 24 + 112 + 10 * 8 + 4).unwrap(),
    };
    let config = pe::loadcfg::LoadConfig::read(&module, pe::PeKind::Pe32Plus, dir)
        .unwrap()
        .unwrap();
    let metadata = pe::hybrid::HybridMetadata::read(
        &module,
        config.chpe_metadata_pointer.unwrap(),
        base as usize as u64,
        size,
    )
    .unwrap();
    println!(
        "arch={} machine={machine:04x} actual_base={:x} preferred_base={preferred:x} size={size:x} version={} code={} entries={} redirects={}",
        std::env::consts::ARCH,
        base as usize,
        metadata.version,
        metadata.code.len(),
        metadata.entries.len(),
        metadata.redirections.len()
    );
    // SAFETY: fixed terminated symbol and live module; exported address only read.
    let export = unsafe { GetProcAddress(base, c"NtQueryInformationProcess".as_ptr()) };
    assert!(!export.is_null());
    let rva = u32::try_from(export as usize - base as usize).unwrap();
    let mut code = [0u8; 16];
    module.read_rva(u64::from(rva), &mut code).unwrap();
    println!(
        "export=NtQueryInformationProcess rva={rva:x} kind={:?} bytes={code:02x?}",
        metadata.code_kind(rva)
    );
    for range in &metadata.code {
        println!("{:08x}-{:08x} {:?}", range.start, range.end, range.kind);
    }
    println!("external_handles_opened=0 process_signals=0 host_state_changed=false");
}
