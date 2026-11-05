//! Read-only parsing of this process's loaded NTDLL, using the owning PE decoder.
#![allow(dead_code)]
#[path = "../../../../src/user/image/pe/mod.rs"]
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

#[repr(C)]
#[derive(Default, Debug)]
struct Region {
    base: usize,
    allocation: usize,
    allocation_protection: u32,
    pad: u32,
    size: usize,
    state: u32,
    protect: u32,
    kind: u32,
}
#[repr(C)]
#[derive(Default, Debug)]
struct Extension {
    kind: u32,
    flags: u32,
    rva: usize,
    size: usize,
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn VirtualQuery(address: *const c_void, out: *mut Region, size: usize) -> usize;
    fn VirtualAlloc(address: *mut c_void, size: usize, kind: u32, protect: u32) -> *mut c_void;
    fn VirtualFree(address: *mut c_void, size: usize, kind: u32) -> i32;
    fn VirtualProtect(address: *mut c_void, size: usize, protect: u32, old: *mut u32) -> i32;
}
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryVirtualMemory(
        process: *mut c_void,
        address: *mut c_void,
        class: u32,
        out: *mut c_void,
        size: usize,
        returned: *mut usize,
    ) -> i32;
}
fn region(at: usize) -> Region {
    let mut r = Region::default();
    assert_eq!(
        unsafe { VirtualQuery(at as *const c_void, &mut r, std::mem::size_of::<Region>()) },
        std::mem::size_of::<Region>()
    );
    r
}
fn main() {
    let name = "ntdll.dll\0".encode_utf16().collect::<Vec<_>>();
    let module = unsafe { GetModuleHandleW(name.as_ptr()) };
    assert!(!module.is_null());
    let head = OwnModule {
        base: module as usize,
        size: 4096,
    };
    let nt = u64::from(head.u32_at(60).unwrap());
    let size = head.u32_at(nt + 80).unwrap();
    let image = OwnModule {
        base: module as usize,
        size,
    };
    let lc = u64::from(head.u32_at(nt + 24 + 112 + 80).unwrap());
    let meta = image.u64_at(lc + 200).unwrap();
    let metadata =
        pe::hybrid::HybridMetadata::read(&image, meta, module as usize as u64, size).unwrap();
    let address = unsafe { GetProcAddress(module, c"RtlIsEcCode".as_ptr()) };
    assert!(!address.is_null(), "RtlIsEcCode absent");
    let classify: unsafe extern "system" fn(u64) -> u8 = unsafe { std::mem::transmute(address) };
    println!(
        "MODULE base={:x} size={size:x} machine={:x} oracle={:x}",
        module as usize,
        head.u16_at(nt + 4).unwrap(),
        address as usize
    );
    let get_peb = unsafe { GetProcAddress(module, c"RtlGetCurrentPeb".as_ptr()) };
    assert!(!get_peb.is_null());
    let get_peb: unsafe extern "system" fn() -> *mut c_void =
        unsafe { std::mem::transmute(get_peb) };
    let peb = unsafe { get_peb() } as usize;
    let mut field = [0u8; 8];
    let mut got = 0;
    assert_ne!(
        unsafe {
            ReadProcessMemory(
                (-1isize) as *mut c_void,
                (peb + 0x368) as *const c_void,
                field.as_mut_ptr().cast(),
                8,
                &mut got,
            )
        },
        0
    );
    assert_eq!(got, 8);
    println!(
        "NATIVE_PEB address={peb:x} ec_code_bitmap={:x} ntdll_global_limit={:x} ntdll_global_bitmap={:x}",
        u64::from_le_bytes(field),
        image.u64_at(0x3e77c0).unwrap(),
        image.u64_at(0x3e77c8).unwrap()
    );
    let mut bases = Vec::new();
    for kind in 0..2 {
        let mut e = Extension {
            kind,
            ..Default::default()
        };
        let mut n = 0;
        let status = unsafe {
            NtQueryVirtualMemory(
                (-1isize) as *mut c_void,
                module,
                14,
                (&mut e as *mut Extension).cast(),
                std::mem::size_of::<Extension>(),
                &mut n,
            )
        };
        println!("EXTENSION kind={kind} status={status:x} returned={n} value={e:?}");
        if status != 0 || e.size == 0 {
            continue;
        }
        assert!(e.rva >= size as usize && e.size <= 131072 && e.size % 4096 == 0);
        let at = (module as usize).checked_add(e.rva).unwrap();
        let policy = region(at);
        assert_eq!(policy.allocation, module as usize);
        assert_eq!(policy.protect, 0x20);
        let mut bytes = vec![0u8; e.size];
        let mut got = 0;
        assert_ne!(
            unsafe {
                ReadProcessMemory(
                    (-1isize) as *mut c_void,
                    at as *const c_void,
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                    &mut got,
                )
            },
            0
        );
        assert_eq!(got, bytes.len());
        let words = bytes
            .chunks_exact(4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .collect::<Vec<_>>();
        for (index, w) in words.windows(10).enumerate() {
            if (w[0] & 0xffe0001f) == 0xd2800010
                && (w[1] & 0xffe0001f) == 0xf2a00010
                && (w[2] & 0xffe0001f) == 0xf2c00010
                && (w[3] & 0xffe0001f) == 0xf2e00010
                && w[4..10]
                    == [
                        0xaa1003ec, 0xd34ffd71, 0x38716a11, 0xd34c3970, 0x9ad02630, 0xf240021f,
                    ]
            {
                let bitmap =
                    (0..4).fold(0u64, |v, n| v | u64::from((w[n] >> 5) & 0xffff) << (n * 16));
                println!(
                    "BITMAP_READER rva={:x} bitmap={bitmap:x}",
                    e.rva + index * 4
                );
                if !bases.contains(&bitmap) {
                    bases.push(bitmap);
                }
            }
        }
    }
    for bitmap in bases {
        let executable = unsafe { GetModuleHandleW(std::ptr::null()) };
        assert!(!executable.is_null());
        let at = executable as usize as u64;
        let byte = bitmap + (at >> 15);
        let mut value = [0u8; 1];
        let mut got = 0;
        let read = unsafe {
            ReadProcessMemory(
                (-1isize) as *mut c_void,
                byte as *const c_void,
                value.as_mut_ptr().cast(),
                1,
                &mut got,
            )
        };
        println!(
            "AMD64_IMAGE base={at:x} oracle={} read={read} byte={:x} bitmap_region={:?}",
            unsafe { classify(at) },
            value[0],
            region(byte as usize)
        );
        let allocation = unsafe { VirtualAlloc(std::ptr::null_mut(), 65536, 0x2000, 4) };
        assert!(!allocation.is_null());
        let at = allocation as usize as u64;
        let byte = bitmap + (at >> 15);
        println!(
            "DYNAMIC stage=reserve address={at:x} bitmap_region={:?}",
            region(byte as usize)
        );
        assert_eq!(
            unsafe { VirtualAlloc(allocation, 65536, 0x1000, 4) },
            allocation
        );
        println!(
            "DYNAMIC stage=commit_rw address={at:x} oracle={} bitmap_region={:?}",
            unsafe { classify(at) },
            region(byte as usize)
        );
        let mut old = 0;
        assert_ne!(
            unsafe { VirtualProtect(allocation, 65536, 0x40, &mut old) },
            0
        );
        let mut value = [0u8; 2];
        let mut got = 0;
        let read = unsafe {
            ReadProcessMemory(
                (-1isize) as *mut c_void,
                byte as *const c_void,
                value.as_mut_ptr().cast(),
                2,
                &mut got,
            )
        };
        println!(
            "DYNAMIC stage=protect_execute address={at:x} oracle={} read={read} value={value:x?} bitmap_region={:?}",
            unsafe { classify(at) },
            region(byte as usize)
        );
        assert_ne!(unsafe { VirtualFree(allocation, 0, 0x8000) }, 0);
        println!(
            "DYNAMIC stage=release address={at:x} bitmap_region={:?}",
            region(byte as usize)
        );
        let kbname = "kernelbase.dll\0".encode_utf16().collect::<Vec<_>>();
        let kb = unsafe { GetModuleHandleW(kbname.as_ptr()) };
        assert!(!kb.is_null());
        let allocate = unsafe { GetProcAddress(kb, c"VirtualAlloc2".as_ptr()) };
        assert!(!allocate.is_null());
        let allocate: unsafe extern "system" fn(
            *mut c_void,
            *mut c_void,
            usize,
            u32,
            u32,
            *const [u64; 2],
            u32,
        ) -> *mut c_void = unsafe { std::mem::transmute(allocate) };
        let parameter = [5u64, 0x40];
        let allocation = unsafe {
            allocate(
                (-1isize) as *mut c_void,
                std::ptr::null_mut(),
                65536,
                0x3000,
                0x40,
                &parameter,
                1,
            )
        };
        println!("EC_ALLOCATION address={:x}", allocation as usize);
        if !allocation.is_null() {
            let at = allocation as usize as u64;
            let byte = bitmap + (at >> 15);
            for stage in ["ec_commit", "ec_release"] {
                if stage == "ec_release" {
                    assert_ne!(unsafe { VirtualFree(allocation, 0, 0x8000) }, 0);
                }
                let mut value = [0u8; 2];
                let mut got = 0;
                let read = unsafe {
                    ReadProcessMemory(
                        (-1isize) as *mut c_void,
                        byte as *const c_void,
                        value.as_mut_ptr().cast(),
                        2,
                        &mut got,
                    )
                };
                println!(
                    "EC_DYNAMIC stage={stage} address={at:x} oracle={} bitmap_read={read} bytes={value:x?} bitmap_region={:?}",
                    unsafe { classify(at) },
                    region(byte as usize)
                );
            }
            let replacement = unsafe { VirtualAlloc(allocation, 65536, 0x3000, 4) };
            assert_eq!(replacement, allocation);
            println!(
                "EC_REUSE stage=normal_rw address={at:x} oracle={} bitmap_region={:?}",
                unsafe { classify(at) },
                region(byte as usize)
            );
            assert_ne!(unsafe { VirtualFree(replacement, 0, 0x8000) }, 0);
        }
        for offset in [0u64, 4096, 0x100000, 0xffff0000, 0xfffff000] {
            let at = bitmap.checked_add(offset).unwrap();
            println!(
                "BITMAP_REGION bitmap={bitmap:x} offset={offset:x} region={:?}",
                region(at as usize)
            );
        }
        for code in &metadata.code {
            for rva in [code.start, code.end - 1] {
                let at = module as usize as u64 + u64::from(rva);
                let byte = bitmap + (at >> 15);
                let mut value = [0u8; 1];
                let mut got = 0;
                let read = unsafe {
                    ReadProcessMemory(
                        (-1isize) as *mut c_void,
                        byte as *const c_void,
                        value.as_mut_ptr().cast(),
                        1,
                        &mut got,
                    )
                };
                println!(
                    "CLASSIFY rva={rva:x} tag={:?} oracle={} byte_address={byte:x} read={read} value={:x} region={:?}",
                    code.kind,
                    unsafe { classify(at) },
                    value[0],
                    region(byte as usize)
                );
            }
        }
    }
    println!(
        "SCOPE=current-process read-only kernel bitmap classification; no bitmap content copied to emulator; no external handles or signals"
    );
}
