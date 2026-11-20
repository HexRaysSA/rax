//! Observe the fixed USER connection in this process. Emit mapping geometry only.
use std::ffi::c_void;
use std::io;
use std::mem::size_of;

const SENTINEL: u64 = 0xa5a5_a5a5_a5a5_a5a5;
const MAX_VIEW_BYTES: usize = 8 * 1024 * 1024;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_MAPPED: u32 = 0x40000;
const PAGE_READONLY: u32 = 2;

#[repr(C)]
#[derive(Default)]
struct Region {
    base: usize,
    allocation: usize,
    allocation_protection: u32,
    partition_and_padding: u32,
    size: usize,
    state: u32,
    protection: u32,
    kind: u32,
}
const _: [(); 48] = [(); size_of::<Region>()];

#[link(name = "ntdll")]
unsafe extern "system" {
    fn CsrClientConnectToServer(
        directory: *const u16,
        server: u32,
        information: *mut c_void,
        bytes: u32,
        inside_server: *mut u8,
    ) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcessId() -> u32;
    fn ProcessIdToSessionId(pid: u32, session: *mut u32) -> i32;
    fn VirtualQuery(address: *const c_void, output: *mut Region, bytes: usize) -> usize;
}

#[derive(Debug, Default)]
struct View {
    bytes: usize,
    committed_bytes: usize,
    runs: usize,
    readonly_mapped: bool,
}

fn view(base: usize) -> io::Result<View> {
    if base == 0 || base % 65536 != 0 {
        return Err(io::Error::other("invalid reported allocation base"));
    }
    let mut result = View {
        readonly_mapped: true,
        ..View::default()
    };
    loop {
        let current = base
            .checked_add(result.bytes)
            .ok_or_else(|| io::Error::other("allocation address overflow"))?;
        let mut region = Region::default();
        // SAFETY: VirtualQuery inspects only this process. The address came
        // from the fixed native response. The output is initialized and local.
        let returned =
            unsafe { VirtualQuery(current as *const c_void, &mut region, size_of::<Region>()) };
        if returned != size_of::<Region>() {
            return Err(io::Error::last_os_error());
        }
        if region.allocation != base && result.runs != 0 {
            return Ok(result);
        }
        if region.allocation != base
            || region.base != current
            || region.size == 0
            || region.size > MAX_VIEW_BYTES - result.bytes
        {
            break;
        }
        result.bytes += region.size;
        result.runs += 1;
        match region.state {
            MEM_COMMIT => {
                result.committed_bytes += region.size;
                result.readonly_mapped &=
                    region.kind == MEM_MAPPED && region.protection == PAGE_READONLY;
            }
            MEM_RESERVE => {}
            _ => result.readonly_mapped = false,
        }
    }
    Err(io::Error::other("unexpected reported allocation geometry"))
}

fn main() -> io::Result<()> {
    let information_bytes = match std::env::args().nth(1).as_deref() {
        Some("576") => 576,
        None | Some("584") => 584,
        _ => {
            return Err(io::Error::other(
                "expected the observed 576- or 584-byte USER size",
            ));
        }
    };
    let information_words = information_bytes / 8;
    let mut session = 0;
    // SAFETY: fixed current process identity and a writable local DWORD.
    if unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let path = if session == 0 {
        String::from("\\Windows")
    } else {
        format!("\\Sessions\\{session}\\Windows")
    };
    let directory: Vec<_> = path.encode_utf16().chain([0]).collect();
    println!(
        "arch={} session={session} information_bytes={information_bytes}",
        std::env::consts::ARCH
    );
    for sample in 0..2 {
        let mut data = [0u64; 128];
        data[information_words..].fill(SENTINEL);
        let mut inside = 0xa5;
        // SAFETY: normal current-session USER initialization, with the proved
        // scalar ULONG ABI and a zeroed, aligned, caller-owned output buffer.
        let status = unsafe {
            CsrClientConnectToServer(
                directory.as_ptr(),
                3,
                data.as_mut_ptr().cast(),
                information_bytes as u32,
                &mut inside,
            )
        };
        let tail_unchanged = data[information_words..]
            .iter()
            .all(|&word| word == SENTINEL);
        println!(
            "sample={sample} status={:#010x} inside={inside} tail_unchanged={tail_unchanged}",
            status.cast_unsigned()
        );
        if status != 0 || inside != 0 || !tail_unchanged {
            return Err(io::Error::other("fixed USER connection did not complete"));
        }
        let table = view(usize::try_from(data[2]).map_err(io::Error::other)?)?;
        let shared = view(usize::try_from(data[5]).map_err(io::Error::other)?)?;
        let shared_info_matches = data[5].checked_add(0x1040) == Some(data[1]) && data[3] == 32;
        println!(
            "table_bytes={} table_committed={} table_runs={} table_readonly_mapped={} \
             shared_bytes={} shared_committed={} shared_runs={} shared_readonly_mapped={} \
             shared_info_matches={shared_info_matches}",
            table.bytes,
            table.committed_bytes,
            table.runs,
            table.readonly_mapped,
            shared.bytes,
            shared.committed_bytes,
            shared.runs,
            shared.readonly_mapped,
        );
    }
    println!("complete samples=2");
    Ok(())
}
