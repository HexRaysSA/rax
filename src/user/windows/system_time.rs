//! Coarse NT wall time and the guest-owned KUSER SystemTime snapshot.
//!
//! The page is updated on the executing guest's thread. No host updater races
//! guest memory, and no guest pointer or value enters the native clock calls.

use super::layout::{KUSER_SHARED_DATA, kuser};
use crate::user::mm::{AddressSpace, Mapping, MmError, PAGE_SIZE, Perms};
use std::io;

/// Maximum guest instructions between shared-time observations within a run.
/// This is an instruction bound, not a host-time accuracy guarantee.
pub(crate) const REFRESH_INSNS: u64 = 1024;

// Windows mappings otherwise use zero personality flags. This bit is set only
// during process construction; guest allocation and section APIs cannot set it.
const SHARED_DATA_VMA: u32 = 1 << 31;

/// Install the readonly kernel mapping after VirtualMemory commits its slot,
/// before process metadata is written. Replacements lose the ownership flag.
pub(crate) fn map_shared_data(space: &AddressSpace) -> Result<(), MmError> {
    let mut mapping = Mapping::anonymous(Perms::READ).named("[KUSER_SHARED_DATA]");
    mapping.flags = SHARED_DATA_VMA;
    space.map(KUSER_SHARED_DATA, PAGE_SIZE, mapping)
}

/// The existing precise host wall-clock profile used by built-in services.
pub(crate) fn wall_time() -> io::Result<u64> {
    let (seconds, nanoseconds) = crate::user::clock::read(crate::user::clock::HostClock::Realtime)?;
    super::nt::time::file_time(seconds, nanoseconds).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "host clock is outside the FILETIME range",
        )
    })
}

/// NT time on Windows; the existing host wall-clock profile on other hosts.
pub(crate) fn now() -> io::Result<u64> {
    #[cfg(windows)]
    {
        native::now()
    }
    #[cfg(not(windows))]
    {
        wall_time()
    }
}

/// Built-in replay retains its measured ULONG-aligned service contract.
/// Installed execution acquires alignment from fixed, owned native scratch.
pub(crate) fn output_alignment(installed: bool) -> io::Result<u64> {
    if !installed {
        return Ok(4);
    }
    #[cfg(windows)]
    {
        native::alignment()
    }
    #[cfg(not(windows))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "installed NT clock requires Windows",
        ))
    }
}

pub(crate) fn observe(ordinal: u64, space: &AddressSpace) -> Result<(), String> {
    if ordinal % REFRESH_INSNS == 0 {
        publish(space).map_err(|error| format!("Windows shared system time: {error}"))?;
    }
    Ok(())
}

/// Publish a complete KSYSTEM_TIME only when this Windows CPU has its page.
/// Raw CPU-only address spaces need not contain process kernel metadata.
pub(crate) fn publish(space: &AddressSpace) -> io::Result<()> {
    const ADDRESS: u64 = KUSER_SHARED_DATA + kuser::SYSTEM_TIME;
    let mappings = space.vmas_in(KUSER_SHARED_DATA, KUSER_SHARED_DATA + PAGE_SIZE);
    if mappings.len() != 1
        || mappings[0].start != KUSER_SHARED_DATA
        || mappings[0].end != KUSER_SHARED_DATA + PAGE_SIZE
        || mappings[0].flags & SHARED_DATA_VMA == 0
    {
        return Ok(());
    }
    let ticks = now()?;
    let mut bytes = [0u8; 12];
    bytes[..8].copy_from_slice(&ticks.to_le_bytes());
    bytes[8..].copy_from_slice(&((ticks >> 32) as u32).to_le_bytes());
    // Windows guest CPUs run cooperatively on this thread. Publishing the
    // complete triplet between instructions also preserves high1/high2 retry
    // semantics when a guest read spans two observations. Guest permissions
    // are unchanged; only the personality writes its readonly metadata.
    space
        .write_raw(ADDRESS, &bytes)
        .map_err(|error| io::Error::other(format!("cannot publish KUSER SystemTime: {error:?}")))
}

#[cfg(windows)]
mod native {
    use super::*;
    use std::sync::OnceLock;

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQuerySystemTime(output: *mut i64) -> i32;
    }

    pub(super) fn now() -> io::Result<u64> {
        let mut ticks = 0i64;
        // SAFETY: one aligned, initialized host LARGE_INTEGER; no guest input.
        let status = unsafe { NtQuerySystemTime(&mut ticks) };
        if status != 0 {
            return Err(io::Error::other(format!(
                "native NT clock status {:#010x}",
                status as u32
            )));
        }
        u64::try_from(ticks)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "negative native NT time"))
    }

    pub(super) fn alignment() -> io::Result<u64> {
        static ALIGNMENT: OnceLock<u64> = OnceLock::new();
        if let Some(&alignment) = ALIGNMENT.get() {
            return Ok(alignment);
        }
        #[repr(align(8))]
        struct Scratch([u8; 24]);
        now()?;
        let mut accepted = [false; 4];
        for offset in 1..=4 {
            let mut scratch = Scratch([0xa5; 24]);
            // SAFETY: eight writable bytes inside exclusively owned scratch.
            // Rust never dereferences the deliberately offset pointer as an
            // i64. No guest address or protection enters this fixed query.
            let status =
                unsafe { NtQuerySystemTime(scratch.0.as_mut_ptr().add(offset).cast()) } as u32;
            let outside_unchanged = scratch.0[..offset].iter().all(|&b| b == 0xa5)
                && scratch.0[offset + 8..].iter().all(|&b| b == 0xa5);
            accepted[offset - 1] = match status {
                0 if outside_unchanged && scratch.0[offset..offset + 8] != [0xa5; 8] => true,
                super::super::nt::status::STATUS_DATATYPE_MISALIGNMENT
                    if scratch.0 == [0xa5; 24] =>
                {
                    false
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        format!(
                            "unmeasured native NT clock output profile: offset {offset}, status {status:#010x}"
                        ),
                    ));
                }
            };
        }
        let alignment = match accepted {
            [true, true, true, true] => 1,
            [false, false, false, true] => 4,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "native NT clock output alignment differs from the measured byte/ULONG profiles",
                ));
            }
        };
        let _ = ALIGNMENT.set(alignment);
        Ok(alignment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::cpu::x86_64::RESERVED_PHYS;
    use crate::user::mm::{Mapping, PAGE_SIZE, Perms, SpaceConfig};
    use crate::user::windows::memory::Mem;

    #[test]
    fn shared_time_publishes_only_a_complete_readonly_ksystem_time() {
        let space = AddressSpace::new(SpaceConfig {
            va_limit: 1 << 47,
            arena_bytes: 64 * PAGE_SIZE,
            reserved_phys: RESERVED_PHYS.to_vec(),
        })
        .unwrap();
        publish(&space).unwrap();
        assert!(space.is_free(KUSER_SHARED_DATA, PAGE_SIZE));
        map_shared_data(&space).unwrap();
        space.write_raw(KUSER_SHARED_DATA, &[0xa5; 4096]).unwrap();
        let before = now().unwrap();
        publish(&space).unwrap();
        let after = now().unwrap();
        let ticks = space.u64(KUSER_SHARED_DATA + kuser::SYSTEM_TIME).unwrap();
        assert!((before..=after).contains(&ticks));
        let mut expected = [0xa5; 4096];
        expected[0x14..0x1c].copy_from_slice(&ticks.to_le_bytes());
        expected[0x1c..0x20].copy_from_slice(&((ticks >> 32) as u32).to_le_bytes());
        assert_eq!(space.bytes(KUSER_SHARED_DATA, 4096).unwrap(), expected);
        assert!(
            space
                .write(KUSER_SHARED_DATA + kuser::SYSTEM_TIME, &[0; 12])
                .is_err()
        );
        assert_eq!(
            space.vmas_in(KUSER_SHARED_DATA, KUSER_SHARED_DATA + PAGE_SIZE)[0].perms,
            Perms::READ
        );
        // A guest replacement at the same VA is a different mapping. Kernel
        // publication must neither clobber it nor follow a file-backed alias.
        space
            .map(
                KUSER_SHARED_DATA,
                PAGE_SIZE,
                Mapping::anonymous(Perms::READ | Perms::WRITE),
            )
            .unwrap();
        space.write(KUSER_SHARED_DATA, &[0x5a; 4096]).unwrap();
        publish(&space).unwrap();
        assert_eq!(space.bytes(KUSER_SHARED_DATA, 4096).unwrap(), [0x5a; 4096]);
    }

    #[test]
    fn builtin_system_time_keeps_its_recorded_alignment_profile() {
        assert_eq!(output_alignment(false).unwrap(), 4);
    }

    #[cfg(windows)]
    #[test]
    fn native_system_time_matches_the_independent_shared_host_clock() {
        fn shared() -> u64 {
            loop {
                // SAFETY: Windows maps this fixed, readonly KUSER field into
                // every supported native/WoW64 process. No guest value is used.
                unsafe {
                    let high1 = std::ptr::read_volatile((0x7ffe0018usize) as *const u32);
                    let low = std::ptr::read_volatile((0x7ffe0014usize) as *const u32);
                    let high2 = std::ptr::read_volatile((0x7ffe001cusize) as *const u32);
                    if high1 == high2 {
                        return (u64::from(high1) << 32) | u64::from(low);
                    }
                }
            }
        }
        let before = shared();
        let actual = now().unwrap();
        let after = shared();
        assert!(
            (before..=after).contains(&actual),
            "native coarse clock: {before} {actual} {after}"
        );
        assert!(matches!(output_alignment(true).unwrap(), 1 | 4));
    }
}
