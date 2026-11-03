//! Physical RISC-V reservation transactions. Translation and MMIO admission
//! must finish before these functions acquire the shared RAM writer domain.
use super::{MemError, MemResult};
use crate::vm::memory::reservations::{Monitor, preflight_write};
use vm_memory::{GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};

fn validate(address: u64, size: usize) -> MemResult<()> {
    if !matches!(size, 4 | 8) {
        return Err(MemError::OutOfBounds {
            addr: address,
            size,
        });
    }
    if address & (size as u64 - 1) != 0 {
        return Err(MemError::Misaligned {
            addr: address,
            size,
        });
    }
    Ok(())
}

pub(crate) fn load(
    memory: &GuestMemoryMmap,
    monitor: &Monitor,
    address: u64,
    buf: &mut [u8],
) -> MemResult<()> {
    let result = (|| {
        validate(address, buf.len())?;
        let mut done = 0;
        while done < buf.len() {
            let current = address
                .checked_add(done as u64)
                .ok_or(MemError::OutOfBounds {
                    addr: address,
                    size: buf.len(),
                })?;
            let region =
                memory
                    .find_region(GuestAddress(current))
                    .ok_or(MemError::OutOfBounds {
                        addr: address,
                        size: buf.len(),
                    })?;
            #[cfg(unix)]
            if region.prot() & libc::PROT_READ == 0 {
                return Err(MemError::OutOfBounds {
                    addr: address,
                    size: buf.len(),
                });
            }
            done +=
                ((region.len() - (current - region.start_addr().0)) as usize).min(buf.len() - done);
        }
        let bytes = monitor
            .read_exclusive(memory, address, buf.len())
            .map_err(|_| MemError::OutOfBounds {
                addr: address,
                size: buf.len(),
            })?;
        buf.copy_from_slice(&bytes);
        Ok(())
    })();
    if result.is_err() {
        monitor.clear();
    }
    result
}

pub(crate) fn store(
    memory: &GuestMemoryMmap,
    monitor: &Monitor,
    address: u64,
    data: &[u8],
    eligible: bool,
) -> MemResult<bool> {
    let result = (|| {
        validate(address, data.len())?;
        // SC must check store access even when the reservation has expired.
        preflight_write(memory, address, data.len()).map_err(|_| MemError::OutOfBounds {
            addr: address,
            size: data.len(),
        })?;
        if !eligible {
            monitor.clear();
            return Ok(false);
        }
        monitor
            .write_exclusive(memory, address, data)
            .map_err(|_| MemError::OutOfBounds {
                addr: address,
                size: data.len(),
            })
    })();
    if result.is_err() {
        monitor.clear();
    }
    result
}
