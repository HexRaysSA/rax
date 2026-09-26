//! Times as a call copies them from and to its caller
//! (`kernel/time/time.c`): `struct __kernel_timespec` (`get_timespec64`,
//! `put_timespec64`), or for a compatibility task's `*_time32` calls
//! [`Ctx::time32`] `struct old_timespec32` (`get_old_timespec32`,
//! `put_old_timespec32`); the interval-and-value pairs of both; `struct
//! __kernel_old_timeval` or, in any 32-bit call, `struct old_timeval32`;
//! and `time_t` or `old_time32_t`.
//!
//! A compatibility task's 64-bit `timespec` holds 32 bits of padding above
//! its nanoseconds, which `get_timespec64` clears before any check. Nothing
//! here validates a value: each call checks what it reads as the kernel
//! does.

use super::super::abi::errno::Errno;
use super::super::abi::types::Timespec;
use super::Ctx;

impl Ctx<'_> {
    /// `sizeof(struct timespec)` as this call reads it.
    pub fn timespec_size(&self) -> u64 {
        if self.time32 { 8 } else { 16 }
    }

    /// A `timespec` from `addr`.
    pub fn get_timespec(&self, addr: u64) -> Result<Timespec, Errno> {
        let b = self.read_mem(addr, self.timespec_size() as usize)?;
        Ok(if self.time32 {
            let w = |i: usize| i64::from(i32::from_le_bytes(b[i..i + 4].try_into().unwrap()));
            Timespec {
                sec: w(0),
                nsec: w(4),
            }
        } else {
            let mut t = Timespec::decode(&b.try_into().unwrap());
            if self.compat {
                t.nsec &= 0xFFFF_FFFF;
            }
            t
        })
    }

    /// A `timespec` to `addr` (32-bit fields truncated for a `*_time32`
    /// call).
    pub fn put_timespec(&self, addr: u64, t: Timespec) -> Result<(), Errno> {
        if self.time32 {
            let mut b = [0u8; 8];
            b[..4].copy_from_slice(&(t.sec as i32).to_le_bytes());
            b[4..].copy_from_slice(&(t.nsec as i32).to_le_bytes());
            self.write_mem(addr, &b)
        } else {
            self.write_mem(addr, &t.encode())
        }
    }

    /// An interval and a value (`struct __kernel_itimerspec` or `struct
    /// old_itimerspec32`), in that order.
    pub fn get_itimerspec(&self, addr: u64) -> Result<(Timespec, Timespec), Errno> {
        let n = self.timespec_size();
        Ok((self.get_timespec(addr)?, self.get_timespec(addr + n)?))
    }

    /// An interval and a value to `addr`.
    pub fn put_itimerspec(
        &self,
        addr: u64,
        interval: Timespec,
        value: Timespec,
    ) -> Result<(), Errno> {
        let n = self.timespec_size() as usize;
        let mut b = vec![0u8; 2 * n];
        let enc = |t: Timespec| -> Vec<u8> {
            if self.time32 {
                [(t.sec as i32).to_le_bytes(), (t.nsec as i32).to_le_bytes()].concat()
            } else {
                t.encode().to_vec()
            }
        };
        b[..n].copy_from_slice(&enc(interval));
        b[n..].copy_from_slice(&enc(value));
        self.write_mem(addr, &b)
    }

    /// `sizeof(struct timeval)` as this call reads it: `struct
    /// old_timeval32` in any 32-bit call.
    pub fn timeval_size(&self) -> u64 {
        if self.compat { 8 } else { 16 }
    }

    /// A `timeval` (seconds, microseconds) from `addr`.
    pub fn get_timeval(&self, addr: u64) -> Result<(i64, i64), Errno> {
        let b = self.read_mem(addr, self.timeval_size() as usize)?;
        Ok(if self.compat {
            let w = |i: usize| i64::from(i32::from_le_bytes(b[i..i + 4].try_into().unwrap()));
            (w(0), w(4))
        } else {
            let w = |i: usize| i64::from_le_bytes(b[i..i + 8].try_into().unwrap());
            (w(0), w(8))
        })
    }

    /// The bytes of a `timeval`.
    pub fn timeval_bytes(&self, sec: i64, usec: i64) -> Vec<u8> {
        if self.compat {
            [(sec as i32).to_le_bytes(), (usec as i32).to_le_bytes()].concat()
        } else {
            [sec.to_le_bytes(), usec.to_le_bytes()].concat()
        }
    }

    /// A `time_t` (`old_time32_t` for a `*_time32` call) to `addr`.
    pub fn put_time(&self, addr: u64, sec: i64) -> Result<(), Errno> {
        if self.time32 {
            self.write_u32(addr, sec as u32)
        } else {
            self.write_u64(addr, sec as u64)
        }
    }
}
