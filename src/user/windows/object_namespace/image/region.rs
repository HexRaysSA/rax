//! A native image query may include reserved allocation padding after its view.
use super::{ImageRegion, MAX_IMAGE_BYTES, MAX_IMAGE_TAIL_BYTES, invalid};
use crate::user::windows::memory::{mem, valid_protection};
use std::io;

pub(crate) struct Query {
    pub(crate) base: u64,
    pub(crate) allocation: u64,
    pub(crate) size: u64,
    pub(crate) state: u32,
    pub(crate) protection: u32,
    pub(crate) kind: u32,
}

pub(crate) struct Selected {
    pub(crate) region: ImageRegion,
    pub(crate) reserved_tail: u64,
}

impl Query {
    /// Query the first page after all explicit image/extension bytes. Only a
    /// bounded same-owner reserved run is retained; adjacent allocations are
    /// outside the image and supply no padding.
    pub(crate) fn reserved_after(self, base: u64, payload: u64) -> io::Result<u64> {
        let at = base
            .checked_add(payload)
            .ok_or_else(|| invalid("native image tail address overflow"))?;
        if base == 0
            || base % 4096 != 0
            || payload < 4096
            || payload % 4096 != 0
            || payload > MAX_IMAGE_BYTES + 2 * super::MAX_EXTENSION_BYTES
        {
            return Err(invalid("native image payload extent exceeds bounds"));
        }
        if self.state == mem::FREE || self.allocation != base {
            return Ok(0);
        }
        if self.base != at
            || self.kind != mem::IMAGE
            || self.state != mem::RESERVE
            || self.protection != 0
            || self.size == 0
            || self.size % 4096 != 0
            || self.size > MAX_IMAGE_TAIL_BYTES
            || at.checked_add(self.size).is_none()
        {
            return Err(invalid(
                "selected native image reserved tail policy changed",
            ));
        }
        Ok(self.size)
    }

    /// O(1) time/storage. Only uncommitted owner padding may exceed the logical
    /// image; it has no source bytes to copy. All copied runs remain in bounds.
    pub(crate) fn select(self, base: u64, size: u64, offset: u64) -> io::Result<Selected> {
        let end = base
            .checked_add(size)
            .ok_or_else(|| invalid("native image view overflow"))?;
        let at = base
            .checked_add(offset)
            .ok_or_else(|| invalid("native image cursor overflow"))?;
        let region_end = self
            .base
            .checked_add(self.size)
            .ok_or_else(|| invalid("native image region overflow"))?;
        if base == 0
            || base % 4096 != 0
            || !(4096..=MAX_IMAGE_BYTES).contains(&size)
            || size % 4096 != 0
            || offset >= size
            || offset % 4096 != 0
            || self.base != at
            || self.allocation != base
            || self.kind != mem::IMAGE
            || self.size == 0
            || self.size % 4096 != 0
            || !matches!(self.state, mem::COMMIT | mem::RESERVE)
            || self.state == mem::COMMIT && !valid_protection(self.protection)
            || self.state == mem::RESERVE && self.protection != 0
        {
            return Err(invalid(
                "selected native image region identity or page policy changed",
            ));
        }
        let reserved_tail = region_end.saturating_sub(end);
        if reserved_tail > MAX_IMAGE_TAIL_BYTES || reserved_tail != 0 && self.state != mem::RESERVE
        {
            return Err(invalid("selected native image region exceeds its view"));
        }
        Ok(Selected {
            region: ImageRegion {
                offset,
                size: self.size.min(size - offset),
                state: self.state,
                protection: self.protection,
            },
            reserved_tail,
        })
    }
}

#[cfg(test)]
mod tests;
