//! Guarded guest memory.
//!
//! Memory is a set of objects. An access names its object through the
//! pointer's origin and is checked against that object before any byte is
//! read or written: provenance, liveness, bounds, alignment, permission and
//! the lifetime of the bytes touched, in that order. An address alone grants
//! nothing.
//!
//! Every byte carries, beside its value bits, a poison mask and an undef mask,
//! and remembers when it is one byte of a stored pointer. A pointer therefore
//! survives being stored and loaded whole, and loses its origin when its
//! bytes are reassembled in any other way.
//!
//! This is the first, simple representation: one record per guest byte. The
//! behaviour, including the address every allocation receives, follows the
//! Python reference machine so that the two can be compared.

use crate::ir::{ObjectId, Pointer, Scalar, Value};

/// Why a memory operation did not happen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fault {
    /// A defined trap, such as an access out of bounds.
    Trap(&'static str),
    /// Undefined behaviour, such as access through a pointer with no origin.
    Ub(&'static str),
    /// A host limit; the run stops without a fault location.
    Resource(&'static str),
}

/// One byte of a stored pointer: which pointer, and which of its bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Fragment {
    pointer: Pointer,
    index: u8,
}

#[derive(Clone, Copy, Debug)]
struct Byte {
    bits: u8,
    poison: u8,
    undef: u8,
    fragment: Option<Fragment>,
}

impl Byte {
    const UNDEF: Self = Self {
        bits: 0,
        poison: 0,
        undef: 0xff,
        fragment: None,
    };
}

struct Object {
    address: u64,
    live: bool,
    mutable: bool,
    /// The address was converted to an integer, so an integer may name it.
    exposed: bool,
    /// Per byte: inside its lifetime.
    active: Vec<bool>,
    bytes: Vec<Byte>,
}

impl Object {
    fn size(&self) -> u64 {
        self.bytes.len() as u64
    }

    /// Whether `address` is inside the object or one past its end.
    fn spans(&self, address: u64) -> bool {
        self.address <= address && address - self.address <= self.size()
    }
}

pub(crate) struct Memory {
    objects: Vec<Object>,
    /// Lowest address the next object may take. Kept wider than an address so
    /// that exhausting the address space is detected, not wrapped.
    next_address: u128,
    live_bytes: u64,
    max_bytes: u64,
}

/// Bytes of live objects a run may hold at once.
pub(crate) const DEFAULT_MAX_BYTES: u64 = 1024 * 1024;

impl Memory {
    pub(crate) fn new(max_bytes: u64) -> Self {
        Self {
            objects: Vec::new(),
            next_address: 0x10000,
            live_bytes: 0,
            max_bytes,
        }
    }

    /// Create a live, mutable object of `size` bytes, every bit undef.
    pub(crate) fn allocate(&mut self, size: u64, alignment: u64) -> Result<Pointer, Fault> {
        if !alignment.is_power_of_two() {
            return Err(Fault::Trap("allocation_shape"));
        }
        if size > self.max_bytes || self.live_bytes + size > self.max_bytes {
            return Err(Fault::Resource("resource_memory"));
        }
        let alignment = u128::from(alignment);
        let address = (self.next_address + alignment - 1) & !(alignment - 1);
        // The last address is reserved so that one past the end of any object
        // is still representable.
        if address >= 1 << 64 || address + u128::from(size) > (1 << 64) - 1 {
            return Err(Fault::Trap("source_object_extent"));
        }
        // A gap after every object keeps one-past-the-end of one object
        // distinct from the start of the next.
        self.next_address = address + u128::from(size.max(1)) + 16;
        self.live_bytes += size;
        let id = ObjectId(
            u32::try_from(self.objects.len()).map_err(|_| Fault::Resource("resource_memory"))?,
        );
        self.objects.push(Object {
            address: address as u64,
            live: true,
            mutable: true,
            exposed: false,
            active: vec![true; size as usize],
            bytes: vec![Byte::UNDEF; size as usize],
        });
        Ok(Pointer {
            address: address as u64,
            origin: Some(id),
        })
    }

    /// End an object. Later accesses through any pointer to it trap.
    pub(crate) fn release(&mut self, id: ObjectId) {
        if let Some(object) = self.objects.get_mut(id.0 as usize)
            && object.live
        {
            object.live = false;
            self.live_bytes -= object.size();
        }
    }

    /// Check an access of `size` bytes and return the object and offset.
    fn guard(
        &self,
        pointer: Pointer,
        size: u64,
        alignment: u64,
        lifetime_check: bool,
        write: bool,
    ) -> Result<(usize, usize), Fault> {
        let index = pointer
            .origin
            .map(|id| id.0 as usize)
            .filter(|index| *index < self.objects.len())
            .ok_or(Fault::Ub("pointer_provenance"))?;
        let object = &self.objects[index];
        if !object.live {
            return Err(Fault::Trap("memory_lifetime"));
        }
        let offset = pointer
            .address
            .checked_sub(object.address)
            .filter(|offset| {
                offset
                    .checked_add(size)
                    .is_some_and(|end| end <= object.size())
            })
            .ok_or(Fault::Trap("memory_bounds"))?;
        if pointer.address % alignment != 0 {
            return Err(Fault::Trap("memory_alignment"));
        }
        if write && !object.mutable {
            return Err(Fault::Trap("memory_permission"));
        }
        let (offset, size) = (offset as usize, size as usize);
        if lifetime_check
            && !object.active[offset..offset + size]
                .iter()
                .all(|active| *active)
        {
            return Err(Fault::Trap("memory_lifetime"));
        }
        Ok((index, offset))
    }

    /// Read a scalar of `kind` from `bytes` bytes at `pointer`.
    pub(crate) fn load(
        &self,
        pointer: Pointer,
        kind: Scalar,
        bytes: u32,
        alignment: u32,
    ) -> Result<Value, Fault> {
        let (index, offset) =
            self.guard(pointer, u64::from(bytes), u64::from(alignment), true, false)?;
        let stored = &self.objects[index].bytes[offset..offset + bytes as usize];
        let (mut bits, mut poison, mut undef) = (0_u128, 0_u128, 0_u128);
        for (position, byte) in stored.iter().enumerate() {
            bits |= u128::from(byte.bits) << (8 * position);
            poison |= u128::from(byte.poison) << (8 * position);
            undef |= u128::from(byte.undef) << (8 * position);
        }
        let width = kind.bits();
        let value_mask = if width == 128 {
            u128::MAX
        } else {
            (1 << width) - 1
        };
        // Padding above the value must read as zero; set or poison padding
        // makes the whole value poison. Undef padding is acceptable.
        if (bits | poison) & !value_mask != 0 || poison & value_mask != 0 {
            return Ok(Value::Poison);
        }
        Ok(match kind {
            // Undef bits are refined to zero by this load.
            Scalar::Int { .. } => Value::Int(bits & value_mask & !undef),
            Scalar::DataPtr => {
                // The origin survives only if these are the eight bytes of one
                // stored pointer, in order.
                let whole =
                    stored[0]
                        .fragment
                        .map(|fragment| fragment.pointer)
                        .filter(|candidate| {
                            stored.iter().enumerate().all(|(position, byte)| {
                                byte.fragment
                                    == Some(Fragment {
                                        pointer: *candidate,
                                        index: position as u8,
                                    })
                            })
                        });
                Value::DataPtr(whole.unwrap_or(Pointer::originless(bits as u64)))
            }
        })
    }

    /// Write `value`, a scalar of `kind`, as `bytes` bytes at `pointer`.
    pub(crate) fn store(
        &mut self,
        pointer: Pointer,
        value: Value,
        kind: Scalar,
        bytes: u32,
        alignment: u32,
    ) -> Result<(), Fault> {
        // The whole write is validated before any byte changes.
        let (index, offset) =
            self.guard(pointer, u64::from(bytes), u64::from(alignment), true, true)?;
        let width = kind.bits();
        let value_mask = if width == 128 {
            u128::MAX
        } else {
            (1 << width) - 1
        };
        let (bits, poison, undef, stored_pointer) = match value {
            Value::Int(bits) => (bits, 0, 0, None),
            Value::Poison => (0, value_mask, 0, None),
            Value::Undef => (0, 0, value_mask, None),
            // A pointer without an origin is stored as plain bits.
            Value::DataPtr(source) => (
                u128::from(source.address),
                0,
                0,
                source.origin.map(|_| source),
            ),
            Value::CodeAddress(_) | Value::CodePtr(_) => {
                return Err(Fault::Trap("memory_code_pointer"));
            }
        };
        let target = &mut self.objects[index].bytes[offset..offset + bytes as usize];
        for (position, byte) in target.iter_mut().enumerate() {
            // Padding above the value is written as defined zero bits.
            *byte = Byte {
                bits: (bits >> (8 * position)) as u8,
                poison: (poison >> (8 * position)) as u8,
                undef: (undef >> (8 * position)) as u8,
                fragment: stored_pointer
                    .filter(|_| position < 8)
                    .map(|pointer| Fragment {
                        pointer,
                        index: position as u8,
                    }),
            };
        }
        Ok(())
    }

    /// Begin or end the lifetime of `size` bytes. Starting a lifetime makes
    /// the bytes undef again.
    pub(crate) fn lifetime(
        &mut self,
        pointer: Pointer,
        size: u64,
        start: bool,
    ) -> Result<(), Fault> {
        let (index, offset) = self.guard(pointer, size, 1, false, false)?;
        let object = &mut self.objects[index];
        let range = offset..offset + size as usize;
        object.active[range.clone()].fill(start);
        if start {
            object.bytes[range].fill(Byte::UNDEF);
        }
        Ok(())
    }

    /// `pointer` moved by `delta`, or `None` when a flag is violated and the
    /// result is poison.
    pub(crate) fn offset(
        &self,
        pointer: Pointer,
        delta: i64,
        inbounds: bool,
        check_base: bool,
        nuw: bool,
        nusw: bool,
    ) -> Option<Pointer> {
        // `nuw` reads the offset as unsigned; `nusw` and `inbounds` read it as
        // signed and forbid leaving the address space.
        if nuw && pointer.address.checked_add(delta as u64).is_none() {
            return None;
        }
        let moved = i128::from(pointer.address) + i128::from(delta);
        if (nusw || inbounds) && !(0..1 << 64).contains(&moved) {
            return None;
        }
        let result = Pointer {
            address: pointer.address.wrapping_add(delta as u64),
            origin: pointer.origin,
        };
        if inbounds && (delta != 0 || check_base) {
            // Both ends must lie in, or one past, the pointer's own object.
            let object = pointer
                .origin
                .and_then(|id| self.objects.get(id.0 as usize))?;
            if !object.spans(pointer.address) || !object.spans(result.address) {
                return None;
            }
        }
        Some(result)
    }

    /// Record that the pointer's address became visible as an integer.
    pub(crate) fn expose(&mut self, pointer: Pointer) {
        if let Some(object) = pointer
            .origin
            .and_then(|id| self.objects.get_mut(id.0 as usize))
        {
            object.exposed = true;
        }
    }

    /// A pointer for an integer address. It gains an origin only if the
    /// address lies in, or one past, a live object that has been exposed.
    pub(crate) fn integer_pointer(&self, address: u64) -> Pointer {
        let origin = self
            .objects
            .iter()
            .position(|object| object.exposed && object.live && object.spans(address))
            .map(|index| ObjectId(index as u32));
        Pointer { address, origin }
    }
}

#[cfg(test)]
#[path = "memory_tests.rs"]
mod tests;
