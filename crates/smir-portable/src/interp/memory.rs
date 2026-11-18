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
//! survives being stored and loaded whole. Reassembled in any other way, its
//! bytes are an address: reading them as an integer exposes the object or
//! function the pointer designated, and an address read as a pointer
//! designates an exposed object that contains it, as the conversion of that
//! integer to a pointer would.
//!
//! This is the first, simple representation: one record per guest byte. The
//! behaviour, including the address every allocation receives, follows the
//! Python reference machine so that the two can be compared.
//!
//! Memory is shared by the program's threads. Every method takes `&self`.
//! Objects are found without a lock: the table only grows, and an object
//! stays in it after it has ended. Each object's bytes are behind a
//! reader-writer lock of their own, held for one operation, so threads that
//! read one object or work on different objects do not wait for each other,
//! and whatever a racing program does, each operation sees and leaves an
//! object in a consistent state. No operation holds two object locks at
//! once. Only creating an object takes a lock all threads share.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{
    Mutex, MutexGuard, OnceLock, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard,
};

use crate::ir::{CodeRef, FuncIdx, ObjectId, Pointer, Scalar, Value};

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

/// A pointer whose bytes are in memory with their origin intact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stored {
    Data(Pointer),
    /// A callable pointer to a function.
    Code(FuncIdx),
}

/// One byte of a stored pointer: which pointer, and which of its bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Fragment {
    pointer: Stored,
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

/// What a pointer read from memory designates, to be exposed once the lock on
/// the bytes it was read from is released.
#[derive(Default)]
struct Exposures {
    objects: Vec<ObjectId>,
    functions: Vec<FuncIdx>,
}

impl Exposures {
    /// Note whatever the pointers stored in `bytes` designate: their bytes
    /// are being read as numbers.
    fn note(&mut self, bytes: &[Byte]) {
        for byte in bytes {
            match byte.fragment.map(|fragment| fragment.pointer) {
                Some(Stored::Data(pointer)) => self.objects.extend(pointer.origin),
                Some(Stored::Code(function)) => self.functions.push(function),
                None => {}
            }
        }
    }
}

struct Object {
    address: u64,
    size: u64,
    live: AtomicBool,
    /// The address was converted to an integer, so an integer may name it.
    exposed: AtomicBool,
    /// The program mapped it, and may unmap it or change its permissions.
    mapped: bool,
    contents: RwLock<Contents>,
}

/// What an access needs the bytes to permit.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Need {
    Read,
    Write,
    /// A read and a write in one step.
    Update,
    /// Neither: the access changes what the bytes are, not what they hold.
    Nothing,
}

struct Contents {
    readable: bool,
    mutable: bool,
    /// Per byte: inside its lifetime.
    active: Vec<bool>,
    bytes: Vec<Byte>,
}

impl Object {
    /// Whether `address` is inside the object or one past its end.
    fn spans(&self, address: u64) -> bool {
        self.address <= address && address - self.address <= self.size
    }

    /// The contents, for reading. A lock whose holder panicked still guards
    /// consistent data here: every critical section validates before it
    /// writes.
    fn read(&self) -> RwLockReadGuard<'_, Contents> {
        self.contents.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> RwLockWriteGuard<'_, Contents> {
        self.contents
            .write()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The checks of an access of `size` bytes at `pointer`, after the
    /// provenance check that found this object: liveness, bounds, alignment,
    /// permission and the lifetime of the bytes, in that order. Returns the
    /// offset of the access.
    fn check(
        &self,
        contents: &Contents,
        pointer: Pointer,
        size: u64,
        alignment: u64,
        lifetime_check: bool,
        need: Need,
    ) -> Result<usize, Fault> {
        if !self.live.load(Ordering::Acquire) {
            return Err(Fault::Trap("memory_lifetime"));
        }
        let offset = pointer
            .address
            .checked_sub(self.address)
            .filter(|offset| offset.checked_add(size).is_some_and(|end| end <= self.size))
            .ok_or(Fault::Trap("memory_bounds"))?;
        if pointer.address % alignment != 0 {
            return Err(Fault::Trap("memory_alignment"));
        }
        let permitted = match need {
            Need::Read => contents.readable,
            Need::Write => contents.mutable,
            Need::Update => contents.readable && contents.mutable,
            Need::Nothing => true,
        };
        if !permitted {
            return Err(Fault::Trap("memory_permission"));
        }
        let (offset, size) = (offset as usize, size as usize);
        if lifetime_check
            && !contents.active[offset..offset + size]
                .iter()
                .all(|active| *active)
        {
            return Err(Fault::Trap("memory_lifetime"));
        }
        Ok(offset)
    }
}

/// As for an object's lock: a panic leaves what a mutex here guards
/// consistent.
fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The pointer these bytes are, if they are all eight bytes of one stored
/// pointer in order.
fn whole(stored: &[Byte]) -> Option<Stored> {
    let candidate = stored.first()?.fragment?.pointer;
    (stored.len() == 8
        && stored.iter().enumerate().all(|(position, byte)| {
            byte.fragment
                == Some(Fragment {
                    pointer: candidate,
                    index: position as u8,
                })
        }))
    .then_some(candidate)
}

fn value_mask(kind: Scalar) -> u128 {
    let width = kind.bits();
    if width == 128 {
        u128::MAX
    } else {
        (1 << width) - 1
    }
}

/// The bytes of a scalar as they were read, before they are given a type.
struct Raw {
    bits: u128,
    poison: u128,
    undef: u128,
    pointer: Option<Stored>,
}

fn read(stored: &[Byte]) -> Raw {
    let (mut bits, mut poison, mut undef) = (0_u128, 0_u128, 0_u128);
    for (position, byte) in stored.iter().enumerate() {
        bits |= u128::from(byte.bits) << (8 * position);
        poison |= u128::from(byte.poison) << (8 * position);
        undef |= u128::from(byte.undef) << (8 * position);
    }
    Raw {
        bits,
        poison,
        undef,
        pointer: whole(stored),
    }
}

/// Write `value`, a scalar of `kind`, over `target`.
fn write(target: &mut [Byte], value: Value, kind: Scalar) -> Result<(), Fault> {
    let mask = value_mask(kind);
    let (bits, poison, undef, stored_pointer) = match value {
        Value::Int(bits) => (bits, 0, 0, None),
        Value::Poison => (0, mask, 0, None),
        Value::Undef => (0, 0, mask, None),
        // A pointer without an origin is stored as plain bits.
        Value::DataPtr(source) => (
            u128::from(source.address),
            0,
            0,
            source.origin.map(|_| Stored::Data(source)),
        ),
        Value::CodePtr(target) => (
            u128::from(target.bits()),
            0,
            0,
            match target {
                CodeRef::Function(function) => Some(Stored::Code(function)),
                CodeRef::Originless(_) => None,
            },
        ),
        Value::CodeAddress(_) => return Err(Fault::Trap("memory_code_pointer")),
    };
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

/// Slots in the first part of the table; each further part is twice the
/// size of the one before.
const FIRST_PART: usize = 1024;
/// Parts enough for every 32-bit identifier.
const PARTS: usize = 23;

/// Every object ever created, by identifier. The table only grows, in parts
/// that never move, so an object is found without a lock while others are
/// added. Identifiers and addresses grow together.
struct Table {
    parts: [OnceLock<Box<[OnceLock<Object>]>>; PARTS],
    /// How many objects there are. Every one below this is in place.
    count: AtomicU32,
}

impl Table {
    fn new() -> Self {
        Self {
            parts: std::array::from_fn(|_| OnceLock::new()),
            count: AtomicU32::new(0),
        }
    }

    /// The part an identifier is in, and its position there.
    fn place(id: u32) -> (usize, usize) {
        let part = (id as usize / FIRST_PART + 1).ilog2() as usize;
        (part, id as usize - FIRST_PART * ((1 << part) - 1))
    }

    fn get(&self, id: u32) -> Option<&Object> {
        let (part, position) = Self::place(id);
        self.parts.get(part)?.get()?.get(position)?.get()
    }

    /// Add an object and return its identifier, or `None` if there are no
    /// more identifiers. One thread at a time may add.
    fn push(&self, object: Object) -> Option<ObjectId> {
        let id = self.count.load(Ordering::Acquire);
        let next = id.checked_add(1)?;
        let (part, position) = Self::place(id);
        let slots = self.parts.get(part)?.get_or_init(|| {
            (0..FIRST_PART << part)
                .map(|_| OnceLock::new())
                .collect::<Vec<_>>()
                .into_boxed_slice()
        });
        slots.get(position)?.set(object).ok()?;
        self.count.store(next, Ordering::Release);
        Some(ObjectId(id))
    }
}

pub(crate) struct Memory {
    table: Table,
    /// Lowest address the next object may take, held while an object is
    /// created. Kept wider than an address so that exhausting the address
    /// space is detected, not wrapped.
    next_address: Mutex<u128>,
    live_bytes: AtomicU64,
    max_bytes: u64,
    /// Functions whose token was read as an integer. Those bits, read back
    /// as a code pointer, designate the function again.
    exposed_code: Mutex<BTreeSet<FuncIdx>>,
}

/// Bytes of live objects a run may hold at once.
pub(crate) const DEFAULT_MAX_BYTES: u64 = 1024 * 1024;

impl Memory {
    pub(crate) fn new(max_bytes: u64) -> Self {
        Self {
            table: Table::new(),
            next_address: Mutex::new(0x10000),
            live_bytes: AtomicU64::new(0),
            max_bytes,
            exposed_code: Mutex::new(BTreeSet::new()),
        }
    }

    fn object(&self, origin: Option<ObjectId>) -> Option<&Object> {
        self.table.get(origin?.0)
    }

    /// Create a live, mutable object of `size` bytes, every bit undef.
    pub(crate) fn allocate(&self, size: u64, alignment: u64) -> Result<Pointer, Fault> {
        self.create(size, alignment, Byte::UNDEF, None)
    }

    /// Create a live object of `size` bytes that each start as `byte`. With
    /// `mapping`, the program mapped it, with these read and write
    /// permissions.
    fn create(
        &self,
        size: u64,
        alignment: u64,
        byte: Byte,
        mapping: Option<(bool, bool)>,
    ) -> Result<Pointer, Fault> {
        if !alignment.is_power_of_two() {
            return Err(Fault::Trap("allocation_shape"));
        }
        let mut next_address = locked(&self.next_address);
        if size > self.max_bytes || self.live_bytes.load(Ordering::Acquire) + size > self.max_bytes
        {
            return Err(Fault::Resource("resource_memory"));
        }
        let alignment = u128::from(alignment);
        let address = (*next_address + alignment - 1) & !(alignment - 1);
        // The last address is reserved so that one past the end of any object
        // is still representable.
        if address >= 1 << 64 || address + u128::from(size) > (1 << 64) - 1 {
            return Err(Fault::Trap("source_object_extent"));
        }
        let id = self
            .table
            .push(Object {
                address: address as u64,
                size,
                live: AtomicBool::new(true),
                exposed: AtomicBool::new(false),
                mapped: mapping.is_some(),
                contents: RwLock::new(Contents {
                    readable: mapping.is_none_or(|(readable, _)| readable),
                    mutable: mapping.is_none_or(|(_, writable)| writable),
                    active: vec![true; size as usize],
                    bytes: vec![byte; size as usize],
                }),
            })
            .ok_or(Fault::Resource("resource_memory"))?;
        // A gap after every object keeps one-past-the-end of one object
        // distinct from the start of the next.
        *next_address = address + u128::from(size.max(1)) + 16;
        self.live_bytes.fetch_add(size, Ordering::AcqRel);
        Ok(Pointer {
            address: address as u64,
            origin: Some(id),
        })
    }

    /// Map `size` bytes of defined zeros for the program, readable and
    /// writable as asked.
    pub(crate) fn map(
        &self,
        size: u64,
        alignment: u64,
        readable: bool,
        writable: bool,
    ) -> Result<Pointer, Fault> {
        let zero = Byte {
            bits: 0,
            poison: 0,
            undef: 0,
            fragment: None,
        };
        self.create(size, alignment, zero, Some((readable, writable)))
    }

    /// The live mapping that `pointer` is the start of and `size` the size
    /// of. A mapping is unmapped and protected whole.
    fn mapping(&self, pointer: Pointer, size: u64) -> Option<(ObjectId, &Object)> {
        let id = pointer.origin?;
        let object = self.object(Some(id))?;
        (object.mapped
            && object.live.load(Ordering::Acquire)
            && object.address == pointer.address
            && object.size == size)
            .then_some((id, object))
    }

    /// End a mapping. Returns whether `pointer` and `size` name one.
    pub(crate) fn unmap(&self, pointer: Pointer, size: u64) -> bool {
        match self.mapping(pointer, size) {
            Some((id, _)) => {
                self.release(id);
                true
            }
            None => false,
        }
    }

    /// Change what a mapping permits. Returns whether `pointer` and `size`
    /// name one.
    pub(crate) fn protect(
        &self,
        pointer: Pointer,
        size: u64,
        readable: bool,
        writable: bool,
    ) -> bool {
        let Some((_, object)) = self.mapping(pointer, size) else {
            return false;
        };
        let mut contents = object.write();
        // It may have been unmapped since it was found.
        if !object.live.load(Ordering::Acquire) {
            return false;
        }
        contents.readable = readable;
        contents.mutable = writable;
        true
    }

    /// Create the object of a data segment from its initial image. The object
    /// stays writable until [`Memory::seal`], so that relocations can be
    /// applied to it.
    pub(crate) fn allocate_image(
        &self,
        bits: &[u8],
        poison: &[u8],
        undef: &[u8],
        alignment: u64,
    ) -> Result<Pointer, Fault> {
        let pointer = self.allocate(bits.len() as u64, alignment)?;
        if let Some(object) = self.object(pointer.origin) {
            for (position, byte) in object.write().bytes.iter_mut().enumerate() {
                *byte = Byte {
                    bits: bits[position],
                    poison: poison[position],
                    undef: undef[position],
                    fragment: None,
                };
            }
        }
        Ok(pointer)
    }

    /// Relocation: write a pointer to `target`, with its origin, at `offset`
    /// bytes into the object `base` points to. The range was checked when the
    /// module was loaded.
    pub(crate) fn patch_pointer(&self, base: Pointer, offset: u64, target: Pointer) {
        self.patch(base, offset, 8, |position| Byte {
            bits: (target.address >> (8 * position)) as u8,
            poison: 0,
            undef: 0,
            fragment: target.origin.map(|_| Fragment {
                pointer: Stored::Data(target),
                index: position as u8,
            }),
        });
    }

    /// Relocation: write a callable pointer to `function`.
    pub(crate) fn patch_function(&self, base: Pointer, offset: u64, function: FuncIdx) {
        let token = CodeRef::Function(function).bits();
        self.patch(base, offset, 8, |position| Byte {
            bits: (token >> (8 * position)) as u8,
            poison: 0,
            undef: 0,
            fragment: Some(Fragment {
                pointer: Stored::Code(function),
                index: position as u8,
            }),
        });
    }

    /// Relocation: write `value` as a plain integer of `bytes` bytes.
    pub(crate) fn patch_integer(&self, base: Pointer, offset: u64, value: u64, bytes: u32) {
        self.patch(base, offset, bytes as usize, |position| Byte {
            bits: (value >> (8 * position)) as u8,
            poison: 0,
            undef: 0,
            fragment: None,
        });
    }

    fn patch(&self, base: Pointer, offset: u64, count: usize, byte: impl Fn(usize) -> Byte) {
        let Some(object) = self.object(base.origin) else {
            return;
        };
        let start = offset as usize;
        if let Some(target) = object.write().bytes.get_mut(start..start + count) {
            for (position, slot) in target.iter_mut().enumerate() {
                *slot = byte(position);
            }
        }
    }

    /// Make an object read-only. Stores to it then trap.
    pub(crate) fn seal(&self, pointer: Pointer) {
        if let Some(object) = self.object(pointer.origin) {
            object.write().mutable = false;
        }
    }

    /// Check an access of `size` bytes at `pointer` that changes nothing,
    /// and perform it: `action` gets the object's contents and the offset of
    /// the access, with the object locked against writers. The bytes must be
    /// readable, or, with `permission`, writable instead: that asks whether
    /// a write could follow.
    fn shared<R>(
        &self,
        pointer: Pointer,
        size: u64,
        alignment: u64,
        permission: bool,
        action: impl FnOnce(&Contents, usize) -> R,
    ) -> Result<R, Fault> {
        let object = self
            .object(pointer.origin)
            .ok_or(Fault::Ub("pointer_provenance"))?;
        // An object ends under its lock, so it cannot end during the access.
        let contents = object.read();
        let need = if permission { Need::Write } else { Need::Read };
        let offset = object.check(&contents, pointer, size, alignment, true, need)?;
        Ok(action(&contents, offset))
    }

    /// Check an access of `size` bytes at `pointer` that may change them,
    /// and perform it with the object locked against every other access.
    fn exclusive<R>(
        &self,
        pointer: Pointer,
        size: u64,
        alignment: u64,
        lifetime_check: bool,
        need: Need,
        action: impl FnOnce(&mut Contents, usize) -> R,
    ) -> Result<R, Fault> {
        let object = self
            .object(pointer.origin)
            .ok_or(Fault::Ub("pointer_provenance"))?;
        let mut contents = object.write();
        let offset = object.check(&contents, pointer, size, alignment, lifetime_check, need)?;
        Ok(action(&mut contents, offset))
    }

    /// Expose what pointers read as numbers designated.
    fn expose_all(&self, exposures: Exposures) {
        for id in exposures.objects {
            if let Some(object) = self.object(Some(id)) {
                object.exposed.store(true, Ordering::Release);
            }
        }
        if !exposures.functions.is_empty() {
            locked(&self.exposed_code).extend(exposures.functions);
        }
    }

    /// Set `count` bytes at `pointer` to the 8-bit `value`.
    pub(crate) fn fill(
        &self,
        pointer: Pointer,
        value: Value,
        count: u64,
        alignment: u32,
    ) -> Result<(), Fault> {
        let byte = match value {
            Value::Int(bits) => Some(Byte {
                bits: bits as u8,
                poison: 0,
                undef: 0,
                fragment: None,
            }),
            Value::Poison => Some(Byte {
                bits: 0,
                poison: 0xff,
                undef: 0,
                fragment: None,
            }),
            Value::Undef => Some(Byte::UNDEF),
            _ => None,
        };
        self.exclusive(
            pointer,
            count,
            u64::from(alignment),
            true,
            Need::Write,
            |contents, offset| {
                // The access is checked before the value is.
                let byte = byte.ok_or(Fault::Trap("memory_code_pointer"))?;
                contents.bytes[offset..offset + count as usize].fill(byte);
                Ok(())
            },
        )?
    }

    /// Copy `count` bytes from `source` to `destination`, with their shadow
    /// and pointer fragments. Unless `overlapping` is allowed, a partial
    /// overlap is undefined behaviour; an exact self-copy is permitted.
    pub(crate) fn copy(
        &self,
        destination: Pointer,
        source: Pointer,
        count: u64,
        alignment: u32,
        overlapping: bool,
    ) -> Result<(), Fault> {
        let alignment = u64::from(alignment);
        // The destination is checked first, then the source is read, then
        // the destination is written: one object is locked at a time. The
        // offsets are those of the two accesses, which the checks validated.
        let target_offset = self.shared(destination, count, alignment, true, |_, at| at)?;
        let (source_offset, data) =
            self.shared(source, count, alignment, false, |contents, at| {
                (at, contents.bytes[at..at + count as usize].to_vec())
            })?;
        let count = count as usize;
        if !overlapping
            && source.origin == destination.origin
            && source_offset != target_offset
            && source_offset.max(target_offset) < source_offset.min(target_offset) + count
        {
            return Err(Fault::Ub("ub_memcpy_overlap"));
        }
        self.exclusive(
            destination,
            count as u64,
            alignment,
            true,
            Need::Write,
            |contents, at| contents.bytes[at..at + count].copy_from_slice(&data),
        )
    }

    /// The values of the first `limit` of `count` readable bytes at `pointer`,
    /// for a service that sends them out of the program. All `count` bytes
    /// are guarded. Undef bits refine to zero; a poison byte among those
    /// returned is undefined behaviour.
    pub(crate) fn read_bytes(
        &self,
        pointer: Pointer,
        count: u64,
        limit: usize,
    ) -> Result<Vec<u8>, Fault> {
        let mut exposures = Exposures::default();
        let taken = (count as usize).min(limit);
        let bytes = self.shared(pointer, count, 1, false, |contents, offset| {
            let stored = &contents.bytes[offset..offset + taken];
            // A pointer among the bytes leaves the program as a number.
            exposures.note(stored);
            stored
                .iter()
                .map(|byte| {
                    if byte.poison == 0 {
                        Ok(byte.bits & !byte.undef)
                    } else {
                        Err(Fault::Ub("ub_service_argument"))
                    }
                })
                .collect::<Result<Vec<u8>, Fault>>()
        })?;
        self.expose_all(exposures);
        bytes
    }

    /// Check that `count` bytes at `pointer` can be written by an access of
    /// `alignment`.
    pub(crate) fn writable(
        &self,
        pointer: Pointer,
        count: u64,
        alignment: u32,
    ) -> Result<(), Fault> {
        self.shared(pointer, count, u64::from(alignment), true, |_, _| ())
    }

    /// Write defined bytes that come from outside the program at `pointer`.
    pub(crate) fn write_bytes(&self, pointer: Pointer, bytes: &[u8]) -> Result<(), Fault> {
        self.exclusive(
            pointer,
            bytes.len() as u64,
            1,
            true,
            Need::Write,
            |contents, offset| {
                for (target, bits) in contents.bytes[offset..offset + bytes.len()]
                    .iter_mut()
                    .zip(bytes)
                {
                    *target = Byte {
                        bits: *bits,
                        poison: 0,
                        undef: 0,
                        fragment: None,
                    };
                }
            },
        )
    }

    /// End an object. Later accesses through any pointer to it trap.
    pub(crate) fn release(&self, id: ObjectId) {
        let Some(object) = self.object(Some(id)) else {
            return;
        };
        // Under the object's lock, so that no access is in progress. Its
        // record stays, for the pointers that still name it; its bytes go.
        let mut contents = object.write();
        if object.live.swap(false, Ordering::AcqRel) {
            contents.bytes = Vec::new();
            contents.active = Vec::new();
            self.live_bytes.fetch_sub(object.size, Ordering::AcqRel);
        }
    }

    /// Record that the function's token became visible as an integer.
    pub(crate) fn expose_code(&self, function: FuncIdx) {
        locked(&self.exposed_code).insert(function);
    }

    /// A code pointer for integer bits. It designates a function only if the
    /// bits are the token of a function that has been exposed.
    pub(crate) fn integer_code(&self, bits: u64) -> CodeRef {
        let function = (bits != 0 && bits % 2 == 0)
            .then(|| u32::try_from(bits / 2 - 1).ok())
            .flatten()
            .map(FuncIdx)
            .filter(|function| locked(&self.exposed_code).contains(function));
        function.map_or(CodeRef::Originless(bits), CodeRef::Function)
    }

    /// The value of bytes read as a scalar of `kind`. Reading the bytes of a
    /// pointer as a number adds what it designates to `exposures`.
    fn typed(&self, raw: &Raw, stored: &[Byte], kind: Scalar, exposures: &mut Exposures) -> Typed {
        let mask = value_mask(kind);
        // Padding above the value must read as zero; set or poison padding
        // makes the whole value poison. Undef padding is acceptable.
        if (raw.bits | raw.poison) & !mask != 0 || raw.poison & mask != 0 {
            return Typed::Value(Value::Poison);
        }
        match kind {
            // Undef bits are refined to zero by this load. The bytes of a
            // pointer read as a number expose what it designates.
            Scalar::Int { .. } => {
                exposures.note(stored);
                Typed::Value(Value::Int(raw.bits & mask & !raw.undef))
            }
            // A pointer's origin survives if these are the eight bytes of
            // one stored pointer of the same kind, in order. Anything else
            // is an address read as a pointer, which is what converting
            // that integer to a pointer would give; that is resolved once
            // the object is unlocked. A whole pointer of the other kind is
            // a pointer converted to an integer and back: what it
            // designated is exposed.
            Scalar::DataPtr => match raw.pointer {
                Some(Stored::Data(pointer)) => Typed::Value(Value::DataPtr(pointer)),
                Some(Stored::Code(function)) => {
                    exposures.functions.push(function);
                    Typed::Address(raw.bits as u64)
                }
                None => Typed::Address(raw.bits as u64),
            },
            Scalar::CodePtr => match raw.pointer {
                Some(Stored::Code(function)) => {
                    Typed::Value(Value::CodePtr(CodeRef::Function(function)))
                }
                Some(Stored::Data(pointer)) => {
                    exposures.objects.extend(pointer.origin);
                    Typed::Token(raw.bits as u64)
                }
                None => Typed::Token(raw.bits as u64),
            },
        }
    }

    fn resolve(&self, typed: Typed) -> Value {
        match typed {
            Typed::Value(value) => value,
            Typed::Address(address) => Value::DataPtr(self.integer_pointer(address)),
            Typed::Token(bits) => Value::CodePtr(self.integer_code(bits)),
        }
    }

    /// Read a scalar of `kind` from `bytes` bytes at `pointer`.
    pub(crate) fn load(
        &self,
        pointer: Pointer,
        kind: Scalar,
        bytes: u32,
        alignment: u32,
    ) -> Result<Value, Fault> {
        let mut exposures = Exposures::default();
        let typed = self.shared(
            pointer,
            u64::from(bytes),
            u64::from(alignment),
            false,
            |contents, offset| {
                let stored = &contents.bytes[offset..offset + bytes as usize];
                self.typed(&read(stored), stored, kind, &mut exposures)
            },
        )?;
        self.expose_all(exposures);
        Ok(self.resolve(typed))
    }

    /// Write `value`, a scalar of `kind`, as `bytes` bytes at `pointer`.
    pub(crate) fn store(
        &self,
        pointer: Pointer,
        value: Value,
        kind: Scalar,
        bytes: u32,
        alignment: u32,
    ) -> Result<(), Fault> {
        // The whole write is validated before any byte changes.
        self.exclusive(
            pointer,
            u64::from(bytes),
            u64::from(alignment),
            true,
            Need::Write,
            |contents, offset| {
                write(
                    &mut contents.bytes[offset..offset + bytes as usize],
                    value,
                    kind,
                )
            },
        )?
    }

    /// Read the scalar of `kind` at `pointer` and, with the object still
    /// locked, replace it by what `action` returns, if anything. `action`
    /// gets the value read and its bits with poison and undef bits as zero.
    /// Returns the value read and what `action` reported.
    ///
    /// This is one atomic step for every thread: no other access to the
    /// object comes between the read and the write.
    pub(crate) fn update<R>(
        &self,
        pointer: Pointer,
        kind: Scalar,
        bytes: u32,
        alignment: u32,
        action: impl FnOnce(Value, u128) -> (Option<Value>, R),
    ) -> Result<(Value, R), Fault> {
        let mut exposures = Exposures::default();
        let outcome = self.exclusive(
            pointer,
            u64::from(bytes),
            u64::from(alignment),
            true,
            Need::Update,
            |contents, offset| {
                let stored = &mut contents.bytes[offset..offset + bytes as usize];
                let raw = read(stored);
                let typed = self.typed(&raw, stored, kind, &mut exposures);
                // An address read as a pointer names an object only through
                // the table, which is not consulted with this object locked;
                // an exchange of pointers that were stored whole needs none.
                let old = match typed {
                    Typed::Value(value) => value,
                    Typed::Address(address) => Value::DataPtr(Pointer::originless(address)),
                    Typed::Token(bits) => Value::CodePtr(CodeRef::Originless(bits)),
                };
                let refined = raw.bits & !(raw.poison | raw.undef) & value_mask(kind);
                let (replacement, report) = action(old, refined);
                if let Some(value) = replacement {
                    write(stored, value, kind)?;
                }
                Ok((typed, report))
            },
        )??;
        self.expose_all(exposures);
        Ok((self.resolve(outcome.0), outcome.1))
    }

    /// Begin or end the lifetime of `size` bytes. Starting a lifetime makes
    /// the bytes undef again.
    pub(crate) fn lifetime(&self, pointer: Pointer, size: u64, start: bool) -> Result<(), Fault> {
        self.exclusive(
            pointer,
            size,
            1,
            false,
            Need::Nothing,
            |contents, offset| {
                let range = offset..offset + size as usize;
                contents.active[range.clone()].fill(start);
                if start {
                    contents.bytes[range].fill(Byte::UNDEF);
                }
            },
        )
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
            let object = self.object(pointer.origin)?;
            if !object.spans(pointer.address) || !object.spans(result.address) {
                return None;
            }
        }
        Some(result)
    }

    /// `pointer` moved `bytes` on, for whoever holds the pointer outside
    /// the program: within the object it points into, or to one past its
    /// end. `Ok(None)` if that is beyond the object, and `Err` if the
    /// object is no longer there. A pointer into no object stays where it
    /// is and goes nowhere else.
    pub(crate) fn advance(&self, pointer: Pointer, bytes: u64) -> Result<Option<Pointer>, ()> {
        let Some(object) = self.object(pointer.origin) else {
            return Ok((bytes == 0).then_some(pointer));
        };
        if !object.live.load(Ordering::Acquire) {
            return Err(());
        }
        Ok(pointer
            .address
            .checked_add(bytes)
            .filter(|address| object.spans(pointer.address) && object.spans(*address))
            .map(|address| Pointer {
                address,
                origin: pointer.origin,
            }))
    }

    /// Record that the pointer's address became visible as an integer.
    pub(crate) fn expose(&self, pointer: Pointer) {
        if let Some(object) = self.object(pointer.origin) {
            object.exposed.store(true, Ordering::Release);
        }
    }

    /// A pointer for an integer address. It gains an origin only if the
    /// address lies in, or one past, a live object that has been exposed.
    pub(crate) fn integer_pointer(&self, address: u64) -> Pointer {
        // Objects are in address order with a gap between them, so at most
        // one spans the address: the last that starts at or below it.
        let (mut low, mut high) = (0, self.table.count.load(Ordering::Acquire));
        while low < high {
            let middle = low + (high - low) / 2;
            if self
                .table
                .get(middle)
                .is_some_and(|object| object.address <= address)
            {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        let origin = low
            .checked_sub(1)
            .filter(|id| {
                self.table.get(*id).is_some_and(|object| {
                    object.exposed.load(Ordering::Acquire)
                        && object.live.load(Ordering::Acquire)
                        && object.spans(address)
                })
            })
            .map(ObjectId);
        Pointer { address, origin }
    }
}

/// A scalar read from memory, before an address among its bytes is resolved.
enum Typed {
    Value(Value),
    /// Bytes read as a data pointer that are not a stored pointer.
    Address(u64),
    /// Bytes read as a code pointer that are not a stored pointer.
    Token(u64),
}

#[cfg(test)]
#[path = "memory_tests.rs"]
mod tests;
