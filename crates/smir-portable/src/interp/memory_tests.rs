//! The memory model in isolation: guard order, the shadow of each byte, and
//! what survives a round trip through memory.

use super::{DEFAULT_MAX_BYTES, Fault, Memory};
use crate::ir::{Pointer, Scalar, Value};

const I8: Scalar = Scalar::Int { bits: 8 };
const I32: Scalar = Scalar::Int { bits: 32 };
const I64: Scalar = Scalar::Int { bits: 64 };

fn memory() -> Memory {
    Memory::new(DEFAULT_MAX_BYTES)
}

fn at(base: Pointer, offset: u64) -> Pointer {
    Pointer {
        address: base.address + offset,
        origin: base.origin,
    }
}

#[test]
fn allocations_get_the_reference_machine_s_addresses() {
    let mut memory = memory();
    // The first object is at 0x10000; each next one starts at least 16 bytes
    // past the previous end, rounded up to its alignment.
    assert_eq!(memory.allocate(4, 4).unwrap().address, 0x10000);
    assert_eq!(memory.allocate(1, 1).unwrap().address, 0x10014);
    assert_eq!(memory.allocate(8, 8).unwrap().address, 0x10028);
    // A zero-sized object still occupies one address.
    assert_eq!(memory.allocate(0, 1).unwrap().address, 0x10040);
    assert_eq!(memory.allocate(16, 16).unwrap().address, 0x10060);
    assert_eq!(memory.allocate(1, 3), Err(Fault::Trap("allocation_shape")));
    assert_eq!(memory.allocate(1, 0), Err(Fault::Trap("allocation_shape")));
}

#[test]
fn fresh_memory_is_undef_and_loads_as_zero() {
    let mut memory = memory();
    let object = memory.allocate(8, 8).unwrap();
    assert_eq!(memory.load(object, I64, 8, 8), Ok(Value::Int(0)));
    memory
        .store(object, Value::Int(0x1122_3344), I32, 4, 4)
        .unwrap();
    // The low half is defined; the undef high half reads as zero.
    assert_eq!(memory.load(object, I64, 8, 8), Ok(Value::Int(0x1122_3344)));
    assert_eq!(memory.load(at(object, 1), I8, 1, 1), Ok(Value::Int(0x33)));
}

#[test]
fn guards_are_checked_in_order_before_any_effect() {
    let mut memory = memory();
    let object = memory.allocate(8, 8).unwrap();
    memory.store(object, Value::Int(7), I64, 8, 8).unwrap();

    // No origin: undefined behaviour, even at a valid address.
    let forged = Pointer::originless(object.address);
    assert_eq!(
        memory.load(forged, I64, 8, 8),
        Err(Fault::Ub("pointer_provenance"))
    );
    // Bounds are checked before alignment.
    assert_eq!(
        memory.load(at(object, 5), I32, 4, 4),
        Err(Fault::Trap("memory_bounds"))
    );
    assert_eq!(
        memory.load(at(object, 2), I32, 4, 4),
        Err(Fault::Trap("memory_alignment"))
    );
    assert_eq!(
        memory.load(at(object, 8), I8, 1, 1),
        Err(Fault::Trap("memory_bounds"))
    );
    let before = Pointer {
        address: object.address - 1,
        origin: object.origin,
    };
    assert_eq!(
        memory.load(before, I8, 1, 1),
        Err(Fault::Trap("memory_bounds"))
    );
    // A refused store leaves the bytes alone.
    assert_eq!(
        memory.store(at(object, 6), Value::Int(1), I32, 4, 1),
        Err(Fault::Trap("memory_bounds"))
    );
    assert_eq!(memory.load(object, I64, 8, 8), Ok(Value::Int(7)));

    // Liveness is checked before bounds.
    memory.release(object.origin.unwrap());
    assert_eq!(
        memory.load(at(object, 99), I8, 1, 1),
        Err(Fault::Trap("memory_lifetime"))
    );
    assert_eq!(
        memory.store(object, Value::Int(1), I64, 8, 8),
        Err(Fault::Trap("memory_lifetime"))
    );
}

#[test]
fn poison_and_undef_are_tracked_per_bit_through_memory() {
    let mut memory = memory();
    let object = memory.allocate(8, 8).unwrap();
    memory
        .store(object, Value::Int(0xaabb_ccdd), I32, 4, 4)
        .unwrap();
    memory
        .store(at(object, 1), Value::Poison, I8, 1, 1)
        .unwrap();
    // Any poison bit in the value read makes the value poison.
    assert_eq!(memory.load(object, I32, 4, 4), Ok(Value::Poison));
    assert_eq!(memory.load(object, I8, 1, 1), Ok(Value::Int(0xdd)));
    assert_eq!(memory.load(at(object, 2), I8, 1, 1), Ok(Value::Int(0xbb)));
    // Undef bits are refined to zero by the load, bit by bit.
    memory.store(at(object, 1), Value::Undef, I8, 1, 1).unwrap();
    assert_eq!(memory.load(object, I32, 4, 4), Ok(Value::Int(0xaabb_00dd)));
}

#[test]
fn padding_above_a_narrow_value_must_read_as_zero() {
    let mut memory = memory();
    let object = memory.allocate(2, 1).unwrap();
    let bit = Scalar::Int { bits: 1 };
    // Storing a one-bit value writes seven defined zero bits above it.
    memory.store(object, Value::Int(1), bit, 1, 1).unwrap();
    assert_eq!(memory.load(object, I8, 1, 1), Ok(Value::Int(1)));
    assert_eq!(memory.load(object, bit, 1, 1), Ok(Value::Int(1)));
    // A byte with a set padding bit is not a one-bit value.
    memory.store(object, Value::Int(3), I8, 1, 1).unwrap();
    assert_eq!(memory.load(object, bit, 1, 1), Ok(Value::Poison));
    // Undef padding is acceptable.
    assert_eq!(memory.load(at(object, 1), bit, 1, 1), Ok(Value::Int(0)));
    // A poison one-bit value poisons only its own bit.
    memory.store(object, Value::Poison, bit, 1, 1).unwrap();
    assert_eq!(memory.load(object, bit, 1, 1), Ok(Value::Poison));
    assert_eq!(memory.load(object, I8, 1, 1), Ok(Value::Poison));
}

#[test]
fn a_pointer_keeps_its_origin_only_when_loaded_whole() {
    let mut memory = memory();
    let target = memory.allocate(4, 4).unwrap();
    let slot = memory.allocate(16, 8).unwrap();
    memory
        .store(slot, Value::DataPtr(target), Scalar::DataPtr, 8, 8)
        .unwrap();
    assert_eq!(
        memory.load(slot, Scalar::DataPtr, 8, 8),
        Ok(Value::DataPtr(target))
    );
    // Read as an integer, the address is visible but the origin is not.
    assert_eq!(
        memory.load(slot, I64, 8, 8),
        Ok(Value::Int(u128::from(target.address)))
    );

    // The same bytes written as an integer carry no origin.
    memory
        .store(
            at(slot, 8),
            Value::Int(u128::from(target.address)),
            I64,
            8,
            8,
        )
        .unwrap();
    let rebuilt = memory.load(at(slot, 8), Scalar::DataPtr, 8, 8).unwrap();
    assert_eq!(rebuilt, Value::DataPtr(Pointer::originless(target.address)));

    // Overwriting one byte of a stored pointer, even with the same value,
    // breaks the pointer.
    let low_byte = u128::from(target.address & 0xff);
    memory.store(slot, Value::Int(low_byte), I8, 1, 1).unwrap();
    let patched = memory.load(slot, Scalar::DataPtr, 8, 8).unwrap();
    assert_eq!(patched, Value::DataPtr(Pointer::originless(target.address)));

    // An unaligned load that straddles two stored pointers is neither.
    memory
        .store(slot, Value::DataPtr(target), Scalar::DataPtr, 8, 8)
        .unwrap();
    memory
        .store(at(slot, 8), Value::DataPtr(target), Scalar::DataPtr, 8, 8)
        .unwrap();
    let straddling = memory.load(at(slot, 4), Scalar::DataPtr, 8, 1).unwrap();
    assert!(matches!(
        straddling,
        Value::DataPtr(Pointer { origin: None, .. })
    ));
}

#[test]
fn lifetime_markers_gate_access_and_reset_contents() {
    let mut memory = memory();
    let object = memory.allocate(8, 4).unwrap();
    memory.store(object, Value::Int(5), I32, 4, 4).unwrap();
    memory.lifetime(object, 4, false).unwrap();
    assert_eq!(
        memory.load(object, I32, 4, 4),
        Err(Fault::Trap("memory_lifetime"))
    );
    // The other half of the object is unaffected.
    memory
        .store(at(object, 4), Value::Int(9), I32, 4, 4)
        .unwrap();
    // Restarting the lifetime makes the bytes undef again.
    memory.lifetime(object, 4, true).unwrap();
    assert_eq!(memory.load(object, I32, 4, 4), Ok(Value::Int(0)));
    assert_eq!(memory.load(at(object, 4), I32, 4, 4), Ok(Value::Int(9)));
    assert_eq!(
        memory.lifetime(object, 9, true),
        Err(Fault::Trap("memory_bounds"))
    );
    assert_eq!(
        memory.lifetime(Pointer::originless(0), 0, true),
        Err(Fault::Ub("pointer_provenance"))
    );
}

#[test]
fn pointer_offsets_follow_their_flags() {
    let mut memory = memory();
    let object = memory.allocate(8, 8).unwrap();
    let plain = |delta| memory.offset(object, delta, false, false, false, false);
    // Without flags, arithmetic wraps and keeps the origin.
    assert_eq!(plain(100), Some(at(object, 100)));
    assert_eq!(plain(-1).unwrap().address, object.address - 1);
    let top = Pointer {
        address: u64::MAX,
        origin: object.origin,
    };
    assert_eq!(
        memory
            .offset(top, 1, false, false, false, false)
            .unwrap()
            .address,
        0
    );
    assert_eq!(memory.offset(top, 1, false, false, true, false), None);
    assert_eq!(memory.offset(top, 1, false, false, false, true), None);
    // A negative offset is a huge unsigned one.
    assert_eq!(memory.offset(object, -1, false, false, true, false), None);
    assert_eq!(
        memory.offset(Pointer::originless(0), -1, false, false, false, true),
        None
    );

    // inbounds: the result must stay in the object or one past its end.
    let inbounds = |base, delta| memory.offset(base, delta, true, false, false, false);
    assert_eq!(inbounds(object, 8), Some(at(object, 8)));
    assert_eq!(inbounds(object, 9), None);
    assert_eq!(inbounds(object, -1), None);
    // A zero offset is not checked unless the base check is requested.
    let outside = at(object, 64);
    assert_eq!(inbounds(outside, 0), Some(outside));
    assert_eq!(memory.offset(outside, 0, true, true, false, false), None);
    assert_eq!(inbounds(Pointer::originless(object.address), 1), None);
}

#[test]
fn an_integer_names_an_object_only_after_its_address_was_exposed() {
    let mut memory = memory();
    let object = memory.allocate(8, 8).unwrap();
    assert_eq!(memory.integer_pointer(object.address).origin, None);
    memory.expose(object);
    assert_eq!(memory.integer_pointer(object.address), object);
    assert_eq!(memory.integer_pointer(object.address + 8), at(object, 8));
    assert_eq!(memory.integer_pointer(object.address + 9).origin, None);
    memory.release(object.origin.unwrap());
    assert_eq!(memory.integer_pointer(object.address).origin, None);
}

#[test]
fn live_memory_is_bounded_and_released_bytes_are_returned() {
    let mut memory = Memory::new(64);
    let first = memory.allocate(40, 1).unwrap();
    assert_eq!(
        memory.allocate(40, 1),
        Err(Fault::Resource("resource_memory"))
    );
    assert_eq!(
        memory.allocate(65, 1),
        Err(Fault::Resource("resource_memory"))
    );
    memory.release(first.origin.unwrap());
    memory.release(first.origin.unwrap());
    assert!(memory.allocate(64, 1).is_ok());
}

#[test]
fn copies_carry_shadow_and_whole_pointers_and_forbid_partial_overlap() {
    let mut memory = memory();
    let target = memory.allocate(4, 4).unwrap();
    let block = memory.allocate(32, 8).unwrap();
    memory
        .store(block, Value::DataPtr(target), Scalar::DataPtr, 8, 8)
        .unwrap();
    memory.store(at(block, 8), Value::Poison, I8, 1, 1).unwrap();
    // Bytes 9..16 stay undef.
    memory.copy(at(block, 16), block, 16, 8, false).unwrap();
    assert_eq!(
        memory.load(at(block, 16), Scalar::DataPtr, 8, 8),
        Ok(Value::DataPtr(target))
    );
    assert_eq!(memory.load(at(block, 24), I8, 1, 1), Ok(Value::Poison));
    assert_eq!(memory.load(at(block, 25), I8, 1, 1), Ok(Value::Int(0)));

    // A partial overlap is undefined for memcpy and defined for memmove; an
    // exact self-copy is allowed either way.
    assert_eq!(
        memory.copy(at(block, 4), block, 8, 1, false),
        Err(Fault::Ub("ub_memcpy_overlap"))
    );
    assert_eq!(memory.copy(block, block, 8, 1, false), Ok(()));
    assert_eq!(memory.copy(at(block, 8), block, 8, 1, false), Ok(()));
    memory.copy(at(block, 4), block, 8, 1, true).unwrap();
    // The moved pointer bytes are intact at their new place, and what they
    // overwrote no longer forms a pointer at the old one.
    assert_eq!(
        memory.load(at(block, 4), Scalar::DataPtr, 8, 1),
        Ok(Value::DataPtr(target))
    );
    assert!(matches!(
        memory.load(block, Scalar::DataPtr, 8, 8),
        Ok(Value::DataPtr(Pointer { origin: None, .. }))
    ));

    // The destination is checked before the source.
    let other = memory.allocate(4, 1).unwrap();
    assert_eq!(
        memory.copy(other, block, 8, 1, false),
        Err(Fault::Trap("memory_bounds"))
    );
    assert_eq!(
        memory.copy(block, other, 8, 1, false),
        Err(Fault::Trap("memory_bounds"))
    );
    assert_eq!(
        memory.copy(at(block, 1), other, 4, 2, false),
        Err(Fault::Trap("memory_alignment"))
    );
}

#[test]
fn fill_writes_one_byte_value_with_its_shadow() {
    let mut memory = memory();
    let object = memory.allocate(8, 1).unwrap();
    memory.fill(object, Value::Int(0xab), 8, 1).unwrap();
    assert_eq!(
        memory.load(object, I64, 8, 1),
        Ok(Value::Int(0xabab_abab_abab_abab))
    );
    memory.fill(at(object, 2), Value::Poison, 2, 1).unwrap();
    assert_eq!(memory.load(object, I32, 4, 1), Ok(Value::Poison));
    assert_eq!(
        memory.load(at(object, 4), I32, 4, 1),
        Ok(Value::Int(0xabab_abab))
    );
    memory.fill(at(object, 2), Value::Undef, 2, 1).unwrap();
    assert_eq!(memory.load(object, I32, 4, 1), Ok(Value::Int(0x0000_abab)));
    assert_eq!(
        memory.fill(at(object, 4), Value::Int(1), 5, 1),
        Err(Fault::Trap("memory_bounds"))
    );
}

#[test]
fn segment_images_take_relocations_before_they_are_sealed() {
    let mut memory = memory();
    let table = memory
        .allocate_image(&[1, 0, 0, 0, 2, 0, 0, 0], &[0; 8], &[0; 8], 4)
        .unwrap();
    let cell = memory
        .allocate_image(
            &[0; 16],
            &[0, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[0; 16],
            8,
        )
        .unwrap();
    // The image's own poison shadow is in place.
    assert_eq!(memory.load(at(cell, 1), I8, 1, 1), Ok(Value::Poison));
    memory.patch_pointer(cell, 0, at(table, 4));
    memory.patch_integer(cell, 8, table.address + 4, 8);
    memory.seal(table);
    assert_eq!(
        memory.load(cell, Scalar::DataPtr, 8, 8),
        Ok(Value::DataPtr(at(table, 4)))
    );
    assert_eq!(
        memory.load(at(cell, 8), I64, 8, 8),
        Ok(Value::Int(u128::from(table.address + 4)))
    );
    // The integer form names the address but carries no origin.
    let from_integer = memory.load(at(cell, 8), Scalar::DataPtr, 8, 8).unwrap();
    assert_eq!(
        from_integer,
        Value::DataPtr(Pointer::originless(table.address + 4))
    );
    // A sealed segment can be read and not written.
    assert_eq!(memory.load(at(table, 4), I32, 4, 4), Ok(Value::Int(2)));
    assert_eq!(
        memory.store(table, Value::Int(9), I32, 4, 4),
        Err(Fault::Trap("memory_permission"))
    );
    assert_eq!(
        memory.fill(table, Value::Int(0), 4, 1),
        Err(Fault::Trap("memory_permission"))
    );
    assert_eq!(
        memory.copy(table, cell, 4, 1, false),
        Err(Fault::Trap("memory_permission"))
    );
}
