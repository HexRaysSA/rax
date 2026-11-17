//! Host-independent, checked byte geometry. Source extents remain symbolic.

use super::value::require;
use crate::Error;

pub(crate) const MAX_OBJECT_BYTES: u64 = (1_u64 << 61) - 1;
pub(crate) const MAX_ALIGNMENT: u64 = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Geometry {
    pub size: u64,
    pub align: u64,
}

pub(crate) fn alignment(value: u64) -> Result<(), Error> {
    require(
        value.is_power_of_two() && value <= MAX_ALIGNMENT,
        "ABI_ALIGNMENT",
    )
}

pub(crate) fn align_up(value: u64, align: u64) -> Result<u64, Error> {
    alignment(align)?;
    let result = value
        .checked_add(align - 1)
        .map(|n| n & !(align - 1))
        .ok_or_else(|| Error::semantic("ABI_SIZE_OVERFLOW", "alignment overflow"))?;
    require(result <= MAX_OBJECT_BYTES, "ABI_SIZE_OVERFLOW")?;
    Ok(result)
}

pub(crate) fn scalar(name: &str) -> Option<Geometry> {
    let (size, align) = match name {
        "bool" | "char" | "signed char" | "unsigned char" | "char8_t" => (1, 1),
        "short" | "unsigned short" | "char16_t" => (2, 2),
        "int" | "unsigned int" | "wchar_t" | "wint_t" | "char32_t" | "float" => (4, 4),
        "long"
        | "unsigned long"
        | "long long"
        | "unsigned long long"
        | "size_t"
        | "ptrdiff_t"
        | "double"
        | "pointer"
        | "nullptr_t"
        | "data_member_pointer" => (8, 8),
        "__int128" | "unsigned __int128" | "long double" => (16, 16),
        "function_member_pointer" => (16, 8),
        _ => return None,
    };
    Some(Geometry { size, align })
}

pub(crate) fn integer_name(name: &str) -> bool {
    scalar(name).is_some()
        && !matches!(
            name,
            "float"
                | "double"
                | "long double"
                | "pointer"
                | "nullptr_t"
                | "data_member_pointer"
                | "function_member_pointer"
        )
}

pub(crate) fn signed_name(name: &str) -> bool {
    matches!(
        name,
        "char"
            | "signed char"
            | "short"
            | "int"
            | "wchar_t"
            | "long"
            | "long long"
            | "ptrdiff_t"
            | "__int128"
    )
}

pub(crate) fn bitint(bits: u32, signed: bool) -> Result<Geometry, Error> {
    require(
        (if signed { 2 } else { 1 }) <= bits && bits <= 65_535,
        "ABI_CC_BITINT_WIDTH",
    )?;
    let bytes = u64::from(bits).div_ceil(8);
    let align = bytes.next_power_of_two().min(8);
    Ok(Geometry {
        size: align_up(bytes, align)?,
        align,
    })
}

pub(crate) fn array(base: Geometry, count: u64) -> Result<Geometry, Error> {
    let size = base
        .size
        .checked_mul(count)
        .ok_or_else(|| Error::semantic("ABI_SIZE_OVERFLOW", "array byte extent"))?;
    require(size <= MAX_OBJECT_BYTES, "ABI_SIZE_OVERFLOW")?;
    Ok(Geometry {
        size,
        align: base.align,
    })
}

pub(crate) fn vector(base: Geometry, count: u64) -> Result<Geometry, Error> {
    require(count > 0, "ABI_CC_ARRAY_COUNT")?;
    let bytes = base
        .size
        .checked_mul(count)
        .ok_or_else(|| Error::semantic("ABI_SIZE_OVERFLOW", "vector byte extent"))?;
    let size = bytes
        .checked_next_power_of_two()
        .ok_or_else(|| Error::semantic("ABI_SIZE_OVERFLOW", "vector rounding"))?;
    require(size <= 64, "ABI_CC_VECTOR_SIZE")?;
    Ok(Geometry { size, align: size })
}

pub(crate) fn atomic(base: Geometry) -> Result<Geometry, Error> {
    require(base.size > 0, "ABI_CC_ATOMIC_TYPE")?;
    if base.size <= 16 {
        let size = base.size.next_power_of_two();
        Ok(Geometry {
            size,
            align: size.max(base.align),
        })
    } else {
        Ok(base)
    }
}

/// All calculations use u64 byte/bit units; no allocation scales with width.
pub(crate) fn bit_extent(offset: u64, width: u64, size_bytes: u64) -> Result<(), Error> {
    require(size_bytes <= MAX_OBJECT_BYTES, "ABI_CC_LAYOUT_EXTENT")?;
    let end = offset
        .checked_add(width)
        .ok_or_else(|| Error::semantic("ABI_CC_FIELD_LAYOUT", "field bit endpoint"))?;
    require(end <= size_bytes * 8, "ABI_CC_FIELD_LAYOUT")
}

pub(crate) fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}
