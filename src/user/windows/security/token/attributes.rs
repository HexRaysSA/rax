//! Owned token security attributes and native/WoW64 pointer-bearing layouts.
//!
//! PHNT `ntseapi.h` defines version1 and its seven value types. Packing order,
//! absolute alignment and publication order are measured on build29683; see
//! `docs/specifications/windows/native-token-security-attributes/`.

#[cfg(windows)]
mod installed;
#[cfg(windows)]
pub(crate) use installed::capture;

/// Selection-time capture limit. Exceeding it is unavailable, never empty.
pub(crate) const MAX_CAPTURE: usize = 1 << 20;
pub(crate) const MAX_ATTRIBUTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Values {
    Int64(Vec<i64>),
    Uint64(Vec<u64>),
    String(Vec<Vec<u16>>),
    Fqbn(Vec<(u64, Vec<u16>)>),
    Sid(Vec<Vec<u8>>),
    Boolean(Vec<u64>),
    Octet(Vec<Vec<u8>>),
}

impl Values {
    pub(crate) fn kind(&self) -> u16 {
        match self {
            Self::Int64(_) => 1,
            Self::Uint64(_) => 2,
            Self::String(_) => 3,
            Self::Fqbn(_) => 4,
            Self::Sid(_) => 5,
            Self::Boolean(_) => 6,
            Self::Octet(_) => 16,
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Int64(values) => values.len(),
            Self::Uint64(values) | Self::Boolean(values) => values.len(),
            Self::String(values) => values.len(),
            Self::Fqbn(values) => values.len(),
            Self::Sid(values) | Self::Octet(values) => values.len(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Attribute {
    pub(crate) name: Vec<u16>,
    /// Opaque native flags, including comparison and custom bits.
    pub(crate) flags: u32,
    pub(crate) values: Values,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Attributes(Vec<Attribute>);

impl Attributes {
    pub(crate) fn new(values: Vec<Attribute>) -> Option<Self> {
        if values.len() > MAX_ATTRIBUTES
            || values.iter().any(|attribute| {
                attribute.name.is_empty()
                    || attribute.name.len() > usize::from(u16::MAX) / 2
                    || attribute.values.len() == 0
                    || attribute.values.len() > MAX_CAPTURE / 8
                    || match &attribute.values {
                        Values::String(values) => values
                            .iter()
                            .any(|text| text.len() > usize::from(u16::MAX) / 2),
                        Values::Fqbn(values) => values
                            .iter()
                            .any(|(_, text)| text.len() > usize::from(u16::MAX) / 2),
                        Values::Sid(values) => values
                            .iter()
                            .any(|value| super::super::sid(value) != Some(value.as_slice())),
                        Values::Octet(values) => {
                            values.iter().any(|value| value.len() > MAX_CAPTURE)
                        }
                        _ => false,
                    }
            })
        {
            return None;
        }
        let result = Self(values);
        result.pack(&result.all(), 8, 0, MAX_CAPTURE)?;
        Some(result)
    }

    pub(crate) fn all(&self) -> Vec<&Attribute> {
        self.0.iter().collect()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Exact UTF-16 name comparison through the selected Windows upcase table.
    /// Separators and embedded zero units retain their name semantics.
    pub(crate) fn find(&self, name: &[u16], upcase: &[u16]) -> Option<&Attribute> {
        if upcase.len() != 65536 {
            return None;
        }
        self.0.iter().find(|attribute| {
            attribute.name.len() == name.len()
                && attribute
                    .name
                    .iter()
                    .zip(name)
                    .all(|(&left, &right)| upcase[usize::from(left)] == upcase[usize::from(right)])
        })
    }

    /// O(B+A+V) time and O(B) storage, B<=1 MiB, A<=4096. Capacity controls
    /// publication only; it never controls host allocation. Native logical size
    /// uses base0/width8, whereas converted size uses the actual caller address.
    pub(crate) fn pack(
        &self,
        selected: &[&Attribute],
        width: usize,
        base: u64,
        capacity: usize,
    ) -> Option<Packet> {
        if !matches!(width, 4 | 8) || selected.len() > MAX_ATTRIBUTES {
            return None;
        }
        let header = if width == 8 { 16 } else { 12 };
        let stride = if width == 8 { 40 } else { 24 };
        let mut writer = Writer {
            bytes: vec![0; header + stride * selected.len()],
            base,
            width,
        };
        let mut complete = true;
        for (index, attribute) in selected.iter().enumerate() {
            let at = header + stride * index;
            writer.string(at, &attribute.name)?;
            let us = 2 * width;
            writer.put(at + us, &attribute.values.kind().to_le_bytes())?;
            writer.put(at + us + 4, &attribute.flags.to_le_bytes())?;
            writer.put(at + us + 8, &(attribute.values.len() as u32).to_le_bytes())?;
            writer.align(8)?;
            let start = writer.bytes.len();
            match &attribute.values {
                Values::Int64(values) => {
                    for value in values {
                        writer.append(&value.to_le_bytes())?;
                    }
                }
                Values::Uint64(values) | Values::Boolean(values) => {
                    for value in values {
                        writer.append(&value.to_le_bytes())?;
                    }
                }
                Values::String(values) => {
                    writer.reserve(values.len().checked_mul(us)?)?;
                    for (i, value) in values.iter().enumerate() {
                        writer.string(start + i * us, value)?;
                    }
                }
                Values::Fqbn(values) => {
                    let size = 8 + us;
                    writer.reserve(values.len().checked_mul(size)?)?;
                    for (i, (version, value)) in values.iter().enumerate() {
                        writer.put(start + i * size, &version.to_le_bytes())?;
                        writer.string(start + i * size + 8, value)?;
                    }
                }
                Values::Sid(values) | Values::Octet(values) => {
                    writer.reserve(values.len().checked_mul(us)?)?;
                    for (i, value) in values.iter().enumerate() {
                        let entry = start + i * us;
                        writer.pointer(entry, writer.bytes.len())?;
                        writer.put(entry + width, &(value.len() as u32).to_le_bytes())?;
                        writer.append(value)?;
                    }
                }
            }
            if writer.bytes.len() <= capacity {
                writer.pointer(at + stride - width, start)?;
            } else {
                complete = false;
                // Native publishes the name and scalar fields before it can
                // reject the values extent. The final header remains zero.
                writer.bytes[start..].fill(0);
            }
        }
        if writer.bytes.len() > MAX_CAPTURE {
            return None;
        }
        if complete {
            writer.put(0, &1u16.to_le_bytes())?;
            writer.put(4, &(selected.len() as u32).to_le_bytes())?;
            if !selected.is_empty() {
                writer.pointer(8, header)?;
            }
        }
        let required = u32::try_from(writer.bytes.len()).ok()?;
        writer.bytes.truncate(capacity);
        Some(Packet {
            bytes: writer.bytes,
            required,
            complete,
        })
    }

    /// Validate every pointer against the successful native output, then own
    /// every value. No host pointer, token handle or ABI padding survives.
    #[cfg(any(windows, test))]
    pub(crate) fn from_native(bytes: &[u8], base: u64, width: usize) -> Option<Self> {
        let reader = Reader { bytes, base, width };
        if !matches!(width, 4 | 8)
            || bytes.len() > MAX_CAPTURE
            || reader.u16(0)? != 1
            || reader.u16(2)? != 0
        {
            return None;
        }
        let count = reader.u32(4)? as usize;
        if count > MAX_ATTRIBUTES {
            return None;
        }
        let stride = if width == 8 { 40 } else { 24 };
        let table = reader.offset(8, count.checked_mul(stride)?)?;
        let mut values = Vec::with_capacity(count);
        for i in 0..count {
            let at = table + stride * i;
            let us = 2 * width;
            let kind = reader.u16(at + us)?;
            if reader.u16(at + us + 2)? != 0 {
                return None;
            }
            let n = reader.u32(at + us + 8)? as usize;
            let element = match kind {
                1 | 2 | 6 => 8,
                3 | 5 | 16 => us,
                4 => 8 + us,
                _ => return None,
            };
            let data = reader.offset(at + stride - width, n.checked_mul(element)?)?;
            let scalar = |i| reader.u64(data + i * 8);
            let value = match kind {
                1 => Values::Int64(
                    (0..n)
                        .map(|i| scalar(i).map(|v| v as i64))
                        .collect::<Option<_>>()?,
                ),
                2 => Values::Uint64((0..n).map(scalar).collect::<Option<_>>()?),
                6 => Values::Boolean((0..n).map(scalar).collect::<Option<_>>()?),
                3 => Values::String(
                    (0..n)
                        .map(|i| reader.string(data + i * us))
                        .collect::<Option<_>>()?,
                ),
                4 => Values::Fqbn(
                    (0..n)
                        .map(|i| {
                            let entry = data + i * element;
                            Some((reader.u64(entry)?, reader.string(entry + 8)?))
                        })
                        .collect::<Option<_>>()?,
                ),
                5 | 16 => {
                    let items = (0..n)
                        .map(|i| {
                            let entry = data + i * us;
                            let size = reader.u32(entry + width)? as usize;
                            let start = reader.offset(entry, size)?;
                            Some(bytes.get(start..start.checked_add(size)?)?.to_vec())
                        })
                        .collect::<Option<_>>()?;
                    if kind == 5 {
                        Values::Sid(items)
                    } else {
                        Values::Octet(items)
                    }
                }
                _ => return None,
            };
            values.push(Attribute {
                name: reader.string(at)?,
                flags: reader.u32(at + us + 4)?,
                values: value,
            });
        }
        Self::new(values)
    }
}

pub(crate) struct Packet {
    pub(crate) bytes: Vec<u8>,
    pub(crate) required: u32,
    pub(crate) complete: bool,
}

struct Writer {
    bytes: Vec<u8>,
    base: u64,
    width: usize,
}

impl Writer {
    fn reserve(&mut self, count: usize) -> Option<()> {
        let end = self.bytes.len().checked_add(count)?;
        if end > MAX_CAPTURE {
            return None;
        }
        self.bytes.resize(end, 0);
        Some(())
    }

    fn append(&mut self, bytes: &[u8]) -> Option<()> {
        let at = self.bytes.len();
        self.reserve(bytes.len())?;
        self.put(at, bytes)
    }

    fn put(&mut self, at: usize, value: &[u8]) -> Option<()> {
        self.bytes
            .get_mut(at..at.checked_add(value.len())?)?
            .copy_from_slice(value);
        Some(())
    }

    fn pointer(&mut self, at: usize, offset: usize) -> Option<()> {
        let pointer = self.base.checked_add(offset as u64)?;
        if self.width == 4 && pointer > u64::from(u32::MAX) {
            return None;
        }
        self.put(at, &pointer.to_le_bytes()[..self.width])
    }

    fn align(&mut self, alignment: u64) -> Option<()> {
        let address = self.base.checked_add(self.bytes.len() as u64)?;
        self.reserve(((alignment - address % alignment) % alignment) as usize)
    }

    fn string(&mut self, at: usize, value: &[u16]) -> Option<()> {
        self.align(2)?;
        let size = u16::try_from(value.len().checked_mul(2)?).ok()?;
        self.put(at, &size.to_le_bytes())?;
        self.put(at + 2, &size.to_le_bytes())?;
        self.pointer(at + self.width, self.bytes.len())?;
        for unit in value {
            self.append(&unit.to_le_bytes())?;
        }
        Some(())
    }
}

#[cfg(any(windows, test))]
struct Reader<'a> {
    bytes: &'a [u8],
    base: u64,
    width: usize,
}

#[cfg(any(windows, test))]
impl Reader<'_> {
    fn u16(&self, at: usize) -> Option<u16> {
        Some(u16::from_le_bytes(
            self.bytes.get(at..at.checked_add(2)?)?.try_into().ok()?,
        ))
    }

    fn u32(&self, at: usize) -> Option<u32> {
        Some(u32::from_le_bytes(
            self.bytes.get(at..at.checked_add(4)?)?.try_into().ok()?,
        ))
    }

    fn u64(&self, at: usize) -> Option<u64> {
        Some(u64::from_le_bytes(
            self.bytes.get(at..at.checked_add(8)?)?.try_into().ok()?,
        ))
    }

    fn offset(&self, at: usize, size: usize) -> Option<usize> {
        let pointer = if self.width == 8 {
            self.u64(at)?
        } else {
            u64::from(self.u32(at)?)
        };
        if size == 0 && pointer == 0 {
            return Some(0);
        }
        let start = usize::try_from(pointer.checked_sub(self.base)?).ok()?;
        self.bytes.get(start..start.checked_add(size)?)?;
        Some(start)
    }

    fn string(&self, at: usize) -> Option<Vec<u16>> {
        let size = usize::from(self.u16(at)?);
        if size % 2 != 0 || self.u16(at + 2)? < size as u16 {
            return None;
        }
        let start = self.offset(at + self.width, size)?;
        Some(
            self.bytes
                .get(start..start.checked_add(size)?)?
                .chunks_exact(2)
                .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
                .collect(),
        )
    }
}

#[cfg(test)]
pub(crate) mod tests;
