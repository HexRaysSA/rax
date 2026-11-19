//! Owned results for the selected token's default security information.

#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub(crate) enum Class {
    Owner = 4,
    PrimaryGroup = 5,
    DefaultDacl = 6,
}

impl Class {
    #[cfg(any(windows, test))]
    pub(crate) const ALL: [Self; 3] = [Self::Owner, Self::PrimaryGroup, Self::DefaultDacl];

    pub(crate) fn from_raw(value: u32) -> Option<Self> {
        match value {
            4 => Some(Self::Owner),
            5 => Some(Self::PrimaryGroup),
            6 => Some(Self::DefaultDacl),
            _ => None,
        }
    }

    fn index(self) -> usize {
        self as usize - Self::Owner as usize
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Defaults {
    // An empty captured DACL is the NULL pointer. An empty ACL has a header.
    records: [Option<Box<[u8]>>; 3],
}

impl Defaults {
    pub(crate) fn get(&self, class: Class) -> Option<&[u8]> {
        self.records[class.index()].as_deref()
    }

    #[cfg(any(windows, test))]
    pub(crate) fn insert(&mut self, class: Class, value: Box<[u8]>) {
        self.records[class.index()] = Some(value);
    }
}

#[cfg(any(windows, test))]
pub(crate) fn decode(class: Class, buffer: &[u8]) -> Option<Box<[u8]>> {
    let width = size_of::<usize>();
    let pointer = usize::from_ne_bytes(buffer.get(..width)?.try_into().ok()?);
    if pointer == 0 {
        return (matches!(class, Class::DefaultDacl) && buffer.len() == width)
            .then(|| Box::from([]));
    }

    let offset = pointer.checked_sub(buffer.as_ptr() as usize)?;
    if offset < width {
        return None;
    }
    let data = buffer.get(offset..)?;
    let size = match class {
        Class::Owner | Class::PrimaryGroup => super::super::sid(data)?.len(),
        Class::DefaultDacl => {
            let header = data.get(..8)?;
            usize::from(u16::from_le_bytes([header[2], header[3]]))
        }
    };
    (size == data.len()).then(|| Box::from(data))
}
