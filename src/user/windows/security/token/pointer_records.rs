//! Owned token query results with a single native pointer and an optional payload.

#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub(crate) enum Class {
    Owner = 4,
    PrimaryGroup = 5,
    DefaultDacl = 6,
    ProcessTrustLevel = 41,
}

impl Class {
    #[cfg(any(windows, test))]
    pub(crate) const ALL: [Self; 4] = [
        Self::Owner,
        Self::PrimaryGroup,
        Self::DefaultDacl,
        Self::ProcessTrustLevel,
    ];

    pub(crate) fn from_raw(value: u32) -> Option<Self> {
        match value {
            4 => Some(Self::Owner),
            5 => Some(Self::PrimaryGroup),
            6 => Some(Self::DefaultDacl),
            41 => Some(Self::ProcessTrustLevel),
            _ => None,
        }
    }

    fn index(self) -> usize {
        match self {
            Self::Owner => 0,
            Self::PrimaryGroup => 1,
            Self::DefaultDacl => 2,
            Self::ProcessTrustLevel => 3,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Records {
    // None means unavailable. An empty captured payload represents NULL.
    records: [Option<Box<[u8]>>; 4],
}

impl Records {
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
        return (matches!(class, Class::DefaultDacl | Class::ProcessTrustLevel)
            && buffer.len() == width)
            .then(|| Box::from([]));
    }

    let offset = pointer.checked_sub(buffer.as_ptr() as usize)?;
    if offset < width {
        return None;
    }
    let data = buffer.get(offset..)?;
    let size = match class {
        Class::Owner | Class::PrimaryGroup | Class::ProcessTrustLevel => {
            super::super::sid(data)?.len()
        }
        Class::DefaultDacl => {
            let header = data.get(..8)?;
            usize::from(u16::from_le_bytes([header[2], header[3]]))
        }
    };
    (size == data.len()).then(|| Box::from(data))
}

#[cfg(test)]
mod tests {
    use super::{Class, decode};

    #[test]
    fn process_trust_level_distinguishes_null_from_missing_or_invalid_data() {
        let width = size_of::<usize>();
        let mut record = vec![0; width + 16];
        assert_eq!(
            decode(Class::ProcessTrustLevel, &record[..width]).as_deref(),
            Some(&[][..])
        );
        assert!(decode(Class::ProcessTrustLevel, &record[..width - 1]).is_none());
        assert!(decode(Class::ProcessTrustLevel, &record).is_none());

        let sid = [1, 2, 0, 0, 0, 0, 0, 19, 0, 2, 0, 0, 0, 16, 0, 0];
        record[width..].copy_from_slice(&sid);
        let payload = record.as_ptr() as usize + width;
        record[..width].copy_from_slice(&payload.to_ne_bytes());
        assert_eq!(
            decode(Class::ProcessTrustLevel, &record).as_deref(),
            Some(sid.as_slice())
        );
        assert!(decode(Class::ProcessTrustLevel, &record[..record.len() - 1]).is_none());
        record[..width].copy_from_slice(&(payload - 1).to_ne_bytes());
        assert!(decode(Class::ProcessTrustLevel, &record).is_none());
    }
}
