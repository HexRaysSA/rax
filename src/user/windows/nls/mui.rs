//! Immutable, self-relative installed MUI query data.
use super::{MAX_TOTAL_BYTES, Nls, invalid};
use std::io;
use std::sync::Arc;

pub(super) const MAX_MUI_BYTES: usize = 1 << 20;

pub(super) fn language_generation(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(12..16)?.try_into().ok()?))
}

impl Nls {
    pub(crate) fn with_mui(mut self, bytes: Vec<u8>) -> io::Result<Self> {
        let used = self
            .sections
            .values()
            .map(|section| section.len())
            .sum::<usize>()
            + self.initialize.as_ref().map_or(0, |init| init.bytes.len());
        if self.mui.is_some()
            || bytes.len() < 16
            || bytes.len() > MAX_MUI_BYTES
            || used + bytes.len() > MAX_TOTAL_BYTES
        {
            return Err(invalid("invalid or oversized installed MUI query snapshot"));
        }
        self.mui = Some(bytes.into());
        Ok(self)
    }

    pub(crate) fn mui(&self) -> Option<Arc<[u8]>> {
        self.mui.clone()
    }

    pub(crate) fn mui_generation(&self) -> Option<u32> {
        self.mui.as_deref().and_then(language_generation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_mui_query_snapshot_is_bounded_shared_and_accounted_with_other_nls_data() {
        let nls = Nls::new(vec![])
            .unwrap()
            .with_mui(vec![0x53; 1232])
            .unwrap();
        let bytes = nls.mui().unwrap();
        assert!(Arc::ptr_eq(&bytes, &nls.clone().mui().unwrap()));
        assert_eq!(bytes.len(), 1232);
        assert_eq!(nls.mui_generation(), Some(0x5353_5353));
        assert!(nls.with_mui(vec![1]).is_err());
        for size in [0, 15, MAX_MUI_BYTES + 1] {
            assert!(Nls::new(vec![]).unwrap().with_mui(vec![0; size]).is_err());
        }
        let full = Nls::new(
            (0..8)
                .map(|code| ((11, code), vec![0; super::super::MAX_SECTION_BYTES]))
                .collect(),
        )
        .unwrap();
        assert!(full.with_mui(vec![0; 16]).is_err());
    }
}
