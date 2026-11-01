//! Firmware data and cursor, including EOF and arbitrary item overrides.
use super::*;
impl FwCfg {
    pub(crate) fn validate_checkpoint(&self) -> crate::error::Result<()> {
        if self.items.len() > 65536
            || self.files.len() > 65504
            || self.next_file_selector < FW_CFG_FILE_FIRST
            || self.files.iter().enumerate().any(|(i, f)| {
                usize::from(f.select) != usize::from(FW_CFG_FILE_FIRST) + i || f.name[55] != 0
            })
            || usize::from(self.next_file_selector)
                != usize::from(FW_CFG_FILE_FIRST) + self.files.len()
        {
            return Err(crate::error::Error::InvalidConfig(
                "invalid fw_cfg checkpoint".into(),
            ));
        }
        Ok(())
    }
}
pub(super) mod name_bytes {
    use serde::de::{Error, SeqAccess, Visitor};
    use serde::ser::SerializeTuple;
    use serde::{Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &[u8; 56], s: S) -> Result<S::Ok, S::Error> {
        let mut t = s.serialize_tuple(56)?;
        for b in value {
            t.serialize_element(b)?;
        }
        t.end()
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 56], D::Error> {
        struct Name;
        impl<'de> Visitor<'de> for Name {
            type Value = [u8; 56];
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("56 name bytes")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                let mut bytes = [0; 56];
                for (i, b) in bytes.iter_mut().enumerate() {
                    *b = a
                        .next_element()?
                        .ok_or_else(|| A::Error::invalid_length(i, &self))?;
                }
                Ok(bytes)
            }
        }
        d.deserialize_tuple(56, Name)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn files_overridden_directory_and_past_eof_cursor_round_trip() {
        let mut source = FwCfg::new();
        let key = source.add_file("test", vec![1, 2]);
        source.add_bytes(FW_CFG_FILE_DIR, vec![0x55]);
        source.select(key);
        for _ in 0..7 {
            source.read_data();
        }
        let raw = crate::codec::serialize(&source).unwrap();
        let mut target: FwCfg = crate::codec::deserialize_strict(&raw).unwrap();
        target.validate_checkpoint().unwrap();
        assert_eq!(target.offset, 7);
        assert_eq!(target.read_data(), 0);
        assert_eq!(target.add_file("next", vec![]), key + 1);
        assert_eq!(target.files.len(), 2);
    }
}

pub(super) fn files<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<FileEntry>, D::Error> {
    crate::devices::checkpoint_serde::vector::<FileEntry, D, 65504>(d)
}

pub(super) fn items<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<BTreeMap<u16, Vec<u8>>, D::Error> {
    use serde::de::{Deserialize, Deserializer, Error, MapAccess, Visitor};
    struct Bytes(Vec<u8>);
    impl<'de> Deserialize<'de> for Bytes {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            crate::devices::checkpoint_serde::vector::<u8, D, 62914560>(d).map(Self)
        }
    }
    struct Items;
    impl<'de> Visitor<'de> for Items {
        type Value = BTreeMap<u16, Vec<u8>>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("at most65536 distinct fw_cfg selectors")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
            if a.size_hint().is_some_and(|n| n > 65536) {
                return Err(A::Error::custom("fw_cfg item count"));
            }
            let mut values = BTreeMap::new();
            while let Some((key, Bytes(value))) = a.next_entry::<u16, Bytes>()? {
                if values.len() == 65536 || values.insert(key, value).is_some() {
                    return Err(A::Error::custom("fw_cfg duplicate/excess selector"));
                }
            }
            Ok(values)
        }
    }
    d.deserialize_map(Items)
}
