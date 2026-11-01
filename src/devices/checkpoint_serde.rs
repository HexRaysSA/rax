//! Length admission before allocating private PC checkpoint collections.
use serde::de::{Deserialize, Deserializer, Error, SeqAccess, Visitor};
use std::marker::PhantomData;

pub(crate) fn vector<'de, T: Deserialize<'de>, D: Deserializer<'de>, const MAX: usize>(
    d: D,
) -> Result<Vec<T>, D::Error> {
    struct Bounded<T, const MAX: usize>(PhantomData<T>);
    impl<'de, T: Deserialize<'de>, const MAX: usize> Visitor<'de> for Bounded<T, MAX> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "at most {MAX} checkpoint elements")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
            if a.size_hint().is_some_and(|n| n > MAX) {
                return Err(A::Error::custom(
                    "checkpoint collection count exceeds bound",
                ));
            }
            let mut values = Vec::new();
            while let Some(value) = a.next_element()? {
                if values.len() == MAX {
                    return Err(A::Error::custom(
                        "checkpoint collection count exceeds bound",
                    ));
                }
                values.try_reserve(1).map_err(A::Error::custom)?;
                values.push(value);
            }
            Ok(values)
        }
    }
    d.deserialize_seq(Bounded::<T, MAX>(PhantomData))
}

#[cfg(test)]
mod tests {
    #[derive(serde::Deserialize)]
    struct Small(#[serde(deserialize_with = "bytes")] Vec<u8>);
    fn bytes<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        super::vector::<u8, D, 3>(d)
    }
    #[test]
    fn count_limit_is_checked_before_reading_elements() {
        for count in [4u64, 1 << 32, u64::MAX] {
            assert!(crate::codec::deserialize_strict::<Small>(&count.to_le_bytes()).is_err());
        }
        let raw = crate::codec::serialize(&vec![1u8, 2, 3]).unwrap();
        assert_eq!(
            crate::codec::deserialize_strict::<Small>(&raw).unwrap().0,
            [1, 2, 3]
        );
    }
}
