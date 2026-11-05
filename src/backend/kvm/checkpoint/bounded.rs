//! Bounded native-record sequences, checked before reserving their storage.
use serde::de::{Error as _, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::fmt;
use std::marker::PhantomData;

pub(in crate::backend::kvm) fn sequence<'de, D, T, const MAX: usize>(
    deserializer: D,
) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Items<T, const MAX: usize>(PhantomData<T>);

    impl<'de, T: Deserialize<'de>, const MAX: usize> Visitor<'de> for Items<T, MAX> {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {MAX} native record elements")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let hint = sequence.size_hint().unwrap_or(0);
            if hint > MAX {
                return Err(A::Error::custom("native record sequence exceeds its bound"));
            }
            let mut items = Vec::with_capacity(hint);
            while let Some(item) = sequence.next_element()? {
                if items.len() == MAX {
                    return Err(A::Error::custom("native record sequence exceeds its bound"));
                }
                items.push(item);
            }
            Ok(items)
        }
    }

    deserializer.deserialize_seq(Items::<T, MAX>(PhantomData))
}
