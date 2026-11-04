//! Exact tagged native banks; SDK compatibility padding is not wire admission.
use serde::de::{Error as _, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::marker::PhantomData;
use zerocopy::{FromBytes, Immutable, IntoBytes};

const VERSION: u16 = 1;
const MAX_BANK_BYTES: usize = 4096;

mod sealed {
    pub trait Sealed {}
}

/// Only SDK structures whose byte representations have compiler-checked layout
/// are admitted here. Dynamic XSAVE, nested buffers, SREGS2 and IRQchip unions
/// have separate records; treating any of them as a fixed bank loses state or
/// requires additional layout/union arguments.
pub(super) trait NativeType: sealed::Sealed + FromBytes + IntoBytes + Immutable {
    const KIND: u16;
}

macro_rules! native_types {
    ($($kind:literal => $native:ty),+ $(,)?) => {
        $(
            impl sealed::Sealed for $native {}
            impl NativeType for $native {
                const KIND: u16 = $kind;
            }
        )+
    };
}

native_types! {
    1 => kvm_bindings::kvm_regs,
    2 => kvm_bindings::kvm_sregs,
    3 => kvm_bindings::kvm_debugregs,
    4 => kvm_bindings::kvm_vcpu_events,
    5 => kvm_bindings::kvm_mp_state,
    6 => kvm_bindings::kvm_xcrs,
    7 => kvm_bindings::kvm_lapic_state,
    8 => kvm_bindings::kvm_clock_data,
    9 => kvm_bindings::kvm_pit_state2,
    10 => kvm_bindings::kvm_cpuid_entry2,
    11 => kvm_bindings::kvm_segment,
    12 => kvm_bindings::kvm_dtable,
}

#[derive(Serialize, Deserialize)]
#[serde(bound = "", deny_unknown_fields)]
pub(super) struct Bank<T> {
    version: u16,
    kind: u16,
    #[serde(deserialize_with = "bounded_bytes")]
    bytes: Vec<u8>,
    #[serde(skip)]
    native: PhantomData<T>,
}

impl<T> Clone for Bank<T> {
    fn clone(&self) -> Self {
        Self {
            version: self.version,
            kind: self.kind,
            bytes: self.bytes.clone(),
            native: PhantomData,
        }
    }
}

impl<T> fmt::Debug for Bank<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeBank")
            .field("version", &self.version)
            .field("kind", &self.kind)
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

impl<T> PartialEq for Bank<T> {
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version && self.kind == other.kind && self.bytes == other.bytes
    }
}

impl<T> Eq for Bank<T> {}

impl<T: NativeType> Bank<T> {
    pub(super) fn capture(native: &T) -> Result<Self, String> {
        let bytes = native.as_bytes();
        if bytes.len() > MAX_BANK_BYTES {
            return Err("native SDK fixed bank exceeds the admitted bound".into());
        }
        Ok(Self {
            version: VERSION,
            kind: T::KIND,
            bytes: bytes.to_vec(),
            native: PhantomData,
        })
    }

    pub(super) fn validate(&self) -> Result<(), String> {
        if self.version != VERSION || self.kind != T::KIND {
            return Err("native bank version or type differs".into());
        }
        if self.bytes.len() != std::mem::size_of::<T>() {
            return Err("native bank length differs from the selected SDK layout".into());
        }
        Ok(())
    }

    pub(super) fn decode(&self) -> Result<T, String> {
        self.validate()?;
        T::read_from_bytes(&self.bytes).map_err(|_| "native bank layout admission failed".into())
    }
}

fn bounded_bytes<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    struct Bytes;
    impl<'de> Visitor<'de> for Bytes {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a native bank of at most 4096 bytes")
        }

        fn visit_bytes<E: serde::de::Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
            if bytes.len() > MAX_BANK_BYTES {
                return Err(E::custom("native bank exceeds 4096 bytes"));
            }
            Ok(bytes.to_vec())
        }

        fn visit_byte_buf<E: serde::de::Error>(self, bytes: Vec<u8>) -> Result<Self::Value, E> {
            if bytes.len() > MAX_BANK_BYTES {
                return Err(E::custom("native bank exceeds 4096 bytes"));
            }
            Ok(bytes)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let hint = sequence.size_hint().unwrap_or(0);
            if hint > MAX_BANK_BYTES {
                return Err(A::Error::custom("native bank exceeds 4096 bytes"));
            }
            let mut bytes = Vec::with_capacity(hint);
            while let Some(byte) = sequence.next_element()? {
                if bytes.len() == MAX_BANK_BYTES {
                    return Err(A::Error::custom("native bank exceeds 4096 bytes"));
                }
                bytes.push(byte);
            }
            Ok(bytes)
        }
    }
    deserializer.deserialize_bytes(Bytes)
}
