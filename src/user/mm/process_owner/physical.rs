//! Export the actual physical storage selected by an owner translation.
//! The receiver gets no allocator, VMA or page-table state of its own.

use std::fs::File;

use super::wire::{Translation, ViewFailure, ViewOperation, ViewValue};
use crate::user::mm::{AddressSpace, EXTENT};

pub(super) struct Export {
    pub(super) value: ViewValue,
    pub(super) file: Option<File>,
}

pub(super) fn export(
    space: &AddressSpace,
    operation: ViewOperation,
) -> Result<Export, ViewFailure> {
    match operation {
        ViewOperation::Arena => {
            let file = space.inner.arena.process_file().ok_or_else(unavailable)?;
            Ok(Export {
                value: ViewValue::Arena {
                    bytes: space.inner.arena.size(),
                },
                file: Some(file.try_clone().map_err(preparation)?),
            })
        }
        ViewOperation::Translate {
            address,
            access,
            raw,
        } => {
            let address = if raw {
                space.translate_raw(address, access)
            } else {
                space.translate(address, access)
            }
            .map_err(|error| ViewFailure::Memory {
                error: error.into(),
            })?;
            let base = address & !(EXTENT - 1);
            let extents = space.inner.extents.lock().map_err(|_| unavailable())?;
            let (translation, file) = if let Some(extent) = extents.at.get(&base) {
                let file = extent.object.host_file().ok_or(ViewFailure::HostMemory)?;
                (
                    Translation::File {
                        address,
                        base,
                        len: extent.len,
                        offset: extent.key.2,
                        writable: extent.writable,
                        identity: [extent.key.0, extent.key.1],
                    },
                    Some(file.try_clone().map_err(preparation)?),
                )
            } else {
                (Translation::Private { address }, None)
            };
            Ok(Export {
                value: ViewValue::Translation { translation },
                file,
            })
        }
    }
}

fn preparation(error: std::io::Error) -> ViewFailure {
    ViewFailure::Preparation {
        error: error.into(),
    }
}

fn unavailable() -> ViewFailure {
    preparation(std::io::Error::other("owner physical storage unavailable"))
}
