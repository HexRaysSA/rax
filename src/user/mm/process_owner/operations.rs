//! Execute transport operations against the authoritative owner MM. No worker
//! VMA, frame allocator or PageSource copy is used to satisfy a request.

use std::collections::BTreeMap;

use super::BackingId;
use super::wire::{Failure, Map, Operation, ReadKind, Value};
use crate::user::mm::{AddressSpace, Backing, CodeChanges, Mapping, MmError, Perms};

pub(super) fn execute(
    space: &AddressSpace,
    backings: &mut BTreeMap<BackingId, Backing>,
    operation: Operation,
) -> Result<Value, Failure> {
    match operation {
        Operation::ReleaseBacking { backing } => {
            backings
                .remove(&backing)
                .ok_or(MmError::InvalidArgument("unknown owner backing"))?;
            Ok(Value::Unit)
        }
        Operation::Read { address, len, kind } => {
            let mut bytes = vec![0; len as usize];
            match kind {
                ReadKind::Read => space.read(address, &mut bytes),
                ReadKind::Fetch => space.fetch(address, &mut bytes),
                ReadKind::Raw => space.read_raw(address, &mut bytes),
            }?;
            Ok(Value::Bytes { bytes })
        }
        Operation::Write {
            address,
            bytes,
            raw,
        } => {
            if raw {
                space.write_raw(address, &bytes)
            } else {
                space.write(address, &bytes)
            }?;
            Ok(Value::Unit)
        }
        Operation::Translate {
            address,
            access,
            raw,
        } => {
            let address = if raw {
                space.translate_raw(address, access)
            } else {
                space.translate(address, access)
            }?;
            Ok(Value::Physical { address })
        }
        Operation::Probe {
            address,
            len,
            access,
        } => {
            space.probe(address, len as usize, access)?;
            Ok(Value::Unit)
        }
        Operation::Map { mapping } => map(space, backings, mapping),
        Operation::Unmap { start, len } => unit(space.unmap(start, len)),
        Operation::Protect { start, len, perms } => {
            unit(space.protect(start, len, permissions(perms)?))
        }
        Operation::SetFlags {
            start,
            len,
            mask,
            bits,
        } => unit(space.set_flags(start, len, mask, bits)),
        Operation::Remap { old, len, new } => unit(space.remap(old, len, new)),
        Operation::Discard { start, len } => unit(space.discard(start, len)),
        Operation::FileCopyPolicy { start, len, copy } => {
            unit(space.set_file_copy_on_write(start, len, copy))
        }
        Operation::CodeChanges { epoch } => {
            let (changes, epoch) = space.code_changes_since(epoch);
            let (all, ranges) = match changes {
                CodeChanges::None => (false, Vec::new()),
                CodeChanges::Ranges(ranges) => (false, ranges),
                CodeChanges::All => (true, Vec::new()),
            };
            Ok(Value::Code { epoch, all, ranges })
        }
        Operation::Mappings { offset } => {
            let ranges: Vec<_> = space
                .vma_snapshot()
                .into_iter()
                .map(|vma| {
                    (
                        vma.start,
                        vma.end,
                        vma.perms.bits(),
                        vma.name.as_ref().map(|name| name.to_string()),
                    )
                })
                .collect();
            let encoded = serde_json::to_vec(&ranges).map_err(|_| MmError::OutOfMemory)?;
            let offset = usize::try_from(offset).map_err(|_| MmError::OutOfRange)?;
            if offset >= encoded.len() {
                return Err(MmError::OutOfRange.into());
            }
            let end = offset
                .saturating_add(super::wire::TRANSFER_BYTES)
                .min(encoded.len());
            Ok(Value::Mappings {
                total: encoded.len() as u64,
                bytes: encoded[offset..end].to_vec(),
            })
        }
        Operation::ResidentAccessible { address } => Ok(Value::ResidentAccessible {
            accessible: space.is_resident(address)
                && space
                    .vma_at(address)
                    .is_some_and(|vma| !vma.perms.is_empty()),
        }),
        Operation::Stats => Ok(Value::Stats {
            va_limit: space.va_limit(),
            resident_pages: space.resident_pages(),
            attached_extents: space.attached_extents() as u64,
        }),
    }
}

fn map(
    space: &AddressSpace,
    backings: &BTreeMap<BackingId, Backing>,
    request: Map,
) -> Result<Value, Failure> {
    let backing = if let Some(id) = request.backing {
        let backing = backings
            .get(&id)
            .ok_or(MmError::InvalidArgument("unknown owner backing"))?;
        backing
            .offset()
            .checked_add(request.offset)
            .and_then(|offset| offset.checked_add(request.len))
            .ok_or(MmError::OutOfRange)?;
        backing.advanced(request.offset)
    } else {
        if request.shared || request.offset != 0 {
            return Err(
                MmError::InvalidArgument("shared mapping requires a registered object").into(),
            );
        }
        Backing::Anonymous
    };
    if request.shared && !matches!(backing, Backing::Shared { .. }) {
        return Err(MmError::InvalidArgument("shared mapping requires a shared object").into());
    }
    let mapping = Mapping {
        perms: permissions(request.perms)?,
        backing,
        shared: request.shared,
        name: request.name.map(Into::into),
        flags: request.flags,
    };
    unit(if request.copy {
        space.map_copy_on_write(request.start, request.len, mapping)
    } else {
        space.map(request.start, request.len, mapping)
    })
}

fn permissions(bits: u8) -> Result<Perms, MmError> {
    Perms::from_bits(bits).ok_or(MmError::InvalidArgument("invalid permission bits"))
}

fn unit(result: Result<(), MmError>) -> Result<Value, Failure> {
    result.map(|()| Value::Unit).map_err(Into::into)
}
