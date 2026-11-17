//! Strict Linux MM transactions inside the private process-family protocol.
//! Decode before touching the MM. Guest errno remains separate from transport
//! or protocol failure; only the former leaves an endpoint usable.

use std::collections::BTreeMap;
use std::io;

use serde::{Deserialize, Serialize};

use super::{
    AioRead, AioReadResult, BrkPolicy, LockPolicy, MmResources, MmState, MmapArgs, MmapPolicy,
    PreparedMmap, ProtectPolicy, RemapArgs,
};
use crate::user::linux::abi::LinuxAbi;
use crate::user::linux::abi::errno::Errno;
use crate::user::linux::aio::Handle;
use crate::user::linux::syscall::SysResult;
use crate::user::mm::process_owner::{Access, BackingId, RemoteError};
use crate::user::mm::{AddressSpace, Backing};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "operation", deny_unknown_fields)]
pub(crate) enum Operation {
    Mmap {
        policy: MmapPolicy,
        arguments: MmapArgs,
        source: MmapSource,
    },
    Brk {
        policy: BrkPolicy,
        address: u64,
    },
    Munmap {
        abi: LinuxAbi,
        address: u64,
        length: u64,
    },
    Mprotect {
        policy: ProtectPolicy,
        address: u64,
        length: u64,
        protection: u32,
    },
    Mseal {
        address: u64,
        length: u64,
        flags: u64,
    },
    Mlock {
        policy: LockPolicy,
        address: u64,
        length: u64,
        flags: u32,
    },
    Munlock {
        address: u64,
        length: u64,
    },
    Mlockall {
        policy: LockPolicy,
        flags: i32,
    },
    Munlockall {},
    Msync {
        address: u64,
        length: u64,
        flags: u32,
    },
    Mincore {
        abi: LinuxAbi,
        address: u64,
        length: u64,
        vector: u64,
    },
    Madvise {
        address: u64,
        length: u64,
        advice: u32,
    },
    Mremap {
        policy: LockPolicy,
        arguments: RemapArgs,
    },
    AioSetup {
        policy: LockPolicy,
        nr_events: u32,
        context: u64,
    },
    AioLookup {
        address: u64,
    },
    AioRead(AioRead),
}

/// Handle lookup retains the actual admitted backing, including its Keep.
/// A worker cannot introduce a PageSource callback through this record.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "source", deny_unknown_fields)]
pub(crate) enum MmapSource {
    Anonymous {},
    Registered {
        backing: BackingId,
        name: Option<String>,
        flags: u32,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "reply", deny_unknown_fields)]
enum MmapReply {
    Mmap { result: Result<u64, i32> },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "reply", deny_unknown_fields)]
enum BrkReply {
    Brk { result: Result<u64, i32> },
}

// A narrow reply type for each operation rejects a valid reply for a different
// operation during endpoint decoding, before access could remain usable.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "reply", deny_unknown_fields)]
enum MunmapReply {
    Munmap { result: Result<u64, i32> },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "reply", deny_unknown_fields)]
enum MprotectReply {
    Mprotect { result: Result<u64, i32> },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "reply", deny_unknown_fields)]
enum MsealReply {
    Mseal { result: Result<u64, i32> },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "reply", deny_unknown_fields)]
enum MlockReply {
    Mlock { result: Result<u64, i32> },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "reply", deny_unknown_fields)]
enum MunlockReply {
    Munlock { result: Result<u64, i32> },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "reply", deny_unknown_fields)]
enum MlockallReply {
    Mlockall { result: Result<u64, i32> },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "reply", deny_unknown_fields)]
enum MunlockallReply {
    Munlockall { result: Result<u64, i32> },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "reply", deny_unknown_fields)]
enum MsyncReply {
    Msync { result: Result<u64, i32> },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "reply", deny_unknown_fields)]
enum MincoreReply {
    Mincore { result: Result<u64, i32> },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "reply", deny_unknown_fields)]
enum MadviseReply {
    Madvise { result: Result<u64, i32> },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "reply", deny_unknown_fields)]
enum MremapReply {
    Mremap { result: Result<u64, i32> },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "reply", deny_unknown_fields)]
enum AioSetupReply {
    AioSetup { result: Result<u64, i32> },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "reply", deny_unknown_fields)]
enum AioLookupReply {
    AioLookup { result: Result<Handle, i32> },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "reply", deny_unknown_fields)]
enum AioReadReply {
    AioRead { result: Result<AioReadResult, i32> },
}

pub(super) fn execute(
    resources: &mut MmResources,
    space: &AddressSpace,
    request: &[u8],
    backings: &BTreeMap<BackingId, Backing>,
) -> io::Result<Vec<u8>> {
    let operation: Operation = serde_json::from_slice(request).map_err(invalid)?;
    let mm = &mut resources.mm;
    match operation {
        Operation::Mmap {
            policy,
            arguments,
            source,
        } => {
            let result = execute_mmap(mm, space, policy, arguments, source, backings)?;
            serde_json::to_vec(&MmapReply::Mmap {
                result: result.map_err(|error| error.0),
            })
        }
        Operation::Brk { policy, address } => serde_json::to_vec(&BrkReply::Brk {
            result: mm
                .change_brk(space, policy, address)
                .map_err(|error| error.0),
        }),
        Operation::Munmap {
            abi,
            address,
            length,
        } => serde_json::to_vec(&MunmapReply::Munmap {
            result: mm
                .unmap_range(space, abi, address, length)
                .map_err(|error| error.0),
        }),
        Operation::Mprotect {
            policy,
            address,
            length,
            protection,
        } => serde_json::to_vec(&MprotectReply::Mprotect {
            result: mm
                .protect_range(space, policy, address, length, protection)
                .map_err(|error| error.0),
        }),
        Operation::Mseal {
            address,
            length,
            flags,
        } => serde_json::to_vec(&MsealReply::Mseal {
            result: mm
                .seal_range(space, address, length, flags)
                .map_err(|error| error.0),
        }),
        Operation::Mlock {
            policy,
            address,
            length,
            flags,
        } => serde_json::to_vec(&MlockReply::Mlock {
            result: mm
                .lock_range(space, policy, address, length, flags)
                .map_err(|error| error.0),
        }),
        Operation::Munlock { address, length } => serde_json::to_vec(&MunlockReply::Munlock {
            result: mm
                .unlock_range(space, address, length)
                .map_err(|error| error.0),
        }),
        Operation::Mlockall { policy, flags } => serde_json::to_vec(&MlockallReply::Mlockall {
            result: mm.lock_all(space, policy, flags).map_err(|error| error.0),
        }),
        Operation::Munlockall {} => serde_json::to_vec(&MunlockallReply::Munlockall {
            result: mm.unlock_all(space).map_err(|error| error.0),
        }),
        Operation::Msync {
            address,
            length,
            flags,
        } => serde_json::to_vec(&MsyncReply::Msync {
            result: mm
                .sync_range(space, address, length, flags)
                .map_err(|error| error.0),
        }),
        Operation::Mincore {
            abi,
            address,
            length,
            vector,
        } => serde_json::to_vec(&MincoreReply::Mincore {
            result: mm
                .residency_into(space, abi, address, length, vector)
                .map_err(|error| error.0),
        }),
        Operation::Madvise {
            address,
            length,
            advice,
        } => serde_json::to_vec(&MadviseReply::Madvise {
            result: mm
                .advise_range(space, address, length, advice)
                .map_err(|error| error.0),
        }),
        Operation::Mremap { policy, arguments } => serde_json::to_vec(&MremapReply::Mremap {
            result: mm
                .remap_range(space, &mut resources.aio, policy, arguments)
                .map_err(|error| error.0),
        }),
        Operation::AioSetup {
            policy,
            nr_events,
            context,
        } => serde_json::to_vec(&AioSetupReply::AioSetup {
            result: mm
                .setup_aio(space, &mut resources.aio, policy, nr_events, context)
                .map_err(|error| error.0),
        }),
        Operation::AioLookup { address } => serde_json::to_vec(&AioLookupReply::AioLookup {
            result: resources
                .aio
                .lookup_in_space(space, address)
                .map_err(|error| error.0),
        }),
        Operation::AioRead(arguments) => serde_json::to_vec(&AioReadReply::AioRead {
            result: resources
                .aio
                .read_events(space, arguments)
                .map_err(|error| error.0),
        }),
    }
    .map_err(invalid)
}

fn execute_mmap(
    mm: &mut MmState,
    space: &AddressSpace,
    policy: MmapPolicy,
    arguments: MmapArgs,
    source: MmapSource,
    backings: &BTreeMap<BackingId, Backing>,
) -> io::Result<SysResult> {
    use crate::user::linux::syscall::mem::mman::MAP_ANONYMOUS;
    let anonymous = arguments.flags & MAP_ANONYMOUS != 0;
    // Resolve protocol resource identity before any allocation or MM change.
    let prepared = match source {
        MmapSource::Anonymous {} if anonymous => None,
        MmapSource::Registered {
            backing,
            name,
            flags,
        } if !anonymous => {
            let backing = backings.get(&backing).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "unknown mmap backing")
            })?;
            Some((backing, name, flags))
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "mmap source disagrees with flags",
            ));
        }
    };
    let arguments = match arguments.checked() {
        Ok(arguments) => arguments,
        Err(error) => return Ok(Err(error)),
    };
    let prepared = match prepared {
        Some((backing, name, flags)) => {
            backing
                .offset()
                .checked_add(arguments.offset)
                .and_then(|offset| offset.checked_add(arguments.length))
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "mmap backing offset overflow")
                })?;
            Ok(PreparedMmap {
                backing: backing.advanced(arguments.offset),
                name: name.map(Into::into),
                flags,
            })
        }
        None => PreparedMmap::anonymous(arguments),
    };
    Ok(prepared.and_then(|prepared| mm.map_prepared(space, policy, arguments, prepared)))
}

pub(crate) fn mmap(
    access: &Access,
    policy: MmapPolicy,
    arguments: MmapArgs,
    source: MmapSource,
) -> Result<SysResult, RemoteError> {
    let MmapReply::Mmap { result } = access.transact(&Operation::Mmap {
        policy,
        arguments,
        source,
    })?;
    Ok(result.map_err(Errno))
}

/// A transport failure is fatal to the worker, not a guest errno. The caller
/// must propagate it out of the current CPU/syscall execution window.
pub(crate) fn brk(
    access: &Access,
    policy: BrkPolicy,
    address: u64,
) -> Result<SysResult, RemoteError> {
    let BrkReply::Brk { result } = access.transact(&Operation::Brk { policy, address })?;
    Ok(result.map_err(Errno))
}

pub(crate) fn munmap(
    access: &Access,
    abi: LinuxAbi,
    address: u64,
    length: u64,
) -> Result<SysResult, RemoteError> {
    let MunmapReply::Munmap { result } = access.transact(&Operation::Munmap {
        abi,
        address,
        length,
    })?;
    Ok(result.map_err(Errno))
}

pub(crate) fn mprotect(
    access: &Access,
    policy: ProtectPolicy,
    address: u64,
    length: u64,
    protection: u32,
) -> Result<SysResult, RemoteError> {
    let MprotectReply::Mprotect { result } = access.transact(&Operation::Mprotect {
        policy,
        address,
        length,
        protection,
    })?;
    Ok(result.map_err(Errno))
}

pub(crate) fn mseal(
    access: &Access,
    address: u64,
    length: u64,
    flags: u64,
) -> Result<SysResult, RemoteError> {
    let MsealReply::Mseal { result } = access.transact(&Operation::Mseal {
        address,
        length,
        flags,
    })?;
    Ok(result.map_err(Errno))
}

pub(crate) fn mlock(
    access: &Access,
    policy: LockPolicy,
    address: u64,
    length: u64,
    flags: u32,
) -> Result<SysResult, RemoteError> {
    let MlockReply::Mlock { result } = access.transact(&Operation::Mlock {
        policy,
        address,
        length,
        flags,
    })?;
    Ok(result.map_err(Errno))
}

pub(crate) fn munlock(
    access: &Access,
    address: u64,
    length: u64,
) -> Result<SysResult, RemoteError> {
    let MunlockReply::Munlock { result } =
        access.transact(&Operation::Munlock { address, length })?;
    Ok(result.map_err(Errno))
}

pub(crate) fn mlockall(
    access: &Access,
    policy: LockPolicy,
    flags: i32,
) -> Result<SysResult, RemoteError> {
    let MlockallReply::Mlockall { result } =
        access.transact(&Operation::Mlockall { policy, flags })?;
    Ok(result.map_err(Errno))
}

pub(crate) fn munlockall(access: &Access) -> Result<SysResult, RemoteError> {
    let MunlockallReply::Munlockall { result } = access.transact(&Operation::Munlockall {})?;
    Ok(result.map_err(Errno))
}

pub(crate) fn msync(
    access: &Access,
    address: u64,
    length: u64,
    flags: u32,
) -> Result<SysResult, RemoteError> {
    let MsyncReply::Msync { result } = access.transact(&Operation::Msync {
        address,
        length,
        flags,
    })?;
    Ok(result.map_err(Errno))
}

pub(crate) fn mincore(
    access: &Access,
    abi: LinuxAbi,
    address: u64,
    length: u64,
    vector: u64,
) -> Result<SysResult, RemoteError> {
    let MincoreReply::Mincore { result } = access.transact(&Operation::Mincore {
        abi,
        address,
        length,
        vector,
    })?;
    Ok(result.map_err(Errno))
}

pub(crate) fn madvise(
    access: &Access,
    address: u64,
    length: u64,
    advice: u32,
) -> Result<SysResult, RemoteError> {
    let MadviseReply::Madvise { result } = access.transact(&Operation::Madvise {
        address,
        length,
        advice,
    })?;
    Ok(result.map_err(Errno))
}

pub(crate) fn mremap(
    access: &Access,
    policy: LockPolicy,
    arguments: RemapArgs,
) -> Result<SysResult, RemoteError> {
    let MremapReply::Mremap { result } =
        access.transact(&Operation::Mremap { policy, arguments })?;
    Ok(result.map_err(Errno))
}

pub(crate) fn aio_setup(
    access: &Access,
    policy: LockPolicy,
    nr_events: u32,
    context: u64,
) -> Result<SysResult, RemoteError> {
    let AioSetupReply::AioSetup { result } = access.transact(&Operation::AioSetup {
        policy,
        nr_events,
        context,
    })?;
    Ok(result.map_err(Errno))
}

pub(crate) fn aio_lookup(
    access: &Access,
    address: u64,
) -> Result<Result<Handle, Errno>, RemoteError> {
    let AioLookupReply::AioLookup { result } =
        access.transact(&Operation::AioLookup { address })?;
    Ok(result.map_err(Errno))
}

pub(crate) fn aio_read(
    access: &Access,
    arguments: AioRead,
) -> Result<Result<AioReadResult, Errno>, RemoteError> {
    let AioReadReply::AioRead { result } = access.transact(&Operation::AioRead(arguments))?;
    Ok(result.map_err(Errno))
}

fn invalid(error: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
