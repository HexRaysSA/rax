//! POSIX block counts use 512-byte units; birth/change/access/write times are
//! read from host metadata. Missing birth time is explicit, never synthesized.

use super::super::super::named_object::Checked;
use super::super::posix;
use super::{Information, io_error};
use crate::user::windows::hle::Ctx;
use std::fs::{File, Metadata};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const UNIX_EPOCH_TICKS: i128 = 116_444_736_000_000_000;

fn ticks(c: &Ctx, seconds: i128, nanoseconds: i128) -> Checked<u64> {
    let value = UNIX_EPOCH_TICKS + seconds * 10_000_000 + nanoseconds / 100;
    u64::try_from(value).map_err(|_| {
        c.unsupported("host timestamp outside FILETIME range")
            .into()
    })
}

fn system_ticks(c: &Ctx, time: SystemTime) -> Checked<u64> {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => ticks(
            c,
            i128::from(duration.as_secs()),
            i128::from(duration.subsec_nanos()),
        ),
        Err(error) => {
            let duration = error.duration();
            let nanos = UNIX_EPOCH_TICKS * 100
                - i128::from(duration.as_secs()) * 1_000_000_000
                - i128::from(duration.subsec_nanos());
            if nanos < 0 {
                return Err(c
                    .unsupported("host birth timestamp precedes FILETIME epoch")
                    .into());
            }
            u64::try_from(nanos / 100).map_err(|_| {
                c.unsupported("host birth timestamp outside FILETIME range")
                    .into()
            })
        }
    }
}

pub(super) fn query_attributes(c: &Ctx, path: &Path) -> Checked<u32> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => return io_error(c, error, path),
    };
    attributes(c, path, None, &metadata)
}

fn attributes(c: &Ctx, path: &Path, file: Option<&File>, metadata: &Metadata) -> Checked<u32> {
    if !metadata.is_file() && !metadata.is_dir() {
        return Err(c
            .unsupported("NT file metadata for a non-regular POSIX object")
            .into());
    }
    let stored = match file {
        Some(file) => posix::attributes(file),
        None => posix::attributes_path(path),
    }
    .map_err(|e| c.unsupported(format!("NT file extended attributes: {e}")))?;
    let attributes = (stored.unwrap_or(0) & !0x11)
        | u32::from(metadata.permissions().readonly())
        | if metadata.is_dir() { 0x10 } else { 0 };
    Ok(if attributes == 0 { 0x80 } else { attributes })
}

pub(super) fn query(c: &Ctx, path: &Path, file: Option<&File>) -> Checked<Information> {
    let metadata = match file.map_or_else(|| std::fs::metadata(path), File::metadata) {
        Ok(metadata) => metadata,
        Err(error) => return io_error(c, error, path),
    };
    let attributes = attributes(c, path, file, &metadata)?;
    let birth = metadata
        .created()
        .map_err(|error| c.unsupported(format!("host birth timestamp unavailable: {error}")))?;
    let directory = metadata.is_dir();
    let allocation = metadata
        .blocks()
        .checked_mul(512)
        .ok_or_else(|| c.unsupported("POSIX allocated-byte count overflow"))?;
    Ok(Information {
        times: [
            system_ticks(c, birth)?,
            ticks(
                c,
                i128::from(metadata.atime()),
                i128::from(metadata.atime_nsec()),
            )?,
            ticks(
                c,
                i128::from(metadata.mtime()),
                i128::from(metadata.mtime_nsec()),
            )?,
            ticks(
                c,
                i128::from(metadata.ctime()),
                i128::from(metadata.ctime_nsec()),
            )?,
        ],
        allocation: if directory { 0 } else { allocation },
        size: if directory { 0 } else { metadata.len() },
        attributes,
    })
}
