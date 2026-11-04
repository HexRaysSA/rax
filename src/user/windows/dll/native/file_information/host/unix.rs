//! POSIX metadata belongs to the mapped guest volume, never to a reopened path.
use super::super::super::file_attributes::metadata;
use super::super::super::named_object::Checked;
use crate::user::windows::fs::FileIdentity;
use crate::user::windows::hle::Ctx;
use crate::user::windows::objects::FileObj;
use std::io::Seek;
use std::os::unix::fs::MetadataExt;

pub(super) fn query(c: &Ctx, file: &FileObj, class: u32) -> Checked<Vec<u8>> {
    let metadata = file
        .host
        .as_ref()
        .map_or_else(
            || std::fs::metadata(&file.host_path),
            std::fs::File::metadata,
        )
        .map_err(|error| c.unsupported(format!("retained file information: {error}")))?;
    let identity = FileIdentity::of(&file.host_path, &metadata)
        .map_err(|error| c.unsupported(format!("retained file identity: {error}")))?;
    if identity != file.lifetime.identity {
        return Err(c
            .unsupported("metadata-only file pathname was replaced")
            .into());
    }
    match class {
        4 | 34 | 35 => {
            let info = metadata::retained(c, file)?;
            let mut data = vec![
                0;
                if class == 4 {
                    40
                } else if class == 34 {
                    56
                } else {
                    8
                }
            ];
            if class == 35 {
                if info.attributes & 0x400 != 0 {
                    return Err(c
                        .unsupported("mapped file reparse tag is unavailable")
                        .into());
                }
                data[..4].copy_from_slice(&info.attributes.to_le_bytes());
            } else {
                for (dest, time) in data[..32].chunks_exact_mut(8).zip(info.times) {
                    dest.copy_from_slice(&time.to_le_bytes());
                }
                let attribute = if class == 34 {
                    data[32..40].copy_from_slice(&info.allocation.to_le_bytes());
                    data[40..48].copy_from_slice(&info.size.to_le_bytes());
                    48
                } else {
                    32
                };
                data[attribute..attribute + 4].copy_from_slice(&info.attributes.to_le_bytes());
            }
            Ok(data)
        }
        5 => {
            let mut data = vec![0; 24];
            let allocation = metadata
                .blocks()
                .checked_mul(512)
                .ok_or_else(|| c.unsupported("allocated byte count overflow"))?;
            let links = u32::try_from(metadata.nlink())
                .map_err(|_| c.unsupported("file link count exceeds ULONG"))?;
            data[..8].copy_from_slice(&allocation.to_le_bytes());
            data[8..16].copy_from_slice(&metadata.len().to_le_bytes());
            data[16..20].copy_from_slice(&links.to_le_bytes());
            data[20] = u8::from(file.lifetime.delete_requested());
            data[21] = u8::from(metadata.is_dir());
            Ok(data)
        }
        6 => Ok(metadata.ino().to_le_bytes().to_vec()),
        // The mapped Windows namespace has no guest EA writer yet. Host POSIX
        // xattrs (including private mapped attributes) are not Windows EAs.
        7 => Ok(0u32.to_le_bytes().to_vec()),
        14 => {
            let position = match file.host.as_ref() {
                Some(mut file) if !metadata.is_dir() => file
                    .stream_position()
                    .map_err(|error| c.unsupported(format!("owned file position: {error}")))?,
                _ => 0,
            };
            Ok(position.to_le_bytes().to_vec())
        }
        // This is the existing virtual mounted-local-disk profile, rather than
        // the Unix device's unrelated st_blksize or direct-I/O alignment.
        17 => Ok(1u32.to_le_bytes().to_vec()),
        51 => Ok(vec![0]), // The mapped guest volume is the modeled local disk.
        59 => {
            let mut data = vec![0; 24];
            data[..8].copy_from_slice(&metadata.dev().to_le_bytes());
            data[8..16].copy_from_slice(&metadata.ino().to_le_bytes());
            Ok(data)
        }
        _ => Err(c
            .unsupported(format!("owned file information class {class}"))
            .into()),
    }
}
