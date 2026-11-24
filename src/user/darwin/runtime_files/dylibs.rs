//! Format checks for files admitted from installed macOS library roots.
use crate::user::image::macho::{
    self, CPU_TYPE_ARM64, CPU_TYPE_X86_64, Identity, MH_MAGIC_64, MachHeader,
};
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
};

const HEADER_PAGE: usize = 16 << 10;
const THIN_HEADER: usize = macho::MACH_HEADER_64_SIZE as usize;

fn supported(header: &MachHeader) -> bool {
    header.magic == MH_MAGIC_64 && matches!(header.cputype, CPU_TYPE_ARM64 | CPU_TYPE_X86_64)
}

pub(super) fn accept(mut file: &File, file_type: u32) -> io::Result<bool> {
    let file_size = file.metadata()?.len();
    let mut header = [0; HEADER_PAGE];
    let length = file_size.min(HEADER_PAGE as u64) as usize;
    file.read_exact(&mut header[..length])?;
    let header = &header[..length];
    match macho::identify(header) {
        Ok(Identity::Thin(header)) => {
            Ok(length >= THIN_HEADER && header.filetype == file_type && supported(&header))
        }
        Ok(Identity::Fat) => {
            let Ok(arches) =
                macho::fat_arches_with_file_size(header, HEADER_PAGE as u64, file_size)
            else {
                return Ok(false);
            };
            let mut supported_slice = false;
            let mut slice = [0; THIN_HEADER];
            for arch in arches {
                if arch.size < THIN_HEADER as u32 {
                    return Ok(false);
                }
                file.seek(SeekFrom::Start(u64::from(arch.offset)))?;
                file.read_exact(&mut slice)?;
                let Ok(Identity::Thin(header)) = macho::identify(&slice) else {
                    return Ok(false);
                };
                if header.filetype != file_type || header.cputype != arch.cputype {
                    return Ok(false);
                }
                supported_slice |= supported(&header);
            }
            Ok(supported_slice)
        }
        Err(_) => Ok(false),
    }
}
