//! Standard PE layout for hosts without a selected native image projection.
use super::{Backing, Error};
use crate::user::image::pe::PeImage;
use crate::user::windows::memory::{mem, prot};
use crate::user::windows::object_namespace::{ImageRegion, ImageTemplate};
use std::fs::File;

pub(super) fn acquire(file: &File, requested: u64) -> Result<Backing, Error> {
    let metadata = file
        .metadata()
        .map_err(|e| Error::Unavailable(format!("retained image metadata: {e}")))?;
    if metadata.is_dir() || metadata.len() == 0 {
        return Err(Error::Status(0xc0000020));
    }
    if !metadata.is_file() || metadata.len() > 64 << 20 {
        return Err(Error::Unavailable(
            "retained PE input exceeds the 64 MiB regular-file bound".into(),
        ));
    }
    let mut bytes = vec![0; metadata.len() as usize];
    let mut at = 0;
    while at < bytes.len() {
        #[cfg(unix)]
        let read = {
            use std::os::unix::fs::FileExt;
            file.read_at(&mut bytes[at..], at as u64)
        };
        #[cfg(windows)]
        let read = {
            use std::io::{Seek, SeekFrom};
            use std::os::windows::fs::FileExt;
            // Windows seek_read changes the shared file cursor, unlike Unix
            // read_at. Scheduler-serialized section capture restores it on
            // both successful and failed reads before returning to the guest.
            // https://doc.rust-lang.org/1.95.0/std/os/windows/fs/trait.FileExt.html
            let mut cursor = file;
            let position = cursor.stream_position().map_err(|error| {
                Error::Unavailable(format!("retained image cursor capture: {error}"))
            })?;
            let result = file.seek_read(&mut bytes[at..], at as u64);
            cursor.seek(SeekFrom::Start(position)).map_err(|error| {
                Error::Unavailable(format!("retained image cursor restore: {error}"))
            })?;
            result
        };
        #[cfg(not(any(unix, windows)))]
        let read: std::io::Result<usize> = Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "positional file reads are not available on this target",
        ));
        let read = read.map_err(|e| Error::Unavailable(format!("retained PE bytes: {e}")))?;
        if read == 0 {
            return Err(Error::Unavailable(
                "retained image changed while reading".into(),
            ));
        }
        at += read;
    }
    let image = PeImage::parse(bytes).map_err(|_| Error::Status(0xc000012f))?;
    let size = u64::from(image.headers().size_of_image);
    if size == 0 || size > 64 << 20 || size % 4096 != 0 {
        return Err(Error::Unavailable(
            "PE image is outside the 64 MiB page-aligned template profile".into(),
        ));
    }
    let maximum = if requested == 0 { size } else { requested };
    if maximum > size {
        return Err(Error::Status(0xc0000040));
    }
    let mut pages = vec![(mem::RESERVE, 0); size as usize / 4096];
    for region in image.regions() {
        let p = region.protection;
        let shared = region
            .section
            .is_some_and(|index| image.sections()[index].characteristics & 0x10000000 != 0);
        let protection = match (p.read, p.write, p.execute, shared) {
            (_, true, true, true) => prot::EXECUTE_READWRITE,
            (_, true, true, false) => prot::EXECUTE_WRITECOPY,
            (_, true, false, true) => prot::READWRITE,
            (_, true, false, false) => prot::WRITECOPY,
            (_, false, true, _) => prot::EXECUTE_READ,
            (true, false, false, _) => prot::READONLY,
            _ => prot::NOACCESS,
        };
        let first = region.rva as usize / 4096;
        let last = (u64::from(region.rva) + u64::from(region.len)) as usize / 4096;
        for page in pages
            .get_mut(first..last)
            .ok_or_else(|| Error::Unavailable("PE region exceeds its template".into()))?
        {
            *page = (mem::COMMIT, protection);
        }
    }
    let mut regions: Vec<ImageRegion> = Vec::new();
    for (page, (state, protection)) in pages.into_iter().enumerate() {
        if let Some(last) = regions.last_mut()
            && last.state == state
            && last.protection == protection
        {
            last.size += 4096;
        } else {
            regions.push(ImageRegion {
                offset: page as u64 * 4096,
                size: 4096,
                state,
                protection,
            });
        }
    }
    let template = ImageTemplate::selected(image.memory_image(), regions)
        .map_err(|e| Error::Unavailable(format!("standard PE template: {e}")))?;
    Ok(Backing {
        template,
        maximum,
        attributes: 0x01800000,
        #[cfg(windows)]
        source: None,
    })
}
