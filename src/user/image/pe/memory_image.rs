//! Fallible PE materialization without eagerly touching untouched zero pages.
use super::{PeImage, section_file_range};
use std::alloc::{Layout, alloc_zeroed};
use std::io;

impl PeImage {
    /// Materialize the same bytes as [`Self::memory_image`], returning a host
    /// allocation error instead of invoking the infallible allocation handler.
    /// This does not change the parser's accepted image sizes or layout rules.
    pub fn try_memory_image(&self) -> io::Result<Vec<u8>> {
        self.memory_image_with(zeroed)
    }

    pub(super) fn memory_image_with(
        &self,
        allocate: impl FnOnce(usize) -> io::Result<Vec<u8>>,
    ) -> io::Result<Vec<u8>> {
        if let Some(mapped) = &self.mapped {
            let mut image = allocate(mapped.len())?;
            image.copy_from_slice(mapped);
            return Ok(image);
        }
        let size = self.mapped_size() as usize;
        let mut image = allocate(size)?;
        if self.low_alignment() {
            let n = self.bytes.len().min(self.headers.size_of_image as usize);
            image[..n].copy_from_slice(&self.bytes[..n]);
            return Ok(image);
        }
        let headers = (self.headers.size_of_headers as usize)
            .min(self.bytes.len())
            .min(size);
        image[..headers].copy_from_slice(&self.bytes[..headers]);
        for section in &self.sections {
            let (offset, length) = section_file_range(&self.headers, section);
            if length == 0 {
                continue;
            }
            let start = section.virtual_address as usize;
            image[start..start + length as usize]
                .copy_from_slice(&self.bytes[offset as usize..(offset + length) as usize]);
        }
        Ok(image)
    }
}

fn zeroed(bytes: usize) -> io::Result<Vec<u8>> {
    if bytes == 0 {
        return Ok(Vec::new());
    }
    let layout =
        Layout::array::<u8>(bytes).map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
    // SAFETY: Layout::array checked the byte extent and isize bound; the
    // nonzero allocation uses the same global allocator and byte alignment as
    // Vec<u8>. Asking the allocator to zero preserves its lazy-zero mechanism;
    // reserve followed by resize would eagerly write a potentially huge image.
    let pointer = unsafe { alloc_zeroed(layout) };
    if pointer.is_null() {
        return Err(io::Error::from(io::ErrorKind::OutOfMemory));
    }
    // SAFETY: this is a uniquely owned, live, fully initialized allocation.
    // Its Layout is exactly that of Vec<u8> with both length and capacity bytes.
    // The Vec now exclusively owns and eventually deallocates the allocation.
    Ok(unsafe { Vec::from_raw_parts(pointer, bytes, bytes) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_pe_zero_allocation_handles_empty_small_and_impossible_extents() {
        for bytes in [0, 1, 4096, 65537] {
            let mut image = zeroed(bytes).unwrap();
            assert_eq!(image.len(), bytes);
            assert!(image.iter().all(|byte| *byte == 0));
            // Vec growth and destruction exercise the transferred layout and
            // global allocator ownership, including the empty sentinel case.
            image.push(0x5a);
            assert_eq!(image[bytes], 0x5a);
        }
        assert_eq!(
            zeroed(usize::MAX).unwrap_err().kind(),
            io::ErrorKind::OutOfMemory
        );
    }
}
