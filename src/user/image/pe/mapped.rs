//! A kernel-selected PE view retains its file identity and uses RVA bytes.
//!
//! ARM64X can change the COFF machine, entry point and data directories when
//! Windows projects one file into a process. Reinterpreting that buffer as a
//! file would read section contents at `PointerToRawData` a second time.

use super::{PeError, PeImage, RvaFault, RvaSource, decode, section_file_range};
use std::sync::Arc;

impl PeImage {
    /// Retains this file's bytes while interpreting an independently selected
    /// mapped view. This validates geometry and source identity, not authority
    /// to execute the projected architecture; the personality owns that check.
    ///
    /// Header and section decoding costs O(S), where S is the section count.
    /// The immutable mapped buffer is retained without copying its contents.
    pub(crate) fn with_mapped_view(&self, bytes: Arc<[u8]>) -> Result<Self, PeError> {
        let (headers, sections) = decode(&bytes, true)?;
        let source = &self.headers;
        if bytes.len() as u64 != u64::from(headers.size_of_image)
            || headers.nt_offset != source.nt_offset
            || headers.kind != source.kind
            || headers.time_date_stamp != source.time_date_stamp
            || headers.characteristics != source.characteristics
            || headers.size_of_optional_header != source.size_of_optional_header
            || headers.size_of_headers != source.size_of_headers
            || headers.size_of_image != source.size_of_image
            || headers.section_alignment != source.section_alignment
            || headers.file_alignment != source.file_alignment
            || sections != self.sections
        {
            return Err(PeError::MappedViewMismatch);
        }
        Ok(Self {
            bytes: self.bytes.clone(),
            headers,
            sections,
            mapped: Some(bytes),
        })
    }
}

impl RvaSource for PeImage {
    /// Reads the selected memory layout without allocating `SizeOfImage`.
    /// File-backed images supply validated headers/section bytes and zero fill;
    /// an explicit kernel view supplies its own already mapped RVA bytes.
    fn read_rva(&self, rva: u64, output: &mut [u8]) -> Result<(), RvaFault> {
        if let Some(mapped) = &self.mapped {
            return mapped.as_ref().read_rva(rva, output);
        }
        let size = u64::from(self.mapped_size());
        let end = rva
            .checked_add(output.len() as u64)
            .filter(|&end| end <= size)
            .ok_or(RvaFault { rva: rva.max(size) })?;
        output.fill(0);
        let mut copy = |start: u64, file_offset: u64, length: u64| {
            let first = rva.max(start);
            let last = end.min(start + length);
            if first < last {
                let offset = file_offset + first - start;
                let count = (last - first) as usize;
                let destination = (first - rva) as usize;
                // decode() validated every file-backed range and its image
                // geometry. The intersections are bounded by the caller slice.
                output[destination..destination + count]
                    .copy_from_slice(&self.bytes[offset as usize..offset as usize + count]);
            }
        };
        if self.low_alignment() {
            copy(
                0,
                0,
                (self.bytes.len() as u64).min(u64::from(self.headers.size_of_image)),
            );
        } else {
            copy(
                0,
                0,
                (self.bytes.len() as u64).min(u64::from(self.headers.size_of_headers)),
            );
            for section in &self.sections {
                let (offset, length) = section_file_range(&self.headers, section);
                copy(u64::from(section.virtual_address), offset, length);
            }
        }
        Ok(())
    }
}
