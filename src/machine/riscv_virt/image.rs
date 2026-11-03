//! Admission and publication of a little-endian bare-metal ELF image.
use super::RiscvVirtMachine;
use crate::error::{Error, Result};
use crate::machine::RiscVBootInfo;
use crate::vm::memory::reservations::{MemoryDomain, preflight_write};
use goblin::elf::{Elf, header, program_header};
use vm_memory::GuestMemoryMmap;

struct Segment {
    address: u64,
    offset: usize,
    file_size: usize,
    memory_size: usize,
}

impl RiscvVirtMachine {
    pub(super) fn load_elf(mem: &GuestMemoryMmap, bytes: &[u8]) -> Result<RiscVBootInfo> {
        let elf = Elf::parse(bytes)
            .map_err(|error| Error::KernelLoad(format!("ELF parse error: {error}")))?;
        if !elf.is_64 {
            return Err(Error::KernelLoad("RISC-V ELF must be 64-bit".into()));
        }
        if elf.header.e_machine != header::EM_RISCV {
            return Err(Error::KernelLoad(format!(
                "not a RISC-V ELF (e_machine={})",
                elf.header.e_machine
            )));
        }
        if !elf.little_endian {
            return Err(Error::KernelLoad(
                "RISC-V machine requires little-endian ELF".into(),
            ));
        }
        if !matches!(elf.header.e_type, header::ET_EXEC | header::ET_DYN)
            || elf.header.e_version != u32::from(header::EV_CURRENT)
            || elf.header.e_ident[header::EI_VERSION] != header::EV_CURRENT
            || elf.header.e_ehsize != 64
            || elf.header.e_phentsize != 56
        {
            return Err(Error::KernelLoad(
                "unsupported RISC-V ELF type, version or header size".into(),
            ));
        }
        let mut segments = Vec::new();
        let mut first = u64::MAX;
        let mut limit = 0;
        let mut executable_entry = false;
        for ph in &elf.program_headers {
            if matches!(
                ph.p_type,
                program_header::PT_INTERP | program_header::PT_DYNAMIC
            ) {
                return Err(Error::KernelLoad(
                    "bare-metal ELF cannot require dynamic linking".into(),
                ));
            }
            if ph.p_type != program_header::PT_LOAD {
                continue;
            }
            if ph.p_filesz > ph.p_memsz {
                return Err(Error::KernelLoad(
                    "ELF file segment exceeds its memory size".into(),
                ));
            }
            let offset = usize::try_from(ph.p_offset)
                .map_err(|_| Error::KernelLoad("ELF segment overflow".into()))?;
            let file_size = usize::try_from(ph.p_filesz)
                .map_err(|_| Error::KernelLoad("ELF segment overflow".into()))?;
            let file_end = offset
                .checked_add(file_size)
                .ok_or_else(|| Error::KernelLoad("ELF segment overflow".into()))?;
            if file_end > bytes.len() {
                return Err(Error::KernelLoad("ELF segment out of range".into()));
            }
            if ph.p_align > 1
                && (!ph.p_align.is_power_of_two()
                    || ph.p_vaddr % ph.p_align != ph.p_offset % ph.p_align)
            {
                return Err(Error::KernelLoad("invalid ELF segment alignment".into()));
            }
            if ph.p_memsz == 0 {
                continue;
            }
            let address = if ph.p_paddr != 0 {
                ph.p_paddr
            } else {
                ph.p_vaddr
            };
            let end = address
                .checked_add(ph.p_memsz)
                .ok_or_else(|| Error::KernelLoad("ELF memory segment overflow".into()))?;
            let memory_size = usize::try_from(ph.p_memsz)
                .map_err(|_| Error::KernelLoad("ELF memory segment exceeds host range".into()))?;
            preflight_write(mem, address, memory_size)?;
            executable_entry |=
                ph.p_flags & program_header::PF_X != 0 && (address..end).contains(&elf.entry);
            first = first.min(address);
            limit = limit.max(end);
            segments.push(Segment {
                address,
                offset,
                file_size,
                memory_size,
            });
        }
        if segments.is_empty() || !executable_entry || elf.entry & 1 != 0 {
            return Err(Error::KernelLoad(
                "ELF entry is not aligned executable image memory".into(),
            ));
        }
        let mut tohost = None;
        for symbol in &elf.syms {
            if symbol.st_shndx != 0 && elf.strtab.get_at(symbol.st_name) == Some("tohost") {
                if tohost.is_some_and(|address| address != symbol.st_value) {
                    return Err(Error::KernelLoad("ambiguous ELF tohost symbol".into()));
                }
                tohost = Some(symbol.st_value);
            }
        }
        // The caller quiesces CPUs during image loading. Admission above covers
        // every segment before the first store; tracked writes also withdraw
        // reservations retained by an embedder's previous image.
        let domain = MemoryDomain::for_memory(mem);
        let zeroes = [0; 64 * 1024];
        for segment in segments {
            domain.write(
                mem,
                segment.address,
                &bytes[segment.offset..segment.offset + segment.file_size],
            )?;
            let mut done = segment.file_size;
            while done < segment.memory_size {
                let count = (segment.memory_size - done).min(zeroes.len());
                domain.write(mem, segment.address + done as u64, &zeroes[..count])?;
                done += count;
            }
        }
        Ok(RiscVBootInfo {
            entry_point: elf.entry,
            load_addr: first,
            image_size: limit - first,
            tohost_addr: tohost,
        })
    }
}
