//! Bounded PRDT planning. No source bytes reach media before full source staging.
use super::*;
#[derive(Clone, Copy, Debug)]
pub(super) enum CommandError {
    HostBus,
    TaskFile,
    Interface,
    WriteOverflow,
}
pub(super) struct Segment {
    pub address: u64,
    pub length: u32,
    pub interrupt: bool,
}
pub(super) struct Plan {
    pub segments: Vec<Segment>,
    pub length: u64,
}
pub(super) struct Transfer {
    pub moved: u32,
    pub overflow: bool,
    pub interrupt: bool,
}
impl<M: Mem> AhciController<M> {
    pub(super) fn transfer_bounds(&self, fis: &FisH2D) -> Result<(usize, usize), CommandError> {
        let count = if fis.count == 0 { 65536 } else { fis.count };
        let length = u64::from(count) * SECTOR_SIZE;
        let start = fis
            .lba
            .checked_mul(SECTOR_SIZE)
            .ok_or(CommandError::TaskFile)?;
        let end = start.checked_add(length).ok_or(CommandError::TaskFile)?;
        if end > self.disk.len() as u64 {
            return Err(CommandError::TaskFile);
        }
        Ok((start as usize, length as usize))
    }
    pub(super) fn plan(&self, header: &CommandHeader) -> Result<Plan, CommandError> {
        if header.prdtl == 0 {
            return Ok(Plan {
                segments: Vec::new(),
                length: 0,
            });
        }
        let base = header
            .ctba
            .checked_add(PRDT_OFFSET)
            .ok_or(CommandError::HostBus)?;
        let extent = u64::from(header.prdtl) * PRD_SIZE;
        if u128::from(base) + u128::from(extent) > 1u128 << 64 {
            return Err(CommandError::HostBus);
        }
        let mut segments = Vec::with_capacity(header.prdtl as usize);
        let mut length = 0;
        for i in 0..u64::from(header.prdtl) {
            let address = base
                .checked_add(i * PRD_SIZE)
                .ok_or(CommandError::HostBus)?;
            let mut bytes = [0; PRD_SIZE as usize];
            if !self.mem.read(address, &mut bytes) {
                return Err(CommandError::HostBus);
            }
            let d = Prd::parse(&bytes).ok_or(CommandError::HostBus)?;
            if d.dba & 1 != 0
                || d.byte_count & 1 != 0
                || u128::from(d.dba) + u128::from(d.byte_count) > 1u128 << 64
            {
                return Err(CommandError::HostBus);
            }
            let flags = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
            segments.push(Segment {
                address: d.dba,
                length: d.byte_count,
                interrupt: flags & (1 << 31) != 0,
            });
            length += u64::from(d.byte_count);
        }
        Ok(Plan { segments, length })
    }
    pub(super) fn read_to_guest(
        &mut self,
        plan: &Plan,
        data: &[u8],
    ) -> Result<Transfer, CommandError> {
        let mut offset = 0;
        let mut interrupt = false;
        for segment in &plan.segments {
            if offset == data.len() {
                break;
            }
            let count = (segment.length as usize).min(data.len() - offset);
            if !self
                .mem
                .write(segment.address, &data[offset..offset + count])
            {
                return Err(CommandError::HostBus);
            }
            offset += count;
            interrupt |= segment.interrupt && count == segment.length as usize;
        }
        Ok(Transfer {
            moved: offset as u32,
            overflow: offset != data.len(),
            interrupt,
        })
    }
    pub(super) fn cmd_read_dma(
        &mut self,
        header: &CommandHeader,
        fis: &FisH2D,
    ) -> Result<Transfer, CommandError> {
        let (start, length) = self.transfer_bounds(fis)?;
        let plan = self.plan(header)?;
        // Own the selected bytes so a DMA provider cannot alias controller media.
        let data = self.disk[start..start + length].to_vec();
        self.read_to_guest(&plan, &data)
    }
    pub(super) fn cmd_write_dma(
        &mut self,
        header: &CommandHeader,
        fis: &FisH2D,
    ) -> Result<Transfer, CommandError> {
        let (start, length) = self.transfer_bounds(fis)?;
        let plan = self.plan(header)?;
        if plan.length < length as u64 {
            return Err(CommandError::WriteOverflow);
        }
        if plan.length > length as u64 {
            return Err(CommandError::TaskFile);
        }
        let mut data = vec![0; length];
        let mut offset = 0;
        let mut interrupt = false;
        for segment in &plan.segments {
            let end = offset + segment.length as usize;
            if !self.mem.read(segment.address, &mut data[offset..end]) {
                return Err(CommandError::HostBus);
            }
            offset = end;
            interrupt |= segment.interrupt;
        }
        self.disk[start..start + length].copy_from_slice(&data);
        Ok(Transfer {
            moved: length as u32,
            overflow: false,
            interrupt,
        })
    }
    pub(super) fn cmd_identify(
        &mut self,
        header: &CommandHeader,
    ) -> Result<Transfer, CommandError> {
        let plan = self.plan(header)?;
        let block = self.build_identify();
        self.post_pio_setup()?;
        self.read_to_guest(&plan, &block)
    }
}
