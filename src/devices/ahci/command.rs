//! Command admission, checked DMA publication and recoverable engine lifecycle.
use super::dma::{CommandError, Transfer};
use super::*;
const HBFS: u32 = 1 << 29;
const IFS: u32 = 1 << 27;
const OFS: u32 = 1 << 24;
const DPS: u32 = 1 << 5;
const BSY: u32 = 1 << 7;
const DRQ: u32 = 1 << 3;
impl<M: Mem> AhciController<M> {
    pub(super) fn process_commands(&mut self) {
        if !self.ae()
            || self.port.fatal
            || self.port.cmd & (PXCMD_ST | PXCMD_FRE) != (PXCMD_ST | PXCMD_FRE)
            || !self.port.present
            || self.port.ssts & 0xf != 3
            || self.port.tfd & (BSY | DRQ) != 0
        {
            return;
        }
        for _ in 0..self.num_slots {
            let slot = u32::from(self.port.next_slot);
            self.port.next_slot = ((slot + 1) % self.num_slots) as u8;
            if self.port.ci & (1 << slot) == 0 {
                continue;
            }
            self.port.current_slot = slot as u8;
            let result = self.run_slot(slot);
            if let Err(error) = result {
                self.fail_command(error);
                break;
            }
            self.port.ci &= !(1 << slot);
        }
    }
    fn run_slot(&mut self, slot: u32) -> Result<(), CommandError> {
        let address = self
            .port
            .clb
            .checked_add(u64::from(slot) * CMD_HEADER_SIZE)
            .ok_or(CommandError::HostBus)?;
        if u128::from(address) + u128::from(CMD_HEADER_SIZE) > 1u128 << 64 {
            return Err(CommandError::HostBus);
        }
        let mut raw = [0; CMD_HEADER_SIZE as usize];
        if !self.mem.read(address, &mut raw) {
            return Err(CommandError::HostBus);
        }
        let header = CommandHeader::parse(&raw).ok_or(CommandError::HostBus)?;
        if !(2..=16).contains(&header.cfl) || header.ctba % 128 != 0 {
            return Err(CommandError::HostBus);
        }
        if header.cfl != 5 {
            return Err(CommandError::Interface);
        }
        if u128::from(header.ctba) + 20 > 1u128 << 64 {
            return Err(CommandError::HostBus);
        }
        let mut raw = [0; 20];
        if !self.mem.read(header.ctba, &mut raw) {
            return Err(CommandError::HostBus);
        }
        if raw[1] & 0x80 == 0 || raw[1] & 0xf != 0 {
            return Err(CommandError::Interface);
        }
        let fis = FisH2D::parse(&raw).ok_or(CommandError::Interface)?;
        self.port.task_fis = fis;
        if header.atapi {
            return Err(CommandError::TaskFile);
        }
        let pio = fis.command == ATA_CMD_IDENTIFY;
        let transfer = match fis.command {
            ATA_CMD_READ_DMA_EXT if !header.write => self.cmd_read_dma(&header, &fis)?,
            ATA_CMD_WRITE_DMA_EXT if header.write => self.cmd_write_dma(&header, &fis)?,
            ATA_CMD_IDENTIFY if !header.write => self.cmd_identify(&header)?,
            0xe7 | 0xea => {
                self.disk.flush().map_err(|_| CommandError::TaskFile)?;
                Transfer {
                    moved: 0,
                    overflow: false,
                    interrupt: false,
                }
            }
            _ => return Err(CommandError::TaskFile),
        };
        if pio {
            self.port.tfd = u32::from(ATA_DRDY);
        }
        let count = address.checked_add(4).ok_or(CommandError::HostBus)?;
        if !self.mem.write(count, &transfer.moved.to_le_bytes()) {
            return Err(CommandError::HostBus);
        }
        if !pio {
            if matches!(fis.command, ATA_CMD_READ_DMA_EXT | ATA_CMD_WRITE_DMA_EXT) {
                self.port.task_fis.lba = fis.lba
                    + if fis.count == 0 {
                        65536
                    } else {
                        u64::from(fis.count)
                    };
                self.port.task_fis.count = 0;
            }
            self.post_d2h_fis(ATA_DRDY, 0)?;
            self.port.tfd = u32::from(ATA_DRDY);
        }
        let mut bits = if pio { PXIS_PSS } else { PXIS_DHRS };
        if transfer.overflow {
            bits |= OFS;
        }
        if transfer.interrupt {
            bits |= DPS;
        }
        self.raise_port_interrupt(bits);
        Ok(())
    }
    fn fail_command(&mut self, error: CommandError) {
        match error {
            CommandError::TaskFile | CommandError::WriteOverflow => {
                let status = ATA_DRDY | ATA_ERR;
                if self.post_d2h_fis(status, ATA_ERR_ABRT).is_err() {
                    self.port.fatal = true;
                    self.raise_port_interrupt(HBFS);
                    return;
                }
                self.port.tfd = u32::from(status) | (u32::from(ATA_ERR_ABRT) << 8);
                self.port.fatal = true;
                self.raise_port_interrupt(
                    PXIS_TFES
                        | if matches!(error, CommandError::WriteOverflow) {
                            OFS
                        } else {
                            0
                        },
                );
            }
            CommandError::HostBus => {
                self.port.fatal = true;
                self.raise_port_interrupt(HBFS);
            }
            CommandError::Interface => {
                self.port.fatal = true;
                self.raise_port_interrupt(IFS);
            }
        }
    }
    fn post_d2h_fis(&mut self, status: u8, error: u8) -> Result<(), CommandError> {
        let address = self
            .port
            .fb
            .checked_add(RFIS_D2H_OFFSET)
            .ok_or(CommandError::HostBus)?;
        if u128::from(address) + 20 > 1u128 << 64 {
            return Err(CommandError::HostBus);
        }
        let mut fis = [0; 20];
        fis[0] = FIS_TYPE_REG_D2H;
        fis[1] = 1 << 6;
        fis[2] = status;
        fis[3] = error;
        let task = self.port.task_fis;
        fis[7] = task.device;
        for (index, offset) in [4, 5, 6, 8, 9, 10].into_iter().enumerate() {
            fis[offset] = (task.lba >> (8 * index)) as u8;
        }
        fis[12..14].copy_from_slice(&(task.count as u16).to_le_bytes());
        if !self.mem.write(address, &fis) {
            return Err(CommandError::HostBus);
        }
        Ok(())
    }
    pub(super) fn post_pio_setup(&mut self) -> Result<(), CommandError> {
        let address = self
            .port
            .fb
            .checked_add(0x20)
            .ok_or(CommandError::HostBus)?;
        if u128::from(address) + 20 > 1u128 << 64 {
            return Err(CommandError::HostBus);
        }
        let mut fis = [0; 20];
        fis[0] = 0x5f;
        fis[1] = (1 << 6) | (1 << 5);
        fis[2] = ATA_DRDY | DRQ as u8;
        fis[15] = ATA_DRDY;
        fis[16..18].copy_from_slice(&512u16.to_le_bytes());
        if !self.mem.write(address, &fis) {
            return Err(CommandError::HostBus);
        }
        self.port.tfd = u32::from(ATA_DRDY) | DRQ;
        Ok(())
    }
    pub(super) fn write_sctl(&mut self, value: u32) {
        let previous = self.port.sctl & 0xf;
        let next = value & 0xf;
        self.port.sctl = value & 0xfff;
        if next == 1 || next == 4 {
            // COMRESET resets the device/link, not the host-owned CI/SACT.
            // Software stops ST to clear outstanding host command state.
            self.port.fatal = true;
            self.port.current_slot = 0;
            self.port.next_slot = 0;
            self.port.ssts = if self.port.present && next == 1 { 1 } else { 0 };
            self.port.tfd = if next == 1 { BSY } else { 0x7f };
        } else if next == 0 && (previous == 1 || previous == 4) {
            self.port.ssts = if self.port.present { SSTS_PRESENT } else { 0 };
            self.port.sig = if self.port.present { SIG_SATA_DISK } else { 0 };
            self.port.tfd = if self.port.present {
                u32::from(ATA_DRDY)
            } else {
                0x7f
            };
            // Link readiness does not replay outstanding commands. ST recovery
            // remains required after the host engine was stopped by reset.
        }
    }
}
