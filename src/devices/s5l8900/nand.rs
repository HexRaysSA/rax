//! NAND controller, FIFO and sparse media binding.
mod backing;
mod checkpoint;
#[cfg(test)]
mod checkpoint_tests;
use backing::{NandBacking, NandPolicy};

pub const NAND_NUM_BANKS: u32 = 8;
pub const NAND_BYTES_PER_PAGE: usize = 2048;
pub const NAND_BYTES_PER_SPARE: usize = 64;
const NAND_PAGES_PER_BLOCK: u32 = 128;
const NAND_CHIP_ID: u32 = 0xA514_D3AD;
const NAND_CMD_ID: u32 = 0x90;
const NAND_CMD_READ: u32 = 0x30;
const NAND_CMD_READSTATUS: u32 = 0x70;
const NAND_DEVICEINFO_BBT_MAGIC: &[u8; 16] = b"DEVICEINFOBBT\0\0\0";
const NAND_VFL_CONTEXT_SPARE_TYPE: u8 = 0x80;

/// S5L8900 NAND controller. iBoot's flash driver programs a bank/page/command
/// then drains the page through the FMFIFO register; the ADM DMA sets those
/// registers up. Page contents come from `<nand>/bank<b>/<page>.page` files
/// (2048 data + 64 spare bytes each); a missing page reads as zeros.
pub struct S5lNand {
    backing: NandBacking,
    policy: Option<NandPolicy>,
    pub fmctrl0: u32,
    fmctrl1: u32,
    fmaddr0: u32,
    fmaddr1: u32,
    fmanum: u32,
    pub fmdnum: u32,
    rsctrl: u32,
    cmd: u32,
    reading_spare: bool,
    page_buffer: Vec<u8>,
    pub spare_buffer: Vec<u8>,
    buffered_bank: i64,
    buffered_page: i64,
    is_writing: bool,
    pub reading_multiple_pages: bool,
    pub cur_bank_reading: i64,
    pub banks_to_read: Vec<u32>,
    pub pages_to_read: Vec<u32>,
    sparse_vfl_context_blocks: Vec<Option<Vec<u32>>>,
    kernel_started: bool,
}

impl S5lNand {
    pub fn new(nand_path: Option<std::path::PathBuf>) -> Self {
        S5lNand {
            backing: NandBacking::Files(nand_path),
            policy: None,
            fmctrl0: 0,
            fmctrl1: 0,
            fmaddr0: 0,
            fmaddr1: 0,
            fmanum: 0,
            fmdnum: 0,
            rsctrl: 0,
            cmd: 0,
            reading_spare: false,
            page_buffer: vec![0u8; NAND_BYTES_PER_PAGE],
            spare_buffer: vec![0u8; NAND_BYTES_PER_SPARE],
            buffered_bank: -1,
            buffered_page: -1,
            is_writing: false,
            reading_multiple_pages: false,
            cur_bank_reading: -1,
            banks_to_read: vec![0u32; 512],
            pages_to_read: vec![0u32; 512],
            sparse_vfl_context_blocks: vec![None; NAND_NUM_BANKS as usize],
            kernel_started: false,
        }
    }

    fn active_bank(&self) -> i64 {
        let bitmap = (self.fmctrl0 >> 1) & 0xFF;
        for b in 0..NAND_NUM_BANKS {
            if bitmap & (1 << b) != 0 {
                return b as i64;
            }
        }
        -1
    }

    /// Activate exactly one bank (clear all bank-select bits, set `bank`).
    pub fn set_bank(&mut self, bank: u32) {
        for b in 0..8 {
            self.fmctrl0 &= !(1 << (b + 1));
        }
        if bank < NAND_NUM_BANKS {
            self.fmctrl0 |= 1 << (bank + 1);
        }
    }

    /// Load `<nand>/bank<bank>/<page>.page` into the page+spare buffers for the
    /// currently active bank (no-op if already buffered).
    pub fn set_buffered_page(&mut self, page: u32) {
        let bank = self.active_bank();
        if bank < 0 {
            return;
        }
        if bank == self.buffered_bank && page as i64 == self.buffered_page {
            return;
        }
        self.page_buffer.iter_mut().for_each(|b| *b = 0);
        self.spare_buffer.iter_mut().for_each(|b| *b = 0);
        if let Some(data) = self.backing.page(bank as u32, page) {
            tracing::debug!(bank, page, len = data.len(), "nand page hit");
            let n = data.len().min(NAND_BYTES_PER_PAGE);
            self.page_buffer[..n].copy_from_slice(&data[..n]);
            if data.len() > NAND_BYTES_PER_PAGE {
                let s = (data.len() - NAND_BYTES_PER_PAGE).min(NAND_BYTES_PER_SPARE);
                self.spare_buffer[..s]
                    .copy_from_slice(&data[NAND_BYTES_PER_PAGE..NAND_BYTES_PER_PAGE + s]);
            }
            self.normalize_deviceinfo_bbt(bank, page);
            self.rewrite_kernel_pmbr_as_fdisk(bank, page);
        } else {
            tracing::debug!(bank, page, "nand page MISS (erased)");
            self.spare_buffer[0xA] = 0xFF;
        }
        self.buffered_bank = bank;
        self.buffered_page = page as i64;
    }

    fn normalize_deviceinfo_bbt(&mut self, bank: i64, page: u32) {
        if !self.page_buffer.starts_with(NAND_DEVICEINFO_BBT_MAGIC) {
            return;
        }
        if !self.page_buffer[NAND_DEVICEINFO_BBT_MAGIC.len()..]
            .iter()
            .all(|&b| b == 0)
        {
            return;
        }

        let policy = self
            .policy
            .clone()
            .unwrap_or_else(NandPolicy::from_environment);
        let all_good = self.kernel_started && policy.bbt_all_good;
        let good_upto = self
            .kernel_started
            .then_some(policy.bbt_good_upto)
            .flatten();
        let blocks = if all_good || good_upto.is_some() {
            Vec::new()
        } else {
            self.sparse_vfl_context_blocks(bank)
        };
        if !all_good && good_upto.is_none() && blocks.is_empty() {
            tracing::debug!(bank, page, "nand DeviceInfo BBT is empty");
            return;
        }

        // This sparse n45ap dump preserves the DeviceInfo BBT header but not
        // its bitmap. Keep the map narrow so the VFL scan lands on the context
        // block; widening it to every sparse data block corrupts the FTL's
        // startup assumptions and can panic the kernel during AppleNANDFTL::start.
        self.page_buffer[NAND_DEVICEINFO_BBT_MAGIC.len()..].fill(0);
        if all_good {
            self.page_buffer[NAND_DEVICEINFO_BBT_MAGIC.len()..].fill(0xff);
            tracing::debug!(bank, page, "nand synthesized all-good DeviceInfo BBT");
            return;
        }

        if let Some(upto) = good_upto {
            // A bitmap has a finite capacity even for a diagnostic u32::MAX limit.
            // Fill complete bytes, then the inclusive final partial byte.
            let bitmap = &mut self.page_buffer[NAND_DEVICEINFO_BBT_MAGIC.len()..];
            let full = ((u64::from(upto) + 1) / 8).min(bitmap.len() as u64) as usize;
            bitmap[..full].fill(0xff);
            let remainder = (u64::from(upto) + 1) % 8;
            if full < bitmap.len() && remainder != 0 {
                bitmap[full] = ((1u16 << remainder) - 1) as u8;
            }
        }
        for block in &blocks {
            let byte_idx = NAND_DEVICEINFO_BBT_MAGIC.len() + (*block as usize / 8);
            if let Some(byte) = self.page_buffer.get_mut(byte_idx) {
                *byte |= 1 << (*block & 7);
            }
        }
        tracing::debug!(
            bank,
            page,
            blocks = ?blocks,
            "nand synthesized sparse DeviceInfo BBT"
        );
    }

    fn rewrite_kernel_pmbr_as_fdisk(&mut self, bank: i64, page: u32) {
        let policy = self
            .policy
            .clone()
            .unwrap_or_else(NandPolicy::from_environment);
        if !policy.rewrite_pmbr {
            return;
        }
        if !self.kernel_started {
            return;
        }
        if self.page_buffer.len() < 512 || self.page_buffer[510..512] != [0x55, 0xaa] {
            return;
        }

        let mut used = 0;
        let mut pmbr_index = None;
        for index in 0..4 {
            let offset = 446 + index * 16;
            let systid = self.page_buffer[offset + 4];
            let numsect = u32::from_le_bytes(
                self.page_buffer[offset + 12..offset + 16]
                    .try_into()
                    .unwrap(),
            );
            if systid != 0 && numsect != 0 {
                used += 1;
                if systid == 0xee {
                    pmbr_index = Some(index);
                }
            }
        }

        let Some(index) = pmbr_index else {
            return;
        };
        if used != 1 {
            return;
        }

        let offset = 446 + index * 16;
        let mut relsect = u32::from_le_bytes(
            self.page_buffer[offset + 8..offset + 12]
                .try_into()
                .unwrap(),
        );
        let mut numsect = u32::from_le_bytes(
            self.page_buffer[offset + 12..offset + 16]
                .try_into()
                .unwrap(),
        );
        if let Some(value) = policy.fdisk_relsect {
            relsect = value;
            self.page_buffer[offset + 8..offset + 12].copy_from_slice(&relsect.to_le_bytes());
        }
        if let Some(value) = policy.fdisk_numsect {
            numsect = value;
            self.page_buffer[offset + 12..offset + 16].copy_from_slice(&numsect.to_le_bytes());
        }
        self.page_buffer[offset + 4] = 0xaf;
        tracing::debug!(
            bank,
            page,
            relsect,
            numsect,
            "nand rewrote sparse PMBR as FDisk Apple_HFS"
        );
    }

    pub fn set_kernel_started(&mut self, enabled: bool) {
        self.kernel_started = enabled;
    }

    pub fn buffered_page_prefix(&self, len: usize) -> &[u8] {
        &self.page_buffer[..len.min(self.page_buffer.len())]
    }

    pub fn sparse_vfl_context_blocks(&mut self, bank: i64) -> Vec<u32> {
        let Ok(bank_idx) = usize::try_from(bank) else {
            return Vec::new();
        };
        if bank_idx >= self.sparse_vfl_context_blocks.len() {
            return Vec::new();
        }
        if let Some(blocks) = &self.sparse_vfl_context_blocks[bank_idx] {
            return blocks.clone();
        }

        let blocks = self.backing.vfl_blocks(bank_idx as u32);
        self.sparse_vfl_context_blocks[bank_idx] = Some(blocks.clone());
        blocks
    }

    fn page_word(&self, idx: usize) -> u32 {
        let o = idx * 4;
        if o + 4 <= self.page_buffer.len() {
            u32::from_le_bytes(self.page_buffer[o..o + 4].try_into().unwrap())
        } else {
            0
        }
    }

    fn spare_word(&self, idx: usize) -> u32 {
        let o = idx * 4;
        if o + 4 <= self.spare_buffer.len() {
            u32::from_le_bytes(self.spare_buffer[o..o + 4].try_into().unwrap())
        } else {
            0
        }
    }

    fn write_page_word(&mut self, val: u32) {
        if !self.is_writing {
            return;
        }
        if self.fmdnum == 0 {
            self.is_writing = false;
            return;
        }

        let offset = NAND_BYTES_PER_PAGE.saturating_sub(self.fmdnum as usize);
        if offset + 4 <= self.page_buffer.len() {
            self.page_buffer[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
        }
        self.fmdnum = self.fmdnum.saturating_sub(4);
        if self.fmdnum == 0 {
            self.is_writing = false;
        }
    }

    pub fn read(&mut self, offset: u32) -> u32 {
        match offset {
            0x0 => self.fmctrl0,
            0x80 => {
                // FMFIFO: drains the buffered page word-by-word.
                if self.cmd == NAND_CMD_ID {
                    return NAND_CHIP_ID;
                }
                if self.cmd == NAND_CMD_READSTATUS {
                    return 1 << 6;
                }
                let read_val;
                if self.reading_multiple_pages {
                    if self.fmdnum % 0x800 == 0 {
                        self.cur_bank_reading = self.cur_bank_reading.saturating_add(1);
                        let idx = self.cur_bank_reading.max(0) as usize;
                        let bank = *self.banks_to_read.get(idx).unwrap_or(&0);
                        self.set_bank(bank);
                    }
                    let mut page_offset = self.fmdnum % 0x800;
                    if page_offset == 0 {
                        page_offset = 0x800;
                    }
                    let idx = self.cur_bank_reading.max(0) as usize;
                    let page = *self.pages_to_read.get(idx).unwrap_or(&0);
                    self.set_buffered_page(page);
                    read_val = self.page_word((NAND_BYTES_PER_PAGE - page_offset as usize) / 4);
                } else {
                    let page = (self.fmaddr1 << 16) | (self.fmaddr0 >> 16);
                    self.set_buffered_page(page);
                    let length = if self.reading_spare {
                        NAND_BYTES_PER_SPARE
                    } else {
                        NAND_BYTES_PER_PAGE
                    };
                    let index = length
                        .checked_sub(self.fmdnum as usize)
                        .and_then(|remaining| remaining.checked_sub(1))
                        .map(|offset| offset / 4);
                    read_val = match (self.reading_spare, index) {
                        (true, Some(index)) => self.spare_word(index),
                        (false, Some(index)) => self.page_word(index),
                        (_, None) => 0,
                    };
                }
                self.fmdnum = self.fmdnum.wrapping_sub(4);
                read_val
            }
            // FMCSTAT: everything ready, all eight banks present.
            0x48 => {
                (1 << 1)
                    | (1 << 2)
                    | (1 << 3)
                    | (1 << 4)
                    | (1 << 5)
                    | (1 << 6)
                    | (1 << 7)
                    | (1 << 8)
                    | (1 << 9)
                    | (1 << 10)
                    | (1 << 11)
                    | (1 << 12)
            }
            0x100 => self.rsctrl,
            _ => 0,
        }
    }

    pub fn begin_page_write(&mut self, bank: u32, page: u32) {
        self.reading_multiple_pages = false;
        self.set_bank(bank);
        self.set_buffered_page(page);
        self.fmdnum = NAND_BYTES_PER_PAGE as u32;
        self.is_writing = true;
    }

    pub fn write(&mut self, offset: u32, val: u32) {
        match offset {
            0x0 => self.fmctrl0 = val,
            0x4 => self.fmctrl1 = val,
            0x8 => self.cmd = val,
            0xC => self.fmaddr0 = val,
            0x10 => self.fmaddr1 = val,
            0x2C => self.fmanum = val,
            0x30 => {
                self.reading_spare = val == NAND_BYTES_PER_SPARE as u32 - 1;
                self.fmdnum = val;
            }
            0x80 => self.write_page_word(val),
            0x100 => self.rsctrl = val,
            _ => {}
        }
    }
}
