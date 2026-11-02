//! Versioned, path-free NAND component image. Full S5L CPU/UART/RAM publication
//! is owned by the machine producer; this codec constructs a detached controller.
use super::backing::BackingImage;
use super::{
    NAND_BYTES_PER_PAGE, NAND_BYTES_PER_SPARE, NAND_NUM_BANKS, NAND_PAGES_PER_BLOCK, NandBacking,
    NandPolicy, S5lNand,
};
use crate::error::{Error, Result};
use std::collections::BTreeMap;
use std::sync::Arc;

const TAG: &[u8; 8] = b"RAXNND01";
const MAX_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const DMA_ROWS: usize = 512;
const MAX_BLOCKS: u32 = u32::MAX / NAND_PAGES_PER_BLOCK + 1;

fn invalid(message: impl std::fmt::Display) -> Error {
    Error::Emulator(format!("S5L NAND checkpoint: {message}"))
}

struct Writer {
    bytes: Vec<u8>,
    limit: usize,
}
impl Writer {
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        let end = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .filter(|&n| n <= self.limit)
            .ok_or_else(|| invalid("byte budget exceeded"))?;
        self.bytes.try_reserve(bytes.len()).map_err(invalid)?;
        self.bytes.extend_from_slice(bytes);
        debug_assert_eq!(self.bytes.len(), end);
        Ok(())
    }
    fn boolean(&mut self, value: bool) -> Result<()> {
        self.put(&[u8::from(value)])
    }
    fn word(&mut self, value: u32) -> Result<()> {
        self.put(&value.to_le_bytes())
    }
    fn optional(&mut self, value: Option<u32>) -> Result<()> {
        self.boolean(value.is_some())?;
        if let Some(value) = value {
            self.word(value)?;
        }
        Ok(())
    }
    fn blocks(&mut self, values: &[u32]) -> Result<()> {
        validate_blocks(values)?;
        self.word(u32::try_from(values.len()).map_err(invalid)?)?;
        for &value in values {
            self.word(value)?;
        }
        Ok(())
    }
}

struct Reader<'a> {
    remaining: &'a [u8],
}
impl<'a> Reader<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8]> {
        let (bytes, rest) = self
            .remaining
            .split_at_checked(size)
            .ok_or_else(|| invalid("truncated image"))?;
        self.remaining = rest;
        Ok(bytes)
    }
    fn word(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(invalid)?,
        ))
    }
    fn wide(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(invalid)?,
        ))
    }
    fn signed(&mut self) -> Result<i64> {
        Ok(i64::from_le_bytes(
            self.take(8)?.try_into().map_err(invalid)?,
        ))
    }
    fn boolean(&mut self) -> Result<bool> {
        match self.take(1)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(invalid("invalid boolean")),
        }
    }
    fn optional(&mut self) -> Result<Option<u32>> {
        if self.boolean()? {
            Ok(Some(self.word()?))
        } else {
            Ok(None)
        }
    }
    fn bytes(&mut self, size: usize) -> Result<Vec<u8>> {
        let input = self.take(size)?;
        let mut output = Vec::new();
        output.try_reserve_exact(size).map_err(invalid)?;
        output.extend_from_slice(input);
        Ok(output)
    }
    fn words(&mut self, size: usize) -> Result<Vec<u32>> {
        let size_bytes = size
            .checked_mul(4)
            .ok_or_else(|| invalid("size overflow"))?;
        // Admit the complete encoded payload before reserving any collection.
        let input = self.take(size_bytes)?;
        let mut output = Vec::new();
        output.try_reserve_exact(size).map_err(invalid)?;
        for word in input.chunks_exact(4) {
            output.push(u32::from_le_bytes(word.try_into().map_err(invalid)?));
        }
        Ok(output)
    }
    fn blocks(&mut self) -> Result<Vec<u32>> {
        let count = self.word()?;
        if count > MAX_BLOCKS {
            return Err(invalid("block count exceeds geometry"));
        }
        let values = self.words(count as usize)?;
        validate_blocks(&values)?;
        Ok(values)
    }
}

fn validate_blocks(values: &[u32]) -> Result<()> {
    if values.len() as u64 > u64::from(MAX_BLOCKS)
        || values.iter().any(|&value| value >= MAX_BLOCKS)
        || values.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(invalid(
            "block index is out of range, duplicated or unordered",
        ));
    }
    Ok(())
}

impl S5lNand {
    /// Captures every represented controller field, pending transfer, cached page,
    /// media transformation option, unread page and VFL-discovery observation.
    /// `limit` includes the entire component image; the bundle owner must also
    /// enforce its aggregate RAM/media budget. No live controller state changes.
    fn controller_writer(&self, limit: usize) -> Result<Writer> {
        if limit as u64 > MAX_BYTES {
            return Err(invalid("limit exceeds bundle budget"));
        }
        let Self {
            backing: _,
            policy,
            fmctrl0,
            fmctrl1,
            fmaddr0,
            fmaddr1,
            fmanum,
            fmdnum,
            rsctrl,
            cmd,
            reading_spare,
            page_buffer,
            spare_buffer,
            buffered_bank,
            buffered_page,
            is_writing,
            reading_multiple_pages,
            cur_bank_reading,
            banks_to_read,
            pages_to_read,
            sparse_vfl_context_blocks,
            kernel_started,
        } = self;
        self.validate_checkpoint_shape()?;
        let policy = policy.clone().unwrap_or_else(NandPolicy::from_environment);
        let mut writer = Writer {
            bytes: Vec::new(),
            limit,
        };
        writer.put(TAG)?;
        for &value in [
            fmctrl0, fmctrl1, fmaddr0, fmaddr1, fmanum, fmdnum, rsctrl, cmd,
        ] {
            writer.word(value)?;
        }
        for &flag in [
            reading_spare,
            is_writing,
            reading_multiple_pages,
            kernel_started,
        ] {
            writer.boolean(flag)?;
        }
        for &value in [buffered_bank, buffered_page, cur_bank_reading] {
            writer.put(&value.to_le_bytes())?;
        }
        writer.put(page_buffer)?;
        writer.put(spare_buffer)?;
        for &value in banks_to_read.iter().chain(pages_to_read) {
            writer.word(value)?;
        }
        for cached in sparse_vfl_context_blocks {
            writer.boolean(cached.is_some())?;
            if let Some(values) = cached {
                writer.blocks(values)?;
            }
        }
        writer.boolean(policy.bbt_all_good)?;
        writer.optional(policy.bbt_good_upto)?;
        writer.boolean(policy.rewrite_pmbr)?;
        writer.optional(policy.fdisk_relsect)?;
        writer.optional(policy.fdisk_numsect)?;
        Ok(writer)
    }

    /// Source-only controller/profile witness; does not read host media.
    pub(crate) fn checkpoint_controller_state(&self) -> Result<Vec<u8>> {
        Ok(self
            .controller_writer(MAX_BYTES.min(usize::MAX as u64) as usize)?
            .bytes)
    }

    pub(crate) fn capture_checkpoint(&self, limit: usize) -> Result<Vec<u8>> {
        let mut writer = self.controller_writer(limit)?;
        let media = self
            .backing
            .capture(limit.saturating_sub(writer.bytes.len()))?;
        writer.put(&(media.pages.len() as u64).to_le_bytes())?;
        for (&(bank, page), data) in &media.pages {
            writer.word(bank)?;
            writer.word(page)?;
            writer.word(u32::try_from(data.len()).map_err(invalid)?)?;
            writer.put(data)?;
        }
        for blocks in &media.vfl_blocks {
            writer.blocks(blocks)?;
        }
        Ok(writer.bytes)
    }

    /// Strict admission into a detached owner. Never consults a host path or
    /// environment; malformed input cannot partially mutate a live controller.
    pub(crate) fn from_checkpoint(raw: &[u8], limit: usize) -> Result<Self> {
        if raw.len() > limit || raw.len() as u64 > MAX_BYTES {
            return Err(invalid("image exceeds byte budget"));
        }
        let mut reader = Reader { remaining: raw };
        if reader.take(TAG.len())? != TAG {
            return Err(invalid("invalid version tag"));
        }
        let fmctrl0 = reader.word()?;
        let fmctrl1 = reader.word()?;
        let fmaddr0 = reader.word()?;
        let fmaddr1 = reader.word()?;
        let fmanum = reader.word()?;
        let fmdnum = reader.word()?;
        let rsctrl = reader.word()?;
        let cmd = reader.word()?;
        let reading_spare = reader.boolean()?;
        let is_writing = reader.boolean()?;
        let reading_multiple_pages = reader.boolean()?;
        let kernel_started = reader.boolean()?;
        let buffered_bank = reader.signed()?;
        let buffered_page = reader.signed()?;
        let cur_bank_reading = reader.signed()?;
        let page_buffer = reader.bytes(NAND_BYTES_PER_PAGE)?;
        let spare_buffer = reader.bytes(NAND_BYTES_PER_SPARE)?;
        let banks_to_read = reader.words(DMA_ROWS)?;
        let pages_to_read = reader.words(DMA_ROWS)?;
        let mut sparse_vfl_context_blocks = Vec::new();
        for _ in 0..NAND_NUM_BANKS {
            sparse_vfl_context_blocks.push(if reader.boolean()? {
                Some(reader.blocks()?)
            } else {
                None
            });
        }
        let policy = NandPolicy {
            bbt_all_good: reader.boolean()?,
            bbt_good_upto: reader.optional()?,
            rewrite_pmbr: reader.boolean()?,
            fdisk_relsect: reader.optional()?,
            fdisk_numsect: reader.optional()?,
        };
        let count = reader.wide()?;
        if count > (reader.remaining.len() / 12) as u64 {
            return Err(invalid("page count exceeds remaining bytes"));
        }
        let mut pages = BTreeMap::new();
        let mut previous = None;
        for _ in 0..count {
            let key = (reader.word()?, reader.word()?);
            let length = reader.word()? as usize;
            if key.0 >= NAND_NUM_BANKS
                || previous.is_some_and(|p| p >= key)
                || length > super::backing::PAGE_BYTES
            {
                return Err(invalid("page geometry, order or size differs"));
            }
            pages.insert(key, reader.bytes(length)?);
            previous = Some(key);
        }
        let mut vfl_blocks: [Vec<u32>; NAND_NUM_BANKS as usize] =
            std::array::from_fn(|_| Vec::new());
        for blocks in &mut vfl_blocks {
            *blocks = reader.blocks()?;
        }
        if !reader.remaining.is_empty() {
            return Err(invalid("trailing bytes"));
        }
        let controller = Self {
            backing: NandBacking::Frozen(Arc::new(BackingImage { pages, vfl_blocks })),
            policy: Some(policy),
            fmctrl0,
            fmctrl1,
            fmaddr0,
            fmaddr1,
            fmanum,
            fmdnum,
            rsctrl,
            cmd,
            reading_spare,
            page_buffer,
            spare_buffer,
            buffered_bank,
            buffered_page,
            is_writing,
            reading_multiple_pages,
            cur_bank_reading,
            banks_to_read,
            pages_to_read,
            sparse_vfl_context_blocks,
            kernel_started,
        };
        controller.validate_checkpoint_shape()?;
        Ok(controller)
    }

    fn validate_checkpoint_shape(&self) -> Result<()> {
        let valid_buffer = (self.buffered_bank == -1 && self.buffered_page == -1)
            || ((0..i64::from(NAND_NUM_BANKS)).contains(&self.buffered_bank)
                && (0..=i64::from(u32::MAX)).contains(&self.buffered_page));
        if !valid_buffer
            || self.cur_bank_reading < -1
            || self.page_buffer.len() != NAND_BYTES_PER_PAGE
            || self.spare_buffer.len() != NAND_BYTES_PER_SPARE
            || self.banks_to_read.len() != DMA_ROWS
            || self.pages_to_read.len() != DMA_ROWS
            || self.sparse_vfl_context_blocks.len() != NAND_NUM_BANKS as usize
        {
            return Err(invalid("controller buffer or cursor shape differs"));
        }
        for blocks in self.sparse_vfl_context_blocks.iter().flatten() {
            validate_blocks(blocks)?;
        }
        Ok(())
    }
}
