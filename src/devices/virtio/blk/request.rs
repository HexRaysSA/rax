//! Parse the logical request stream independently of descriptor boundaries.
use super::super::{QueueError, VRING_DESC_F_INDIRECT};
use super::{
    BlkReqHeader, DescriptorChain, Mem, REQ_HEADER_LEN, SECTOR_SIZE, VIRTIO_BLK_S_IOERR,
    VIRTIO_BLK_S_OK, VIRTIO_BLK_S_UNSUPP, VIRTIO_BLK_T_FLUSH, VIRTIO_BLK_T_GET_ID, VIRTIO_BLK_T_IN,
    VIRTIO_BLK_T_OUT, VirtioBlk,
};

#[derive(Clone, Copy)]
struct Buffer {
    address: u64,
    length: usize,
}
struct RequestBuffers {
    readable: Vec<Buffer>,
    writable: Vec<Buffer>,
    read_length: usize,
    write_length: usize,
}
fn invalid(field: &'static str, value: u64) -> QueueError {
    QueueError::Invalid { field, value }
}
impl RequestBuffers {
    fn new(chain: &DescriptorChain) -> Result<Self, QueueError> {
        let mut result = Self {
            readable: vec![],
            writable: vec![],
            read_length: 0,
            write_length: 0,
        };
        let mut seen_write = false;
        let mut total = 0u64;
        for descriptor in &chain.descriptors {
            if descriptor.flags & VRING_DESC_F_INDIRECT != 0 {
                return Err(invalid("unresolved indirect buffer", descriptor.addr));
            }
            if u128::from(descriptor.addr) + u128::from(descriptor.len) > 1u128 << 64 {
                return Err(invalid("block buffer extent", descriptor.addr));
            }
            total = total
                .checked_add(u64::from(descriptor.len))
                .ok_or_else(|| invalid("block chain byte length", u64::MAX))?;
            if total > 1u64 << 32 {
                return Err(invalid("block chain byte length", total));
            }
            let writable = descriptor.is_write_only();
            if seen_write && !writable {
                return Err(invalid(
                    "block readable buffer after writable buffer",
                    descriptor.addr,
                ));
            }
            seen_write |= writable;
            let length = descriptor.len as usize;
            let buffer = Buffer {
                address: descriptor.addr,
                length,
            };
            if writable {
                result.write_length += length;
                if length != 0 {
                    result.writable.push(buffer);
                }
            } else {
                result.read_length += length;
                if length != 0 {
                    result.readable.push(buffer);
                }
            }
        }
        if result.write_length == 0 {
            return Err(invalid("missing block status byte", 0));
        }
        Ok(result)
    }
    fn status(&self) -> u64 {
        let last = self.writable.last().unwrap();
        last.address + (last.length - 1) as u64
    }
    fn slices(buffers: &[Buffer], start: usize, length: usize) -> Vec<Buffer> {
        let mut result = vec![];
        let mut skip = start;
        let mut remaining = length;
        for buffer in buffers {
            if skip >= buffer.length {
                skip -= buffer.length;
                continue;
            }
            let take = (buffer.length - skip).min(remaining);
            if take != 0 {
                result.push(Buffer {
                    address: buffer.address + skip as u64,
                    length: take,
                });
                remaining -= take;
            }
            skip = 0;
            if remaining == 0 {
                break;
            }
        }
        debug_assert_eq!(remaining, 0);
        result
    }
    fn read_into<M: Mem>(memory: &M, buffers: &[Buffer], bytes: &mut [u8]) -> bool {
        let mut offset = 0;
        for buffer in buffers {
            let end = offset + buffer.length;
            if !memory.read(buffer.address, &mut bytes[offset..end]) {
                return false;
            }
            offset = end;
        }
        offset == bytes.len()
    }
    fn write_from<M: Mem>(
        memory: &mut M,
        buffers: &[Buffer],
        bytes: &[u8],
    ) -> Result<(), QueueError> {
        let mut offset = 0;
        for buffer in buffers {
            let end = offset + buffer.length;
            if !memory.write(buffer.address, &bytes[offset..end]) {
                return Err(QueueError::Dma {
                    address: buffer.address,
                    length: buffer.length,
                    write: true,
                });
            }
            offset = end;
        }
        Ok(())
    }
    fn finish<M: Mem>(
        &self,
        memory: &mut M,
        status: u8,
        data_written: usize,
    ) -> Result<u32, QueueError> {
        let address = self.status();
        if !memory.write(address, &[status]) {
            return Err(QueueError::Dma {
                address,
                length: 1,
                write: true,
            });
        }
        u32::try_from(data_written + 1)
            .map_err(|_| invalid("block completion byte length", data_written as u64 + 1))
    }
}

impl VirtioBlk {
    /// Compatibility direct-call API. The checked transport path propagates
    /// failures and enters DEVICE_NEEDS_RESET rather than publishing false use.
    pub fn handle_chain<M: Mem>(&mut self, chain: &DescriptorChain, memory: &mut M) -> u32 {
        self.handle_chain_checked(chain, memory).unwrap_or(0)
    }
    pub(super) fn handle_chain_checked<M: Mem>(
        &mut self,
        chain: &DescriptorChain,
        memory: &mut M,
    ) -> Result<u32, QueueError> {
        let buffers = RequestBuffers::new(chain)?;
        if buffers.read_length < REQ_HEADER_LEN {
            return buffers.finish(memory, VIRTIO_BLK_S_IOERR, 0);
        }
        let header_view = RequestBuffers::slices(&buffers.readable, 0, REQ_HEADER_LEN);
        let mut header = [0; REQ_HEADER_LEN];
        if !RequestBuffers::read_into(memory, &header_view, &mut header) {
            return buffers.finish(memory, VIRTIO_BLK_S_IOERR, 0);
        }
        let header = BlkReqHeader::parse(&header).unwrap();
        let (status, written) = match header.req_type {
            VIRTIO_BLK_T_IN | VIRTIO_BLK_T_OUT => self.transfer_checked(
                memory,
                &buffers,
                header.sector,
                header.req_type == VIRTIO_BLK_T_IN,
            )?,
            VIRTIO_BLK_T_FLUSH => (VIRTIO_BLK_S_OK, 0),
            VIRTIO_BLK_T_GET_ID => {
                let length = buffers.write_length - 1;
                if buffers.read_length != REQ_HEADER_LEN || length != self.id.len() {
                    (VIRTIO_BLK_S_IOERR, 0)
                } else {
                    let view = RequestBuffers::slices(&buffers.writable, 0, length);
                    RequestBuffers::write_from(memory, &view, &self.id)?;
                    (VIRTIO_BLK_S_OK, length)
                }
            }
            _ => (VIRTIO_BLK_S_UNSUPP, 0),
        };
        buffers.finish(memory, status, written)
    }
    fn transfer_checked<M: Mem>(
        &mut self,
        memory: &mut M,
        buffers: &RequestBuffers,
        sector: u64,
        to_guest: bool,
    ) -> Result<(u8, usize), QueueError> {
        let length = if to_guest {
            if buffers.read_length != REQ_HEADER_LEN {
                return Ok((VIRTIO_BLK_S_IOERR, 0));
            }
            buffers.write_length - 1
        } else {
            if buffers.write_length != 1 || self.read_only {
                return Ok((VIRTIO_BLK_S_IOERR, 0));
            }
            buffers.read_length - REQ_HEADER_LEN
        };
        if length % SECTOR_SIZE as usize != 0 {
            return Ok((VIRTIO_BLK_S_IOERR, 0));
        }
        let Some(start) = sector.checked_mul(SECTOR_SIZE) else {
            return Ok((VIRTIO_BLK_S_IOERR, 0));
        };
        let Some(end) = start.checked_add(length as u64) else {
            return Ok((VIRTIO_BLK_S_IOERR, 0));
        };
        if end > self.disk.len() as u64 {
            return Ok((VIRTIO_BLK_S_IOERR, 0));
        }
        if to_guest {
            let view = RequestBuffers::slices(&buffers.writable, 0, length);
            // Failed writes can leave a partial destination. No status/used
            // entry is falsely published; the checked transport requires reset.
            RequestBuffers::write_from(memory, &view, &self.disk[start as usize..end as usize])?;
            Ok((VIRTIO_BLK_S_OK, length))
        } else {
            let view = RequestBuffers::slices(&buffers.readable, REQ_HEADER_LEN, length);
            let mut data = vec![0; length];
            if !RequestBuffers::read_into(memory, &view, &mut data) {
                return Ok((VIRTIO_BLK_S_IOERR, 0));
            }
            self.disk[start as usize..end as usize].copy_from_slice(&data);
            Ok((VIRTIO_BLK_S_OK, 0))
        }
    }
}
