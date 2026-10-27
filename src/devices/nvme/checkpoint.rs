//! Complete controller-private state plus detached logical media.
use super::super::virtio::block_image::ImageCheckpoint;
use super::*;
use std::io;
#[path = "../checkpoint_wire.rs"]
mod wire;
use wire::{Reader, Writer, invalid};
const TAG: &[u8; 8] = b"RAXNVM01";
/// Versioned controller bytes and all logical media. Guest RAM is external and
/// must be captured/restored at the same quiescent boundary by the VM owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NvmeCheckpoint {
    pub state: Vec<u8>,
    pub media: ImageCheckpoint,
}
fn save_queue(w: &mut Writer, q: &Queue) {
    w.long(q.base);
    w.word(q.size);
    w.word(q.tail);
    w.word(q.head);
    w.boolean(q.phase);
    w.short(q.cqid);
    w.boolean(q.active);
}
fn load_queue(r: &mut Reader<'_>) -> io::Result<Queue> {
    Ok(Queue {
        base: r.long()?,
        size: r.word()?,
        tail: r.word()?,
        head: r.word()?,
        phase: r.boolean()?,
        cqid: r.short()?,
        active: r.boolean()?,
    })
}
fn validate(q: &Queue, maximum: u32) -> io::Result<()> {
    if q.active
        && (!(2..=maximum).contains(&q.size)
            || q.head >= q.size
            || q.tail >= q.size
            || q.base & 0xfff != 0)
    {
        return Err(invalid("invalid active NVMe checkpoint queue"));
    }
    if !q.active && (q.size != 0 || q.head != 0 || q.tail != 0) {
        return Err(invalid("invalid inactive NVMe checkpoint queue"));
    }
    Ok(())
}
impl<M: Mem> NvmeController<M> {
    /// Capture every register, queue, phase, IEN and feature-lock field.
    pub fn checkpoint(&self) -> io::Result<NvmeCheckpoint> {
        if self.io_sqs.len() != 5 || self.io_cqs.len() != 5 || self.io_cq_interrupts.len() != 5 {
            return Err(invalid("unsupported NVMe checkpoint queue profile"));
        }
        let media = self.disk.checkpoint()?;
        let mut w = Writer::new(TAG);
        w.long(self.base);
        w.long(media.bytes.len() as u64);
        w.boolean(media.read_only);
        for v in [self.cc, self.csts, self.intms, self.aqa] {
            w.word(v);
        }
        w.long(self.asq);
        w.long(self.acq);
        w.short(self.max_io_queues);
        w.boolean(self.io_queues_created);
        for q in [&self.admin_sq, &self.admin_cq] {
            validate(q, 4096)?;
            save_queue(&mut w, q);
        }
        for q in self.io_sqs.iter().chain(self.io_cqs.iter()) {
            validate(q, 256)?;
            save_queue(&mut w, q);
        }
        for flag in &self.io_cq_interrupts {
            w.boolean(*flag);
        }
        Ok(NvmeCheckpoint { state: w.0, media })
    }
    /// Restore atomically without DMA, command execution or host-file effects.
    /// The restored media is detached; persistent rebinding belongs to the VM.
    pub fn restore_checkpoint(&mut self, checkpoint: NvmeCheckpoint) -> io::Result<()> {
        let mut r = Reader::new(&checkpoint.state, TAG)?;
        let base = r.long()?;
        let length = r.long()?;
        let readonly = r.boolean()?;
        if length != checkpoint.media.bytes.len() as u64 || readonly != checkpoint.media.read_only {
            return Err(invalid("NVMe checkpoint media metadata mismatch"));
        }
        let cc = r.word()?;
        let csts = r.word()?;
        let intms = r.word()?;
        let aqa = r.word()?;
        let asq = r.long()?;
        let acq = r.long()?;
        let maximum = r.short()?;
        let locked = r.boolean()?;
        if maximum != 4 {
            return Err(invalid("invalid NVMe checkpoint queue allocation"));
        }
        let admin_sq = load_queue(&mut r)?;
        let admin_cq = load_queue(&mut r)?;
        let mut sqs = Vec::with_capacity(5);
        let mut cqs = Vec::with_capacity(5);
        for _ in 0..5 {
            sqs.push(load_queue(&mut r)?);
        }
        for _ in 0..5 {
            cqs.push(load_queue(&mut r)?);
        }
        let mut ien = Vec::with_capacity(5);
        for _ in 0..5 {
            ien.push(r.boolean()?);
        }
        r.end()?;
        for q in [&admin_sq, &admin_cq] {
            validate(q, 4096)?;
        }
        for q in sqs.iter().chain(cqs.iter()) {
            validate(q, 256)?;
        }
        if admin_sq.cqid != 0 || admin_cq.cqid != 0 {
            return Err(invalid("invalid NVMe checkpoint admin queue association"));
        }
        for (index, q) in cqs.iter().enumerate().skip(1) {
            if q.active && q.cqid as usize != index {
                return Err(invalid("invalid NVMe checkpoint completion queue identity"));
            }
        }
        if sqs[0].active || cqs[0].active || ien[0] {
            return Err(invalid("reserved NVMe checkpoint queue zero is active"));
        }
        for q in sqs.iter().filter(|q| q.active) {
            if q.cqid == 0 || q.cqid as usize >= cqs.len() || !cqs[q.cqid as usize].active {
                return Err(invalid("NVMe checkpoint SQ has no active CQ"));
            }
        }
        let media = checkpoint.media.into_detached()?;
        self.base = base;
        self.cc = cc;
        self.csts = csts;
        self.intms = intms;
        self.aqa = aqa;
        self.asq = asq;
        self.acq = acq;
        self.max_io_queues = maximum;
        self.io_queues_created = locked;
        self.admin_sq = admin_sq;
        self.admin_cq = admin_cq;
        self.io_sqs = sqs;
        self.io_cqs = cqs;
        self.io_cq_interrupts = ien;
        self.disk = media;
        Ok(())
    }
}
