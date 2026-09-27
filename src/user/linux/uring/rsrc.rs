//! Registered files and buffers (`io_uring/rsrc.c`, `io_uring/filetable.c`,
//! Linux 6.19): the tables an instance keeps and the nodes their slots
//! hold.
//!
//! A slot holds a node (`struct io_rsrc_node`), which holds a file or a
//! buffer and the tag its release posts as a CQE. The table holds one
//! reference to a node and each request using it another, so a node a
//! table lets go of stays until the last request using it is freed. A
//! buffer (`struct io_mapped_ubuf`) is shared by the nodes of the rings it
//! was cloned to and unpins its memory as the last of them lets go. The
//! pages a buffer pins are charged to the address space (`pinned_vm`,
//! shown as `VmPin`) and, unless its creator could lock memory without
//! limit, to the user (`locked_vm`, capped by `RLIMIT_MEMLOCK`), which a
//! ring's own regions are charged to as well.
//!
//! Pinning is not modelled beyond its checks: a buffer names its guest
//! addresses, which requests read and write when they use it.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use super::super::abi::errno::Errno;
use super::super::abi::errno_table::*;
use super::super::fs::fd::OpenFile;

/// `IORING_MAX_FIXED_FILES`.
pub const MAX_FIXED_FILES: u32 = 1 << 20;
/// `IORING_MAX_REG_BUFFERS`.
pub const MAX_REG_BUFFERS: u32 = 1 << 14;
/// `IORING_REGISTER_FILES_SKIP`: an update leaves the slot as it is.
pub const FILES_SKIP: i32 = -2;
/// `IORING_FILE_INDEX_ALLOC`: the next free slot of the allocation range.
pub const FILE_INDEX_ALLOC: u32 = u32::MAX;

/// What an instance charges the memory it pins to: its creator's user
/// (`ctx->user`), unless the creator held `CAP_IPC_LOCK`, and address
/// space (`ctx->mm_account`). Both counts are in pages.
#[derive(Clone, Debug)]
pub struct Account {
    /// `user->locked_vm`.
    pub user: Option<Arc<AtomicU64>>,
    /// `mm->pinned_vm`.
    pub mm: Arc<AtomicU64>,
}

impl Account {
    /// `__io_account_mem`: `pages` more for the user, `ENOMEM` past
    /// `limit` pages (`RLIMIT_MEMLOCK`).
    pub fn charge_user(&self, pages: u64, limit: u64) -> Result<(), Errno> {
        let Some(user) = &self.user else {
            return Ok(());
        };
        if pages == 0 {
            return Ok(());
        }
        user.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
            cur.checked_add(pages).filter(|&n| n <= limit)
        })
        .map(|_| ())
        .map_err(|_| Errno(ENOMEM))
    }

    /// `__io_unaccount_mem`.
    pub fn uncharge_user(&self, pages: u64) {
        if let Some(user) = &self.user {
            user.fetch_sub(pages, Ordering::Relaxed);
        }
    }

    /// Whether two instances charge the same user and address space.
    pub fn same(&self, other: &Account) -> bool {
        let user = match (&self.user, &other.user) {
            (None, None) => true,
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            _ => false,
        };
        user && Arc::ptr_eq(&self.mm, &other.mm)
    }
}

/// A registered buffer (`struct io_mapped_ubuf`): its guest range and the
/// pages charged for it, uncharged as the last ring holding it lets go
/// (`io_buffer_unmap`).
#[derive(Debug)]
pub struct Imu {
    pub addr: u64,
    pub len: u32,
    /// `acct_pages`.
    pub acct_pages: u64,
    pub account: Account,
}

impl Drop for Imu {
    fn drop(&mut self) {
        // io_unaccount_mem.
        self.account.uncharge_user(self.acct_pages);
        self.account
            .mm
            .fetch_sub(self.acct_pages, Ordering::Relaxed);
    }
}

/// What a node holds.
#[derive(Clone, Debug)]
pub enum Rsrc {
    File(Arc<OpenFile>),
    Buf(Arc<Imu>),
}

/// A table slot's node (`struct io_rsrc_node`).
#[derive(Debug)]
pub struct Node {
    /// `refs`: the table's reference and the requests'.
    refs: u32,
    /// The `user_data` of the CQE its release posts, if not 0.
    pub tag: u64,
    pub rsrc: Rsrc,
}

/// A node's identifier in its instance.
pub type NodeId = u64;

/// The registered files and buffers (`file_table`, `buf_table`), and the
/// file table's allocation range and hint (`file_alloc_start`,
/// `file_alloc_end`, `alloc_hint`). An empty table is none registered.
#[derive(Debug, Default)]
pub struct Tables {
    nodes: HashMap<NodeId, Node>,
    next: NodeId,
    pub files: Vec<Option<NodeId>>,
    pub bufs: Vec<Option<NodeId>>,
    pub alloc_start: u32,
    pub alloc_end: u32,
    pub alloc_hint: u32,
    /// What released nodes and freed requests held: dropped once the
    /// instance's lock is let go, as dropping a file can wake others.
    pub dead: Vec<Rsrc>,
}

impl Tables {
    /// `io_rsrc_node_alloc`: a node with the table's reference.
    pub fn alloc(&mut self, tag: u64, rsrc: Rsrc) -> NodeId {
        let id = self.next;
        self.next += 1;
        self.nodes.insert(id, Node { refs: 1, tag, rsrc });
        id
    }

    /// A live node.
    pub fn node(&self, id: NodeId) -> &Node {
        &self.nodes[&id]
    }

    /// Clears a live node's tag (`io_clear_table_tags`).
    pub fn clear_tag(&mut self, id: NodeId) {
        if let Some(n) = self.nodes.get_mut(&id) {
            n.tag = 0;
        }
    }

    /// Takes another reference to a node.
    pub fn get(&mut self, id: NodeId) {
        if let Some(n) = self.nodes.get_mut(&id) {
            n.refs += 1;
        }
    }

    /// `io_put_rsrc_node`: drops a reference; the last one frees the node,
    /// whose tag is returned (`io_free_rsrc_node` posts it).
    pub fn put(&mut self, id: NodeId) -> Option<u64> {
        let n = self.nodes.get_mut(&id)?;
        n.refs -= 1;
        if n.refs != 0 {
            return None;
        }
        let n = self.nodes.remove(&id).expect("live");
        self.dead.push(n.rsrc);
        Some(n.tag)
    }

    /// `io_rsrc_node_lookup` in the file table.
    pub fn file(&self, index: u32) -> Option<NodeId> {
        self.files.get(index as usize).copied().flatten()
    }

    /// `io_rsrc_node_lookup` in the buffer table.
    pub fn buf(&self, index: u32) -> Option<NodeId> {
        self.bufs.get(index as usize).copied().flatten()
    }

    /// The file a node holds.
    pub fn node_file(&self, id: NodeId) -> Option<&Arc<OpenFile>> {
        match &self.node(id).rsrc {
            Rsrc::File(f) => Some(f),
            Rsrc::Buf(_) => None,
        }
    }

    /// The buffer a node holds.
    pub fn node_buf(&self, id: NodeId) -> Option<&Arc<Imu>> {
        match &self.node(id).rsrc {
            Rsrc::Buf(b) => Some(b),
            Rsrc::File(_) => None,
        }
    }

    /// `io_file_bitmap_set`: the slot is taken; allocation looks after it.
    pub fn bitmap_set(&mut self, index: u32) {
        self.alloc_hint = index + 1;
    }

    /// `io_file_bitmap_clear`: the slot is free; allocation looks there.
    pub fn bitmap_clear(&mut self, index: u32) {
        self.alloc_hint = index;
    }

    /// `io_file_table_set_alloc_range`.
    pub fn set_alloc_range(&mut self, off: u32, len: u32) {
        self.alloc_start = off;
        self.alloc_end = off.wrapping_add(len);
        self.alloc_hint = off;
    }

    /// `io_file_bitmap_get`: the first free slot from the hint to the end
    /// of the allocation range, then from its start to the hint (which may
    /// lie past the range: that search can find a slot there); `ENFILE`
    /// if none or no table.
    pub fn bitmap_get(&mut self) -> Result<u32, Errno> {
        if self.files.is_empty() {
            return Err(Errno(ENFILE));
        }
        let mut nr = self.alloc_end;
        loop {
            // find_next_zero_bit over the table's bitmap.
            let size = nr.min(self.files.len() as u32);
            if let Some(i) = (self.alloc_hint..size).find(|&i| self.files[i as usize].is_none()) {
                return Ok(i);
            }
            if self.alloc_hint == self.alloc_start {
                return Err(Errno(ENFILE));
            }
            nr = self.alloc_hint;
            self.alloc_hint = self.alloc_start;
        }
    }
}
