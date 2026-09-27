//! The io_uring user ABI (`include/uapi/linux/io_uring.h`, Linux 6.19) and
//! the kernel's flag sets over it (`io_uring/io_uring.h`).

/// `IORING_SETUP_*`.
pub mod setup {
    pub const IOPOLL: u32 = 1 << 0;
    pub const SQPOLL: u32 = 1 << 1;
    pub const SQ_AFF: u32 = 1 << 2;
    pub const CQSIZE: u32 = 1 << 3;
    pub const CLAMP: u32 = 1 << 4;
    pub const ATTACH_WQ: u32 = 1 << 5;
    pub const R_DISABLED: u32 = 1 << 6;
    pub const SUBMIT_ALL: u32 = 1 << 7;
    pub const COOP_TASKRUN: u32 = 1 << 8;
    pub const TASKRUN_FLAG: u32 = 1 << 9;
    pub const SQE128: u32 = 1 << 10;
    pub const CQE32: u32 = 1 << 11;
    pub const SINGLE_ISSUER: u32 = 1 << 12;
    pub const DEFER_TASKRUN: u32 = 1 << 13;
    pub const NO_MMAP: u32 = 1 << 14;
    pub const REGISTERED_FD_ONLY: u32 = 1 << 15;
    pub const NO_SQARRAY: u32 = 1 << 16;
    pub const HYBRID_IOPOLL: u32 = 1 << 17;
    pub const CQE_MIXED: u32 = 1 << 18;
    pub const SQE_MIXED: u32 = 1 << 19;
    /// `IORING_SETUP_FLAGS`: every flag the kernel knows.
    pub const ALL: u32 = (1 << 20) - 1;
}

/// `IORING_ENTER_*`.
pub mod enter {
    pub const GETEVENTS: u32 = 1 << 0;
    pub const SQ_WAKEUP: u32 = 1 << 1;
    pub const SQ_WAIT: u32 = 1 << 2;
    pub const EXT_ARG: u32 = 1 << 3;
    pub const REGISTERED_RING: u32 = 1 << 4;
    pub const ABS_TIMER: u32 = 1 << 5;
    pub const EXT_ARG_REG: u32 = 1 << 6;
    pub const NO_IOWAIT: u32 = 1 << 7;
    /// `IORING_ENTER_FLAGS`.
    pub const ALL: u32 = (1 << 8) - 1;
}

/// `IORING_FEAT_*`.
pub mod feat {
    pub const SINGLE_MMAP: u32 = 1 << 0;
    pub const NODROP: u32 = 1 << 1;
    pub const SUBMIT_STABLE: u32 = 1 << 2;
    pub const RW_CUR_POS: u32 = 1 << 3;
    pub const CUR_PERSONALITY: u32 = 1 << 4;
    pub const FAST_POLL: u32 = 1 << 5;
    pub const POLL_32BITS: u32 = 1 << 6;
    pub const SQPOLL_NONFIXED: u32 = 1 << 7;
    pub const EXT_ARG: u32 = 1 << 8;
    pub const NATIVE_WORKERS: u32 = 1 << 9;
    pub const RSRC_TAGS: u32 = 1 << 10;
    pub const CQE_SKIP: u32 = 1 << 11;
    pub const LINKED_FILE: u32 = 1 << 12;
    pub const REG_REG_RING: u32 = 1 << 13;
    pub const RECVSEND_BUNDLE: u32 = 1 << 14;
    pub const MIN_TIMEOUT: u32 = 1 << 15;
    pub const RW_ATTR: u32 = 1 << 16;
    pub const NO_IOWAIT: u32 = 1 << 17;
    /// `IORING_FEAT_FLAGS`: what `io_uring_setup` reports.
    pub const ALL: u32 = (1 << 18) - 1;
}

/// `IOSQE_*`.
pub mod sqe_flags {
    pub const FIXED_FILE: u8 = 1 << 0;
    pub const IO_DRAIN: u8 = 1 << 1;
    pub const IO_LINK: u8 = 1 << 2;
    pub const IO_HARDLINK: u8 = 1 << 3;
    pub const ASYNC: u8 = 1 << 4;
    pub const BUFFER_SELECT: u8 = 1 << 5;
    pub const CQE_SKIP_SUCCESS: u8 = 1 << 6;
    /// `SQE_COMMON_FLAGS`: those `io_init_req` needs no more look at.
    pub const COMMON: u8 = FIXED_FILE | IO_LINK | IO_HARDLINK | ASYNC;
    /// `SQE_VALID_FLAGS`.
    pub const VALID: u8 = COMMON | IO_DRAIN | BUFFER_SELECT | CQE_SKIP_SUCCESS;
}

/// `IORING_SQ_*`: `sq_flags`.
pub mod sq_flags {
    pub const NEED_WAKEUP: u32 = 1 << 0;
    pub const CQ_OVERFLOW: u32 = 1 << 1;
    pub const TASKRUN: u32 = 1 << 2;
}

/// `IORING_CQ_EVENTFD_DISABLED`: `cq_flags`.
pub const CQ_EVENTFD_DISABLED: u32 = 1;

/// `IORING_CQE_F_*`.
pub mod cqe_flags {
    pub const BUFFER: u32 = 1 << 0;
    pub const MORE: u32 = 1 << 1;
    pub const SOCK_NONEMPTY: u32 = 1 << 2;
    pub const NOTIF: u32 = 1 << 3;
    pub const BUF_MORE: u32 = 1 << 4;
    pub const SKIP: u32 = 1 << 5;
    pub const F_32: u32 = 1 << 15;
}

/// The `mmap` offsets (`IORING_OFF_*`).
pub mod off {
    pub const SQ_RING: u64 = 0;
    pub const CQ_RING: u64 = 0x800_0000;
    pub const SQES: u64 = 0x1000_0000;
    pub const PBUF_RING: u64 = 0x8000_0000;
    pub const PBUF_SHIFT: u32 = 16;
    pub const MMAP_MASK: u64 = 0xf800_0000;
    /// `IORING_MAP_OFF_PARAM_REGION` and `IORING_MAP_OFF_ZCRX_REGION`.
    pub const PARAM_REGION: u64 = 0x2000_0000;
    pub const ZCRX_REGION: u64 = 0x3000_0000;
}

/// `IORING_NOP_*`.
pub mod nop {
    pub const INJECT_RESULT: u32 = 1 << 0;
    pub const FILE: u32 = 1 << 1;
    pub const FIXED_FILE: u32 = 1 << 2;
    pub const FIXED_BUFFER: u32 = 1 << 3;
    pub const TW: u32 = 1 << 4;
    pub const CQE32: u32 = 1 << 5;
}

/// `IORING_MAX_ENTRIES` and `IORING_MAX_CQ_ENTRIES`.
pub const MAX_ENTRIES: u32 = 32768;
pub const MAX_CQ_ENTRIES: u32 = 2 * MAX_ENTRIES;
/// `IO_RINGFD_REG_MAX`: the registered ring descriptors of a task.
pub const RINGFD_REG_MAX: u32 = 16;
/// `SMP_CACHE_BYTES` on the emulated machines: the CQE array's alignment.
pub const CACHE_BYTES: u64 = 64;

/// `sizeof(struct io_uring_sqe)`, `sizeof(struct io_uring_cqe)`, and
/// `sizeof(struct io_uring_params)`.
pub const SQE_SIZE: u64 = 64;
pub const CQE_SIZE: u64 = 16;
pub const PARAMS_SIZE: usize = 120;

/// `struct io_rings`: the field offsets, the same for every ABI (32-bit
/// words and the cache-line-aligned `cqes`).
pub mod rings {
    pub const SQ_HEAD: u64 = 0;
    pub const SQ_TAIL: u64 = 4;
    pub const CQ_HEAD: u64 = 8;
    pub const CQ_TAIL: u64 = 12;
    pub const SQ_RING_MASK: u64 = 16;
    pub const CQ_RING_MASK: u64 = 20;
    pub const SQ_RING_ENTRIES: u64 = 24;
    pub const CQ_RING_ENTRIES: u64 = 28;
    pub const SQ_DROPPED: u64 = 32;
    pub const SQ_FLAGS: u64 = 36;
    pub const CQ_FLAGS: u64 = 40;
    pub const CQ_OVERFLOW: u64 = 44;
    pub const CQES: u64 = 64;
}

/// `enum io_uring_op`.
pub mod op {
    pub const NOP: u8 = 0;
    pub const READV: u8 = 1;
    pub const WRITEV: u8 = 2;
    pub const FSYNC: u8 = 3;
    pub const READ_FIXED: u8 = 4;
    pub const WRITE_FIXED: u8 = 5;
    pub const POLL_ADD: u8 = 6;
    pub const POLL_REMOVE: u8 = 7;
    pub const SYNC_FILE_RANGE: u8 = 8;
    pub const SENDMSG: u8 = 9;
    pub const RECVMSG: u8 = 10;
    pub const TIMEOUT: u8 = 11;
    pub const TIMEOUT_REMOVE: u8 = 12;
    pub const ACCEPT: u8 = 13;
    pub const ASYNC_CANCEL: u8 = 14;
    pub const LINK_TIMEOUT: u8 = 15;
    pub const CONNECT: u8 = 16;
    pub const FALLOCATE: u8 = 17;
    pub const OPENAT: u8 = 18;
    pub const CLOSE: u8 = 19;
    pub const FILES_UPDATE: u8 = 20;
    pub const STATX: u8 = 21;
    pub const READ: u8 = 22;
    pub const WRITE: u8 = 23;
    pub const FADVISE: u8 = 24;
    pub const MADVISE: u8 = 25;
    pub const SEND: u8 = 26;
    pub const RECV: u8 = 27;
    pub const OPENAT2: u8 = 28;
    pub const EPOLL_CTL: u8 = 29;
    pub const SPLICE: u8 = 30;
    pub const PROVIDE_BUFFERS: u8 = 31;
    pub const REMOVE_BUFFERS: u8 = 32;
    pub const TEE: u8 = 33;
    pub const SHUTDOWN: u8 = 34;
    pub const RENAMEAT: u8 = 35;
    pub const UNLINKAT: u8 = 36;
    pub const MKDIRAT: u8 = 37;
    pub const SYMLINKAT: u8 = 38;
    pub const LINKAT: u8 = 39;
    pub const MSG_RING: u8 = 40;
    pub const FSETXATTR: u8 = 41;
    pub const SETXATTR: u8 = 42;
    pub const FGETXATTR: u8 = 43;
    pub const GETXATTR: u8 = 44;
    pub const SOCKET: u8 = 45;
    pub const URING_CMD: u8 = 46;
    pub const SEND_ZC: u8 = 47;
    pub const SENDMSG_ZC: u8 = 48;
    pub const READ_MULTISHOT: u8 = 49;
    pub const WAITID: u8 = 50;
    pub const FUTEX_WAIT: u8 = 51;
    pub const FUTEX_WAKE: u8 = 52;
    pub const FUTEX_WAITV: u8 = 53;
    pub const FIXED_FD_INSTALL: u8 = 54;
    pub const FTRUNCATE: u8 = 55;
    pub const BIND: u8 = 56;
    pub const LISTEN: u8 = 57;
    pub const RECV_ZC: u8 = 58;
    pub const EPOLL_WAIT: u8 = 59;
    pub const READV_FIXED: u8 = 60;
    pub const WRITEV_FIXED: u8 = 61;
    pub const PIPE: u8 = 62;
    pub const NOP128: u8 = 63;
    pub const URING_CMD128: u8 = 64;
    /// `IORING_OP_LAST`.
    pub const LAST: u8 = 65;
}

/// `io_uring_get_opcode`: the names `fdinfo` prints (`io_cold_defs`).
pub const OP_NAMES: [&str; op::LAST as usize] = [
    "NOP",
    "READV",
    "WRITEV",
    "FSYNC",
    "READ_FIXED",
    "WRITE_FIXED",
    "POLL_ADD",
    "POLL_REMOVE",
    "SYNC_FILE_RANGE",
    "SENDMSG",
    "RECVMSG",
    "TIMEOUT",
    "TIMEOUT_REMOVE",
    "ACCEPT",
    "ASYNC_CANCEL",
    "LINK_TIMEOUT",
    "CONNECT",
    "FALLOCATE",
    "OPENAT",
    "CLOSE",
    "FILES_UPDATE",
    "STATX",
    "READ",
    "WRITE",
    "FADVISE",
    "MADVISE",
    "SEND",
    "RECV",
    "OPENAT2",
    "EPOLL",
    "SPLICE",
    "PROVIDE_BUFFERS",
    "REMOVE_BUFFERS",
    "TEE",
    "SHUTDOWN",
    "RENAMEAT",
    "UNLINKAT",
    "MKDIRAT",
    "SYMLINKAT",
    "LINKAT",
    "MSG_RING",
    "FSETXATTR",
    "SETXATTR",
    "FGETXATTR",
    "GETXATTR",
    "SOCKET",
    "URING_CMD",
    "SEND_ZC",
    "SENDMSG_ZC",
    "READ_MULTISHOT",
    "WAITID",
    "FUTEX_WAIT",
    "FUTEX_WAKE",
    "FUTEX_WAITV",
    "FIXED_FD_INSTALL",
    "FTRUNCATE",
    "BIND",
    "LISTEN",
    "RECV_ZC",
    "EPOLL_WAIT",
    "READV_FIXED",
    "WRITEV_FIXED",
    "PIPE",
    "NOP128",
    "URING_CMD128",
];

/// `struct io_uring_params` as `io_uring_setup` reads and writes it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Params {
    pub sq_entries: u32,
    pub cq_entries: u32,
    pub flags: u32,
    pub sq_thread_cpu: u32,
    pub sq_thread_idle: u32,
    pub features: u32,
    pub wq_fd: u32,
    pub resv: [u32; 3],
    /// `struct io_sqring_offsets`: head, tail, ring_mask, ring_entries,
    /// flags, dropped, array, resv1, and `user_addr`.
    pub sq_off: [u32; 8],
    pub sq_user_addr: u64,
    /// `struct io_cqring_offsets`: head, tail, ring_mask, ring_entries,
    /// overflow, cqes, flags, resv1, and `user_addr`.
    pub cq_off: [u32; 8],
    pub cq_user_addr: u64,
}

fn word(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn dword(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

fn words<const N: usize>(b: &[u8], at: usize) -> [u32; N] {
    std::array::from_fn(|i| word(b, at + 4 * i))
}

impl Params {
    /// The structure's 120 bytes, read.
    pub fn decode(b: &[u8]) -> Self {
        Params {
            sq_entries: word(b, 0),
            cq_entries: word(b, 4),
            flags: word(b, 8),
            sq_thread_cpu: word(b, 12),
            sq_thread_idle: word(b, 16),
            features: word(b, 20),
            wq_fd: word(b, 24),
            resv: words(b, 28),
            sq_off: words(b, 40),
            sq_user_addr: dword(b, 72),
            cq_off: words(b, 80),
            cq_user_addr: dword(b, 112),
        }
    }

    /// The structure's 120 bytes.
    pub fn encode(&self) -> [u8; PARAMS_SIZE] {
        let mut b = [0u8; PARAMS_SIZE];
        let mut put = |at: usize, v: u32| b[at..at + 4].copy_from_slice(&v.to_le_bytes());
        for (i, v) in [
            self.sq_entries,
            self.cq_entries,
            self.flags,
            self.sq_thread_cpu,
            self.sq_thread_idle,
            self.features,
            self.wq_fd,
        ]
        .into_iter()
        .chain(self.resv)
        .enumerate()
        {
            put(4 * i, v);
        }
        for (i, v) in self.sq_off.into_iter().enumerate() {
            put(40 + 4 * i, v);
        }
        for (i, v) in self.cq_off.into_iter().enumerate() {
            put(80 + 4 * i, v);
        }
        b[72..80].copy_from_slice(&self.sq_user_addr.to_le_bytes());
        b[112..120].copy_from_slice(&self.cq_user_addr.to_le_bytes());
        b
    }
}

/// A submission queue entry (`struct io_uring_sqe`), read once from the
/// shared ring (the kernel's `READ_ONCE` of each field it uses): the
/// unions keep their raw words.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sqe {
    pub opcode: u8,
    pub flags: u8,
    pub ioprio: u16,
    pub fd: i32,
    /// `off`, `addr2`, or `cmd_op`.
    pub off: u64,
    /// `addr`, `splice_off_in`, or `level` and `optname`.
    pub addr: u64,
    pub len: u32,
    /// `rw_flags` and the other per-operation flag words.
    pub op_flags: u32,
    pub user_data: u64,
    /// `buf_index` or `buf_group`.
    pub buf_index: u16,
    pub personality: u16,
    /// `splice_fd_in`, `file_index`, `optlen`, or `addr_len`.
    pub file_index: u32,
    /// `addr3`, `attr_ptr`, or `optval`.
    pub addr3: u64,
    /// `__pad2[0]` or `attr_type_mask`.
    pub pad2: u64,
}

impl Sqe {
    /// The first 64 bytes of an entry.
    pub fn decode(b: &[u8]) -> Self {
        Sqe {
            opcode: b[0],
            flags: b[1],
            ioprio: u16::from_le_bytes([b[2], b[3]]),
            fd: word(b, 4) as i32,
            off: dword(b, 8),
            addr: dword(b, 16),
            len: word(b, 24),
            op_flags: word(b, 28),
            user_data: dword(b, 32),
            buf_index: u16::from_le_bytes([b[40], b[41]]),
            personality: u16::from_le_bytes([b[42], b[43]]),
            file_index: word(b, 44),
            addr3: dword(b, 48),
            pad2: dword(b, 56),
        }
    }
}

/// A completion queue entry: `user_data`, `res`, `flags`, and the two
/// extra words of a 32-byte entry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cqe {
    pub user_data: u64,
    pub res: i32,
    pub flags: u32,
    pub big: [u64; 2],
}

impl Cqe {
    /// A 16-byte entry's fields.
    pub fn new(user_data: u64, res: i32, flags: u32) -> Self {
        Cqe {
            user_data,
            res,
            flags,
            big: [0; 2],
        }
    }

    /// The entry's 32 bytes; a 16-byte entry is the first half.
    pub fn encode(&self) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&self.user_data.to_le_bytes());
        b[8..12].copy_from_slice(&self.res.to_le_bytes());
        b[12..16].copy_from_slice(&self.flags.to_le_bytes());
        b[16..24].copy_from_slice(&self.big[0].to_le_bytes());
        b[24..].copy_from_slice(&self.big[1].to_le_bytes());
        b
    }
}
/// `struct io_issue_def`: what `io_init_req` and the issue path need to
/// know of each operation (`io_uring/opdef.c`).
#[derive(Clone, Copy, Debug)]
pub struct OpDef {
    pub needs_file: bool,
    pub ioprio: bool,
    pub buffer_select: bool,
    pub iopoll: bool,
    pub is_128: bool,
    pub pollin: bool,
    pub pollout: bool,
}

const fn def(bits: u8) -> OpDef {
    OpDef {
        needs_file: bits & 1 != 0,
        ioprio: bits & 2 != 0,
        buffer_select: bits & 4 != 0,
        iopoll: bits & 8 != 0,
        is_128: bits & 16 != 0,
        pollin: bits & 32 != 0,
        pollout: bits & 64 != 0,
    }
}

/// The definitions in opcode order; the bits are, from the lowest,
/// `needs_file`, `ioprio`, `buffer_select`, `iopoll`, `is_128`, `pollin`, `pollout`.
pub const OP_DEFS: [OpDef; op::LAST as usize] = [
    def(0b0001000), // NOP
    def(0b0101111), // READV
    def(0b1001011), // WRITEV
    def(0b0000001), // FSYNC
    def(0b0101011), // READ_FIXED
    def(0b1001011), // WRITE_FIXED
    def(0b0000001), // POLL_ADD
    def(0b0000000), // POLL_REMOVE
    def(0b0000001), // SYNC_FILE_RANGE
    def(0b1000011), // SENDMSG
    def(0b0100111), // RECVMSG
    def(0b0000000), // TIMEOUT
    def(0b0000000), // TIMEOUT_REMOVE
    def(0b0100011), // ACCEPT
    def(0b0000000), // ASYNC_CANCEL
    def(0b0000000), // LINK_TIMEOUT
    def(0b1000001), // CONNECT
    def(0b0000001), // FALLOCATE
    def(0b0000000), // OPENAT
    def(0b0000000), // CLOSE
    def(0b0001000), // FILES_UPDATE
    def(0b0000000), // STATX
    def(0b0101111), // READ
    def(0b1001011), // WRITE
    def(0b0000001), // FADVISE
    def(0b0000000), // MADVISE
    def(0b1000111), // SEND
    def(0b0100111), // RECV
    def(0b0000000), // OPENAT2
    def(0b0000000), // EPOLL_CTL
    def(0b0000001), // SPLICE
    def(0b0001000), // PROVIDE_BUFFERS
    def(0b0001000), // REMOVE_BUFFERS
    def(0b0000001), // TEE
    def(0b0000001), // SHUTDOWN
    def(0b0000000), // RENAMEAT
    def(0b0000000), // UNLINKAT
    def(0b0000000), // MKDIRAT
    def(0b0000000), // SYMLINKAT
    def(0b0000000), // LINKAT
    def(0b0001001), // MSG_RING
    def(0b0000001), // FSETXATTR
    def(0b0000000), // SETXATTR
    def(0b0000001), // FGETXATTR
    def(0b0000000), // GETXATTR
    def(0b0000000), // SOCKET
    def(0b0001101), // URING_CMD
    def(0b1000011), // SEND_ZC
    def(0b1000011), // SENDMSG_ZC
    def(0b0100101), // READ_MULTISHOT
    def(0b0000000), // WAITID
    def(0b0000000), // FUTEX_WAIT
    def(0b0000000), // FUTEX_WAKE
    def(0b0000000), // FUTEX_WAITV
    def(0b0000001), // FIXED_FD_INSTALL
    def(0b0000001), // FTRUNCATE
    def(0b0000001), // BIND
    def(0b0000001), // LISTEN
    def(0b0100011), // RECV_ZC
    def(0b0100001), // EPOLL_WAIT
    def(0b0101011), // READV_FIXED
    def(0b1001011), // WRITEV_FIXED
    def(0b0000000), // PIPE
    def(0b0011000), // NOP128
    def(0b0011101), // URING_CMD128
];
