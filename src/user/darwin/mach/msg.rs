//! Mach messages in transit (`osfmk/ipc/ipc_kmsg.c`, `mach/message.h`).
//!
//! A message sent to a port is copied in from the sender's space: its
//! header and descriptor rights become in-transit [`Right`]s and
//! out-of-line regions are copied, so the [`Message`] owns everything it
//! carries until a receiver copies it out or it is destroyed.
//!
//! Every task of the emulator is 64-bit, so a message body keeps the
//! 64-bit user layout from sender to receiver: copy-out rewrites the
//! descriptors' name, address, and disposition fields in place.

use super::ipc::{PortName, Right};

/// `sizeof(mach_msg_header_t)` (user and kernel view of 64-bit tasks).
pub const HEADER_SIZE: usize = 24;

/// `MACH_MSGH_BITS_*`.
pub mod bits {
    /// `MACH_MSGH_BITS_REMOTE_MASK`.
    pub const REMOTE_MASK: u32 = 0x0000_001f;
    /// `MACH_MSGH_BITS_LOCAL_MASK`.
    pub const LOCAL_MASK: u32 = 0x0000_1f00;
    /// `MACH_MSGH_BITS_VOUCHER_MASK`.
    pub const VOUCHER_MASK: u32 = 0x001f_0000;
    /// `MACH_MSGH_BITS_PORTS_MASK`.
    pub const PORTS_MASK: u32 = REMOTE_MASK | LOCAL_MASK | VOUCHER_MASK;
    /// `MACH_MSGH_BITS_COMPLEX`.
    pub const COMPLEX: u32 = 0x8000_0000;
    /// `MACH_MSGH_BITS_USER`: the bits a sender may set.
    pub const USER: u32 = 0x801f_1f1f;
    /// `MACH_MSGH_BITS_CIRCULAR`.
    pub const CIRCULAR: u32 = 0x1000_0000;

    /// `MACH_MSGH_BITS_REMOTE`.
    pub fn remote(b: u32) -> u32 {
        b & REMOTE_MASK
    }

    /// `MACH_MSGH_BITS_LOCAL`.
    pub fn local(b: u32) -> u32 {
        (b & LOCAL_MASK) >> 8
    }

    /// `MACH_MSGH_BITS_VOUCHER`.
    pub fn voucher(b: u32) -> u32 {
        (b & VOUCHER_MASK) >> 16
    }

    /// `MACH_MSGH_BITS_SET(remote, local, voucher, other)`.
    pub fn set(remote: u32, local: u32, voucher: u32, other: u32) -> u32 {
        (remote & 0x1f) | ((local & 0x1f) << 8) | ((voucher & 0x1f) << 16) | (other & !PORTS_MASK)
    }
}

/// Descriptor types (`MACH_MSG_*_DESCRIPTOR`).
pub mod desc {
    /// `MACH_MSG_PORT_DESCRIPTOR`.
    pub const PORT: u8 = 0;
    /// `MACH_MSG_OOL_DESCRIPTOR`.
    pub const OOL: u8 = 1;
    /// `MACH_MSG_OOL_PORTS_DESCRIPTOR`.
    pub const OOL_PORTS: u8 = 2;
    /// `MACH_MSG_OOL_VOLATILE_DESCRIPTOR`.
    pub const OOL_VOLATILE: u8 = 3;
    /// `MACH_MSG_GUARDED_PORT_DESCRIPTOR`.
    pub const GUARDED_PORT: u8 = 4;

    /// The 64-bit user size of a descriptor of type `t`
    /// (`mach_msg_user_port_descriptor_t` is 12 bytes, the others 16).
    pub fn size(t: u8) -> usize {
        if t == PORT { 12 } else { 16 }
    }

    /// `MACH_MSG_PHYSICAL_COPY`.
    pub const PHYSICAL_COPY: u8 = 0;
    /// `MACH_MSG_VIRTUAL_COPY`.
    pub const VIRTUAL_COPY: u8 = 1;
}

/// Receive options that shape the trailer and header.
pub mod opt {
    /// `MACH_SEND_MSG`.
    pub const SEND_MSG: u64 = 0x1;
    /// `MACH_RCV_MSG`.
    pub const RCV_MSG: u64 = 0x2;
    /// `MACH_RCV_LARGE`.
    pub const RCV_LARGE: u64 = 0x4;
    /// `MACH_RCV_LARGE_IDENTITY`.
    pub const RCV_LARGE_IDENTITY: u64 = 0x8;
    /// `MACH_SEND_TIMEOUT`.
    pub const SEND_TIMEOUT: u64 = 0x10;
    /// `MACH_SEND_INTERRUPT`.
    pub const SEND_INTERRUPT: u64 = 0x40;
    /// `MACH_SEND_TRAILER`.
    pub const SEND_TRAILER: u64 = 0x2_0000;
    /// `MACH_RCV_TIMEOUT`.
    pub const RCV_TIMEOUT: u64 = 0x100;
    /// `MACH_RCV_INTERRUPT`.
    pub const RCV_INTERRUPT: u64 = 0x400;
    /// `MACH_RCV_VOUCHER`.
    pub const RCV_VOUCHER: u64 = 0x800;
    /// `MACH_RCV_GUARDED_DESC`.
    pub const RCV_GUARDED_DESC: u64 = 0x1000;
    /// `MACH_RCV_SYNC_WAIT`.
    pub const RCV_SYNC_WAIT: u64 = 0x4000;
    /// `MACH64_MSG_VECTOR`.
    pub const MSG_VECTOR: u64 = 0x1_0000_0000;
    /// `MACH64_SEND_KOBJECT_CALL`.
    pub const SEND_KOBJECT_CALL: u64 = 0x2_0000_0000;
    /// `MACH64_SEND_MQ_CALL`.
    pub const SEND_MQ_CALL: u64 = 0x4_0000_0000;
    /// `MACH64_SEND_ANY`.
    pub const SEND_ANY: u64 = 0x8_0000_0000;
    /// `MACH64_SEND_DK_CALL`.
    pub const SEND_DK_CALL: u64 = 0x10_0000_0000;
    /// `MACH64_MSG_OPTION_CFI_MASK`.
    pub const CFI_MASK: u64 = SEND_KOBJECT_CALL | SEND_MQ_CALL | SEND_ANY | SEND_DK_CALL;

    /// `GET_RCV_ELEMENTS`.
    pub fn rcv_elements(o: u64) -> u32 {
        ((o >> 24) & 0xf) as u32
    }
}

/// `REQUESTED_TRAILER_SIZE` for a 64-bit receiver.
pub fn trailer_size(options: u64) -> usize {
    match opt::rcv_elements(options) {
        0 => 8,
        1 => 12,
        2 => 20,
        3 => 52,
        4 => 60,
        7 => 68,
        _ => 68,
    }
}

/// `MACH_MSG_TRAILER_FORMAT_0` sender identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sender {
    /// `security_token_t` (effective uid and gid).
    pub sec: [u32; 2],
    /// `audit_token_t`: auid, euid, egid, ruid, rgid, pid, asid,
    /// pidversion.
    pub audit: [u32; 8],
}

impl Sender {
    /// `KERNEL_SECURITY_TOKEN` / `KERNEL_AUDIT_TOKEN`.
    pub const KERNEL: Sender = Sender {
        sec: [0, 1],
        audit: [0; 8],
    };
}

/// A descriptor's payload in transit.
#[derive(Debug)]
pub enum Item {
    /// A port right (`MACH_MSG_PORT_DESCRIPTOR`); `None` for
    /// `MACH_PORT_NULL`. `disp` is the right's type
    /// (`MACH_MSG_TYPE_PORT_*`).
    Port {
        /// The right.
        right: Option<Right>,
        /// Its type.
        disp: u32,
    },
    /// A guarded receive right (`MACH_MSG_GUARDED_PORT_DESCRIPTOR`).
    Guarded {
        /// The right.
        right: Option<Right>,
        /// Its type.
        disp: u32,
        /// `MACH_MSG_GUARD_FLAGS_*`.
        flags: u16,
        /// The guard context.
        context: u64,
    },
    /// Out-of-line memory: the bytes and the sender's copy option.
    Ool {
        /// The data.
        data: Vec<u8>,
        /// `MACH_MSG_PHYSICAL_COPY` or `MACH_MSG_VIRTUAL_COPY`.
        copy: u8,
        /// The data's offset within its first page when it travels as a
        /// page list (large regions), else 0.
        page_offset: u64,
    },
    /// An out-of-line array of port rights, all of type `disp`.
    OolPorts {
        /// The rights (`None` for null names).
        rights: Vec<Option<Right>>,
        /// Their type.
        disp: u32,
    },
}

/// A message in transit.
#[derive(Debug)]
pub struct Message {
    /// `msgh_bits` in kernel form: the remote field holds the
    /// destination right's type, the local field the reply right's type,
    /// the voucher field `MACH_MSG_TYPE_MOVE_SEND` when a voucher rides
    /// along.
    pub bits: u32,
    /// The destination right the send consumed.
    pub dest: Right,
    /// The reply right (`None` for `MACH_PORT_NULL`).
    pub reply: Option<Right>,
    /// The voucher right.
    pub voucher: Option<Right>,
    /// `msgh_voucher_port` as sent when the voucher bits are zero (it
    /// round-trips unmodified).
    pub voucher_name: PortName,
    /// `msgh_id`.
    pub id: i32,
    /// The body after the header in the 64-bit user layout.
    pub body: Vec<u8>,
    /// Descriptor payloads with their descriptor's offset in `body`.
    pub items: Vec<(usize, Item)>,
    /// Who sent it.
    pub sender: Sender,
    /// Auxiliary data (`mach_msg_aux_header_t` and payload), empty when
    /// the sender attached none.
    pub aux: Vec<u8>,
}

impl Message {
    /// `msgh_size` of the message as a 64-bit receiver sees it, trailer
    /// excluded.
    pub fn size(&self) -> usize {
        HEADER_SIZE + self.body.len()
    }

    /// Takes every right the message holds (for destruction): header
    /// rights first, then descriptor rights in order.
    pub fn take_rights(&mut self) -> Vec<Right> {
        let mut out = Vec::new();
        out.push(std::mem::replace(&mut self.dest, Right::Dead));
        out.extend(self.reply.take());
        out.extend(self.voucher.take());
        for (_, item) in self.items.drain(..) {
            match item {
                Item::Port { right, .. } | Item::Guarded { right, .. } => out.extend(right),
                Item::OolPorts { rights, .. } => out.extend(rights.into_iter().flatten()),
                Item::Ool { .. } => {}
            }
        }
        out
    }
}

/// `NDR_record` for little-endian 64-bit tasks.
pub const NDR_RECORD: [u8; 8] = [0, 0, 0, 0, 1, 0, 0, 0];

/// Writes the trailer a receiver asked for (`ipc_kmsg_deflate` with
/// `mach_msg_mac_trailer_t` fields).
pub fn trailer(options: u64, seqno: u32, sender: &Sender, context: u64) -> Vec<u8> {
    let size = trailer_size(options);
    let mut t = Vec::with_capacity(68);
    t.extend_from_slice(&0u32.to_le_bytes()); // MACH_MSG_TRAILER_FORMAT_0
    t.extend_from_slice(&(size as u32).to_le_bytes());
    t.extend_from_slice(&seqno.to_le_bytes());
    t.extend_from_slice(&sender.sec[0].to_le_bytes());
    t.extend_from_slice(&sender.sec[1].to_le_bytes());
    for w in sender.audit {
        t.extend_from_slice(&w.to_le_bytes());
    }
    t.extend_from_slice(&context.to_le_bytes());
    t.extend_from_slice(&0i32.to_le_bytes()); // msgh_ad
    t.extend_from_slice(&0u32.to_le_bytes()); // msgh_labels.sender
    t.truncate(size);
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trailer_sizes_follow_requested_elements() {
        // REQUESTED_TRAILER_SIZE_NATIVE: NULL, SEQNO, SENDER, AUDIT, CTX,
        // AV, and the maximum for everything else.
        let sizes: Vec<usize> = (0u64..9).map(|e| trailer_size(e << 24)).collect();
        assert_eq!(sizes, [8, 12, 20, 52, 60, 68, 68, 68, 68]);
        let t = trailer(3 << 24, 7, &Sender::KERNEL, 0);
        assert_eq!(t.len(), 52);
        assert_eq!(&t[4..8], &52u32.to_le_bytes());
        assert_eq!(&t[8..12], &7u32.to_le_bytes());
        assert_eq!(&t[12..20], &[0, 0, 0, 0, 1, 0, 0, 0]);
    }

    #[test]
    fn header_bits_compose() {
        let b = bits::set(18, 17, 17, bits::COMPLEX | 0x1f);
        assert_eq!(bits::remote(b), 18);
        assert_eq!(bits::local(b), 17);
        assert_eq!(bits::voucher(b), 17);
        assert_eq!(b & bits::COMPLEX, bits::COMPLEX);
    }
}
