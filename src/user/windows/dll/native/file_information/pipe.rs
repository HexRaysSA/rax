//! File-information records derived from the owned anonymous-pipe channel.

use super::records::{Publication, Record, value};
use crate::user::windows::objects::{PipeEnd, PipeInformation};

pub(super) fn record(end: &PipeEnd, class: u32) -> Record {
    let pipe = end.information();
    let data = match class {
        4 => basic().to_vec(),
        5 => standard(&pipe).to_vec(),
        6 => pipe.file_index.to_le_bytes().to_vec(),
        23 => vec![0; 8], // Byte-stream read and queued completion.
        24 => [
            0, // FILE_PIPE_BYTE_STREAM_TYPE
            2, // FILE_PIPE_FULL_DUPLEX
            1, // MaximumInstances
            pipe.instances,
            pipe.quota,
            pipe.readable,
            pipe.quota,
            pipe.write_quota,
            pipe.state,
            u32::from(pipe.server_end),
        ]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect(),
        _ => unreachable!("caller selected a fixed anonymous-pipe record"),
    };
    value(data, Publication::InformationFirst, true)
}

pub(super) fn all(end: &PipeEnd, grant: u32) -> Record {
    let pipe = end.information();
    let mut data = vec![0; 100];
    data[..40].copy_from_slice(&basic());
    data[40..64].copy_from_slice(&standard(&pipe));
    data[64..72].copy_from_slice(&pipe.file_index.to_le_bytes());
    data[76..80].copy_from_slice(&grant.to_le_bytes());
    // NPFS places the inbound queue length here and an empty file name at
    // byte 96. The separate FilePositionInformation query still reports zero.
    data[80..88].copy_from_slice(&u64::from(pipe.readable).to_le_bytes());
    data[88..92].copy_from_slice(&0x20u32.to_le_bytes()); // FILE_SYNCHRONOUS_IO_NONALERT
    value(data, Publication::InformationFirst, true)
}

fn basic() -> [u8; 40] {
    let mut basic = [0; 40];
    basic[32..36].copy_from_slice(&0x80u32.to_le_bytes());
    basic
}

fn standard(pipe: &PipeInformation) -> [u8; 24] {
    let mut standard = [0; 24];
    standard[..8].copy_from_slice(&(2 * u64::from(pipe.quota)).to_le_bytes());
    standard[8..16].copy_from_slice(&u64::from(pipe.readable).to_le_bytes());
    standard[16..20].copy_from_slice(&1u32.to_le_bytes());
    standard[20] = 1;
    standard
}
