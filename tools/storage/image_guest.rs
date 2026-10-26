//! Execute a retained operation stream through the public media API.
use rax::devices::virtio::block_image::{BlockImage, ImageMode};
use std::io::{Read, Write};
fn word(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(data[at..at + 4].try_into().unwrap())
}
fn wide(data: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(data[at..at + 8].try_into().unwrap())
}
fn main() {
    let mut args = std::env::args_os().skip(1);
    let folder = std::path::PathBuf::from(args.next().expect("evidence directory"));
    assert!(args.next().is_none());
    let input = std::fs::read(folder.join("input.bin")).unwrap();
    assert_eq!(&input[..8], b"RAXIMG01");
    let mode = match word(&input, 8) {
        0 => ImageMode::ReadOnly,
        1 => ImageMode::ReadWrite,
        2 => ImageMode::CopyOnWrite,
        _ => panic!("invalid mode"),
    };
    let path = folder.join("disk.raw");
    let mut image = BlockImage::open(&path, mode, wide(&input, 12)).unwrap();
    let count = word(&input, 20);
    let mut at = 24;
    let mut records =
        std::io::BufWriter::new(std::fs::File::create(folder.join("records.bin")).unwrap());
    records.write_all(b"IMGREC01").unwrap();
    records.write_all(&count.to_le_bytes()).unwrap();
    for _ in 0..count {
        let op = word(&input, at);
        let offset = wide(&input, at + 4);
        let length = word(&input, at + 12) as usize;
        at += 16;
        let result = match op {
            0 => {
                let result = usize::try_from(offset)
                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))
                    .and_then(|start| image.write_bytes(start, &input[at..at + length]));
                at += length;
                result
            }
            1 => usize::try_from(offset)
                .ok()
                .and_then(|start| start.checked_add(length).map(|end| start..end))
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))
                .and_then(|range| image.zero_bytes(range)),
            2 => image.flush(),
            3 => std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .and_then(|file| file.set_len(offset)),
            _ => panic!("invalid operation"),
        };
        let status = match result {
            Ok(()) => 0,
            Err(e) => match e.kind() {
                std::io::ErrorKind::InvalidInput => 1,
                std::io::ErrorKind::PermissionDenied => 2,
                std::io::ErrorKind::InvalidData => 3,
                _ => 4,
            },
        };
        let host = std::fs::read(&path).unwrap();
        records.write_all(&[status]).unwrap();
        records
            .write_all(&(image.len() as u32).to_le_bytes())
            .unwrap();
        records
            .write_all(&(host.len() as u32).to_le_bytes())
            .unwrap();
        records.write_all(&image).unwrap();
        records.write_all(&host).unwrap();
    }
    assert_eq!(at, input.len());
    records.flush().unwrap();
    // Preserve the final public byte view separately for reproducible diagnostics.
    std::fs::write(folder.join("cache.raw"), &*image).unwrap();
    let mut check = Vec::new();
    std::fs::File::open(&path)
        .unwrap()
        .read_to_end(&mut check)
        .unwrap();
    assert_eq!(check, std::fs::read(&path).unwrap());
}
