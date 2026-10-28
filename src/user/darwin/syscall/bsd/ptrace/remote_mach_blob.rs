//! Anonymous file snapshots for out-of-line memory crossing a family link.

use std::fs::File;
use std::io::{self, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::FileExt;

/// Copies a complete memory snapshot into a nameless, close-on-exec file.
pub(super) fn create(data: &[u8]) -> io::Result<OwnedFd> {
    let mut file = crate::user::mm::anonymous_file()?;
    file.write_all(data)?;
    Ok(file.into())
}

/// Reads exactly the advertised snapshot, independently of the shared cursor.
pub(super) fn read(fd: OwnedFd, size: u32) -> io::Result<Vec<u8>> {
    let file = File::from(fd);
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != u64::from(size) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid remote memory snapshot",
        ));
    }
    let mut data = Vec::new();
    data.try_reserve_exact(size as usize)
        .map_err(|_| io::Error::other("remote memory snapshot allocation failed"))?;
    data.resize(size as usize, 0);
    file.read_exact_at(&mut data, 0)?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshots_have_exact_contents_and_size() {
        let contents: Vec<u8> = (0..4097).map(|i| (i % 251) as u8).collect();
        let fd = create(&contents).unwrap();
        assert_eq!(read(fd, contents.len() as u32).unwrap(), contents);
        let fd = create(&contents).unwrap();
        assert_eq!(
            read(fd, 4096).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
