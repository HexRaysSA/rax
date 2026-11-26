use std::{
    fs::File,
    io::{self, Read},
};

/// Accept compiled ncurses entries filed under the name's first byte or
/// its two-digit hexadecimal spelling.
pub(in crate::user) fn accepts(path: &str, mut file: &File) -> io::Result<bool> {
    let Some((bucket, name)) = path.split_once('/') else {
        return Ok(false);
    };
    let Some(&initial) = name.as_bytes().first() else {
        return Ok(false);
    };
    let hex_bucket = bucket.len() == 2 && u8::from_str_radix(bucket, 16) == Ok(initial);
    if name.contains('/') || (bucket.as_bytes() != [initial] && !hex_bucket) {
        return Ok(false);
    }
    let mut header = [0; 12];
    match file.read_exact(&mut header) {
        Ok(()) => Ok(matches!(
            u16::from_le_bytes([header[0], header[1]]),
            0o432 | 0o1036
        )),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error),
    }
}
