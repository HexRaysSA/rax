//! Fixed child metadata under a current-session parent lacking query access.
use super::*;

#[cfg(test)]
#[path = "session_parent_tests.rs"]
mod tests;

fn canonical_name(handle: &Owned) -> io::Result<Vec<u16>> {
    let mut words = [0u64; 512];
    let mut returned = 0u32;
    // SAFETY: live owned handle, fixed ObjectNameInformation class, initialized
    // aligned 4 KiB storage and exclusive ULONG output. Returned pointers are
    // checked against the returned extent before their bytes are copied.
    let status = unsafe {
        NtQueryObject(
            handle.0,
            1,
            words.as_mut_ptr().cast(),
            std::mem::size_of_val(&words) as u32,
            &mut returned,
        )
    };
    check(status, "fixed session child native name")?;
    let extent = returned as usize;
    if extent < std::mem::size_of::<Unicode>() || extent > std::mem::size_of_val(&words) {
        return Err(invalid("fixed session child name exceeds capture bounds"));
    }
    // SAFETY: the aligned initialized output contains the complete native
    // UNICODE_STRING header. Its pointee is validated independently below.
    let name = unsafe { std::ptr::read(words.as_ptr().cast::<Unicode>()) };
    let start = words.as_ptr() as usize;
    let at = name.buffer as usize;
    let length = usize::from(name.length);
    if length % 2 != 0
        || at % 2 != 0
        || at < start
        || at - start > extent
        || length > extent - (at - start)
    {
        return Err(invalid(
            "fixed session child native name is outside its output",
        ));
    }
    // SAFETY: even length/alignment and containment in the initialized returned
    // output were checked. No native pointer survives this copied name.
    Ok(unsafe { std::slice::from_raw_parts(name.buffer, length / 2) }.to_vec())
}

fn entry(
    parent: &[u16],
    name: &[u16],
    canonical: Vec<u16>,
    link: bool,
) -> io::Result<CapturedEntry> {
    let expected: Vec<_> = parent
        .iter()
        .copied()
        .chain([92])
        .chain(name.iter().copied())
        .collect();
    if canonical != expected {
        return Err(invalid(
            "fixed session child canonical name differs from selected path",
        ));
    }
    Ok(CapturedEntry {
        name: canonical[parent.len() + 1..].to_vec(),
        kind: if link { "SymbolicLink" } else { "Directory" }
            .encode_utf16()
            .collect(),
        target: None,
        link_access: None,
        section: None,
    })
}

fn child(parent: &Owned, path: &[u16], name: &[u16]) -> io::Result<CapturedEntry> {
    // NtOpenSymbolicLinkObject preserves the final link's type. A type
    // mismatch alone permits the Directory alternative. OBJ_OPENLINK is
    // deliberately absent: NtOpenDirectoryObject rejects that attribute.
    let (relative, link) = match open(name, parent.0, 0x0200_0000, true, 0x40)? {
        Ok(handle) => (handle, true),
        Err(STATUS_OBJECT_TYPE_MISMATCH) => {
            let handle = open(name, parent.0, 0x0200_0000, false, 0x40)?.map_err(|status| {
                invalid(&format!("fixed session directory child: {status:#010x}"))
            })?;
            (handle, false)
        }
        Err(status) => {
            return Err(invalid(&format!(
                "fixed session child type capture: {status:#010x}"
            )));
        }
    };
    let absolute_name: Vec<_> = path
        .iter()
        .copied()
        .chain([92])
        .chain(name.iter().copied())
        .collect();
    let absolute =
        open(&absolute_name, null_mut(), 0x0200_0000, link, 0x40)?.map_err(|status| {
            invalid(&format!(
                "fixed session child absolute verification: {status:#010x}"
            ))
        })?;
    directory_alias::same_identity(&relative, &absolute)?;
    if basic(&relative)? != basic(&absolute)? {
        return Err(invalid(
            "fixed session child authorization changed during capture",
        ));
    }
    let captured = entry(path, name, canonical_name(&relative)?, link)?;
    absolute.close()?;
    relative.close()?;
    Ok(captured)
}

pub(super) fn capture(
    upcase: &[u16],
    parent: &Owned,
    path: &[u16],
    session: u32,
) -> io::Result<Vec<CapturedEntry>> {
    let expected: Vec<_> = format!("\\Sessions\\{session}").encode_utf16().collect();
    if path != expected || upcase.len() != 65536 {
        return Err(invalid("invalid fixed session parent capture subject"));
    }
    let names: &[&str] = if session == 0 {
        &["Windows"]
    } else {
        &["BaseNamedObjects", "Windows"]
    };
    let sample = || -> io::Result<Vec<CapturedEntry>> {
        names
            .iter()
            .map(|name| child(parent, path, &name.encode_utf16().collect::<Vec<_>>()))
            .collect()
    };
    for _ in 0..3 {
        let first = sample()?;
        let second = sample()?;
        if entries_coherent(upcase, &first, &second) {
            return Ok(first);
        }
    }
    Err(invalid(
        "fixed session child metadata changed during bounded capture",
    ))
}
