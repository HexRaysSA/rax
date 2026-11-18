//! The measured Windows ARM64 CSR exchange for a suspended guest child.
use super::super::query::probe_write;
use crate::user::windows::arch::WinArch;
use crate::user::windows::hle::{ApiResult, Ctx, Flow};
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::objects::Object;
use std::borrow::Cow;
use std::ops::Range;

const API: u32 = 0x0001_001d;
const MESSAGE_BYTES: usize = 0x258;
const CAPTURE_HEADER_BYTES: usize = 0x40;
const POINTER_SLOTS: [usize; 4] = [0x90, 0xa0, 0x108, 0x128];
const MAX_CAPTURE_BYTES: usize = 4096;
const MAX_MANIFEST_BYTES: usize = 65_536;
const ASSEMBLY_NS: &str = "urn:schemas-microsoft-com:asm.v1";

pub(super) fn is_request(message: &[u8]) -> bool {
    message.len() == MESSAGE_BYTES
        && message[..8] == [0x30, 0x02, 0x58, 0x02, 0, 0, 0, 0]
        && read_u32(message, 0x30) == API
}

pub(super) fn register(
    c: &mut Ctx,
    port: u64,
    [
        receive,
        received,
        send_attributes,
        receive_attributes,
        timeout,
    ]: [u64; 5],
    capacity: u64,
    message: &[u8],
) -> ApiResult {
    let version = &c.p.cfg.version;
    if c.arch() != WinArch::Arm64
        || (version.major, version.minor, version.build) != (10, 0, 29708)
        || (send_attributes | receive_attributes | timeout) != 0
    {
        return Err(c.unsupported("unmeasured CSR child-start profile"));
    }

    let process_handle = read_u64(message, 0x40);
    let thread_handle = read_u64(message, 0x48);
    let (Some(Object::Process { pid, .. }), Some(process), Some(thread)) = (
        c.p.objects.get(process_handle),
        c.p.objects.id(process_handle),
        c.p.objects.id(thread_handle),
    ) else {
        return Flow::ret(STATUS_INVALID_HANDLE.into());
    };
    let pid = *pid;
    let capture = read_u64(message, 0x28);
    let mut data = {
        let Some(Object::LpcPort(port)) = c.p.objects.get(port) else {
            unreachable!("verified ALPC port");
        };
        let Some((peer, view)) = port.peer().zip(port.view()) else {
            return Err(c.unsupported("CSR child-start peer view missing"));
        };
        if !peer.arm64_29708_session_one || !c.p.vm.owns_shared_view(view) {
            return Err(c.unsupported("CSR child-start peer outside the selected profile"));
        }
        let remote_end = peer.base.checked_add(view.size);
        let owns = |bytes| {
            capture >= peer.base
                && capture % 8 == 0
                && capture
                    .checked_add(bytes)
                    .zip(remote_end)
                    .is_some_and(|(end, limit)| end <= limit)
        };
        if !owns(CAPTURE_HEADER_BYTES as u64) {
            return Err(c.unsupported("CSR child-start capture header outside peer view"));
        }
        let mem = peer.vm.space();
        let size = mem.u32(capture)? as usize;
        if !(CAPTURE_HEADER_BYTES..=MAX_CAPTURE_BYTES).contains(&size) || !owns(size as u64) {
            return Err(c.unsupported("CSR child-start capture size outside peer view"));
        }
        mem.bytes(capture, size)?
    };
    let Some([dos_path, nt_path, _languages, output]) = capture_strings(message, capture, &data)
    else {
        return Err(c.unsupported("unmeasured CSR child-start capture fields"));
    };
    let Some((dos, nt)) = read_string(&data, &dos_path).zip(read_string(&data, &nt_path)) else {
        return Err(c.unsupported("CSR child-start paths are not valid UTF-16"));
    };
    let Some(identity) =
        c.p.children
            .with_csr_start(pid, process, thread, |child| {
                let path = child.cfg.guest_image_path.as_deref()?;
                if !path.eq_ignore_ascii_case(&dos)
                    || !nt
                        .strip_prefix(r"\??\")
                        .is_some_and(|name| path.eq_ignore_ascii_case(name))
                {
                    return None;
                }
                let (base, size) = child.creation_manifest?;
                if size as usize > MAX_MANIFEST_BYTES {
                    return None;
                }
                let manifest = child.space.bytes(base, size as usize).ok()?;
                manifest_name(&manifest)
            })
            .flatten()
    else {
        return Err(c.unsupported(
            "CSR child-start requires an owned suspended child with a supported manifest",
        ));
    };
    let name: Vec<_> = identity.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let name_end = output.start + name.len();
    if name_end + 2 > output.end {
        return Err(c.unsupported("CSR child-start assembly name exceeds capture buffer"));
    }

    if received != 0 {
        probe_write(c, received, 8)?;
    }
    if capacity < MESSAGE_BYTES as u64 {
        if received != 0 {
            c.write_ptr(received, MESSAGE_BYTES as u64)?;
        }
        return Flow::ret(STATUS_BUFFER_TOO_SMALL.into());
    }
    probe_write(c, receive, MESSAGE_BYTES)?;
    data[output.start..name_end].copy_from_slice(&name);
    data[name_end..name_end + 2].fill(0);
    let (remote_capture, message_id, server_pid, server_thread) = {
        let Some(Object::LpcPort(port)) = c.p.objects.get_mut(port) else {
            unreachable!("verified ALPC port");
        };
        let peer = port.peer_mut().expect("verified CSR peer");
        let (remote_capture, message_id) = match peer.prepare_capture_buffer(&mut data) {
            Ok(reply) => reply,
            Err(error) => return Flow::ret(error.status().into()),
        };
        peer.vm.space().wr(capture, &data)?;
        (
            remote_capture,
            message_id,
            peer.server_pid,
            peer.server_thread,
        )
    };

    let mut reply = message.to_vec();
    reply[4..40].fill(0);
    reply[4..6].copy_from_slice(&2_u16.to_le_bytes());
    reply[8..16].copy_from_slice(&u64::from(server_pid).to_le_bytes());
    reply[16..24].copy_from_slice(&u64::from(server_thread).to_le_bytes());
    reply[24..28].copy_from_slice(&message_id.to_le_bytes());
    reply[32..36].copy_from_slice(&message_id.to_le_bytes());
    reply[0x28..0x30].copy_from_slice(&remote_capture.to_le_bytes());
    reply[0x34..0x38].fill(0);
    reply[0x40..0x50].fill(0);
    reply[0x114..0x118].copy_from_slice(&1_u32.to_le_bytes());
    reply[0x120..0x122].copy_from_slice(&(name.len() as u16).to_le_bytes());
    c.mem().wr(receive, &reply)?;
    if received != 0 {
        c.write_ptr(received, MESSAGE_BYTES as u64)?;
    }
    c.p.children.finish_csr_start(pid);
    Flow::ret(STATUS_SUCCESS.into())
}

struct CapturedString {
    start: usize,
    end: usize,
    input: Range<usize>,
}

fn capture_strings(message: &[u8], capture: u64, data: &[u8]) -> Option<[CapturedString; 4]> {
    if data.len() < CAPTURE_HEADER_BYTES
        || read_u32(data, 0x10) != POINTER_SLOTS.len() as u32
        || read_u64(data, 0x18) != 0
    {
        return None;
    }
    let mut previous_end = CAPTURE_HEADER_BYTES;
    let mut fields = Vec::with_capacity(POINTER_SLOTS.len());
    for (index, slot) in POINTER_SLOTS.into_iter().enumerate() {
        if read_u64(data, 0x20 + 8 * index) != slot as u64 {
            return None;
        }
        let start = usize::try_from(read_u64(message, slot).checked_sub(capture)?).ok()?;
        let used = read_u16(message, slot - 8);
        let length = read_u16(message, slot - 6);
        let end = start.checked_add(length)?;
        if start < previous_end
            || end > data.len()
            || used > length
            || (start | used | length) % 2 != 0
        {
            return None;
        }
        fields.push(CapturedString {
            start,
            end,
            input: start..start + used,
        });
        previous_end = end;
    }
    fields.try_into().ok()
}

fn read_string(data: &[u8], field: &CapturedString) -> Option<String> {
    String::from_utf16(&units(&data[field.input.clone()], u16::from_le_bytes)).ok()
}

fn units(data: &[u8], decode: fn([u8; 2]) -> u16) -> Vec<u16> {
    data.chunks_exact(2)
        .map(|unit| decode(unit.try_into().expect("UTF-16 code unit")))
        .collect()
}

fn manifest_name(manifest: &[u8]) -> Option<String> {
    let xml = match manifest {
        [0xFF, 0xFE, rest @ ..] if rest.len() % 2 == 0 => {
            Cow::Owned(String::from_utf16(&units(rest, u16::from_le_bytes)).ok()?)
        }
        [0xFE, 0xFF, rest @ ..] if rest.len() % 2 == 0 => {
            Cow::Owned(String::from_utf16(&units(rest, u16::from_be_bytes)).ok()?)
        }
        bytes => Cow::Borrowed(
            std::str::from_utf8(bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes)).ok()?,
        ),
    };
    let document = roxmltree::Document::parse_with_options(
        xml.trim_end_matches('\0'),
        roxmltree::ParsingOptions {
            nodes_limit: 4096,
            ..Default::default()
        },
    )
    .ok()?;
    let root = document.root_element();
    if !root.has_tag_name((ASSEMBLY_NS, "assembly"))
        || root.attribute("manifestVersion") != Some("1.0")
        || root
            .children()
            .any(|child| child.has_tag_name((ASSEMBLY_NS, "dependency")))
    {
        return None;
    }
    let mut identities = root
        .children()
        .filter(|child| child.has_tag_name((ASSEMBLY_NS, "assemblyIdentity")));
    let identity = identities.next()?;
    if identities.next().is_some() || identity.attribute("type") != Some("win32") {
        return None;
    }
    let name = identity.attribute("name")?;
    (!name.is_empty()).then(|| name.to_owned())
}

fn read_u16(bytes: &[u8], offset: usize) -> usize {
    usize::from(u16::from_le_bytes(
        bytes[offset..offset + 2].try_into().expect("wire u16"),
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("wire u32"))
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("wire u64"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_csr_child_start_uses_the_application_identity_and_rejects_ambiguous_manifests() {
        let plain = r#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
            <assemblyIdentity type="win32" name="Example.Case&amp;Spacing" version="1.0.0.0"/>
        </assembly>"#;
        assert_eq!(
            manifest_name(plain.as_bytes()).as_deref(),
            Some("Example.Case&Spacing")
        );
        let utf16: Vec<_> = [0xFF, 0xFE]
            .into_iter()
            .chain(plain.encode_utf16().flat_map(u16::to_le_bytes))
            .collect();
        assert_eq!(manifest_name(&utf16), manifest_name(plain.as_bytes()));
        assert!(manifest_name(plain.replace(ASSEMBLY_NS, "urn:other").as_bytes()).is_none());
        for extra in [
            r#"<assemblyIdentity name="Unrelated.Component" type="win32"/>"#,
            r#"<dependency><dependentAssembly><assemblyIdentity name="Library"/></dependentAssembly></dependency>"#,
        ] {
            let invalid = plain.replace("</assembly>", &format!("{extra}</assembly>"));
            assert!(manifest_name(invalid.as_bytes()).is_none());
        }
        let dtd = format!("<!DOCTYPE assembly [<!ELEMENT assembly ANY>]>{plain}");
        assert!(manifest_name(dtd.as_bytes()).is_none());
    }

    #[test]
    fn native_csr_child_start_bounds_all_captured_ranges_before_writing() {
        const REMOTE: u64 = 0x10000;
        let mut message = [0; MESSAGE_BYTES];
        let mut data = [0; 0x150];
        data[0x10..0x14].copy_from_slice(&4u32.to_le_bytes());
        for (i, offset) in POINTER_SLOTS.into_iter().enumerate() {
            let start = 0x40 + i * 8;
            let metadata = 0x20 + i * 8;
            data[metadata..metadata + 8].copy_from_slice(&(offset as u64).to_le_bytes());
            let ptr = REMOTE + start as u64;
            message[offset..offset + 8].copy_from_slice(&ptr.to_le_bytes());
            message[offset - 8..offset - 6].copy_from_slice(&4u16.to_le_bytes());
            message[offset - 6..offset - 4].copy_from_slice(&8u16.to_le_bytes());
        }
        let captured = capture_strings(&message, REMOTE, &data).unwrap();
        assert_eq!(captured[0].input, 0x40..0x44);
        assert_eq!(captured[3].start..captured[3].end, 0x58..0x60);
        assert!(capture_strings(&message, REMOTE, &data[..63]).is_none());
        assert!(capture_strings(&message, REMOTE, &data[..0x5f]).is_none());
        data[0x20] = 0;
        assert!(capture_strings(&message, REMOTE, &data).is_none());
        data[0x20] = POINTER_SLOTS[0] as u8;
        for invalid in [REMOTE - 2, REMOTE + 0x40, REMOTE + 0x59, u64::MAX] {
            message[0x128..0x130].copy_from_slice(&invalid.to_le_bytes());
            assert!(capture_strings(&message, REMOTE, &data).is_none());
        }
    }
}
