//! WoW64 BASE child registration for the measured ARM64 kernel and x86 call site.
use super::super::{alpc::application_manifest_name, process_create::wow64_child_alias};
use super::{ApiErr, ApiResult, Ctx, Flow, Mem, Object, probe_write, selected, write_guard_result};
use crate::user::windows::arch::WinArch;
use crate::user::windows::nt::status::*;
use std::ops::Range;

const REQUEST_BYTES: usize = 0x110;
const ASSEMBLY_PRESENT: u64 = 0x8c;
const ASSEMBLY_LENGTH: u64 = 0x98;

pub(in crate::user::windows::dll::native) fn create_process(c: &mut Ctx) -> ApiResult {
    let result = register(c);
    write_guard_result(c, result)
}

fn register(c: &mut Ctx) -> ApiResult {
    let server = selected(c, true)?;
    if server.metadata.arch != WinArch::Arm64
        || server.metadata.kernel != (10, 0, 29708)
        || !c.p.wow64.as_ref().is_some_and(|state| state.csr.is_some())
    {
        return Err(c.unsupported("WoW64 CSR child-start requires the measured connected process"));
    }

    let argument = c.ptr(0)?;
    let packet: [u8; REQUEST_BYTES] = c
        .mem()
        .bytes(argument, REQUEST_BYTES)?
        .try_into()
        .expect("exact request length");
    let unsupported = || c.unsupported("unmeasured WoW64 CSR child-start fields");
    if !measured_fields(&packet) {
        return Err(unsupported());
    }

    let process_handle = u64::from(dword(&packet, 0));
    let thread_handle = u64::from(dword(&packet, 4));
    let auxiliary_handle = u64::from(dword(&packet, 0x28));
    let pid = dword(&packet, 8);
    let tid = dword(&packet, 0x0c);
    let live_process = matches!(c.p.objects.get(process_handle),
        Some(Object::Process { pid: object_pid, exit_code: None }) if *object_pid == pid);
    let live_thread = matches!(c.p.objects.get(thread_handle),
        Some(Object::Thread { tid: object_tid, exit_code: None }) if *object_tid == tid);
    let (Some(process), Some(thread), Some(_)) = (
        c.p.objects.id(process_handle),
        c.p.objects.id(thread_handle),
        c.p.objects.id(auxiliary_handle),
    ) else {
        return Flow::ret(STATUS_INVALID_HANDLE.into());
    };
    if !live_process || !live_thread {
        return Flow::ret(STATUS_INVALID_HANDLE.into());
    }

    let dos = Utf16::parse(&packet, 0x2c).ok_or_else(unsupported)?;
    let nt = Utf16::parse(&packet, 0x34).ok_or_else(unsupported)?;
    let languages = Utf16::parse(&packet, 0x80).ok_or_else(unsupported)?;
    let output = Utf16::parse(&packet, ASSEMBLY_LENGTH as usize).ok_or_else(unsupported)?;
    let request = argument..argument + REQUEST_BYTES as u64;
    let output_buffer = output.range();
    if intersects(&output_buffer, &request)
        || [&dos, &nt, &languages]
            .iter()
            .any(|input| intersects(&output_buffer, &input.range()))
    {
        return Err(unsupported());
    }
    let dos = dos.read(c)?;
    let nt = nt.read(c)?;
    let _ = languages.read(c)?;
    if !nt
        .strip_prefix(r"\??\")
        .is_some_and(|nt| nt.eq_ignore_ascii_case(&dos))
    {
        return Err(unsupported());
    }
    let path =
        c.p.native
            .as_ref()
            .and_then(|runtime| wow64_child_alias(runtime, &dos))
            .unwrap_or(dos);
    let manifest = (
        u64::from_le_bytes(packet[0x60..0x68].try_into().unwrap()),
        dword(&packet, 0x68),
    );
    let identity =
        c.p.children
            .with_csr_start(pid, process, thread, |child| {
                let expected_path = child.cfg.guest_image_path.as_deref()?;
                if child.creation_manifest != Some(manifest)
                    || !path.eq_ignore_ascii_case(expected_path)
                {
                    return None;
                }
                application_manifest_name(child, manifest)
            })
            .flatten()
            .ok_or_else(|| {
                c.unsupported(
                    "WoW64 CSR child-start requires the owned suspended child and its manifest",
                )
            })?;
    let reply = assembly_reply(&identity, output.capacity).ok_or_else(|| {
        c.unsupported("WoW64 CSR child-start assembly name exceeds the output buffer")
    })?;

    probe_write(c, argument + ASSEMBLY_PRESENT, 4)?;
    probe_write(c, argument + ASSEMBLY_LENGTH, 2)?;
    probe_write(c, output.address, reply.len())?;
    c.mem().wr(output.address, &reply)?;
    c.mem()
        .w16(argument + ASSEMBLY_LENGTH, (reply.len() - 2) as u16)?;
    c.mem().w32(argument + ASSEMBLY_PRESENT, 1)?;
    c.p.children.finish_csr_start(pid);
    Flow::ret(STATUS_SUCCESS.into())
}

fn measured_fields(packet: &[u8; REQUEST_BYTES]) -> bool {
    dword(packet, 0x10) == 0x0008_0000
        && dword(packet, 0x20) == 0x40
        && dword(packet, 0x24) == 0x6001
        && [
            (0x14, 0x20),
            (0x3c, 0x60),
            (0x6c, 0x80),
            (0x88, 0x98),
            (0xa0, REQUEST_BYTES),
        ]
        .into_iter()
        .all(|(start, end)| packet[start..end].iter().all(|&value| value == 0))
}

fn dword(packet: &[u8; REQUEST_BYTES], offset: usize) -> u32 {
    u32::from_le_bytes(packet[offset..offset + 4].try_into().unwrap())
}

fn intersects(a: &Range<u64>, b: &Range<u64>) -> bool {
    a.start < b.end && b.start < a.end
}

struct Utf16 {
    address: u64,
    length: u16,
    capacity: u16,
}

impl Utf16 {
    fn parse(packet: &[u8; REQUEST_BYTES], offset: usize) -> Option<Self> {
        let length = u16::from_le_bytes(packet[offset..offset + 2].try_into().unwrap());
        let capacity = u16::from_le_bytes(packet[offset + 2..offset + 4].try_into().unwrap());
        let address = u64::from(dword(packet, offset + 4));
        (length <= capacity
            && (length | capacity) % 2 == 0
            && address != 0
            && address % 2 == 0
            && address + u64::from(capacity) <= 1 << 32)
            .then_some(Self {
                address,
                length,
                capacity,
            })
    }

    fn range(&self) -> Range<u64> {
        self.address..self.address + u64::from(self.capacity)
    }

    fn read(&self, c: &Ctx) -> Result<String, ApiErr> {
        let bytes = c.mem().bytes(self.address, usize::from(self.length))?;
        let units: Vec<_> = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        String::from_utf16(&units)
            .map_err(|_| c.unsupported("invalid WoW64 CSR child-start UTF-16"))
    }
}

fn assembly_reply(identity: &str, capacity: u16) -> Option<Vec<u8>> {
    let bytes: Vec<_> = identity
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect();
    (bytes.len() <= usize::from(capacity)).then_some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wow64_csr_child_start_bounds_x86_strings_and_preserves_the_output_tail() {
        let mut packet = [0; REQUEST_BYTES];
        packet[0x10..0x14].copy_from_slice(&0x0008_0000u32.to_le_bytes());
        packet[0x20..0x24].copy_from_slice(&0x40u32.to_le_bytes());
        packet[0x24..0x28].copy_from_slice(&0x6001u32.to_le_bytes());
        assert!(measured_fields(&packet));
        for offset in [0x14, 0x3c, 0x6c, 0x88, 0xa0, REQUEST_BYTES - 1] {
            packet[offset] = 1;
            assert!(!measured_fields(&packet));
            packet[offset] = 0;
        }

        let offset = ASSEMBLY_LENGTH as usize;
        packet[offset..offset + 4].copy_from_slice(&[0x76, 0, 0x78, 0]);
        for (pointer, valid) in [
            (0x0000_0000u32, false),
            (0x0000_1041, false),
            (0xffff_ff88, true),
            (0xffff_ff8a, false),
            (0x11000, true),
        ] {
            packet[offset + 4..offset + 8].copy_from_slice(&pointer.to_le_bytes());
            assert_eq!(Utf16::parse(&packet, offset).is_some(), valid);
        }
        let output = Utf16::parse(&packet, offset).unwrap();
        assert!(!intersects(&(0x10ff0..0x11000), &output.range()));
        assert!(intersects(&(0x10ff0..0x11001), &output.range()));

        let name = "Microsoft.Windows.FileSystem.CMD";
        let reply = assembly_reply(name, output.capacity).unwrap();
        let mut actual = [0xa5; 0x78];
        actual[..reply.len()].copy_from_slice(&reply);
        assert_eq!(reply.len(), 66);
        assert_eq!(&actual[64..66], &[0, 0]);
        assert!(actual[66..].iter().all(|byte| *byte == 0xa5));
        assert!(assembly_reply(name, 64).is_none());
    }
}
