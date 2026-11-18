//! Creation of an ordinary guest process from a mapped drive.
//! The guest creates another RAX address space, never a host process.

use super::named_object::{Checked, Failure, finish, status};
use super::query::probe_write;
use crate::user::windows::arch::WinArch;
use crate::user::windows::fs::{self, FileIdentity, FileLifetime};
use crate::user::windows::hle::{ApiResult, Ctx};
use crate::user::windows::layout::offsets;
use crate::user::windows::memory::Mem;
use crate::user::windows::nt::status::*;
use crate::user::windows::object_namespace::{ImageSection, file_image};
use crate::user::windows::objects::{FileObj, Object, Objects};
use crate::user::windows::process::family::{
    ChildInfo, ChildIo, Prepared, create_handle, file_status,
};
use crate::user::windows::registry::{IFEO_KEY, Lookup, RegistryView};
use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::Arc;

const PROCESS_INHERIT_HANDLES: u32 = 4;
const PROCESS_SUSPENDED: u32 = 0x200;
const THREAD_SUSPENDED: u32 = 1;
const ALL_ACCESS: u32 = 0x001f_ffff;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
const NATIVE_CREATE_SIZE: usize = 0x58;
const WOW64_CREATE_SIZE: usize = 0x48;
const ATTR_IMAGE_NAME: u64 = 0x2_0005;
const ATTR_CLIENT_ID: u64 = 0x1_0003;
const ATTR_IMAGE_INFO: u64 = 6;
const ATTR_CHPE: u64 = 0x6_001a;
const WRITE_OUTPUT_ON_EXIT: u32 = 1;
const RTL_PARAMS_NORMALIZED: u32 = 1;
const RTL_APP_MANIFEST_PRESENT: u32 = 0x2000;
const RTL_IMAGE_KEY_MISSING: u32 = 0x4000;
const MAX_ENVIRONMENT: u64 = 1 << 20;
const IMAGE_ACCESS: u32 = 0x0012_00a9;
const IMAGE_SHARE: u32 = 5;
const SECTION_ACCESS: u32 = 0x000f_001f;

pub(super) fn create(c: &mut Ctx) -> ApiResult {
    let result = checked(c);
    finish(c, result)
}

#[derive(Clone, Copy)]
struct CallerAbi {
    pointer: usize,
    create_size: usize,
    image_size: usize,
}

impl CallerAbi {
    fn new(arch: WinArch) -> Self {
        if arch == WinArch::X86 {
            Self {
                pointer: 4,
                create_size: WOW64_CREATE_SIZE,
                image_size: 48,
            }
        } else {
            Self {
                pointer: 8,
                create_size: NATIVE_CREATE_SIZE,
                image_size: 64,
            }
        }
    }

    fn wow64(self) -> bool {
        self.pointer == 4
    }

    fn pointer(self, bytes: &[u8], at: usize) -> u64 {
        if self.wow64() {
            u64::from(dword(bytes, at))
        } else {
            word(bytes, at)
        }
    }
}

#[derive(Default)]
struct Attributes {
    image: Option<String>,
    client_id: Option<Output>,
    image_info: Option<Output>,
    chpe: bool,
}

#[derive(Clone, Copy)]
struct Output {
    value: u64,
    returned: u64,
    size: usize,
}

fn checked(c: &mut Ctx) -> Checked<u32> {
    let (process, thread, process_access, thread_access) =
        (c.ptr(0)?, c.ptr(1)?, grant(c.u32(2)?)?, grant(c.u32(3)?)?);
    let (process_flags, thread_flags) = (c.u32(6)?, c.u32(7)?);
    let (parameters, create_info, attribute_list) = (c.ptr(8)?, c.ptr(9)?, c.ptr(10)?);
    if !c.p.cfg.host_filesystem {
        return status(STATUS_ACCESS_DENIED);
    }
    let abi = CallerAbi::new(c.arch());
    if abi.wow64()
        && !c.p.wow64.as_ref().is_some_and(|state| {
            state.kernel == (10, 0, 29708) && state.machine == WinArch::Arm64.machine()
        })
    {
        return Err(c
            .unsupported("NtCreateUserProcess WoW64 kernel profile")
            .into());
    }
    if c.ptr(4)? != 0
        || c.ptr(5)? != 0
        || process_flags & !(PROCESS_INHERIT_HANDLES | PROCESS_SUSPENDED) != 0
        || thread_flags & !THREAD_SUSPENDED != 0
    {
        return Err(c
            .unsupported("NtCreateUserProcess object attributes or creation flags")
            .into());
    }
    let initial = c.mem().bytes(create_info, abi.create_size)?;
    if abi.pointer(&initial, 0) != abi.create_size as u64 || dword(&initial, abi.pointer) != 0 {
        return status(STATUS_INVALID_PARAMETER);
    }
    let init_flags = dword(&initial, 2 * abi.pointer);
    let image_access = dword(&initial, 2 * abi.pointer + 4);
    if init_flags & 0xffff & !3 != 0 || image_access & !IMAGE_ACCESS != 0 {
        return Err(c
            .unsupported("NtCreateUserProcess initial image flags or access")
            .into());
    }
    let attrs = attributes(c, abi, attribute_list)?;
    let image = attrs
        .image
        .as_ref()
        .ok_or(Failure::Status(STATUS_INVALID_PARAMETER))?;
    let inputs = Parameters::capture(c, abi, parameters, image)?;
    let child_io =
        if process_flags & PROCESS_INHERIT_HANDLES != 0 && c.p.objects.has_inheritable_handles() {
            let objects =
                c.p.objects
                    .inherit_pipe_and_console_handles()
                    .ok_or_else(|| {
                        c.unsupported("NtCreateUserProcess inherits an unsupported object type")
                    })?;
            let standard = inputs.standard.map(|handle| {
                u32::try_from(handle)
                    .ok()
                    .filter(|_| objects.get(handle).is_some())
            });
            ChildIo { objects, standard }
        } else {
            ChildIo::default()
        };
    probe_outputs(c, abi, process, thread, create_info, &attrs)?;
    let mut parameter_flags = initial_parameter_flags(c, &inputs.image)?;

    let path = &inputs.host_image;
    let mut config = (*c.p.cfg).clone();
    config.exe_host_path = path.clone();
    config.guest_image_path = Some(inputs.image.clone());
    config.command_line = Some(inputs.command);
    config.cwd = Some(inputs.cwd);
    config.instruction_trace = None;
    let mut file = File::open(path).map_err(|error| Failure::Status(file_status(&error)))?;
    let metadata = file
        .metadata()
        .map_err(|error| Failure::Status(file_status(&error)))?;
    if !metadata.is_file() {
        return status(STATUS_FILE_IS_A_DIRECTORY);
    }
    let identity = FileIdentity::of_open(path, Some(&file), &metadata)
        .map_err(|error| Failure::Status(file_status(&error)))?;
    let lifetime = super::file_open::shared_lifetime(c, &identity, IMAGE_ACCESS, IMAGE_SHARE)?
        .unwrap_or_else(|| Arc::new(FileLifetime::new(identity)));
    let suspended = thread_flags & THREAD_SUSPENDED != 0 || process_flags & PROCESS_SUSPENDED != 0;
    let mut child = Prepared::spawn(
        c.p,
        config,
        &file,
        &inputs.environment,
        init_flags,
        suspended,
        child_io,
    )
    .map_err(Failure::Status)?;
    if child.state().arch != c.arch() {
        return Err(c
            .unsupported("NtCreateUserProcess cross-architecture startup")
            .into());
    }
    let manifest = child.manifest();
    if manifest.is_some() {
        parameter_flags |= RTL_APP_MANIFEST_PRESENT;
    }
    child
        .state()
        .space
        .w32(
            child.info.parameters + offsets(c.arch()).pp_flags,
            parameter_flags,
        )
        .map_err(|_| Failure::Status(STATUS_NO_MEMORY))?;
    let image_info = if attrs.image_info.is_some() {
        Some(
            child
                .state()
                .image_information
                .as_ref()
                .map_err(|reason| *reason)
                .and_then(|info| info.encode(child.state().arch))
                .map_err(|reason| {
                    c.unsupported(format!("NtCreateUserProcess image information: {reason}"))
                })?,
        )
    } else {
        None
    };
    let native_addresses = if abi.wow64() {
        Some(child.wow64_creation_addresses().map_err(Failure::Status)?)
    } else {
        None
    };
    let extras = if init_flags & WRITE_OUTPUT_ON_EXIT != 0 {
        file.seek(SeekFrom::Start(0))
            .map_err(|error| Failure::Status(file_status(&error)))?;
        Some(image_objects(
            c,
            file,
            path.clone(),
            inputs.image,
            lifetime,
        )?)
    } else {
        None
    };
    let handles = child
        .handles(&mut c.p.objects, process_access, thread_access)
        .ok_or(Failure::Status(STATUS_NO_MEMORY))?;
    let (file_handle, section_handle) = match publish_image_handles(&mut c.p.objects, extras) {
        Ok(result) => result,
        Err(error) => {
            handles.close(&mut c.p.objects);
            return Err(error);
        }
    };
    let success = creation_reply(
        abi,
        child.info,
        file_handle,
        section_handle,
        parameter_flags,
        manifest,
        native_addresses,
    );
    let stores = (|| {
        let mem = c.mem();
        let width = abi.pointer as u64;
        if let Some(out) = attrs.client_id {
            mem.wptr(out.value, width, u64::from(child.info.pid))?;
            mem.wptr(out.value + width, width, u64::from(child.info.primary_tid))?;
            out.write_length(mem, width)?;
        }
        if let (Some(out), Some((bytes, size))) = (attrs.image_info, image_info) {
            mem.wr(out.value, &bytes[..size])?;
            out.write_length(mem, width)?;
        }
        mem.wr(create_info, &success[..abi.create_size])?;
        mem.wptr(process, width, u64::from(handles.process))?;
        mem.wptr(thread, width, u64::from(handles.thread))
    })();
    if let Err(fault) = stores {
        handles.close(&mut c.p.objects);
        let _ = c.p.objects.close(file_handle.into());
        let _ = c.p.objects.close(section_handle.into());
        return Err(fault.into());
    }
    child.install(c.p, handles);
    Ok(STATUS_SUCCESS)
}

fn creation_reply(
    abi: CallerAbi,
    child: ChildInfo,
    file: u32,
    section: u32,
    parameter_flags: u32,
    manifest: Option<(u64, u32)>,
    native_addresses: Option<(u64, u64)>,
) -> [u8; NATIVE_CREATE_SIZE] {
    let mut bytes = [0; NATIVE_CREATE_SIZE];
    put(&mut bytes, abi.pointer, 4, 6);
    let (parameters, peb, parameter_flags_at, manifest_at) =
        if let Some((native_parameters, native_peb)) = native_addresses {
            put(&mut bytes, 0, 4, WOW64_CREATE_SIZE as u64);
            put(&mut bytes, 12, 4, u64::from(file));
            put(&mut bytes, 16, 4, u64::from(section));
            put(&mut bytes, 32, 4, child.parameters);
            put(&mut bytes, 48, 4, child.peb);
            (native_parameters, native_peb, 36, 56)
        } else {
            put(&mut bytes, 24, 8, u64::from(file));
            put(&mut bytes, 32, 8, u64::from(section));
            (child.parameters, child.peb, 52, 72)
        };
    let native_parameters_at = if abi.wow64() { 24 } else { 40 };
    put(&mut bytes, native_parameters_at, 8, parameters);
    put(
        &mut bytes,
        parameter_flags_at,
        4,
        u64::from(parameter_flags),
    );
    put(&mut bytes, parameter_flags_at + 4, 8, peb);
    if let Some((address, size)) = manifest {
        put(&mut bytes, 2 * abi.pointer, 4, 8);
        put(&mut bytes, manifest_at, 8, address);
        put(&mut bytes, manifest_at + 8, 4, u64::from(size));
    }
    bytes
}

fn put(bytes: &mut [u8], at: usize, width: usize, value: u64) {
    bytes[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
}

fn initial_parameter_flags(c: &Ctx, image: &str) -> Checked<u32> {
    if c.p.native.is_none() {
        return Ok(RTL_PARAMS_NORMALIZED);
    }
    let name = image.rsplit('\\').next().expect("normalized image name");
    let path: Vec<_> = format!("{IFEO_KEY}\\{name}").encode_utf16().collect();
    match c.p.registry.lookup_view(&path, RegistryView::Native64) {
        Lookup::Missing | Lookup::MissingPath => Ok(RTL_PARAMS_NORMALIZED | RTL_IMAGE_KEY_MISSING),
        Lookup::Present(_) => Err(c
            .unsupported("NtCreateUserProcess image-specific execution options")
            .into()),
        Lookup::Unselected => Err(c
            .unsupported("NtCreateUserProcess image execution-options lookup unavailable")
            .into()),
    }
}

fn image_objects(
    c: &Ctx,
    file: File,
    path: PathBuf,
    guest_path: String,
    lifetime: Arc<FileLifetime>,
) -> Checked<(Object, Object)> {
    let backing =
        file_image::acquire(&file, 0, 2, 0x0100_0000, c.p.native.is_some()).map_err(|error| {
            match error {
                file_image::Error::Status(value) => Failure::Status(value),
                file_image::Error::Unavailable(reason) => Failure::Api(c.unsupported(reason)),
            }
        })?;
    let section = ImageSection::created(backing, Arc::clone(&lifetime), None);
    let file = FileObj {
        host: Some(file),
        host_path: path,
        path: guest_path,
        access: IMAGE_ACCESS,
        share: IMAGE_SHARE,
        lifetime,
        null: false,
        append: false,
        delete_on_close: false,
        directory: false,
        overlapped: false,
    };
    Ok((Object::File(file), Object::ImageSection(section)))
}

fn publish_image_handles(
    objects: &mut Objects,
    extras: Option<(Object, Object)>,
) -> Checked<(u32, u32)> {
    let Some((file, section)) = extras else {
        return Ok((0, 0));
    };
    let (_, file) =
        create_handle(objects, file, IMAGE_ACCESS).ok_or(Failure::Status(STATUS_NO_MEMORY))?;
    if let Some((_, section)) = create_handle(objects, section, SECTION_ACCESS) {
        return Ok((file, section));
    }
    let _ = objects.close(file.into());
    status(STATUS_NO_MEMORY)
}

fn grant(access: u32) -> Checked<u32> {
    if access & !(ALL_ACCESS | MAXIMUM_ALLOWED) != 0 {
        return status(STATUS_ACCESS_DENIED);
    }
    Ok(if access & MAXIMUM_ALLOWED != 0 {
        ALL_ACCESS
    } else {
        access
    })
}

fn attributes(c: &Ctx, abi: CallerAbi, address: u64) -> Checked<Attributes> {
    let mem = c.mem();
    let width = abi.pointer;
    let row_width = 4 * width;
    let length = c.read_ptr(address)?;
    if !((width + row_width) as u64..=(width + 4 * row_width) as u64).contains(&length)
        || (length as usize - width) % row_width != 0
    {
        return status(STATUS_INVALID_PARAMETER);
    }
    let raw = mem.bytes(address, length as usize)?;
    let mut attrs = Attributes::default();
    for row in raw[width..].chunks_exact(row_width) {
        let [kind, size, value, returned] =
            [0, width, 2 * width, 3 * width].map(|offset| abi.pointer(row, offset));
        match kind {
            ATTR_IMAGE_NAME if attrs.image.is_none() && returned == 0 => {
                attrs.image = Some(string(mem, size, value)?);
            }
            ATTR_CLIENT_ID if attrs.client_id.is_none() && size == (2 * width) as u64 => {
                attrs.client_id = Some(Output {
                    value,
                    returned,
                    size: 2 * width,
                });
            }
            ATTR_IMAGE_INFO if attrs.image_info.is_none() && size == abi.image_size as u64 => {
                attrs.image_info = Some(Output {
                    value,
                    returned,
                    size: abi.image_size,
                });
            }
            ATTR_CHPE
                if !attrs.chpe
                    && size == 1
                    && value == 1
                    && returned == 0
                    && (c.arch() == WinArch::Arm64 || abi.wow64()) =>
            {
                attrs.chpe = true;
            }
            ATTR_IMAGE_NAME | ATTR_CLIENT_ID | ATTR_IMAGE_INFO | ATTR_CHPE => {
                return status(STATUS_INVALID_PARAMETER);
            }
            _ => {
                return Err(c
                    .unsupported(format!("NtCreateUserProcess attribute {kind:#x}"))
                    .into());
            }
        }
    }
    Ok(attrs)
}

fn probe_outputs(
    c: &Ctx,
    abi: CallerAbi,
    process: u64,
    thread: u64,
    create: u64,
    attrs: &Attributes,
) -> Checked<()> {
    let mut spans = vec![
        (process, abi.pointer, abi.pointer),
        (thread, abi.pointer, abi.pointer),
        (create, abi.create_size, 8),
    ];
    for out in [attrs.client_id, attrs.image_info].into_iter().flatten() {
        spans.push((out.value, out.size, abi.pointer));
        if out.returned != 0 {
            spans.push((out.returned, abi.pointer, abi.pointer));
        }
    }
    for &(addr, size, alignment) in &spans {
        if addr % alignment as u64 != 0 {
            return status(STATUS_DATATYPE_MISALIGNMENT);
        }
        probe_write(c, addr, size)?;
    }
    spans.sort_unstable();
    if spans
        .windows(2)
        .any(|pair| pair[0].0.saturating_add(pair[0].1 as u64) > pair[1].0)
    {
        return status(STATUS_INVALID_PARAMETER);
    }
    Ok(())
}

impl Output {
    fn write_length(
        self,
        mem: &impl Mem,
        width: u64,
    ) -> Result<(), crate::user::windows::memory::MemFault> {
        if self.returned != 0 {
            mem.wptr(self.returned, width, self.size as u64)?;
        }
        Ok(())
    }
}

struct Parameters {
    host_image: PathBuf,
    image: String,
    command: String,
    cwd: String,
    environment: Vec<u8>,
    standard: [u64; 3],
}

impl Parameters {
    fn capture(c: &Ctx, abi: CallerAbi, address: u64, image: &str) -> Checked<Self> {
        let layout = offsets(c.arch());
        let mem = c.mem();
        let header = mem.bytes(
            address,
            (layout.pp_environment_size + abi.pointer as u64) as usize,
        )?;
        let max = dword(&header, layout.pp_maximum_length as usize);
        let len = dword(&header, layout.pp_length as usize);
        if len < header.len() as u32
            || len > max
            || dword(&header, layout.pp_flags as usize) & 1 == 0
        {
            return status(STATUS_INVALID_PARAMETER);
        }
        let command = unicode(mem, abi, &header, layout.pp_command_line as usize)?;
        let cwd = unicode(mem, abi, &header, layout.pp_current_directory as usize)?;
        let image = image.strip_prefix("\\??\\").unwrap_or(image);
        let bytes = image.as_bytes();
        if bytes.get(1) != Some(&b':') || !matches!(bytes.get(2), Some(b'\\' | b'/')) {
            return status(STATUS_OBJECT_PATH_SYNTAX_BAD);
        }
        let mut path = fs::full_path(image, "C:\\")
            .filter(|path| {
                !path.parts.is_empty() && path.parts.iter().all(|part| !part.contains(':'))
            })
            .ok_or(Failure::Status(STATUS_OBJECT_PATH_SYNTAX_BAD))?;
        if abi.wow64()
            && let Some(redirected) =
                c.p.native
                    .as_ref()
                    .and_then(|runtime| wow64_child_alias(runtime, &path.to_string_path()))
        {
            path = fs::full_path(&redirected, "C:\\")
                .ok_or(Failure::Status(STATUS_OBJECT_PATH_SYNTAX_BAD))?;
        }
        let host_image =
            c.p.cfg
                .drives
                .resolve(&path)
                .ok_or(Failure::Status(STATUS_OBJECT_PATH_NOT_FOUND))?;
        let length = abi.pointer(&header, layout.pp_environment_size as usize);
        let environment = if length == 0 {
            vec![0; 4]
        } else {
            if !(4..=MAX_ENVIRONMENT).contains(&length) || length % 2 != 0 {
                return status(STATUS_INVALID_PARAMETER);
            }
            let bytes = mem.bytes(
                abi.pointer(&header, layout.pp_environment as usize),
                length as usize,
            )?;
            if !bytes.ends_with(&[0; 4]) {
                return status(STATUS_INVALID_PARAMETER);
            }
            bytes
        };
        Ok(Self {
            host_image,
            image: path.to_string_path(),
            command,
            cwd,
            environment,
            standard: [
                layout.pp_std_input,
                layout.pp_std_output,
                layout.pp_std_error,
            ]
            .map(|offset| abi.pointer(&header, offset as usize)),
        })
    }
}

fn unicode(mem: &impl Mem, abi: CallerAbi, input: &[u8], offset: usize) -> Checked<String> {
    let len = u64::from(u16::from_le_bytes(
        input[offset..offset + 2].try_into().unwrap(),
    ));
    let max = u64::from(u16::from_le_bytes(
        input[offset + 2..offset + 4].try_into().unwrap(),
    ));
    if len > max {
        return status(STATUS_INVALID_PARAMETER);
    }
    string(mem, len, abi.pointer(input, offset + abi.pointer))
}

fn string(mem: &impl Mem, size: u64, address: u64) -> Checked<String> {
    if size > 0xfffe || size % 2 != 0 {
        return status(STATUS_INVALID_PARAMETER);
    }
    if size == 0 {
        return Ok(String::new());
    }
    let raw = mem.bytes(address, size as usize)?;
    String::from_utf16(
        &raw.chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect::<Vec<_>>(),
    )
    .ok()
    .filter(|string| !string.contains('\0'))
    .ok_or(Failure::Status(STATUS_INVALID_PARAMETER))
}

pub(super) fn wow64_child_alias(
    runtime: &crate::user::windows::native::NativeRuntime,
    path: &str,
) -> Option<String> {
    let windows = runtime.guest_root.trim_end_matches('\\');
    let system = runtime.guest_directory.trim_end_matches('\\');
    path.eq_ignore_ascii_case(&format!(r"{windows}\System32\cmd.exe"))
        .then(|| format!(r"{system}\cmd.exe"))
}

fn dword(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn word(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wow64_process_create_reply_keeps_each_record_width_and_address_space() {
        let child = ChildInfo {
            pid: 0x104,
            primary_tid: 0x108,
            peb: 0x026a_1000,
            parameters: 0x0247_0000,
        };
        let manifest = Some((0x0043_3350, 0x426));
        let native_parameters = 0x0245_0000;
        let native_peb = 0x026a_0000;
        let wow = CallerAbi::new(WinArch::X86);
        let reply = creation_reply(
            wow,
            child,
            0x228,
            0x224,
            0x6001,
            manifest,
            Some((native_parameters, native_peb)),
        );
        let expected = [
            0x48,
            6,
            8,
            0x228,
            0x224,
            0,
            0x0245_0000,
            0,
            0x0247_0000,
            0x6001,
            0x026a_0000,
            0,
            0x026a_1000,
            0,
            0x0043_3350,
            0,
            0x426,
            0,
        ];
        assert_eq!(
            reply[..wow.create_size]
                .chunks_exact(4)
                .map(|word| dword(word, 0))
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(reply[wow.create_size..], [0; 16]);
        for arch in [WinArch::Arm64, WinArch::X64] {
            let native = CallerAbi::new(arch);
            let reply = creation_reply(native, child, 0x228, 0x224, 0x6001, manifest, None);
            let expected = [
                0,
                0,
                6,
                0,
                8,
                0,
                0x228,
                0,
                0x224,
                0,
                0x0247_0000,
                0,
                0,
                0x6001,
                0x026a_1000,
                0,
                0,
                0,
                0x0043_3350,
                0,
                0x426,
                0,
            ];
            assert_eq!(
                reply
                    .chunks_exact(4)
                    .map(|word| dword(word, 0))
                    .collect::<Vec<_>>(),
                expected
            );
        }
    }
}
