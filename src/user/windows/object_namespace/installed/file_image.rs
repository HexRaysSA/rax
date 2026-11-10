//! Native image-section acquisition receives only owned host buffers and files.
use super::{Handle, NtQueryObject, Owned, check, image::Source};
use crate::user::windows::object_namespace::file_image::{Backing, Error};
use std::ffi::c_void;
use std::fs::File;
use std::os::windows::io::AsRawHandle;
use std::ptr::null_mut;

#[repr(C)]
#[derive(Default)]
struct Basic {
    base: usize,
    attributes: u32,
    size: i64,
}
const _: [(); if std::mem::size_of::<usize>() == 8 {
    24
} else {
    16
}] = [(); std::mem::size_of::<Basic>()];

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateSection(
        out: *mut Handle,
        access: u32,
        object: *const c_void,
        maximum: *const i64,
        protection: u32,
        flags: u32,
        file: Handle,
    ) -> i32;
    fn NtQuerySection(
        section: Handle,
        class: u32,
        output: *mut c_void,
        length: usize,
        returned: *mut usize,
    ) -> i32;
}

fn open(file: &File, maximum: u64, protection: u32, flags: u32) -> Result<(Owned, Basic), Error> {
    let value = maximum as i64;
    let mut handle = null_mut();
    // SAFETY: the file owns a live host HANDLE; every other pointer is NULL or
    // references an initialized local native output/input for this synchronous
    // call. No guest pointer, inheritance, name or descriptor is forwarded.
    let status = unsafe {
        NtCreateSection(
            &mut handle,
            0x02000000,
            null_mut(),
            if maximum == 0 {
                std::ptr::null()
            } else {
                &value
            },
            protection,
            flags,
            file.as_raw_handle(),
        )
    };
    if status < 0 {
        if !handle.is_null() {
            drop(Owned(handle));
        }
        return Err(Error::Status(status as u32));
    }
    if handle.is_null() {
        return Err(Error::Unavailable(
            "native image creation returned no handle".into(),
        ));
    }
    let owned = Owned(handle);
    let mut info = Basic::default();
    let mut returned = 0;
    // SAFETY: the owned queryable Section and exact native SIZE_T/structure
    // outputs remain live; neither API retains a caller pointer.
    let status = unsafe {
        NtQuerySection(
            owned.0,
            0,
            (&mut info as *mut Basic).cast(),
            std::mem::size_of::<Basic>(),
            &mut returned,
        )
    };
    check(status, "NtQuerySection created image").map_err(|e| Error::Unavailable(e.to_string()))?;
    if returned != std::mem::size_of::<Basic>()
        || info.base != 0
        || info.size <= 0
        || info.attributes != 0x01800000
    {
        return Err(Error::Unavailable(
            "created native image basic-information profile is unavailable".into(),
        ));
    }
    let mut object = [0u64; 7];
    let mut length = 0;
    // SAFETY: initialized aligned 56-byte OBJECT_BASIC_INFORMATION scratch.
    let status = unsafe { NtQueryObject(owned.0, 0, object.as_mut_ptr().cast(), 56, &mut length) };
    check(status, "NtQueryObject created private image")
        .map_err(|e| Error::Unavailable(e.to_string()))?;
    let bytes = object[0].to_le_bytes();
    if u32::from_le_bytes(bytes[4..8].try_into().unwrap()) & 5 != 5 {
        return Err(Error::Unavailable(
            "private native image lacks query/read authority".into(),
        ));
    }
    Ok((owned, info))
}

pub(in crate::user::windows::object_namespace) fn acquire(
    file: &File,
    maximum: u64,
    protection: u32,
    flags: u32,
    no_execute: bool,
) -> Result<Backing, Error> {
    let requested = maximum;
    let (created, original) = open(file, maximum, protection, flags)?;
    let maximum = original.size as u64;
    let source = if requested == 0 {
        Source::created(created, original.attributes, maximum, None, no_execute)
    } else {
        // Even a page-aligned maximum may truncate the image. Its full template
        // and original reported extent have separate retained kernel handles.
        let (full, info) = open(file, 0, protection, flags)?;
        Source::created(
            full,
            info.attributes,
            info.size as u64,
            Some(created),
            no_execute,
        )
    };
    let template = source
        .image()
        .map_err(|e| Error::Unavailable(format!("created kernel image template: {e}")))?;
    Ok(Backing {
        template,
        maximum,
        attributes: original.attributes,
        no_execute,
        source: Some(source),
    })
}
