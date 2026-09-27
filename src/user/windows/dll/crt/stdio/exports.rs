use super::api;
use super::io;
use crate::user::windows::hle::{Archs, Arg::*, Conv::Cdecl, DataSize, Export};

pub(crate) static STDIO_EXPORTS: &[Export] = &[
    Export::func("setvbuf", Cdecl, &[Ptr, Ptr, I32, Ptr], api::setvbuf),
    Export::func("fflush", Cdecl, &[Ptr], io::fflush),
    Export::func("fread", Cdecl, &[Ptr, Ptr, Ptr, Ptr], io::fread),
    Export::func("fwrite", Cdecl, &[Ptr, Ptr, Ptr, Ptr], io::fwrite),
    Export::func("fclose", Cdecl, &[Ptr], io::fclose),
    Export::func("feof", Cdecl, &[Ptr], api::feof),
    Export::func("ferror", Cdecl, &[Ptr], api::ferror),
    Export::func("clearerr", Cdecl, &[Ptr], api::clearerr),
    Export::func("_fileno", Cdecl, &[Ptr], api::fileno),
    Export::func("_open_osfhandle", Cdecl, &[Ptr, I32], api::open_osfhandle),
    Export::func("_get_osfhandle", Cdecl, &[I32], api::get_osfhandle),
    Export::func("_fdopen", Cdecl, &[I32, Ptr], api::fdopen),
    Export::func("_wfdopen", Cdecl, &[I32, Ptr], api::wfdopen),
    Export::func("_close", Cdecl, &[I32], api::close),
    Export::func("_setmode", Cdecl, &[I32, I32], api::setmode),
    Export::func("_read", Cdecl, &[I32, Ptr, I32], io::read),
    Export::func("_write", Cdecl, &[I32, Ptr, I32], io::write),
];

pub(crate) static MSVCRT_STDIO_EXPORTS: &[Export] = &[
    Export::data("_fmode", DataSize::Bytes(4)),
    Export::data("_commode", DataSize::Bytes(4)),
    // This EAT entry is the array itself, not a pointer cell.
    Export::data("_iob", DataSize::Bytes(20 * 32)).only(Archs::X86),
    Export::data("_iob", DataSize::Bytes(20 * 48)).only(Archs::WIN64),
    Export::func("__p__iob", Cdecl, &[], api::iob).only(Archs::X86),
    Export::func("__iob_func", Cdecl, &[], api::iob).only(Archs::WIN64),
    Export::func("__p__fmode", Cdecl, &[], api::fmode_pointer).only(Archs::X86),
    Export::func("__p__commode", Cdecl, &[], api::commode_pointer).only(Archs::X86),
    Export::func("_get_fmode", Cdecl, &[Ptr], api::get_fmode).only(Archs::ARM64),
    Export::func("_set_fmode", Cdecl, &[I32], api::set_fmode).only(Archs::ARM64),
];

pub(crate) static UCRT_STDIO_EXPORTS: &[Export] = &[
    Export::func("__acrt_iob_func", Cdecl, &[I32], api::acrt_iob),
    Export::func("__p__fmode", Cdecl, &[], api::fmode_pointer),
    Export::func("__p__commode", Cdecl, &[], api::commode_pointer),
    Export::func("_get_fmode", Cdecl, &[Ptr], api::get_fmode),
    Export::func("_set_fmode", Cdecl, &[I32], api::set_fmode),
];
