//! True named DLL bindings, not local compatibility members in import archives.
//! Inventory/provenance: docs/specifications/windows/crt-startup/README.md.

use super::*;
use crate::user::windows::hle::{Archs, Arg::*, Conv::Cdecl, DataSize, Export};

pub(crate) static MSVCRT_STARTUP_EXPORTS: &[Export] = &[
    Export::data("__argc", DataSize::Bytes(4)),
    Export::data("__argv", DataSize::Ptrs(1)),
    Export::data("__wargv", DataSize::Ptrs(1)),
    Export::data("_acmdln", DataSize::Ptrs(1)),
    Export::data("_wcmdln", DataSize::Ptrs(1)),
    Export::data("_pgmptr", DataSize::Ptrs(1)),
    Export::data("_wpgmptr", DataSize::Ptrs(1)),
    Export::data("_environ", DataSize::Ptrs(1)).only(Archs::X86_FAMILY),
    Export::data("_wenviron", DataSize::Ptrs(1)).only(Archs::X86_FAMILY),
    Export::data("__initenv", DataSize::Ptrs(1)).only(Archs::X86_FAMILY),
    Export::data("__winitenv", DataSize::Ptrs(1)).only(Archs::X86_FAMILY),
    Export::func("__p___argc", Cdecl, &[], argc_pointer).only(Archs::X86),
    Export::func("__p___argv", Cdecl, &[], argv_pointer).only(Archs::X86),
    Export::func("__p___wargv", Cdecl, &[], wargv_pointer).only(Archs::X86),
    Export::func("__p___initenv", Cdecl, &[], initenv_pointer).only(Archs::X86),
    Export::func("__p___winitenv", Cdecl, &[], winitenv_pointer).only(Archs::X86),
    Export::func("__p__environ", Cdecl, &[], environ_pointer).only(Archs::X86),
    Export::func("__p__wenviron", Cdecl, &[], wenviron_pointer).only(Archs::X86),
    Export::func("__p__acmdln", Cdecl, &[], acmdln_pointer).only(Archs::X86),
    Export::func("__p__wcmdln", Cdecl, &[], wcmdln_pointer).only(Archs::X86),
    Export::func("__p__pgmptr", Cdecl, &[], pgmptr_pointer).only(Archs::X86),
    Export::func("__p__wpgmptr", Cdecl, &[], wpgmptr_pointer).only(Archs::X86),
    Export::func(
        "__getmainargs",
        Cdecl,
        &[Ptr, Ptr, Ptr, I32, Ptr],
        getmainargs,
    ),
    Export::func(
        "__wgetmainargs",
        Cdecl,
        &[Ptr, Ptr, Ptr, I32, Ptr],
        wgetmainargs,
    ),
    // ARM64 headers declare void getters instead of absent environment DATA.
    Export::func("_get_environ", Cdecl, &[Ptr], get_environ).only(Archs::ARM64),
    Export::func("_get_wenviron", Cdecl, &[Ptr], get_wenviron).only(Archs::ARM64),
    Export::func("?_set_new_mode@@YAHH@Z", Cdecl, &[I32], set_new_mode),
    Export::func("?_query_new_mode@@YAHXZ", Cdecl, &[], query_new_mode).only(Archs::X86_FAMILY),
];

pub(crate) static UCRT_STARTUP_EXPORTS: &[Export] = &[
    Export::func("__p___argc", Cdecl, &[], argc_pointer),
    Export::func("__p___argv", Cdecl, &[], argv_pointer),
    Export::func("__p___wargv", Cdecl, &[], wargv_pointer),
    Export::func("__p__environ", Cdecl, &[], environ_pointer),
    Export::func("__p__wenviron", Cdecl, &[], wenviron_pointer),
    Export::func("__p__acmdln", Cdecl, &[], acmdln_pointer),
    Export::func("__p__wcmdln", Cdecl, &[], wcmdln_pointer),
    Export::func("__p__pgmptr", Cdecl, &[], pgmptr_pointer),
    Export::func("__p__wpgmptr", Cdecl, &[], wpgmptr_pointer),
    Export::func("_configure_narrow_argv", Cdecl, &[I32], configure_narrow),
    Export::func("_configure_wide_argv", Cdecl, &[I32], configure_wide),
    Export::func(
        "_initialize_narrow_environment",
        Cdecl,
        &[],
        initialize_narrow_environment,
    ),
    Export::func(
        "_initialize_wide_environment",
        Cdecl,
        &[],
        initialize_wide_environment,
    ),
    Export::func(
        "_get_initial_narrow_environment",
        Cdecl,
        &[],
        initial_narrow_environment,
    ),
    Export::func(
        "_get_initial_wide_environment",
        Cdecl,
        &[],
        initial_wide_environment,
    ),
    Export::func(
        "_get_narrow_winmain_command_line",
        Cdecl,
        &[],
        narrow_winmain,
    ),
    Export::func("_get_wide_winmain_command_line", Cdecl, &[], wide_winmain),
    Export::func("_get_pgmptr", Cdecl, &[Ptr], get_pgmptr),
    Export::func("_get_wpgmptr", Cdecl, &[Ptr], get_wpgmptr),
    Export::func("_set_new_mode", Cdecl, &[I32], set_new_mode),
    Export::func("_query_new_mode", Cdecl, &[], query_new_mode),
];
