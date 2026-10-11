//! Address-space layout and the offsets of the process and thread
//! environment structures.
//!
//! Field offsets marked "(winternl.h)" or "(winnt.h)" are verified by
//! compiling `offsetof` probes against the mingw-w64 14.0 headers for
//! i686, x86_64, and (with Zig's bundled mingw-w64 13.0 headers) aarch64
//! (`tests/fixtures/user/windows/layout/`). The remaining `PEB`, `TEB`,
//! `LDR_DATA_TABLE_ENTRY`, and `RTL_USER_PROCESS_PARAMETERS` fields are not
//! in the public headers. ApiSetMap and the x86 transition slot carry the
//! native probe identities documented below. The remaining fields belong to
//! the supplied modern private-layout profile; no Windows build/PDB identifiers or retained symbol probes
//! establish their native provenance. Native equivalence of those private
//! fields is unknown. Matching a public padding span does not establish the
//! private field's identity or semantics.
//!
//! ARM64 processes use the 64-bit layouts.

use super::arch::WinArch;

/// `KUSER_SHARED_DATA`, mapped read-only in every process.
pub const KUSER_SHARED_DATA: u64 = 0x7FFE_0000;
/// Lowest address an allocation may use (the first 64 KiB are reserved).
pub const LOWEST_USER_ADDRESS: u64 = 0x1_0000;

/// Exclusive upper bound of user addresses: 2 GiB for a 32-bit process
/// (4 GiB minus 64 KiB when it is large-address-aware, under WoW64), and
/// `MmHighestUserAddress + 1` (0x7FFF_FFFF_0000) for a 64-bit process.
pub fn user_limit(arch: WinArch, large_address_aware: bool) -> u64 {
    match arch {
        WinArch::X86 if large_address_aware => 0xFFFF_0000,
        WinArch::X86 => 0x7FFF_0000,
        _ => 0x7FFF_FFFF_0000,
    }
}

/// The region holding the PEB and the TEBs, just below
/// `KUSER_SHARED_DATA` (the Windows XP x86 placement: PEB at 0x7FFDF000,
/// TEBs below it).
pub const SYSTEM_AREA: u64 = 0x7FF0_0000;
/// End of [`SYSTEM_AREA`].
pub const SYSTEM_AREA_END: u64 = 0x7FFE_0000;
/// The PEB.
pub const PEB_ADDRESS: u64 = 0x7FFD_F000;
/// x86 TEB transition pointer read by selected WoW64 NTDLL leaves. Verified
/// on Windows 10.0.29683.1000 with a native x86 TEB and export-byte probe.
pub(crate) const WOW64_TEB_TRANSITION: u64 = 0xC0;

/// Bytes reserved for one TEB (the 64-bit TEB is 0x1838 bytes).
pub fn teb_stride(arch: WinArch) -> u64 {
    if arch.is64() { 0x2000 } else { 0x1000 }
}

/// Where built-in DLL images are placed: upward from this address.
pub fn builtin_dll_base(arch: WinArch) -> u64 {
    match arch {
        WinArch::X86 => 0x7600_0000,
        _ => 0x7FFA_0000_0000,
    }
}

/// Upper bound of the built-in DLL region.
pub fn builtin_dll_limit(arch: WinArch) -> u64 {
    match arch {
        WinArch::X86 => 0x7F00_0000,
        _ => 0x7FFF_0000_0000,
    }
}

/// Structure offsets for one pointer width.
#[derive(Clone, Copy, Debug)]
pub struct Offsets {
    /// Pointer size.
    pub ptr: u64,
    /// `sizeof(UNICODE_STRING)`.
    pub unicode_string: u64,
    /// `sizeof(LIST_ENTRY)`.
    pub list_entry: u64,

    // ---- PEB
    /// `PEB.BeingDebugged` (winternl.h).
    pub peb_being_debugged: u64,
    /// `PEB.Mutant`.
    pub peb_mutant: u64,
    /// `PEB.ImageBaseAddress`.
    pub peb_image_base: u64,
    /// `PEB.Ldr` (winternl.h).
    pub peb_ldr: u64,
    /// `PEB.ProcessParameters` (winternl.h).
    pub peb_process_parameters: u64,
    /// `PEB.ProcessHeap`.
    pub peb_process_heap: u64,
    /// `PEB.FastPebLock`.
    pub peb_fast_peb_lock: u64,
    /// Modern private `PEB.ApiSetMap`; the ARM64 installed version-6
    /// namespace is checked against `RtlGetCurrentPeb` by the native probe.
    pub peb_api_set_map: u64,
    /// `PEB.TlsExpansionCounter`.
    pub peb_tls_expansion_counter: u64,
    /// `PEB.TlsBitmap`.
    pub peb_tls_bitmap: u64,
    /// `PEB.TlsBitmapBits`.
    pub peb_tls_bitmap_bits: u64,
    /// `PEB.NumberOfProcessors`.
    pub peb_number_of_processors: u64,
    /// `PEB.NtGlobalFlag`.
    pub peb_nt_global_flag: u64,
    /// `PEB.HeapSegmentReserve`.
    pub peb_heap_segment_reserve: u64,
    /// `PEB.NumberOfHeaps`.
    pub peb_number_of_heaps: u64,
    /// `PEB.MaximumNumberOfHeaps`.
    pub peb_maximum_number_of_heaps: u64,
    /// `PEB.ProcessHeaps`.
    pub peb_process_heaps: u64,
    /// `PEB.LoaderLock`.
    pub peb_loader_lock: u64,
    /// `PEB.OSMajorVersion`.
    pub peb_os_major: u64,
    /// `PEB.OSMinorVersion`.
    pub peb_os_minor: u64,
    /// `PEB.OSBuildNumber`.
    pub peb_os_build: u64,
    /// `PEB.OSPlatformId`.
    pub peb_os_platform_id: u64,
    /// `PEB.ImageSubsystem`.
    pub peb_image_subsystem: u64,
    /// `PEB.ImageSubsystemMajorVersion`.
    pub peb_image_subsystem_major: u64,
    /// `PEB.ImageSubsystemMinorVersion`.
    pub peb_image_subsystem_minor: u64,
    /// `PEB.PostProcessInitRoutine` (winternl.h).
    pub peb_post_process_init_routine: u64,
    /// `PEB.SessionId` (winternl.h).
    pub peb_session_id: u64,
    /// Bytes to commit for the PEB.
    pub peb_size: u64,

    // ---- TEB
    /// `NT_TIB.ExceptionList` (winnt.h).
    pub teb_exception_list: u64,
    /// `NT_TIB.StackBase` (winnt.h).
    pub teb_stack_base: u64,
    /// `NT_TIB.StackLimit` (winnt.h).
    pub teb_stack_limit: u64,
    /// `NT_TIB.FiberData`.
    pub teb_fiber_data: u64,
    /// `NT_TIB.Self` (winnt.h).
    pub teb_self: u64,
    /// `TEB.EnvironmentPointer`.
    pub teb_environment_pointer: u64,
    /// `TEB.ClientId.UniqueProcess`.
    pub teb_client_id: u64,
    /// `TEB.ThreadLocalStoragePointer` (the PE specification: "at the
    /// offset of 0x2C from the beginning of TEB" on x86).
    pub teb_tls_pointer: u64,
    /// `TEB.ProcessEnvironmentBlock` (winternl.h).
    pub teb_peb: u64,
    /// `TEB.LastErrorValue`.
    pub teb_last_error: u64,
    /// `TEB.CurrentLocale`.
    pub teb_current_locale: u64,
    /// `TEB.LastStatusValue`.
    pub teb_last_status: u64,
    /// `TEB.DeallocationStack`.
    pub teb_deallocation_stack: u64,
    /// `TEB.TlsSlots` (winternl.h).
    pub teb_tls_slots: u64,
    /// `TEB.TlsLinks`.
    pub teb_tls_links: u64,
    /// `TEB.GuaranteedStackBytes`.
    pub teb_guaranteed_stack_bytes: u64,
    /// `TEB.ReservedForOle` (winternl.h).
    pub teb_reserved_for_ole: u64,
    /// `TEB.TlsExpansionSlots` (winternl.h).
    pub teb_tls_expansion_slots: u64,
    /// Bytes to commit for a TEB.
    pub teb_size: u64,

    // ---- PEB_LDR_DATA
    /// `PEB_LDR_DATA.Length`.
    pub ldr_length: u64,
    /// `PEB_LDR_DATA.Initialized`.
    pub ldr_initialized: u64,
    /// `PEB_LDR_DATA.InLoadOrderModuleList`.
    pub ldr_in_load_order: u64,
    /// `PEB_LDR_DATA.InMemoryOrderModuleList` (winternl.h).
    pub ldr_in_memory_order: u64,
    /// `PEB_LDR_DATA.InInitializationOrderModuleList`.
    pub ldr_in_init_order: u64,
    /// `sizeof(PEB_LDR_DATA)` (Windows 10: 0x30 / 0x58).
    pub ldr_size: u64,

    // ---- LDR_DATA_TABLE_ENTRY
    /// `InLoadOrderLinks`.
    pub entry_in_load_order: u64,
    /// `InMemoryOrderLinks` (winternl.h).
    pub entry_in_memory_order: u64,
    /// `InInitializationOrderLinks`.
    pub entry_in_init_order: u64,
    /// `DllBase` (winternl.h).
    pub entry_dll_base: u64,
    /// `EntryPoint`.
    pub entry_entry_point: u64,
    /// `SizeOfImage`.
    pub entry_size_of_image: u64,
    /// `FullDllName` (winternl.h).
    pub entry_full_name: u64,
    /// `BaseDllName`.
    pub entry_base_name: u64,
    /// `Flags`.
    pub entry_flags: u64,
    /// `ObsoleteLoadCount`.
    pub entry_load_count: u64,
    /// `TlsIndex`.
    pub entry_tls_index: u64,
    /// `HashLinks`.
    pub entry_hash_links: u64,
    /// `TimeDateStamp` (winternl.h).
    pub entry_time_date_stamp: u64,
    /// `OriginalBase`.
    pub entry_original_base: u64,
    /// `LoadReason`.
    pub entry_load_reason: u64,
    /// `ReferenceCount`.
    pub entry_reference_count: u64,
    /// `sizeof(LDR_DATA_TABLE_ENTRY)` (Windows 10: 0xA8 / 0x120).
    pub entry_size: u64,

    // ---- RTL_USER_PROCESS_PARAMETERS
    /// `MaximumLength`.
    pub pp_maximum_length: u64,
    /// `Length`.
    pub pp_length: u64,
    /// `Flags`.
    pub pp_flags: u64,
    /// `ConsoleHandle`.
    pub pp_console_handle: u64,
    /// `ConsoleFlags`.
    pub pp_console_flags: u64,
    /// `StandardInput`.
    pub pp_std_input: u64,
    /// `StandardOutput`.
    pub pp_std_output: u64,
    /// `StandardError`.
    pub pp_std_error: u64,
    /// `CurrentDirectory.DosPath`.
    pub pp_current_directory: u64,
    /// `CurrentDirectory.Handle`.
    pub pp_current_directory_handle: u64,
    /// `DllPath`.
    pub pp_dll_path: u64,
    /// `ImagePathName` (winternl.h).
    pub pp_image_path_name: u64,
    /// `CommandLine` (winternl.h).
    pub pp_command_line: u64,
    /// `Environment`.
    pub pp_environment: u64,
    /// `WindowFlags`.
    pub pp_window_flags: u64,
    /// `ShowWindowFlags`.
    pub pp_show_window_flags: u64,
    /// `WindowTitle`.
    pub pp_window_title: u64,
    /// `DesktopInfo`.
    pub pp_desktop_info: u64,
    /// `ShellInfo`.
    pub pp_shell_info: u64,
    /// `RuntimeData`.
    pub pp_runtime_data: u64,
    /// `EnvironmentSize`.
    pub pp_environment_size: u64,
    /// Structure size through Windows 11 22H2 `HeapMemoryTypeMask`, including
    /// native tail alignment: 0x2C4 bytes (x86), 0x448 bytes (x64/ARM64).
    /// Optional modern fields remain zero in the default process parameters.
    pub pp_size: u64,
}

const OFFSETS32: Offsets = Offsets {
    ptr: 4,
    unicode_string: 8,
    list_entry: 8,
    peb_being_debugged: 0x002,
    peb_mutant: 0x004,
    peb_image_base: 0x008,
    peb_ldr: 0x00C,
    peb_process_parameters: 0x010,
    peb_process_heap: 0x018,
    peb_fast_peb_lock: 0x01C,
    peb_api_set_map: 0x038,
    peb_tls_expansion_counter: 0x03C,
    peb_tls_bitmap: 0x040,
    peb_tls_bitmap_bits: 0x044,
    peb_number_of_processors: 0x064,
    peb_nt_global_flag: 0x068,
    peb_heap_segment_reserve: 0x078,
    peb_number_of_heaps: 0x088,
    peb_maximum_number_of_heaps: 0x08C,
    peb_process_heaps: 0x090,
    peb_loader_lock: 0x0A0,
    peb_os_major: 0x0A4,
    peb_os_minor: 0x0A8,
    peb_os_build: 0x0AC,
    peb_os_platform_id: 0x0B0,
    peb_image_subsystem: 0x0B4,
    peb_image_subsystem_major: 0x0B8,
    peb_image_subsystem_minor: 0x0BC,
    peb_post_process_init_routine: 0x14C,
    peb_session_id: 0x1D4,
    peb_size: 0x480,
    teb_exception_list: 0x000,
    teb_stack_base: 0x004,
    teb_stack_limit: 0x008,
    teb_fiber_data: 0x010,
    teb_self: 0x018,
    teb_environment_pointer: 0x01C,
    teb_client_id: 0x020,
    teb_tls_pointer: 0x02C,
    teb_peb: 0x030,
    teb_last_error: 0x034,
    teb_current_locale: 0x0C4,
    teb_last_status: 0xBF4,
    teb_deallocation_stack: 0xE0C,
    teb_tls_slots: 0xE10,
    teb_tls_links: 0xF10,
    teb_guaranteed_stack_bytes: 0xF78,
    teb_reserved_for_ole: 0xF80,
    teb_tls_expansion_slots: 0xF94,
    teb_size: 0x1000,
    ldr_length: 0x00,
    ldr_initialized: 0x04,
    ldr_in_load_order: 0x0C,
    ldr_in_memory_order: 0x14,
    ldr_in_init_order: 0x1C,
    ldr_size: 0x30,
    entry_in_load_order: 0x00,
    entry_in_memory_order: 0x08,
    entry_in_init_order: 0x10,
    entry_dll_base: 0x18,
    entry_entry_point: 0x1C,
    entry_size_of_image: 0x20,
    entry_full_name: 0x24,
    entry_base_name: 0x2C,
    entry_flags: 0x34,
    entry_load_count: 0x38,
    entry_tls_index: 0x3A,
    entry_hash_links: 0x3C,
    entry_time_date_stamp: 0x44,
    entry_original_base: 0x80,
    entry_load_reason: 0x94,
    entry_reference_count: 0x9C,
    entry_size: 0xA8,
    pp_maximum_length: 0x00,
    pp_length: 0x04,
    pp_flags: 0x08,
    pp_console_handle: 0x10,
    pp_console_flags: 0x14,
    pp_std_input: 0x18,
    pp_std_output: 0x1C,
    pp_std_error: 0x20,
    pp_current_directory: 0x24,
    pp_current_directory_handle: 0x2C,
    pp_dll_path: 0x30,
    pp_image_path_name: 0x38,
    pp_command_line: 0x40,
    pp_environment: 0x48,
    pp_window_flags: 0x68,
    pp_show_window_flags: 0x6C,
    pp_window_title: 0x70,
    pp_desktop_info: 0x78,
    pp_shell_info: 0x80,
    pp_runtime_data: 0x88,
    pp_environment_size: 0x290,
    pp_size: 0x2C4,
};

const OFFSETS64: Offsets = Offsets {
    ptr: 8,
    unicode_string: 16,
    list_entry: 16,
    peb_being_debugged: 0x002,
    peb_mutant: 0x008,
    peb_image_base: 0x010,
    peb_ldr: 0x018,
    peb_process_parameters: 0x020,
    peb_process_heap: 0x030,
    peb_fast_peb_lock: 0x038,
    peb_api_set_map: 0x068,
    peb_tls_expansion_counter: 0x070,
    peb_tls_bitmap: 0x078,
    peb_tls_bitmap_bits: 0x080,
    peb_number_of_processors: 0x0B8,
    peb_nt_global_flag: 0x0BC,
    peb_heap_segment_reserve: 0x0C8,
    peb_number_of_heaps: 0x0E8,
    peb_maximum_number_of_heaps: 0x0EC,
    peb_process_heaps: 0x0F0,
    peb_loader_lock: 0x110,
    peb_os_major: 0x118,
    peb_os_minor: 0x11C,
    peb_os_build: 0x120,
    peb_os_platform_id: 0x124,
    peb_image_subsystem: 0x128,
    peb_image_subsystem_major: 0x12C,
    peb_image_subsystem_minor: 0x130,
    peb_post_process_init_routine: 0x230,
    peb_session_id: 0x2C0,
    peb_size: 0x7C8,
    teb_exception_list: 0x000,
    teb_stack_base: 0x008,
    teb_stack_limit: 0x010,
    teb_fiber_data: 0x020,
    teb_self: 0x030,
    teb_environment_pointer: 0x038,
    teb_client_id: 0x040,
    teb_tls_pointer: 0x058,
    teb_peb: 0x060,
    teb_last_error: 0x068,
    teb_current_locale: 0x108,
    teb_last_status: 0x1250,
    teb_deallocation_stack: 0x1478,
    teb_tls_slots: 0x1480,
    teb_tls_links: 0x1680,
    teb_guaranteed_stack_bytes: 0x1748,
    teb_reserved_for_ole: 0x1758,
    teb_tls_expansion_slots: 0x1780,
    teb_size: 0x2000,
    ldr_length: 0x00,
    ldr_initialized: 0x04,
    ldr_in_load_order: 0x10,
    ldr_in_memory_order: 0x20,
    ldr_in_init_order: 0x30,
    ldr_size: 0x58,
    entry_in_load_order: 0x00,
    entry_in_memory_order: 0x10,
    entry_in_init_order: 0x20,
    entry_dll_base: 0x30,
    entry_entry_point: 0x38,
    entry_size_of_image: 0x40,
    entry_full_name: 0x48,
    entry_base_name: 0x58,
    entry_flags: 0x68,
    entry_load_count: 0x6C,
    entry_tls_index: 0x6E,
    entry_hash_links: 0x70,
    entry_time_date_stamp: 0x80,
    entry_original_base: 0xF8,
    entry_load_reason: 0x10C,
    entry_reference_count: 0x114,
    entry_size: 0x120,
    pp_maximum_length: 0x00,
    pp_length: 0x04,
    pp_flags: 0x08,
    pp_console_handle: 0x10,
    pp_console_flags: 0x18,
    pp_std_input: 0x20,
    pp_std_output: 0x28,
    pp_std_error: 0x30,
    pp_current_directory: 0x38,
    pp_current_directory_handle: 0x48,
    pp_dll_path: 0x50,
    pp_image_path_name: 0x60,
    pp_command_line: 0x70,
    pp_environment: 0x80,
    pp_window_flags: 0xA4,
    pp_show_window_flags: 0xA8,
    pp_window_title: 0xB0,
    pp_desktop_info: 0xC0,
    pp_shell_info: 0xD0,
    pp_runtime_data: 0xE0,
    pp_environment_size: 0x3F0,
    pp_size: 0x448,
};

/// The offsets for `arch`.
pub fn offsets(arch: WinArch) -> &'static Offsets {
    if arch.is64() { &OFFSETS64 } else { &OFFSETS32 }
}

/// `KUSER_SHARED_DATA` field offsets (identical for every architecture;
/// ntddk.h, verified for i686 and x86_64).
pub mod kuser {
    /// `TickCountLowDeprecated`.
    pub const TICK_COUNT_LOW_DEPRECATED: u64 = 0x000;
    /// `TickCountMultiplier`.
    pub const TICK_COUNT_MULTIPLIER: u64 = 0x004;
    /// `InterruptTime` (`KSYSTEM_TIME`).
    pub const INTERRUPT_TIME: u64 = 0x008;
    /// `SystemTime` (`KSYSTEM_TIME`).
    pub const SYSTEM_TIME: u64 = 0x014;
    /// `TimeZoneBias` (`KSYSTEM_TIME`).
    pub const TIME_ZONE_BIAS: u64 = 0x020;
    /// `ImageNumberLow`.
    pub const IMAGE_NUMBER_LOW: u64 = 0x02C;
    /// `ImageNumberHigh`.
    pub const IMAGE_NUMBER_HIGH: u64 = 0x02E;
    /// `NtSystemRoot[260]`.
    pub const NT_SYSTEM_ROOT: u64 = 0x030;
    /// `MaxStackTraceDepth`.
    pub const MAX_STACK_TRACE_DEPTH: u64 = 0x238;
    /// `CryptoExponent`.
    pub const CRYPTO_EXPONENT: u64 = 0x23C;
    /// `TimeZoneId`.
    pub const TIME_ZONE_ID: u64 = 0x240;
    /// `LargePageMinimum`.
    pub const LARGE_PAGE_MINIMUM: u64 = 0x244;
    /// `NtBuildNumber` (Windows 10 and later; `Reserved2[0]` in older
    /// headers).
    pub const NT_BUILD_NUMBER: u64 = 0x260;
    /// `NtProductType`.
    pub const NT_PRODUCT_TYPE: u64 = 0x264;
    /// `ProductTypeIsValid`.
    pub const PRODUCT_TYPE_IS_VALID: u64 = 0x268;
    /// `NativeProcessorArchitecture` (Windows 10 and later; not in the
    /// vendored headers, which predate it).
    pub const NATIVE_PROCESSOR_ARCHITECTURE: u64 = 0x26A;
    /// `NtMajorVersion`.
    pub const NT_MAJOR_VERSION: u64 = 0x26C;
    /// `NtMinorVersion`.
    pub const NT_MINOR_VERSION: u64 = 0x270;
    /// `ProcessorFeatures[64]`.
    pub const PROCESSOR_FEATURES: u64 = 0x274;
    /// `SuiteMask`.
    pub const SUITE_MASK: u64 = 0x2D0;
    /// `KdDebuggerEnabled`.
    pub const KD_DEBUGGER_ENABLED: u64 = 0x2D4;
    /// `ActiveConsoleId`.
    pub const ACTIVE_CONSOLE_ID: u64 = 0x2D8;
    /// `NumberOfPhysicalPages`.
    pub const NUMBER_OF_PHYSICAL_PAGES: u64 = 0x2E8;
    /// `SafeBootMode`.
    pub const SAFE_BOOT_MODE: u64 = 0x2EC;
    /// `TickCount` (`KSYSTEM_TIME`).
    pub const TICK_COUNT: u64 = 0x320;
    /// `Cookie`.
    pub const COOKIE: u64 = 0x330;
    /// `ActiveProcessorCount`.
    pub const ACTIVE_PROCESSOR_COUNT: u64 = 0x3C0;
    /// `ActiveGroupCount`.
    pub const ACTIVE_GROUP_COUNT: u64 = 0x3C4;
}
