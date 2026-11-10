/* Fixed-path, user-mode device-handle observations. No device control requests. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <shellapi.h>
#include <sddl.h>
#include <fcntl.h>
#include <io.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>

typedef NTSTATUS (NTAPI *open_fn)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
    PIO_STATUS_BLOCK, ULONG, ULONG);
typedef NTSTATUS (NTAPI *create_fn)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
    PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *query_object_fn)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *query_file_fn)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);
typedef NTSTATUS (NTAPI *duplicate_fn)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
typedef NTSTATUS (NTAPI *close_fn)(HANDLE);
typedef NTSTATUS (NTAPI *version_fn)(PRTL_OSVERSIONINFOW);

struct case_input {
    const char *label;
    const wchar_t *name;
    ULONG access;
    ULONG share;
    ULONG options;
    ULONG attributes;
};

static const struct case_input cases[] = {
    {"observed", L"\\Device\\KsecDD", 0x100001, 7, 0x20, 0x40},
    {"asynchronous", L"\\Device\\KsecDD", 0x100001, 7, 0, 0x40},
    {"zero_access", L"\\Device\\KsecDD", 0, 7, 0, 0x40},
    {"read_data", L"\\Device\\KsecDD", 1, 7, 0, 0x40},
    {"read_attributes", L"\\Device\\KsecDD", 0x80, 7, 0, 0x40},
    {"synchronize", L"\\Device\\KsecDD", 0x100000, 7, 0x20, 0x40},
    {"generic_read", L"\\Device\\KsecDD", 0x80000000, 7, 0x20, 0x40},
    {"generic_all", L"\\Device\\KsecDD", 0x10000000, 7, 0x20, 0x40},
    {"read_control", L"\\Device\\KsecDD", 0x20000, 7, 0, 0x40},
    {"exclusive", L"\\Device\\KsecDD", 0x100001, 0, 0x20, 0x40},
    {"directory", L"\\Device\\KsecDD", 0x100001, 7, 0x21, 0x40},
    {"non_directory", L"\\Device\\KsecDD", 0x100001, 7, 0x60, 0x40},
    {"contradictory_directory", L"\\Device\\KsecDD", 0x100001, 7, 0x61, 0x40},
    {"exact_case_sensitive", L"\\Device\\KsecDD", 0x100001, 7, 0x20, 0},
    {"lower_case_insensitive", L"\\device\\ksecdd", 0x100001, 7, 0x20, 0x40},
    {"lower_case_sensitive", L"\\device\\ksecdd", 0x100001, 7, 0x20, 0},
    {"child_name", L"\\Device\\KsecDD\\child", 0x100001, 7, 0x20, 0x40}
};

static void bytes(FILE *output, const void *data, size_t length)
{
    const unsigned char *input = (const unsigned char *)data;
    fputc('"', output);
    for (size_t i = 0; i < length; ++i)
        fprintf(output, "%02x", input[i]);
    fputc('"', output);
}

static NTSTATUS completed(HANDLE handle, NTSTATUS status, PIO_STATUS_BLOCK io)
{
    if ((ULONG)status != 0x103)
        return status;
    /* Keep the caller's IO_STATUS_BLOCK and destination alive until completion.
       An unexpected unwaitable pending request fails this producer, not the OS. */
    if (!handle || handle == INVALID_HANDLE_VALUE ||
        handle == (HANDLE)(ULONG_PTR)0x13579bdf ||
        WaitForSingleObject(handle, INFINITE) != WAIT_OBJECT_0)
        ExitProcess(8);
    return io->Status;
}

static int observe(const wchar_t *output_path)
{
    HMODULE module = GetModuleHandleW(L"ntdll.dll");
    open_fn open_file = (open_fn)GetProcAddress(module, "NtOpenFile");
    create_fn create_file = (create_fn)GetProcAddress(module, "NtCreateFile");
    query_object_fn query_object = (query_object_fn)GetProcAddress(module, "NtQueryObject");
    query_file_fn query_file = (query_file_fn)GetProcAddress(module, "NtQueryInformationFile");
    query_file_fn query_volume = (query_file_fn)GetProcAddress(module, "NtQueryVolumeInformationFile");
    duplicate_fn duplicate = (duplicate_fn)GetProcAddress(module, "NtDuplicateObject");
    close_fn close_handle = (close_fn)GetProcAddress(module, "NtClose");
    version_fn version_query = (version_fn)GetProcAddress(module, "RtlGetVersion");
    if (!open_file || !create_file || !query_object || !query_file || !query_volume || !duplicate || !close_handle || !version_query)
        return 2;

    HANDLE destination = CreateFileW(output_path, GENERIC_WRITE, FILE_SHARE_READ,
        NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (destination == INVALID_HANDLE_VALUE)
        return 3;
    int descriptor = _open_osfhandle((intptr_t)destination, _O_BINARY | _O_WRONLY);
    if (descriptor < 0) {
        CloseHandle(destination);
        return 4;
    }
    FILE *output = _fdopen(descriptor, "wb");
    if (!output) {
        _close(descriptor);
        return 5;
    }

    RTL_OSVERSIONINFOW version = {0};
    version.dwOSVersionInfoSize = sizeof(version);
    NTSTATUS version_status = version_query(&version);
    USHORT process_machine = 0, native_machine = 0;
    BOOL machine_known = IsWow64Process2(GetCurrentProcess(), &process_machine, &native_machine);
    DWORD revision = 0, revision_bytes = sizeof(revision);
    LSTATUS revision_status = RegGetValueW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"UBR", RRF_RT_REG_DWORD,
        NULL, &revision, &revision_bytes);
    fprintf(output, "{\"schema\":\"rax-native-ksecdd-query-boundaries-v1\",\"pointer_bytes\":%u,"
        "\"kernel\":[%lu,%lu,%lu],\"revision\":%lu,\"revision_status\":%ld,"
        "\"version_status\":%lu,\"machine_known\":%s,\"process_machine\":%u,"
        "\"native_machine\":%u,\"rows\":[", (unsigned)sizeof(void *), version.dwMajorVersion,
        version.dwMinorVersion, version.dwBuildNumber, revision, revision_status,
        (ULONG)version_status, machine_known ? "true" : "false", process_machine, native_machine);

    for (size_t index = 0; index < 2; ++index) {
        const BOOL use_create = FALSE;
        const struct case_input *input = &cases[index * 4];
        UNICODE_STRING name = {0};
        name.Length = (USHORT)(wcslen(input->name) * sizeof(wchar_t));
        name.MaximumLength = name.Length + sizeof(wchar_t);
        name.Buffer = (PWSTR)input->name;
        OBJECT_ATTRIBUTES attributes = {0};
        attributes.Length = sizeof(attributes);
        attributes.ObjectName = &name;
        attributes.Attributes = input->attributes;
        HANDLE handle = (HANDLE)(ULONG_PTR)0x13579bdf;
        IO_STATUS_BLOCK io;
        memset(&io, 0xa5, sizeof(io));
        NTSTATUS status = use_create
            ? create_file(&handle, input->access, &attributes, &io, NULL, 0, input->share,
                1 /* FILE_OPEN */, input->options, NULL, 0)
            : open_file(&handle, input->access, &attributes, &io, input->share, input->options);
        status = completed(handle, status, &io);
        fprintf(output, "%s{\"label\":\"%s\",\"access\":%lu,\"share\":%lu,\"options\":%lu,"
            "\"attributes\":%lu,\"status\":%lu,\"handle_changed\":%s,\"io\":",
            index ? "," : "", input->label, input->access, input->share, input->options,
            input->attributes, (ULONG)status, handle != (HANDLE)(ULONG_PTR)0x13579bdf ? "true" : "false");
        bytes(output, &io, sizeof(io));
        fprintf(output, ",\"create\":%s", use_create ? "true" : "false");
        if (status >= 0 && handle && handle != (HANDLE)(ULONG_PTR)0x13579bdf) {
            SetLastError(0x1234);
            DWORD waited = WaitForSingleObject(handle, 0);
            fprintf(output, ",\"initial_wait\":%lu,\"initial_wait_error\":%lu", waited, GetLastError());
        }
        if (status >= 0 && handle && handle != INVALID_HANDLE_VALUE && handle != (HANDLE)(ULONG_PTR)0x13579bdf) {
            __declspec(align(16)) unsigned char basic[56];
            memset(basic, 0xa5, sizeof(basic));
            ULONG returned = 0xcccccccc;
            NTSTATUS basic_status = query_object(handle, 0, basic, sizeof(basic), &returned);
            fprintf(output, ",\"object_basic_status\":%lu,\"object_basic_returned\":%lu,\"object_basic\":",
                (ULONG)basic_status, returned);
            bytes(output, basic, 16);
            SetLastError(0x1234);
            DWORD file_type = GetFileType(handle);
            DWORD file_type_error = GetLastError();
            fprintf(output, ",\"file_type\":%lu,\"file_type_error\":%lu,\"queries\":[", file_type, file_type_error);
            static const ULONG classes[] = {5, 8, 14, 16, 17, 41, 43, 51};
            static const ULONG required[] = {24, 4, 8, 4, 4, 4, 4, 1};
            size_t emitted = 0;
            for (size_t q = 0; q < sizeof(classes) / sizeof(classes[0]); ++q) {
                const ULONG lengths[] = {0, 1, required[q] - 1, required[q], required[q] + 1, 64};
                for (size_t length_index = 0; length_index < 6; ++length_index) {
                    for (size_t layout = 0; layout < 3; ++layout) {
                        __declspec(align(16)) unsigned char region[256];
                        memset(region, 0xa5, sizeof(region));
                        PIO_STATUS_BLOCK caller_io = (PIO_STATUS_BLOCK)(void *)(region + 128);
                        unsigned char *buffer = layout == 0 ? region : region + 128 + (layout == 2 ? sizeof(void *) : 0);
                        NTSTATUS result = query_file(handle, caller_io, buffer, lengths[length_index], classes[q]);
                        result = completed(handle, result, caller_io);
                        fprintf(output, "%s{\"class\":%lu,\"length\":%lu,\"length_index\":%u,\"layout\":%u,\"status\":%lu,\"io\":",
                            emitted++ ? "," : "", classes[q], lengths[length_index], (unsigned)length_index,
                            (unsigned)layout, (ULONG)result);
                        bytes(output, caller_io, sizeof(*caller_io));
                        fputs(",\"data\":", output);
                        bytes(output, buffer, 64);
                        fputs(",\"region\":", output);
                        bytes(output, region, sizeof(region));
                        fputc('}', output);
                    }
                }
            }
            __declspec(align(16)) unsigned char device[8];
            memset(device, 0xa5, sizeof(device));
            memset(&io, 0xa5, sizeof(io));
            NTSTATUS device_status = query_volume(handle, &io, device, sizeof(device), 4);
            device_status = completed(handle, device_status, &io);
            fprintf(output, "],\"volume_device_status\":%lu,\"volume_device_io\":", (ULONG)device_status);
            bytes(output, &io, sizeof(io));
            fputs(",\"volume_device\":", output);
            bytes(output, device, sizeof(device));
            SetLastError(0x1234);
            DWORD waited = WaitForSingleObject(handle, 0);
            fprintf(output, ",\"after_queries_wait\":%lu,\"after_queries_wait_error\":%lu", waited, GetLastError());
            HANDLE copy = NULL;
            NTSTATUS duplicate_status = duplicate(GetCurrentProcess(), handle, GetCurrentProcess(), &copy, 0, 0, 2);
            fprintf(output, ",\"duplicate_status\":%lu", (ULONG)duplicate_status);
            if (duplicate_status >= 0 && copy) {
                memset(basic, 0xa5, sizeof(basic));
                basic_status = query_object(handle, 0, basic, sizeof(basic), &returned);
                fprintf(output, ",\"duplicate_basic_status\":%lu,\"duplicate_basic\":", (ULONG)basic_status);
                bytes(output, basic, 16);
                fprintf(output, ",\"duplicate_close_status\":%lu", (ULONG)close_handle(copy));
                memset(basic, 0xa5, sizeof(basic));
                basic_status = query_object(handle, 0, basic, sizeof(basic), &returned);
                fprintf(output, ",\"after_close_basic_status\":%lu,\"after_close_basic\":", (ULONG)basic_status);
                bytes(output, basic, 16);
            }
            fprintf(output, ",\"close_status\":%lu", (ULONG)close_handle(handle));
        }
        fputc('}', output);
        fflush(output);
    }
    fputs("],\"complete\":true}\n", output);
    return fclose(output) == 0 ? 0 : 6;
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous, PWSTR command, int show)
{
    (void)instance;
    (void)previous;
    (void)command;
    (void)show;
    int count = 0;
    wchar_t **arguments = CommandLineToArgvW(GetCommandLineW(), &count);
    int result = count == 2 ? observe(arguments[1]) : 7;
    if (arguments)
        LocalFree(arguments);
    return result;
}
