#define _UNICODE
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>

static BOOL read_own(uintptr_t address, void *destination, SIZE_T size) {
    SIZE_T copied = 0;
    return ReadProcessMemory(GetCurrentProcess(), (void *)address, destination,
                             size, &copied) && copied == size;
}

int wmain(void) {
    USHORT process = 0, machine = 0;
    if (!IsWow64Process2(GetCurrentProcess(), &process, &machine) ||
        process != IMAGE_FILE_MACHINE_I386 || machine != IMAGE_FILE_MACHINE_ARM64) return 1;
    printf("pointer_bytes=%zu process=0x%04x native=0x%04x\n",
           sizeof(void *), (unsigned)process, (unsigned)machine);
    uintptr_t teb = (uintptr_t)NtCurrentTeb();
    int32_t delta = 0;
    if (!read_own(teb + 0xfdc, &delta, sizeof(delta)) || delta != -0x2000) return 2;
    uintptr_t slot = teb - 0x2000 + 0x14c0;
    uint64_t before = 0, disabled = 0, restored = 0;
    if (!read_own(slot, &before, sizeof(before))) return 3;

    wchar_t path[MAX_PATH];
    UINT root_length = GetWindowsDirectoryW(path, MAX_PATH);
    const wchar_t suffix[] = L"\\System32\\en-US\\cmd.exe.mui";
    if (!root_length || root_length + sizeof(suffix) / sizeof(*suffix) > MAX_PATH) return 4;
    wcscpy(path + root_length, suffix);
    HANDLE first = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD first_error = first == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    if (first != INVALID_HANDLE_VALUE && !CloseHandle(first)) return 5;

    PVOID old = NULL;
    if (!Wow64DisableWow64FsRedirection(&old)) return 6;
    BOOL captured = read_own(slot, &disabled, sizeof(disabled));
    HANDLE handle = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD open_error = handle == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    if (!Wow64RevertWow64FsRedirection(old)) return 7;
    if (!captured || !read_own(slot, &restored, sizeof(restored))) return 8;

    printf("companion_delta=%ld slot=0x14c0 default=%llu disabled=%llu restored=%llu\n",
           (long)delta, (unsigned long long)before, (unsigned long long)disabled,
           (unsigned long long)restored);
    printf("default_open_error=%lu disabled_open_error=%lu\n",
           (unsigned long)first_error, (unsigned long)open_error);
    if (before != 0 || disabled != 1 || restored != 0 ||
        handle == INVALID_HANDLE_VALUE) return 9;
    wchar_t final_path[512];
    DWORD length = GetFinalPathNameByHandleW(handle, final_path, 512, FILE_NAME_NORMALIZED);
    if (!CloseHandle(handle) || !length || length >= 512) return 10;
    printf("physical=%ls\n", final_path);
    const size_t tail = wcslen(suffix);
    return length < tail || _wcsicmp(final_path + length - tail, suffix) != 0;
}
