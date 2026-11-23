#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef LONG (NTAPI *cache_control)(ULONG, void *);

static void put16(unsigned char *base, size_t offset, uint16_t value) {
    memcpy(base + offset, &value, sizeof(value));
}

static void put32(unsigned char *base, size_t offset, uint32_t value) {
    memcpy(base + offset, &value, sizeof(value));
}

static void put_pointer(unsigned char *base, size_t offset, const void *pointer) {
    uintptr_t value = (uintptr_t)pointer;
    memcpy(base + offset, &value, sizeof(value));
}

static int query(cache_control call, HANDLE image, const wchar_t *path,
                 uint16_t path_bytes, uint32_t flags) {
    static const uint32_t stock[] = {2, 0, 8, 8, 0, 0, 4, 8, 0, 0, 16, 8, 0, 0, 1, 0};
    unsigned char input[392] = {0}, output[4096], untouched[4096];
    memset(output, 0xa5, sizeof(output));
    memset(untouched, 0xa5, sizeof(untouched));
    put32(input, 0, 0x1f);
    put32(input, 4, flags);
    put_pointer(input, 0x18, image);
    put16(input, 0x30, path_bytes);
    put16(input, 0x32, (uint16_t)(path_bytes + sizeof(*path)));
    put_pointer(input, 0x38, path);
    put_pointer(input, 0x178, output);
    put32(input, 0x180, sizeof(output));

    LONG status = call(11, input);
    uint32_t written;
    memcpy(&written, input + 0x180, sizeof(written));
    printf("handle=%s flags=0x%02lx status=0x%08lx size=%lu",
           image ? "file" : "null", (unsigned long)flags,
           (unsigned long)status, (unsigned long)written);
    if (!status && written < sizeof(output)) {
        fputs(" bytes=", stdout);
        for (uint32_t i = 0; i < written; ++i) printf("%02x", output[i]);
        printf(" canary=%02x", output[written]);
    }
    putchar('\n');

    if (!image)
        return (uint32_t)status == 0xc0000008u && written == sizeof(output) &&
               !memcmp(output, untouched, sizeof(output));
    return !status && written == sizeof(stock) && !memcmp(output, stock, sizeof(stock)) &&
           !memcmp(output + sizeof(stock), untouched, sizeof(output) - sizeof(stock));
}

int main(void) {
    USHORT process = 0, machine = 0;
    if (!IsWow64Process2(GetCurrentProcess(), &process, &machine) ||
        process != IMAGE_FILE_MACHINE_UNKNOWN || machine != IMAGE_FILE_MACHINE_ARM64 ||
        sizeof(void *) != 8) return 1;

    FARPROC symbol = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtApphelpCacheControl");
    if (!symbol) return 2;
    cache_control call;
    memcpy(&call, &symbol, sizeof(call));

    wchar_t path[MAX_PATH];
    const wchar_t suffix[] = L"\\cmd.exe";
    UINT root = GetSystemDirectoryW(path, MAX_PATH);
    if (!root || root >= MAX_PATH || root + sizeof(suffix) / sizeof(*suffix) > MAX_PATH)
        return 3;
    memcpy(path + root, suffix, sizeof(suffix));
    uint16_t path_bytes = (uint16_t)(root * sizeof(*path) + sizeof(suffix) - sizeof(*path));

    HANDLE image = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (image == INVALID_HANDLE_VALUE) return 4;
    printf("process=0x%04x native=0x%04x pointer_bytes=%zu\n",
           (unsigned)process, (unsigned)machine, sizeof(void *));
    int matched = 1;
    const uint32_t flags[] = {0x10, 0x14, 0x30, 0x34};
    for (size_t i = 0; i < sizeof(flags) / sizeof(*flags); ++i) {
        matched &= query(call, NULL, path, path_bytes, flags[i]);
        matched &= query(call, image, path, path_bytes, flags[i]);
    }
    if (!CloseHandle(image)) return 5;
    return matched ? 0 : 6;
}
