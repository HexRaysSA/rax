#include <windows.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef LONG (NTAPI *enumerate_value_fn)(HANDLE, ULONG, ULONG, void *, ULONG, ULONG *);

static void observe(enumerate_value_fn enumerate, HKEY key, unsigned path, unsigned view,
                    unsigned index, unsigned info, unsigned size, unsigned offset)
{
    union {
        uint64_t align;
        uint8_t bytes[144];
    } storage;
    ULONG returned = 0xcccccccc;
    memset(storage.bytes, 0xa5, sizeof(storage.bytes));
    LONG status = enumerate(key, index, info, storage.bytes + offset, size, &returned);
    for (unsigned i = 0; i < sizeof(storage.bytes); ++i) {
        if ((i < offset || i >= offset + size) && storage.bytes[i] != 0xa5) {
            fprintf(stderr, "destination canary changed at %u\n", i);
            ExitProcess(2);
        }
    }
    printf("%u,%u,%u,%u,%u,%u,%08" PRIx32 ",%08" PRIx32 ",",
           path, view, index, info, size, offset, (uint32_t)status, (uint32_t)returned);
    for (unsigned i = 0; i < size; ++i)
        printf("%02x", storage.bytes[offset + i]);
    putchar('\n');
}

int main(void)
{
    const WCHAR *paths[] = {
        L"SYSTEM\\CurrentControlSet\\Control\\MUI\\Settings\\LanguageConfiguration",
        L"SYSTEM\\CurrentControlSet\\Control\\MUI\\UILanguages\\en-US",
    };
    const unsigned views[] = {KEY_WOW64_32KEY, KEY_WOW64_64KEY};
    const unsigned lengths[] = {0, 1, 7, 8, 11, 12, 19, 20, 21, 23, 24, 28, 32, 33, 35, 36, 64};
    const unsigned alignments[] = {0, 1, 4};
    HMODULE module = GetModuleHandleW(L"ntdll.dll");
    FARPROC raw = module ? GetProcAddress(module, "NtEnumerateValueKey") : NULL;
    if (!raw)
        return 3;
    enumerate_value_fn enumerate;
    _Static_assert(sizeof(enumerate) == sizeof(raw), "native function pointer size");
    memcpy(&enumerate, &raw, sizeof(enumerate));
    puts("path,view,index,class,length,offset,status,returned,bytes");
    for (unsigned p = 0; p < 2; ++p) {
        for (unsigned v = 0; v < 2; ++v) {
            HKEY key = NULL;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, paths[p], 0, KEY_QUERY_VALUE | views[v], &key))
                return 4;
            for (unsigned cls = 0; cls <= 5; ++cls) {
                for (unsigned a = 0; a < sizeof(alignments) / sizeof(alignments[0]); ++a) {
                    for (unsigned j = 0; j < sizeof(lengths) / sizeof(lengths[0]); ++j) {
                        observe(enumerate, key, p, views[v], 0, cls, lengths[j], alignments[a]);
                    }
                }
                observe(enumerate, key, p, views[v], 1, cls, 64, 0);
                observe(enumerate, key, p, views[v], 8, cls, 64, 0);
            }
            if (RegCloseKey(key))
                return 5;
        }
    }
    return ferror(stdout) ? 6 : 0;
}
