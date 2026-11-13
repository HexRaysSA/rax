/* Initialize process-local registry/cache handles before measuring cleanup.
 * The included native campaign and its strict before/after check are unchanged.
 */
#define main captured_main
#if defined(RAX_ENUMERATION_FAULT)
#include "fault-v1.c"
#else
#include "probe-v1.c"
#endif
#undef main

int main(void) {
    for (unsigned view = 0; view < 2; ++view) {
        HKEY key = NULL;
        REGSAM flag = view == 0 ? KEY_WOW64_64KEY : KEY_WOW64_32KEY;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software", 0,
                          KEY_READ | flag, &key) != ERROR_SUCCESS || !key ||
            RegCloseKey(key) != ERROR_SUCCESS) return 120;
    }
    DWORD previous = 0;
    unsigned stable = 0;
    for (unsigned sample = 0; sample < 100; ++sample) {
        DWORD count = 0;
        if (!GetProcessHandleCount(GetCurrentProcess(), &count)) return 121;
        if (sample == 0 || count != previous) {
            fprintf(stderr, "PRECONDITION sample=%u handles=%lu\n", sample, count);
            stable = 0;
        } else ++stable;
        previous = count;
        if (stable == 20) {
            fprintf(stderr, "PRECONDITION stable_handles=%lu interval_ms=1000\n", count);
            return captured_main();
        }
        Sleep(50);
    }
    return 122;
}
