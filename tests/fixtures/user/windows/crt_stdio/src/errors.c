#include "common.h"
#if defined(LEGACY)
#error Genuine returning-handler imports are UCRT-only in this selected inventory.
#endif
typedef void (CRTCALL *InvalidHandler)(const WCHAR *, const WCHAR *, const WCHAR *, unsigned int, UPTR);
DLL InvalidHandler CRTCALL _set_invalid_parameter_handler(InvalidHandler);
static volatile DWORD calls;
static void CRTCALL handler(const WCHAR *expression, const WCHAR *function,
    const WCHAR *file_name, unsigned int line, UPTR reserved) {
    (void)expression; (void)function; (void)file_name; (void)line; (void)reserved;
    ++calls;
}
void entry(void) {
    FILE *input = standard(0), *output = standard(1);
    int *error = _errno(); check(error != 0, 200);
    InvalidHandler previous = _set_invalid_parameter_handler(handler);
    unsigned char byte = 0x33;
    *error = 0; check(_read(-1, &byte, 1) == -1 && *error == 9 && calls == 1, 201);
    check(byte == 0x33, 202);
    *error = 0; check(setvbuf(output, 0, IOFBF, 1) == -1 && *error == 22 && calls == 2, 203);
    *error = 0; check(_setmode(0, 0xdead) == -1 && *error == 22 && calls == 3, 204);
    *error = 0; check(fread(0, 1, 1, input) == 0 && *error == 22 && calls == 4, 205);
    *error = 0; check(fwrite(0, 1, 1, output) == 0 && *error == 22 && calls == 5, 206);
    *error = 0; check(fclose(0) == -1 && *error == 22 && calls == 6, 207);
    *error = 0; check(_read(0, &byte, 0x80000000u) == -1 && *error == 22 && calls == 7, 209);
    *error = 0; check(_write(1, &byte, 0x80000000u) == -1 && *error == 22 && calls == 8, 210);
    check(byte == 0x33, 211);
    check(_set_invalid_parameter_handler(previous) == handler, 208);
    ExitProcess(0);
}
