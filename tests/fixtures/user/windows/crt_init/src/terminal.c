#include "common.h"
static void CRTCALL terminate(void) { ExitProcess(42); }
static void CRTCALL forbidden(void) { ExitProcess(182); }
#pragma section(".CRT$XCA", read, write)
#pragma section(".CRT$XCB", read, write)
#pragma section(".CRT$XCC", read, write)
#pragma section(".CRT$XCZ", read, write)
SLOT(".CRT$XCA") PVFV ctor_begin = 0;
SLOT(".CRT$XCB") PVFV ctor_terminate = terminate;
SLOT(".CRT$XCC") PVFV ctor_after = forbidden;
SLOT(".CRT$XCZ") PVFV ctor_end = forbidden;
__declspec(dllexport) const void *fixture_bounds[2] = {&ctor_begin, &ctor_end};
int main(void) {
    check((UPTR)&ctor_end - (UPTR)&ctor_begin == 3 * sizeof(PVFV), 141);
    _initterm(&ctor_begin, &ctor_end);
    ExitProcess(183);
}
void entry(void) { ExitProcess((DWORD)main()); }
