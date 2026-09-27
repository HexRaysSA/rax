#include "common.h"
static volatile DWORD *shared;
__declspec(dllexport) int CRTCALL configure(volatile DWORD *counter) {
    if (!counter || shared || *counter) return 0;
    shared = counter;
    return 1;
}
BOOL WINAPI DllMain(void *module, DWORD reason, void *reserved) {
    (void)module; (void)reserved;
    if (reason == 0) {
        check(shared && *shared == 0, 152);
        ++*shared;
        tag('D');
    }
    return 1;
}
