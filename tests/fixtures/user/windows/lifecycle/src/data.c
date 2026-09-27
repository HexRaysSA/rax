#include "common.h"
DLL DWORD WINAPI DeliberatelyMissing(void);
DWORD WINAPI DataMarker(void) { return 0xdecafbad; }
void entry(void) {
    Log(DATA, DLL_MAIN, 0, 1, 0, 0, GetCurrentThreadId(), current_sp(), COOKIE);
    ExitProcess(DeliberatelyMissing());
}
