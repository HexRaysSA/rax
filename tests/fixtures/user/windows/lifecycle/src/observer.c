#define Log internal_import_Log
#define LogCount internal_import_LogCount
#define LogAt internal_import_LogAt
#define LogClear internal_import_LogClear
#include "common.h"
#undef Log
#undef LogCount
#undef LogAt
#undef LogClear
static Record records[CAPACITY];
static DWORD count;
void WINAPI Log(DWORD module, DWORD kind, void *base, DWORD reason, void *reserved,
                UPTR tls, DWORD tid, UPTR sp, UPTR cookie) {
    if (count >= CAPACITY) {
        count = CAPACITY + 1;
        return;
    }
    Record *r = &records[count++];
    r->module = module; r->kind = kind; r->base = (UPTR)base; r->reason = reason;
    r->reserved = (UPTR)reserved; r->tls = tls; r->tid = tid;
    r->sp = sp; r->cookie = cookie;
}
DWORD WINAPI LogCount(void) { return count; }
const Record *WINAPI LogAt(DWORD index) {
    return index < count && index < CAPACITY ? &records[index] : 0;
}
void WINAPI LogClear(void) { count = 0; }
