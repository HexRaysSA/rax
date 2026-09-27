#include "common.h"
static const WORD root_name[] = {'r','o','o','t',0};
static const WORD fail_name[] = {'f','a','i','l','.','d','l','l',0};
static const WORD fixed_name[] = {'f','a','i','l','-','o','k','.','d','l','l',0};
static const WORD data_name[] = {'d','a','t','a','.','e','x','e',0};

static DWORD notifications(DWORD module, DWORD kind, DWORD reason, DWORD tid) {
    DWORD n = 0, count = LogCount();
    check(count <= CAPACITY, 10);
    for (DWORD i = 0; i < count; ++i) {
        const Record *r = LogAt(i);
        check(r != 0 && r->cookie == COOKIE && r->base != 0, 11);
        check((r->sp & (sizeof(UPTR) == 4 ? 3 : 15)) == 0, 12);
        if (r->kind != DLL_MAIN || r->reason == 2 || r->reason == 3)
            check(r->reserved == 0, 13);
        if (r->module == module && (kind == 0 || r->kind == kind) &&
            r->reason == reason && (tid == 0 || r->tid == tid)) ++n;
    }
    return n;
}
static void complete_notifications(DWORD module, DWORD reason, DWORD tid) {
    for (DWORD kind = TLS_FIRST; kind <= DLL_MAIN; ++kind)
        check(notifications(module, kind, reason, tid) == 1, 14);
    /* PE specifies callback-array order, not its order relative to DllMain. */
    DWORD first = CAPACITY, second = CAPACITY;
    for (DWORD i = 0; i < LogCount(); ++i) {
        const Record *r = LogAt(i);
        if (r->module != module || r->reason != reason || (tid && r->tid != tid)) continue;
        if (r->kind == TLS_FIRST) first = i;
        if (r->kind == TLS_SECOND) second = i;
    }
    check(first < second, 15);
}
static void unmapped(UPTR base) {
    MBI info;
    check(VirtualQuery((void *)base, &info, sizeof(info)) == sizeof(info), 16);
    check(info.state == MEM_FREE && info.allocation == 0, 17);
}
static void mapped(HANDLE base) {
    MBI info;
    check(VirtualQuery(base, &info, sizeof(info)) == sizeof(info), 18);
    check(info.type == MEM_IMAGE && info.allocation == base, 19);
}
static UPTR module_base(DWORD id) {
    for (DWORD i = 0; i < LogCount(); ++i)
        if (LogAt(i)->module == id) return LogAt(i)->base;
    check(0, 20);
    return 0;
}

#if defined(STATIC_ROOT)
DLL DWORD WINAPI Ready(void);
DLL DWORD WINAPI TlsRead(void);
DLL void WINAPI TlsSet(DWORD);
void entry(void) {
    DWORD tid = GetCurrentThreadId();
    check(Ready() == INITIAL(ROOT) && TlsRead() == INITIAL(ROOT), 21);
    check(LogCount() == 6, 22);
    complete_notifications(LEAF, 1, tid);
    complete_notifications(ROOT, 1, tid);
    for (DWORD i = 0; i < LogCount(); ++i) {
        const Record *r = LogAt(i);
        if (r->kind == DLL_MAIN) check(r->reserved != 0, 23);
    }
    TlsSet(0xabcdef01);
    check(TlsRead() == 0xabcdef01, 24);
    HANDLE root = LoadLibraryW(root_name);
    check(root == GetModuleHandleA("root.dll"), 25);
    check(LogCount() == 6 && FreeLibrary(root), 26);
    check(LogCount() == 6 && GetModuleHandleA("root.dll") == root, 27);
    mapped(root); /* The executable's import edge still owns this dependency. */
    ExitProcess(0);
}
#elif defined(FORWARD_MISS)
void entry(void) {
    DWORD tid = GetCurrentThreadId();
    LogClear();
    check(GetModuleHandleA("leaf.dll") == 0, 84);
    check(*(volatile UPTR *)(current_teb() + TLS_POINTER) == 0, 85);
    HANDLE forward = LoadLibraryA("forward.dll");
    check(forward != 0 && LogCount() == 0, 86);
    for (DWORD attempt = 0; attempt < 2; ++attempt) {
        void *missing = GetProcAddress(forward, "Missing");
        DWORD error = GetLastError();
        check(missing == 0 && error == 127, 87);
        check(LogCount() == 0 && GetModuleHandleA("leaf.dll") == 0, 88);
        check(GetModuleHandleA("forward.dll") == forward, 89);
        check(*(volatile UPTR *)(current_teb() + TLS_POINTER) == 0, 90);
        mapped(forward);
    }
    HANDLE leaf = LoadLibraryA("leaf.dll");
    check(leaf != 0 && LogCount() == 3, 91);
    complete_notifications(LEAF, 1, tid);
    ReadTls read = (ReadTls)GetProcAddress(leaf, "TlsRead");
    ReadTls ready = (ReadTls)GetProcAddress(leaf, "Ready");
    check(read && ready && read() == INITIAL(LEAF) && ready() == INITIAL(LEAF), 92);
    mapped(leaf);
    /* A failed forwarder must not retain an edge owning this later load. */
    check(FreeLibrary(leaf) && GetModuleHandleA("leaf.dll") == 0, 93);
    unmapped((UPTR)leaf);
    check(LogCount() == 6, 94);
    complete_notifications(LEAF, 0, tid);
    check(*(volatile UPTR *)(current_teb() + TLS_POINTER) == 0, 95);
    check(FreeLibrary(forward) && LogCount() == 6, 96);
    unmapped((UPTR)forward);
    ExitProcess(0);
}
#else
static HANDLE ready_event, start_event, done_event, release_event;
static ReadTls volatile leaf_read;
static SetTls volatile leaf_set;
static DWORD WINAPI old_worker(void *unused) {
    (void)unused;
    check(SetEvent(ready_event), 30);
    check(WaitForSingleObject(start_event, INFINITE) == 0, 31);
    check(leaf_read() == INITIAL(LEAF), 32);
    leaf_set(0x11112222);
    check(leaf_read() == 0x11112222, 33);
    check(SetEvent(done_event), 34);
    check(WaitForSingleObject(release_event, INFINITE) == 0, 35);
    check(leaf_read() == 0x11112222, 36);
    return 0;
}
static DWORD WINAPI new_worker(void *unused) {
    (void)unused;
    check(leaf_read() == INITIAL(LEAF), 37);
    leaf_set(0x33334444);
    check(leaf_read() == 0x33334444, 38);
    return 0;
}
static void replace_failed_dll(void) {
    /* These paths resolve only within the runner's unique temporary drive. */
    HANDLE input = CreateFileW(fixed_name, 0x80000000u, 1, 0, 3, 0, 0);
    HANDLE output = CreateFileW(fail_name, 0x40000000u, 0, 0, 2, 0, 0);
    check((UPTR)input != (UPTR)-1 && (UPTR)output != (UPTR)-1, 39);
    BYTE bytes[128];
    DWORD n, written;
    for (;;) {
        check(ReadFile(input, bytes, sizeof(bytes), &n, 0), 40);
        if (n == 0) break;
        check(WriteFile(output, bytes, n, &written, 0) && written == n, 41);
    }
    check(CloseHandle(input) && CloseHandle(output), 42);
}
static void failed_load(BOOL leaf_was_present) {
    DWORD before = LogCount();
    HANDLE h = LoadLibraryA("fail.dll");
    check(h == 0 && GetLastError() == 1114, 43);
    check(GetModuleHandleA("fail.dll") == 0, 44);
    check((GetModuleHandleA("leaf.dll") != 0) == leaf_was_present, 45);
    DWORD fail_attach = 0, fail_detach = 0;
    UPTR base = 0;
    for (DWORD i = before; i < LogCount(); ++i) {
        const Record *r = LogAt(i);
        if (r->module != FAIL) continue;
        check(r->reserved == 0 && r->tls == INITIAL(FAIL), 46);
        base = r->base;
        if (r->reason == 1) ++fail_attach;
        if (r->reason == 0) ++fail_detach;
    }
    check(fail_attach == 3 && fail_detach == 3, 47);
    unmapped(base);
}
void entry(void) {
    DWORD main_tid = GetCurrentThreadId(), old_tid, new_tid;
    LogClear();
    check(GetModuleHandleA("root.dll") == 0 && GetModuleHandleA("leaf.dll") == 0, 50);
    ready_event = CreateEventW(0, 1, 0, 0);
    start_event = CreateEventW(0, 1, 0, 0);
    done_event = CreateEventW(0, 1, 0, 0);
    release_event = CreateEventW(0, 1, 0, 0);
    check(ready_event && start_event && done_event && release_event, 51);
    HANDLE old = CreateThread(0, 0, old_worker, 0, 0, &old_tid);
    check(old && WaitForSingleObject(ready_event, INFINITE) == 0, 52);
    HANDLE root = LoadLibraryW(root_name);
    check(root != 0, 53);
    HANDLE repeated = LoadLibraryA("ROOT.DLL");
    check(root == repeated && GetModuleHandleW(root_name) == root, 54);
    check(LogCount() == 6, 55);
    complete_notifications(LEAF, 1, main_tid);
    complete_notifications(ROOT, 1, main_tid);
    for (DWORD i = 0; i < LogCount(); ++i) check(LogAt(i)->reserved == 0, 56);
    mapped(root);
    ProbeFn probe = (ProbeFn)GetProcAddress(root, "Probe");
    check(probe && probe(COOKIE, 2, 3, 4, 5, 6, 7, 8, 9) == probe_expected(), 57);
    HANDLE leaf = GetModuleHandleA("leaf.dll");
    leaf_read = (ReadTls)GetProcAddress(leaf, "TlsRead");
    leaf_set = (SetTls)GetProcAddress(leaf, "TlsSet");
    check(leaf_read && leaf_set && leaf_read() == INITIAL(LEAF), 58);
    leaf_set(0x55556666);
    check(FreeLibrary(repeated) && LogCount() == 6, 59);
    mapped(root);
    check(SetEvent(start_event) && WaitForSingleObject(done_event, INFINITE) == 0, 60);
    HANDLE newer = CreateThread(0, 0, new_worker, 0, 0, &new_tid);
    check(newer && WaitForSingleObject(newer, INFINITE) == 0, 61);
    check(leaf_read() == 0x55556666, 62);
    for (DWORD module = LEAF; module <= ROOT; ++module) {
        check(notifications(module, 0, 2, old_tid) == 0, 63);
        complete_notifications(module, 2, new_tid);
        complete_notifications(module, 3, new_tid);
    }
    check(SetEvent(release_event) && WaitForSingleObject(old, INFINITE) == 0, 64);
    for (DWORD module = LEAF; module <= ROOT; ++module)
        complete_notifications(module, 3, old_tid);
    check(CloseHandle(old) && CloseHandle(newer), 65);
    check(CloseHandle(ready_event) && CloseHandle(start_event) &&
          CloseHandle(done_event) && CloseHandle(release_event), 66);
    UPTR root_base = (UPTR)root, leaf_base = (UPTR)leaf;
    check(FreeLibrary(root), 67);
    check(GetModuleHandleA("root.dll") == 0 && GetModuleHandleA("leaf.dll") == 0, 68);
    check(GetProcAddress(root, "Probe") == 0, 69);
    unmapped(root_base); unmapped(leaf_base);
    complete_notifications(LEAF, 0, main_tid);
    complete_notifications(ROOT, 0, main_tid);

    LogClear();
    root = LoadLibraryA("root.dll");
    check(root != 0, 70);
    failed_load(1);
    failed_load(1); /* A FALSE-attach retry must not expose the old mapping. */
    check(FreeLibrary(root) && GetModuleHandleA("leaf.dll") == 0, 71);
    failed_load(0); /* Roll back fresh native dependencies, too. */
    replace_failed_dll();
    HANDLE fixed = LoadLibraryW(fail_name);
    check(fixed != 0, 72);
    ReadTls fixed_read = (ReadTls)GetProcAddress(fixed, "TlsRead");
    check(fixed_read && fixed_read() == INITIAL(FAIL), 73);
    check(FreeLibrary(fixed) && GetModuleHandleA("fail.dll") == 0, 74);
    unmapped((UPTR)fixed);

    LogClear();
    check(GetModuleHandleA("leaf.dll") == 0, 75);
    HANDLE forward = LoadLibraryA("forward.dll");
    check(forward != 0 && LogCount() == 0, 76);
    probe = (ProbeFn)GetProcAddress(forward, "Probe");
    check(probe && probe(COOKIE, 2, 3, 4, 5, 6, 7, 8, 9) == probe_expected(), 77);
    complete_notifications(LEAF, 1, main_tid);
    leaf_base = module_base(LEAF);
    check(FreeLibrary(forward), 78);
    unmapped((UPTR)forward);
    /* Personality graph-reachability policy, not a native lifetime oracle. */
    check(GetModuleHandleA("leaf.dll") == 0, 79);
    unmapped(leaf_base);

    LogClear();
    HANDLE data = LoadLibraryW(data_name);
    check(data != 0 && LogCount() == 0, 80);
    check(GetProcAddress(data, "DataMarker") != 0, 81);
    check(GetModuleHandleA("absent-lifecycle.dll") == 0, 82);
    check(FreeLibrary(data) && LogCount() == 0, 83);
    unmapped((UPTR)data);
    ExitProcess(0);
}
#endif
