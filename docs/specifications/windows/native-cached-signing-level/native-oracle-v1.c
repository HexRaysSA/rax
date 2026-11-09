/* Native read-only signing-cache observations. No CRT and no signing setters. */
#define _WIN32_WINNT 0x0A00
#include <windows.h>

typedef LONG (NTAPI *QuerySigning)(HANDLE, ULONG *, UCHAR *, UCHAR *, ULONG *, ULONG *);
typedef BOOL (WINAPI *QuerySigningWin32)(HANDLE, ULONG *, ULONG *, UCHAR *, ULONG *, ULONG *);
static QuerySigning query;
static QuerySigningWin32 query_win32;
static char line[8192];
static unsigned used;
static union { ULONG alignment; UCHAR bytes[192]; } arena;

#if defined(_M_ARM64)
#define ARCH "arm64"
#elif defined(_M_X64)
#define ARCH "x64"
#else
#define ARCH "x86"
#endif

static void put(char c) {
    if (used == sizeof(line)) ExitProcess(80);
    line[used++] = c;
}
static void text(const char *s) { while (*s) put(*s++); }
static void hex(ULONG_PTR value, unsigned digits) {
    const char *alphabet = "0123456789abcdef";
    while (digits) { --digits; put(alphabet[(value >> (digits * 4)) & 15]); }
}
static void quoted(const char *s) {
    put('"');
    while (*s) {
        if (*s == '"' || *s == '\\') put('\\');
        put(*s++);
    }
    put('"');
}
static void wide(const WCHAR *s) {
    put('"');
    while (*s) {
        unsigned c = *s++;
        if (c == '"' || c == '\\') { put('\\'); put((char)c); }
        else if (c >= 32 && c < 127) put((char)c);
        else { text("\\u"); hex(c, 4); }
    }
    put('"');
}
static void begin(const char *kind, const char *role) {
    used = 0;
    text("{\"schema\":\"rax-native-cached-signing-level-v1\",\"arch\":\"" ARCH "\",\"kind\":");
    quoted(kind); text(",\"role\":"); quoted(role);
}
static void finish(void) {
    DWORD written = 0;
    text("}\n");
    if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), line, used, &written, 0) || written != used)
        ExitProcess(81);
}
static void initialize(ULONG capacity) {
    unsigned i;
    for (i = 0; i < sizeof(arena.bytes); ++i) arena.bytes[i] = 0xA5;
    for (i = 0; i < 4; ++i) arena.bytes[112 + i] = (UCHAR)(capacity >> (8 * i));
}
static void observe(const char *role, HANDLE file, ULONG access, unsigned mask,
                    ULONG capacity, unsigned flags_offset, int win32) {
    unsigned i;
    LONG status;
    DWORD last_error = 0;
    initialize(capacity);
    if (win32) {
        SetLastError(0);
        status = query_win32(file, (ULONG *)&arena.bytes[flags_offset],
                             (ULONG *)&arena.bytes[16], &arena.bytes[32],
                             (ULONG *)&arena.bytes[112], (ULONG *)&arena.bytes[128]);
        last_error = GetLastError();
    } else {
        status = query(file,
                       mask & 1 ? 0 : (ULONG *)&arena.bytes[flags_offset],
                       mask & 2 ? 0 : &arena.bytes[16],
                       mask & 4 ? 0 : &arena.bytes[32],
                       mask & 8 ? 0 : (ULONG *)&arena.bytes[112],
                       mask & 16 ? 0 : (ULONG *)&arena.bytes[128]);
    }
    begin(win32 ? "win32" : "nt", role);
    text(",\"handle\":\""); hex((ULONG_PTR)file, sizeof(void *) * 2); put('"');
    text(",\"access\":\""); hex(access, 8); put('"');
    text(",\"null_mask\":\""); hex(mask, 2); put('"');
    text(",\"capacity\":\""); hex(capacity, 8); put('"');
    text(",\"flags_offset\":\""); hex(flags_offset, 2); put('"');
    text(",\"result\":\""); hex((ULONG)status, 8); put('"');
    text(",\"last_error\":\""); hex(last_error, 8); put('"');
    text(",\"arena\":\"");
    for (i = 0; i < sizeof(arena.bytes); ++i) hex(arena.bytes[i], 2);
    put('"'); finish();
}
static void campaign(const char *role, HANDLE file, ULONG access) {
    static const ULONG capacities[] = {0, 20, 64};
    unsigned mask, i;
    for (mask = 0; mask != 32; ++mask)
        for (i = 0; i != sizeof(capacities) / sizeof(capacities[0]); ++i)
            observe(role, file, access, mask, capacities[i], 0, 0);
    observe(role, file, access, 0, 64, 1, 0);
    if (query_win32) observe(role, file, access, 0, 64, 0, 1);
}
static void open_file(const WCHAR *path, const char *role, ULONG access, DWORD flags) {
    WCHAR final_name[1024];
    HANDLE file = CreateFileW(path, access, 7, 0, OPEN_EXISTING, flags, 0);
    DWORD error = file == INVALID_HANDLE_VALUE ? GetLastError() : 0;
    DWORD length = 0;
    begin("open", role); text(",\"path\":"); wide(path);
    text(",\"access\":\""); hex(access, 8); put('"');
    text(",\"last_error\":\""); hex(error, 8); put('"');
    if (file != INVALID_HANDLE_VALUE) {
        length = GetFinalPathNameByHandleW(file, final_name, 1024, 0);
        if (length && length < 1024) { text(",\"final_path\":"); wide(final_name); }
    }
    finish();
    if (file == INVALID_HANDLE_VALUE) return;
    campaign(role, file, access);
    if (!CloseHandle(file)) ExitProcess(82);
    observe("closed-file", file, access, 0, 64, 0, 0);
}
static void path_join(WCHAR *out, const WCHAR *directory, const WCHAR *leaf) {
    unsigned n = 0;
    while (*directory && n < 1000) out[n++] = *directory++;
    if (n == 1000) ExitProcess(83);
    out[n++] = '\\';
    while (*leaf && n < 1023) out[n++] = *leaf++;
    if (*leaf) ExitProcess(83);
    out[n] = 0;
}
void entry(void) {
    WCHAR directory[512], path[1024];
    static const WCHAR *names[] = {L"ntdll.dll", L"kernelbase.dll", L"xtajit64.dll", L"cmd.exe"};
    static const char *roles[] = {"ntdll", "kernelbase", "xtajit64", "cmd"};
    static const ULONG access[] = {GENERIC_READ, FILE_READ_ATTRIBUTES, FILE_READ_EA};
    unsigned i, j;
    HANDLE event;
    query = (QuerySigning)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtGetCachedSigningLevel");
    query_win32 = (QuerySigningWin32)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetCachedSigningLevel");
    if (!query || !GetSystemDirectoryW(directory, 512)) ExitProcess(10);
    begin("profile", "exports"); text(",\"win32_available\":"); text(query_win32 ? "true" : "false"); finish();
    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        path_join(path, directory, names[i]);
        for (j = 0; j < sizeof(access) / sizeof(access[0]); ++j)
            open_file(path, roles[i], access[j], FILE_ATTRIBUTE_NORMAL);
    }
    if (!GetModuleFileNameW(0, path, 1024)) ExitProcess(11);
    open_file(path, "owned-unsigned-program", GENERIC_READ, FILE_ATTRIBUTE_NORMAL);
    open_file(directory, "system-directory", FILE_READ_ATTRIBUTES, FILE_FLAG_BACKUP_SEMANTICS);
    open_file(L"NUL", "null-device", GENERIC_READ, FILE_ATTRIBUTE_NORMAL);
    campaign("null-handle", 0, 0);
    campaign("process-pseudo-handle", (HANDLE)(LONG_PTR)-1, 0);
    event = CreateEventW(0, FALSE, FALSE, 0);
    if (!event) ExitProcess(12);
    campaign("event-handle", event, 0);
    if (!CloseHandle(event)) ExitProcess(13);
    ExitProcess(0);
}
