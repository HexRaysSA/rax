#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef LONG (WINAPI *CreateSectionFn)(HANDLE *, ACCESS_MASK, const void *,
                                       const LARGE_INTEGER *, ULONG, ULONG, HANDLE);
typedef LONG (WINAPI *QuerySectionFn)(HANDLE, ULONG, void *, SIZE_T, SIZE_T *);

enum { section_query = 1, section_map_read = 4, image_no_execute = 0x11000000 };
static __declspec(align(8)) DWORD output[24];

static void write_all(const void *data, DWORD length) {
    DWORD written = 0;
    if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), data, length, &written, NULL)
        || written != length)
        ExitProcess(21);
}

static void exercise(CreateSectionFn create, QuerySectionFn query, HANDLE file, DWORD attributes) {
    const DWORD record_size = sizeof(void *) == 4 ? 48 : 64;
    const DWORD lengths[] = {record_size - 1, record_size, record_size + 16};
    for (unsigned allowed = 0; allowed < 2; ++allowed) {
        const DWORD access = section_map_read | (allowed ? section_query : 0);
        HANDLE section = NULL;
        const LONG creation = create(&section, access, NULL, NULL, PAGE_READONLY, attributes, file);
        if (creation < 0 || !section)
            ExitProcess(22);
        for (unsigned i = 0; i < ARRAYSIZE(lengths); ++i) {
            SIZE_T returned = 0x11223344;
            for (unsigned j = 0; j < ARRAYSIZE(output); ++j)
                output[j] = 0xa5a5a5a5;
            const LONG status = query(section, 1, output, lengths[i], &returned);
            const DWORD fields[] = {sizeof(void *), attributes, access, lengths[i],
                                    (DWORD)status, (DWORD)returned};
            write_all(fields, sizeof(fields));
            write_all(output, sizeof(output));
        }
        if (!CloseHandle(section))
            ExitProcess(23);
    }
}

void entry(void) {
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        ExitProcess(24);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-function-type-strict"
    const CreateSectionFn create = (CreateSectionFn)GetProcAddress(ntdll, "NtCreateSection");
    const QuerySectionFn query = (QuerySectionFn)GetProcAddress(ntdll, "NtQuerySection");
#pragma clang diagnostic pop
    if (!create || !query)
        ExitProcess(25);
    WCHAR filename[MAX_PATH];
    static const WCHAR name[] = L"\\cmd.exe";
    const UINT length = GetSystemWow64DirectoryW(filename, ARRAYSIZE(filename));
    if (!length || length > MAX_PATH - ARRAYSIZE(name))
        ExitProcess(26);
    for (unsigned i = 0; i < ARRAYSIZE(name); ++i)
        filename[length + i] = name[i];
    HANDLE file = CreateFileW(filename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        ExitProcess(27);
    exercise(create, query, file, image_no_execute);
    exercise(create, query, file, SEC_IMAGE);
    if (!CloseHandle(file))
        ExitProcess(28);
    ExitProcess(0);
}
