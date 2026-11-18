#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static void pipe_round_trip(SECURITY_ATTRIBUTES *attributes, DWORD quota) {
    HANDLE reader = NULL, writer = NULL;
    const char bytes[4] = {'p','i','p','e'};
    char result[4] = {0};
    DWORD count = 0;
    if (!CreatePipe(&reader, &writer, attributes, quota))
        ExitProcess(20);
    if (!WriteFile(writer, bytes, sizeof(bytes), &count, NULL) || count != sizeof(bytes))
        ExitProcess(21);
    if (!CloseHandle(writer))
        ExitProcess(22);
    if (!ReadFile(reader, result, sizeof(result), &count, NULL) || count != sizeof(result))
        ExitProcess(23);
    for (unsigned index = 0; index != sizeof(result); ++index)
        if (result[index] != bytes[index])
            ExitProcess(24);
    if (ReadFile(reader, result, sizeof(result), &count, NULL) || GetLastError() != ERROR_BROKEN_PIPE || count)
        ExitProcess(25);
    if (!CloseHandle(reader))
        ExitProcess(26);
}

void entry(void) {
    SECURITY_ATTRIBUTES inheritable = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};
    pipe_round_trip(NULL, 0);
    pipe_round_trip(&inheritable, 4);
    static const char verified[] = "anonymous pipe payload and EOF\n";
    DWORD count = 0;
    if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), verified, sizeof(verified)-1, &count, NULL) ||
        count != sizeof(verified)-1)
        ExitProcess(27);
    ExitProcess(0);
}
