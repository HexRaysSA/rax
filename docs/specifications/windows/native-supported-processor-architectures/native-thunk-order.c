typedef unsigned long U32;
typedef __UINTPTR_TYPE__ Word;
#define API __declspec(dllimport) __stdcall

API U32 NtQuerySystemInformationEx(U32, const void *, U32, void *, U32, U32 *);
API const char *GetCommandLineA(void);
API void *GetStdHandle(U32);
API void *VirtualAlloc(void *, Word, U32, U32);
API int VirtualFree(void *, Word, U32);
API int WriteFile(void *, const void *, U32, U32 *, void *);
API __declspec(noreturn) void ExitProcess(U32);

struct Reply {
    U32 status, returned;
    unsigned char output[32];
};

void mainCRTStartup(void) {
    const char *line = GetCommandLineA();
    U32 mode = 0;
    for (const char *end = line; *end; ++end) {
        if (*end >= '0' && *end <= '9') mode = 10 * mode + *end - '0';
        else mode = 0;
    }
    const U32 room = 4096;
    void *unmapped = VirtualAlloc(0, room, 0x3000, 1);
    if (!unmapped) ExitProcess(2);
    __declspec(align(8)) Word subject = 0;
    struct Reply result;
    for (U32 at=0; at < 32; ++at) result.output[at] = 0xa5;
    result.returned = 0xa5a5a5a5;
    void *input = &subject;
    void *output = result.output;
    U32 *returned = &result.returned;
    U32 input_length = sizeof(subject);
    U32 output_length = 16;
    switch (mode) {
        case 0: break;
        case 1: input = 0; break;
        case 2: input = 0; input_length = 0; break;
        case 3: input = unmapped; break;
        case 4: input = unmapped; input_length = 0; break;
        case 5: output = unmapped; break;
        case 6: output = unmapped; output_length = 4; break;
        case 7: returned = unmapped; break;
        case 8: returned = unmapped; output_length = 0; break;
        case 9: input = unmapped; output = result.output + 1; break;
        case 10: input = unmapped; returned = unmapped; break;
        case 11: input = 0; output = result.output + 1; break;
        case 12: returned = (U32 *)result.output; break;
        case 13: input_length = 4; output = unmapped; break;
        case 14: input_length = 4; returned = unmapped; break;
        case 15: input_length = 0xffffffff; break;
        case 16: subject = 0xf1234560; returned = unmapped; break;
        case 17: subject = 0xf1234560; output = result.output + 1; break;
        default: ExitProcess(3);
    }
    result.status = NtQuerySystemInformationEx(230, input, input_length, output, output_length, returned);
    U32 written = 0;
    if (!VirtualFree(unmapped, 0, 0x8000)) ExitProcess(4);
    if (!WriteFile(GetStdHandle((U32)-11), &result, sizeof(result), &written, 0)
        || written != sizeof(result)) ExitProcess(5);
    ExitProcess(0);
}
