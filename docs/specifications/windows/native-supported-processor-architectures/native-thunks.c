typedef unsigned long U32;
typedef __UINTPTR_TYPE__ Handle;
#define API __declspec(dllimport) __stdcall

API U32 NtQuerySystemInformationEx(U32, const void *, U32, void *, U32, U32 *);
API void *GetStdHandle(U32);
API int WriteFile(void *, const void *, U32, U32 *, void *);
API __declspec(noreturn) void ExitProcess(U32);

struct Record {
    U32 index, input_length, capacity, input_offset, output_offset, status, returned;
    U32 output[12];
};

void mainCRTStartup(void) {
    static const Handle subjects[] = {0, (Handle)-1, 0xf1234560};
    static const U32 lengths[] = {0, 4, 8, 16};
    static const U32 capacities[] = {0, 1, 8, 15, 16, 32};
    void *log = GetStdHandle((U32)-11);
    __declspec(align(8)) Handle input[4];
    struct Record row;
    for (U32 index = 0; index < 3; ++index) {
        for (U32 slot = 0; slot < 4; ++slot) {
            for (U32 cap = 0; cap < 6; ++cap) {
                for (U32 variant = 0; variant < 4; ++variant) {
                    if (variant && (lengths[slot] != sizeof(Handle) || capacities[cap] != 16))
                        continue;
                    input[0] = subjects[index];
                    for (U32 i = 1; i < 4; ++i) input[i] = 0;
                    row.index = index;
                    row.input_length = lengths[slot];
                    row.capacity = capacities[cap];
                    row.input_offset = variant == 1 ? 1 : variant == 2 ? 4 : 0;
                    row.output_offset = variant == 3 ? 1 : 0;
                    row.returned = 0xa5a5a5a5;
                    for (U32 i = 0; i < 12; ++i) row.output[i] = 0xa5a5a5a5;
                    row.status = NtQuerySystemInformationEx(230,
                        (const unsigned char *)input + row.input_offset, row.input_length,
                        row.capacity ? (unsigned char *)row.output + row.output_offset : 0,
                        row.capacity, &row.returned);
                    U32 written = 0;
                    if (!WriteFile(log, &row, sizeof(row), &written, 0) || written != sizeof(row))
                        ExitProcess(1);
                }
            }
        }
    }
    ExitProcess(0);
}
