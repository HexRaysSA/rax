#include <windows.h>

using ContextCall = LONG(NTAPI *)(HANDLE, void *);
static ContextCall get_context, set_context;
static HANDLE worker_ready, worker_release;
static DWORD WINAPI worker(void *) {
    if (!SetEvent(worker_ready)) return 101;
    if (WaitForSingleObject(worker_release, INFINITE) != WAIT_OBJECT_0) return 102;
    return 0x52415843;
}
static void check(bool value, UINT stage) { if (!value) ExitProcess(stage); }
static void copy(unsigned char *to, const unsigned char *from, unsigned size) {
    for (unsigned i = 0; i < size; ++i) to[i] = from[i];
}
static void fill(unsigned char *to, unsigned size, unsigned char value) {
    for (unsigned i = 0; i < size; ++i) to[i] = value;
}
static void put32(unsigned char *at, ULONG value) { copy(at, reinterpret_cast<unsigned char *>(&value), 4); }
static ULONG read32(const unsigned char *at) { ULONG value; copy(reinterpret_cast<unsigned char *>(&value), at, 4); return value; }
static unsigned long long read64(const unsigned char *at) {
    unsigned long long value; copy(reinterpret_cast<unsigned char *>(&value), at, 8); return value;
}
static void output(const ULONG *values, unsigned count, const unsigned char *mask = nullptr, unsigned bytes = 0) {
    static const char digits[] = "0123456789abcdef";
    char line[8192]; unsigned at = 0;
    line[at++] = 'c'; line[at++] = 'a'; line[at++] = 's'; line[at++] = 'e'; line[at++] = ' ';
    for (unsigned i = 0; i < count; ++i) {
        for (int shift = 28; shift >= 0; shift -= 4) line[at++] = digits[(values[i] >> shift) & 15];
        line[at++] = ' ';
    }
    for (unsigned i = 0; i < bytes; ++i) line[at++] = digits[mask[i]];
    line[at++] = '\n'; DWORD written = 0;
    check(WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), line, at, &written, nullptr) && written == at, 99);
}
static ULONG invoke(ContextCall call, HANDLE thread, void *context, ULONG &exception) {
    exception = 0;
    __try { return ULONG(call(thread, context)); }
    __except(EXCEPTION_EXECUTE_HANDLER) { exception = GetExceptionCode(); return exception; }
}

extern "C" __declspec(noreturn) void entry() {
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    get_context = reinterpret_cast<ContextCall>(GetProcAddress(ntdll, "NtGetContextThread"));
    set_context = reinterpret_cast<ContextCall>(GetProcAddress(ntdll, "NtSetContextThread"));
    check(get_context && set_context, 10);
    for (ULONG operation = 0; operation < 2; ++operation) {
        const auto *code = reinterpret_cast<const unsigned char *>(operation ? set_context : get_context);
        ULONG row[12] = {0xfffffffe, 7, operation, ULONG(ULONG_PTR(code) - ULONG_PTR(ntdll))};
        for (unsigned at = 0; at < 8; ++at) row[4 + at] = read32(code + at * 4);
        output(row, 12);
    }
    USHORT process_machine = 0, native_machine = 0;
    check(IsWow64Process2(GetCurrentProcess(), &process_machine, &native_machine) && native_machine == 0xaa64, 11);
#if defined(_M_IX86)
    const ULONG tag = 0x10000, all = 0x1003f, size = 716, flags_offset = 0, sp_offset = 196, pc_offset = 184;
#elif defined(_M_X64)
    const ULONG tag = 0x100000, all = 0x10001f, size = 1232, flags_offset = 48, sp_offset = 152, pc_offset = 248;
#else
    const ULONG tag = 0x400000, all = 0x40001f, size = 912, flags_offset = 0, sp_offset = 256, pc_offset = 264;
#endif
    using EnabledFeatures = unsigned long long(WINAPI *)();
    const auto enabled_features = reinterpret_cast<EnabledFeatures>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetEnabledXStateFeatures"));
    const unsigned long long enabled = enabled_features ? enabled_features() : ~0ull;
    ULONG feature_row[] = {0xfffffffd, 15, ULONG(enabled), ULONG(enabled >> 32),
        ULONG(IsProcessorFeaturePresent(PF_XSAVE_ENABLED)), ULONG(IsProcessorFeaturePresent(PF_AVX_INSTRUCTIONS_AVAILABLE)),
        ULONG(IsProcessorFeaturePresent(PF_AVX2_INSTRUCTIONS_AVAILABLE)), ULONG(IsProcessorFeaturePresent(PF_AVX512F_INSTRUCTIONS_AVAILABLE))};
    output(feature_row, sizeof(feature_row) / sizeof(feature_row[0]));
    DWORD tid = 0;
    worker_ready = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    worker_release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    check(worker_ready && worker_release, 122);
    HANDLE thread = CreateThread(nullptr, 0, worker, nullptr, 0, &tid);
    check(thread != nullptr, 12);
    check(WaitForSingleObject(worker_ready, INFINITE) == WAIT_OBJECT_0, 123);
    check(SuspendThread(thread) == 0, 124);
    auto *memory = static_cast<unsigned char *>(VirtualAlloc(nullptr, 65536, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    check(memory != nullptr, 13);
    unsigned char *saved = memory, *first = memory + 4096, *second = memory + 8192;
    put32(saved + flags_offset, all); ULONG exception = 0;
    const ULONG captured = invoke(get_context, thread, saved, exception);
    ULONG header[] = {0xffffffff, tag, size, captured, exception, read32(saved), read32(saved + 48),
                      ULONG(read64(saved + sp_offset)), ULONG(read64(saved + pc_offset))};
    output(header, sizeof(header) / sizeof(header[0]));
    check(captured == 0 && exception == 0 && (read32(saved + flags_offset) & 0xff0000) == tag, 80);
    const ULONG flags[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 15, 16, 31, 32, 63, 64, 128, 256,
                          0x10000, 0x1003f, 0x100000, 0x10000f, 0x400000, 0x400017,
                          0x40001f, 0x20000000, 0xf8000000, 0xffffffff,
                          tag | 1, tag | 2, tag | 4, tag | 8, tag | 16, tag | 31,
                          tag | 32, tag | 64, tag | 128, tag | 0x04000000, tag | 0x08000000,
                          tag | 0x10000000, tag | 0x20000000, tag | 0x40000000, tag | 0x80000000,
                          tag | 0x00000000, tag | 0x08000000, tag | 0x10000000, tag | 0x18000000, tag | 0x20000000, tag | 0x28000000, tag | 0x30000000, tag | 0x38000000, tag | 0x40000000, tag | 0x48000000, tag | 0x50000000, tag | 0x58000000, tag | 0x60000000, tag | 0x68000000, tag | 0x70000000, tag | 0x78000000, tag | 0x80000000, tag | 0x88000000, tag | 0x90000000, tag | 0x98000000, tag | 0xa0000000, tag | 0xa8000000, tag | 0xb0000000, tag | 0xb8000000, tag | 0xc0000000, tag | 0xc8000000, tag | 0xd0000000, tag | 0xd8000000, tag | 0xe0000000, tag | 0xe8000000, tag | 0xf0000000, tag | 0xf8000000};
    ULONG index = 0;
    for (ULONG request : flags) {
        fill(first, 2048, 0xa5); fill(second, 2048, 0x5a);
        put32(first + flags_offset, request); put32(second + flags_offset, request);
        SetLastError(0x76543210); ULONG ex1 = 0, ex2 = 0;
        const ULONG status1 = invoke(get_context, thread, first, ex1), error1 = GetLastError();
        SetLastError(0x76543210);
        const ULONG status2 = invoke(get_context, thread, second, ex2), error2 = GetLastError();
        unsigned char mask[6144];
        for (unsigned i = 0; i < 2048; ++i) {
            const unsigned char before1 = i >= flags_offset && i < flags_offset + 4 ? reinterpret_cast<const unsigned char *>(&request)[i - flags_offset] : 0xa5;
            const unsigned char before2 = i >= flags_offset && i < flags_offset + 4 ? reinterpret_cast<const unsigned char *>(&request)[i - flags_offset] : 0x5a;
            mask[i] = (first[i] == before1 && second[i] == before2) ? 0 : first[i] == second[i] ? 1 : 2;
        }
        for (unsigned i = 0; i < 2048; ++i) {
            mask[2048 + 2 * i] = first[i] >> 4;
            mask[2048 + 2 * i + 1] = first[i] & 15;
        }
        ULONG row[] = {index++, 0, request, status1, ex1, error1, status2, ex2, error2,
                       read32(first), read32(second), read32(first + 48), read32(second + 48)};
        output(row, sizeof(row) / sizeof(row[0]), mask, 6144);
    }
    for (ULONG request : flags) {
        copy(first, saved, size); put32(first + flags_offset, request);
        SetLastError(0x76543210); ULONG ex = 0;
        const ULONG status = invoke(set_context, thread, first, ex), error = GetLastError();
        ULONG row[] = {index++, 1, request, status, ex, error}; output(row, sizeof(row) / sizeof(row[0]));
        ULONG restore_exception = 0;
        check(invoke(set_context, thread, saved, restore_exception) == 0 && restore_exception == 0, 81);
    }
    for (ULONG offset = 0; offset < 16; ++offset) {
        for (ULONG operation = 0; operation < 2; ++operation) {
            fill(first, 2048, 0); copy(first + offset, saved, size); put32(first + offset + flags_offset, tag);
            ULONG ex = 0; SetLastError(0x76543210);
            const ULONG status = invoke(operation ? set_context : get_context, thread, first + offset, ex);
            ULONG row[] = {index++, 2, operation, offset, status, ex, GetLastError()};
            output(row, sizeof(row) / sizeof(row[0]));
        }
    }
#if defined(_M_IX86)
    const ULONG debug_offset = 4, debug_size = 24, debug_flag = 16;
#elif defined(_M_X64)
    const ULONG debug_offset = 72, debug_size = 48, debug_flag = 16;
#else
    const ULONG debug_offset = 792, debug_size = 120, debug_flag = 8;
#endif
    const ULONG debug_values[] = {0, 1, 2, 3, 0x10, 0x100, 0x10000, 0x80000000, 0xffffffff};
    for (ULONG value : debug_values) {
        copy(first, saved, size); put32(first + flags_offset, tag | debug_flag);
        for (ULONG at = 0; at < debug_size; at += 4) put32(first + debug_offset + at, value);
        ULONG set_exception = 0; SetLastError(0x76543210);
        const ULONG set_status = invoke(set_context, thread, first, set_exception);
        const ULONG set_error = GetLastError();
        fill(second, 2048, 0); put32(second + flags_offset, tag | debug_flag);
        ULONG get_exception = 0; SetLastError(0x76543210);
        const ULONG get_status = invoke(get_context, thread, second, get_exception);
        const ULONG get_error = GetLastError();
        ULONG row[42] = {index++, 5, value, set_status, set_exception, set_error,
                         get_status, get_exception, get_error, read32(second + flags_offset)};
        for (ULONG at = 0; at < debug_size; at += 4) row[10 + at / 4] = read32(second + debug_offset + at);
        output(row, 10 + debug_size / 4);
        ULONG restored = 0; check(invoke(set_context, thread, saved, restored) == 0 && restored == 0, 104);
    }

    for (ULONG test = 0; test < 34; ++test) {
        const ULONG value = test == 32 ? 0 : test == 33 ? 0xffffffff : (ULONG(1) << test);
        copy(first, saved, size); put32(first + flags_offset, tag | debug_flag);
        fill(first + debug_offset, debug_size, 0);
#if defined(_M_ARM64)
        for (ULONG n = 0; n < 8; ++n) { put32(first + debug_offset + n * 4, value); put32(first + debug_offset + 32 + n * 8, 0x12345000 + n * 256); }
        for (ULONG n = 0; n < 2; ++n) { put32(first + debug_offset + 96 + n * 4, value); put32(first + debug_offset + 104 + n * 8, 0x12346000 + n * 256); }
#else
        const ULONG width = sizeof(void *);
        for (ULONG n = 0; n < 4; ++n) put32(first + debug_offset + n * width, 0x12345000 + n * 256);
        put32(first + debug_offset + 4 * width, 0x9abcdef0);
        if (width == 8) put32(first + debug_offset + 4 * width + 4, 0x12345678);
        put32(first + debug_offset + 5 * width, value);
#endif
        ULONG ex = 0; SetLastError(0x76543210);
        const ULONG status = invoke(set_context, thread, first, ex), last = GetLastError();
        fill(second, 2048, 0); put32(second + flags_offset, tag | debug_flag);
        ULONG get_ex = 0; const ULONG get_status = invoke(get_context, thread, second, get_ex);
        ULONG row[42] = {index++, 8, value, status, ex, last, get_status, get_ex, GetLastError(), read32(second + flags_offset)};
        for (ULONG at = 0; at < debug_size; at += 4) row[10 + at / 4] = read32(second + debug_offset + at);
        output(row, 10 + debug_size / 4);
        ULONG restored = 0; check(invoke(set_context, thread, saved, restored) == 0 && restored == 0, 109);
    }
    const unsigned long long debug_addresses[] = {0, 0x12345000, 0x7ffffffeffff, 0x7fffffff0000,
        0x7fffffffffff, 0x800000000000, 0xffffffffffff, 0x1000000000000, ~0ull};
    for (unsigned long long value : debug_addresses) {
        copy(first, saved, size); put32(first + flags_offset, tag | debug_flag);
        fill(first + debug_offset, debug_size, 0);
#if defined(_M_ARM64)
        for (ULONG n = 0; n < 8; ++n) { put32(first + debug_offset + n * 4, 1); copy(first + debug_offset + 32 + n * 8, reinterpret_cast<unsigned char *>(&value), 8); }
        for (ULONG n = 0; n < 2; ++n) { put32(first + debug_offset + 96 + n * 4, 1); copy(first + debug_offset + 104 + n * 8, reinterpret_cast<unsigned char *>(&value), 8); }
#else
        const ULONG width = sizeof(void *);
        for (ULONG n = 0; n < 4; ++n) copy(first + debug_offset + n * width, reinterpret_cast<unsigned char *>(&value), width);
        put32(first + debug_offset + 5 * width, 0x55);
#endif
        ULONG ex = 0; SetLastError(0x76543210);
        const ULONG status = invoke(set_context, thread, first, ex), last = GetLastError();
        fill(second, 2048, 0); put32(second + flags_offset, tag | debug_flag);
        ULONG get_ex = 0; const ULONG get_status = invoke(get_context, thread, second, get_ex);
        ULONG row[43] = {index++, 9, ULONG(value), ULONG(value >> 32), status, ex, last, get_status, get_ex, GetLastError(), read32(second + flags_offset)};
        for (ULONG at = 0; at < debug_size; at += 4) row[11 + at / 4] = read32(second + debug_offset + at);
        output(row, 11 + debug_size / 4);
        ULONG restored = 0; check(invoke(set_context, thread, saved, restored) == 0 && restored == 0, 110);
    }

#if !defined(_M_ARM64)
    for (ULONG test = 0; test < 80; ++test) {
        const ULONG slot = test / 16, mode = test % 16;
        const ULONG value = slot < 4 ? (ULONG(1) << (slot * 2)) | (mode << (16 + slot * 4))
            : 0x55 | (mode * 0x11110000);
        copy(first, saved, size); put32(first + flags_offset, tag | debug_flag);
        fill(first + debug_offset, debug_size, 0);
        const ULONG width = sizeof(void *);
        for (ULONG n = 0; n < 4; ++n) put32(first + debug_offset + n * width, 0x12345000 + n * 256);
        put32(first + debug_offset + 5 * width, value);
        ULONG ex = 0; SetLastError(0x76543210);
        const ULONG status = invoke(set_context, thread, first, ex), last = GetLastError();
        fill(second, 2048, 0); put32(second + flags_offset, tag | debug_flag);
        ULONG get_ex = 0; const ULONG get_status = invoke(get_context, thread, second, get_ex);
        ULONG row[42] = {index++, 10, value, status, ex, last, get_status, get_ex, GetLastError(), read32(second + flags_offset)};
        for (ULONG at = 0; at < debug_size; at += 4) row[10 + at / 4] = read32(second + debug_offset + at);
        output(row, 10 + debug_size / 4);
        ULONG restored = 0; check(invoke(set_context, thread, saved, restored) == 0 && restored == 0, 111);
    }
#endif
    using ExtendedLength = LONG(NTAPI *)(ULONG, ULONG *);
    using ExtendedInitialize = LONG(NTAPI *)(void *, ULONG, void **);
    auto length_call = reinterpret_cast<ExtendedLength>(GetProcAddress(ntdll, "RtlGetExtendedContextLength"));
    auto initialize_call = reinterpret_cast<ExtendedInitialize>(GetProcAddress(ntdll, "RtlInitializeExtendedContext"));
    ULONG needed = 0, length_status = 0xffffffff, initialize_status = 0xffffffff;
    ULONG get_status = 0xffffffff, set_status = 0xffffffff, get_ex = 0, set_ex = 0, output_flags = 0;
    ULONG chunk[6] = {}; void *context_ex = nullptr; unsigned char *area = memory + 49152;
    const ULONG extended_flags = tag | (tag == 0x400000 ? 32 : 64);
    if (length_call && initialize_call) {
        length_status = ULONG(length_call(extended_flags, &needed));
        if (length_status == 0 && needed <= 16384) {
            fill(area, 16384, 0); initialize_status = ULONG(initialize_call(area, extended_flags, &context_ex));
            if (initialize_status == 0) {
                const auto *ex_bytes = static_cast<unsigned char *>(context_ex);
                check(ex_bytes >= area && ex_bytes + 24 <= area + 16384, 112);
                for (unsigned n = 0; n < 6; ++n) chunk[n] = read32(ex_bytes + 4 * n);
                auto *legacy = static_cast<unsigned char *>(context_ex) + LONG(chunk[2]);
                check(legacy >= area && legacy + size <= area + 16384, 113);
                get_status = invoke(get_context, thread, legacy, get_ex);
                output_flags = read32(legacy + flags_offset);
                put32(legacy + flags_offset, extended_flags);
                set_status = invoke(set_context, thread, legacy, set_ex);
                ULONG restored = 0; check(invoke(set_context, thread, saved, restored) == 0 && restored == 0, 114);
            }
        }
    }
    ULONG extended_row[] = {index++, 11, extended_flags, length_status, initialize_status, needed,
        get_status, get_ex, set_status, set_ex, output_flags, chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5]};
    output(extended_row, sizeof(extended_row) / sizeof(extended_row[0]));

    const unsigned long long feature_masks[] = {0, 1, 2, 3, 4, 7, 0xffffffffffffffffull};
    for (unsigned long long requested : feature_masks) {
        ULONG gs = 0xffffffff, ss = 0xffffffff, ge = 0, se = 0, restored_status = 0xffffffff;
        unsigned long long returned = 0, compact = 0, word = 0;
        if (length_status == 0 && needed <= 16384) {
            fill(area, 16384, 0); void *ex = nullptr;
            ULONG initialized = ULONG(initialize_call(area, extended_flags, &ex));
            if (initialized == 0) {
                auto *ex_bytes = static_cast<unsigned char *>(ex);
                auto *legacy = ex_bytes + LONG(read32(ex_bytes + 8));
                auto *state = ex_bytes + LONG(read32(ex_bytes + 16));
                const ULONG state_size = read32(ex_bytes + 20);
                check(state >= area && state_size >= 64 && state_size <= 4096 && state + state_size <= area + 16384, 115);
                copy(state, reinterpret_cast<unsigned char *>(&requested), 8);
                gs = invoke(get_context, thread, legacy, ge);
                returned = read64(state); compact = read64(state + 8);
                if (gs == 0 && requested == 4 && (returned & 4) && state_size >= 320) {
                    unsigned char *backup = memory + 12288; copy(backup, state, state_size);
                    fill(state + 64, 256, 0x5a);
                    ss = invoke(set_context, thread, legacy, se);
                    ULONG again_ex = 0; check(invoke(get_context, thread, legacy, again_ex) == 0 && again_ex == 0, 116);
                    word = read64(state + 64);
                    copy(state, backup, state_size);
                    ULONG restore_ex = 0; restored_status = invoke(set_context, thread, legacy, restore_ex);
                    check(restored_status == 0 && restore_ex == 0, 117);
                } else if (gs == 0) {
                    ss = invoke(set_context, thread, legacy, se);
                }
                ULONG restore_ex = 0; check(invoke(set_context, thread, saved, restore_ex) == 0 && restore_ex == 0, 118);
            }
        }
        ULONG row[] = {index++, 12, ULONG(requested), ULONG(requested >> 32), length_status,
            gs, ge, ss, se, ULONG(returned), ULONG(returned >> 32), ULONG(compact), ULONG(compact >> 32),
            ULONG(word), ULONG(word >> 32), restored_status};
        output(row, sizeof(row) / sizeof(row[0]));
    }

    // Vary only XSTATE chunk metadata in an otherwise initialized frame.
    if (length_status == 0) {
        const LONG offsets[] = {-1024, -64, -1, 0, 1, 16, 32, 48, 52, 64, 128, 4096};
        const ULONG lengths[] = {0, 1, 63, 64, 128, 192, 256, 319, 320, 321, 4096, 0xffffffff};
        for (ULONG field = 0; field < 2; ++field) for (ULONG n = 0; n < 12; ++n) {
            fill(area, 16384, 0); void *ex = nullptr;
            check(initialize_call(area, extended_flags, &ex) == 0, 126);
            auto *ex_bytes = static_cast<unsigned char *>(ex);
            auto *legacy = ex_bytes + LONG(read32(ex_bytes + 8));
            const ULONG value = field == 0 ? ULONG(offsets[n]) : lengths[n];
            put32(ex_bytes + (field == 0 ? 16 : 20), value);
            ULONG exception = 0; const ULONG status = invoke(get_context, thread, legacy, exception);
            ULONG row[] = {index++, 16, field, value, status, exception}; output(row, 6);
        }
    }
    const ULONG rights[] = {0, 8, 16, 24, 0x800, 0x1fffff};
    HANDLE handles[12] = {};
    for (unsigned i = 0; i < 6; ++i)
        check(DuplicateHandle(GetCurrentProcess(), thread, GetCurrentProcess(), &handles[i], rights[i], FALSE, 0), 87);
    handles[6] = CreateEventW(nullptr, TRUE, FALSE, nullptr); check(handles[6] != nullptr, 88);
    handles[7] = GetCurrentThread(); handles[8] = GetCurrentProcess();
    handles[9] = nullptr; handles[10] = reinterpret_cast<HANDLE>(ULONG_PTR(3));
    check(DuplicateHandle(GetCurrentProcess(), thread, GetCurrentProcess(), &handles[11], 0, FALSE, DUPLICATE_SAME_ACCESS), 89);
    check(CloseHandle(handles[11]), 90);
    // No new handles are allocated while the stale duplicate is exercised.
    unsigned char *region = memory + 16384;
    for (ULONG kind = 0; kind < 12; ++kind) {
        const ULONG tags = kind < 7 || kind == 11 ? 4 : 1;
        for (ULONG tag_bits = 0; tag_bits < tags; ++tag_bits) {
            for (ULONG pointer_case = 0; pointer_case < 10; ++pointer_case) {
                for (ULONG operation = 0; operation < 2; ++operation) {
                    DWORD old = 0;
                    check(VirtualProtect(region, 12288, PAGE_READWRITE, &old), 91);
                    fill(region, 12288, 0xa5);
                    unsigned char *address = region;
                    if (pointer_case == 1) address = nullptr;
                    if (pointer_case == 2) address = reinterpret_cast<unsigned char *>(ULONG_PTR(1));
                    if (pointer_case == 3) address = region + 1;
                    if (pointer_case == 8) address = region + 4096 - size + 16;
                    if (pointer_case == 9) address = region + 4096 - 64;
                    if (pointer_case != 1 && pointer_case != 2) {
                        copy(address, saved, size); put32(address + flags_offset, tag);
                    }
                    if (pointer_case == 4) check(VirtualProtect(region, 4096, PAGE_NOACCESS, &old), 92);
                    if (pointer_case == 5) check(VirtualProtect(region, 4096, PAGE_READONLY, &old), 93);
                    if (pointer_case == 6) check(VirtualProtect(region, 4096, PAGE_READWRITE | PAGE_GUARD, &old), 94);
                    if (pointer_case == 7) check(VirtualProtect(region, 4096, PAGE_READONLY | PAGE_GUARD, &old), 95);
                    if (pointer_case >= 8) check(VirtualProtect(region + 4096, 4096, PAGE_NOACCESS, &old), 96);
                    HANDLE target = reinterpret_cast<HANDLE>(ULONG_PTR(handles[kind]) | tag_bits);
                    ULONG ex = 0; SetLastError(0x76543210);
                    const ULONG status = invoke(operation ? set_context : get_context, target, address, ex);
                    const ULONG last = GetLastError(); MEMORY_BASIC_INFORMATION info = {};
                    check(VirtualQuery(region, &info, sizeof(info)) == sizeof(info), 97);
                    ULONG row[] = {index++, 3, kind, kind < 6 ? rights[kind] : 0, tag_bits,
                                   pointer_case, operation, status, ex, last, info.Protect};
                    output(row, sizeof(row) / sizeof(row[0]));
                }
            }
        }
    }
    DWORD old = 0; check(VirtualProtect(region, 12288, PAGE_READWRITE, &old), 98);
    for (unsigned i = 0; i < 7; ++i) check(CloseHandle(handles[i]), 100);

    const ULONG groups[] = {0, 1, 2, 4, 8, 16, 32, 64, 128};
    const ULONG readable[] = {4, 16, 48, 52, 64, 128, 152, 160, 180, 184, 196, 200,
                              204, 240, 256, 272, 288, 416, 492, 512, 528, 672, 700,
                              704, 712, 716, 784, 792, 896, 900, 908, 912, 1216, 1232};
    unsigned char *span_region = memory + 32768;
    for (ULONG group : groups) {
        for (ULONG bytes : readable) {
            for (ULONG operation = 0; operation < 2; ++operation) {
                DWORD old = 0; check(VirtualProtect(span_region, 12288, PAGE_READWRITE, &old), 101);
                unsigned char *address = span_region + 4096 - bytes;
                fill(span_region, 12288, 0); copy(address, saved, size);
                put32(address + flags_offset, tag | group);
                check(VirtualProtect(span_region + 4096, 4096, PAGE_NOACCESS, &old), 102);
                ULONG ex = 0; SetLastError(0x76543210);
                const ULONG status = invoke(operation ? set_context : get_context, thread, address, ex);
                ULONG row[] = {index++, 4, operation, group, bytes, status, ex, GetLastError()};
                output(row, sizeof(row) / sizeof(row[0]));
            }
        }
    }
    DWORD span_old = 0; check(VirtualProtect(span_region, 12288, PAGE_READWRITE, &span_old), 103);

    // Direct input feature masks, independent of the Get normalization above.
    const wchar_t *option = GetCommandLineW();
    if (*option == L'"') { ++option; while (*option && *option != L'"') ++option; if (*option) ++option; }
    else { while (*option && *option != L' ') ++option; }
    while (*option == L' ') ++option;
    const unsigned long long direct_masks[] = {*option == L'f' ? ~0ull : (*option >= L'0' && *option <= L'7' ? unsigned(*option - L'0') : 4)};
    const bool lower_only = option[1] == L'l' || option[1] == L'f';
    const ULONG direct_flags = option[1] == L'f' ? (all | extended_flags) : extended_flags;
    for (unsigned long long requested : direct_masks) {
        ULONG ss = 0xffffffff, se = 0, gs = 0xffffffff, ge = 0;
        unsigned long long returned = 0, word = 0;
        if (length_status == 0 && needed <= 16384) {
            fill(area, 16384, 0); void *ex = nullptr;
            check(initialize_call(area, direct_flags, &ex) == 0, 119);
            auto *ex_bytes = static_cast<unsigned char *>(ex);
            auto *legacy = ex_bytes + LONG(read32(ex_bytes + 8));
            auto *state = ex_bytes + LONG(read32(ex_bytes + 16));
            // Preserve a valid legacy FP/control frame even for direct masks 1/2.
            copy(legacy, saved, size); put32(legacy + flags_offset, direct_flags);
            copy(state, reinterpret_cast<const unsigned char *>(&requested), 8);
            fill(state + 64, lower_only && size == 716 ? 128 : 256, 0x3c);
            ss = invoke(set_context, thread, legacy, se);
            const unsigned long long query = 4;
            copy(state, reinterpret_cast<const unsigned char *>(&query), 8);
            gs = invoke(get_context, thread, legacy, ge);
            returned = read64(state); word = read64(state + 64);
            fill(state + 64, 256, 0);
            const unsigned long long restore_mask = ss == 0 ? requested & 4 : 0;
            copy(state, reinterpret_cast<const unsigned char *>(&restore_mask), 8);
            ULONG re = 0; check(invoke(set_context, thread, legacy, re) == 0 && re == 0, 120);
            check(invoke(set_context, thread, saved, re) == 0 && re == 0, 121);
        }
        ULONG row[] = {index++, 13, ULONG(requested), ULONG(requested >> 32), length_status,
            ss, se, gs, ge, ULONG(returned), ULONG(returned >> 32), ULONG(word), ULONG(word >> 32)};
        output(row, sizeof(row) / sizeof(row[0]));
    }

    ULONG restore_exception = 0;
    check(invoke(set_context, thread, saved, restore_exception) == 0 && restore_exception == 0, 82);
    check(ResumeThread(thread) == 1, 83);
    check(SetEvent(worker_release), 125);
    check(WaitForSingleObject(thread, INFINITE) == WAIT_OBJECT_0, 84);
    DWORD result = 0; check(GetExitCodeThread(thread, &result) && result == 0x52415843, 85);
    for (ULONG operation = 0; operation < 2; ++operation) {
        for (ULONG pointer_case = 0; pointer_case < 5; ++pointer_case) {
            DWORD old = 0; check(VirtualProtect(first, 4096, PAGE_READWRITE, &old), 105);
            copy(first, saved, size); put32(first + flags_offset, tag);
            void *address = first;
            if (pointer_case == 1) address = nullptr;
            if (pointer_case == 2) address = reinterpret_cast<void *>(ULONG_PTR(1));
            if (pointer_case == 3) address = first + 1;
            if (pointer_case == 4) check(VirtualProtect(first, 4096, PAGE_READWRITE | PAGE_GUARD, &old), 106);
            ULONG ex = 0; SetLastError(0x76543210);
            const ULONG status = invoke(operation ? set_context : get_context, thread, address, ex);
            const ULONG last = GetLastError(); MEMORY_BASIC_INFORMATION info = {};
            check(VirtualQuery(first, &info, sizeof(info)) == sizeof(info), 107);
            ULONG row[] = {index++, 6, operation, pointer_case, status, ex, last, info.Protect};
            output(row, sizeof(row) / sizeof(row[0]));
        }
    }
    DWORD retired_old = 0; check(VirtualProtect(first, 4096, PAGE_READWRITE, &retired_old), 108);

    check(CloseHandle(thread) && CloseHandle(worker_ready) && CloseHandle(worker_release) && VirtualFree(memory, 0, MEM_RELEASE), 86);
    ExitProcess(0);
}
