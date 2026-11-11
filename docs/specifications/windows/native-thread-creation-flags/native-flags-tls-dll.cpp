#include <windows.h>

struct State {
    volatile LONG dll_attach, dll_detach, tls_attach, tls_detach;
};
static State state;
extern "C" DWORD _tls_index = 0;

static void NTAPI tls_callback(void *, DWORD reason, void *) {
    if (reason == DLL_THREAD_ATTACH) InterlockedIncrement(&state.tls_attach);
    if (reason == DLL_THREAD_DETACH) InterlockedIncrement(&state.tls_detach);
}
#pragma section(".tls", read, write)
__declspec(allocate(".tls")) static unsigned char template_data[8] = {0x26, 0x59, 0x41, 0x31, 0, 0, 0, 0};
static PIMAGE_TLS_CALLBACK callbacks[] = {tls_callback, nullptr};
#pragma section(".rdata$T", read)
extern "C" __declspec(allocate(".rdata$T")) const IMAGE_TLS_DIRECTORY _tls_used = {
    reinterpret_cast<ULONG_PTR>(template_data),
    reinterpret_cast<ULONG_PTR>(template_data + sizeof(template_data)),
    reinterpret_cast<ULONG_PTR>(&_tls_index),
    reinterpret_cast<ULONG_PTR>(callbacks), 0, 0
};
extern "C" BOOL WINAPI dll_entry(HINSTANCE, DWORD reason, void *) {
    if (reason == DLL_THREAD_ATTACH) InterlockedIncrement(&state.dll_attach);
    if (reason == DLL_THREAD_DETACH) InterlockedIncrement(&state.dll_detach);
    return TRUE;
}
extern "C" __declspec(dllexport) State *get_state() { return &state; }
extern "C" __declspec(dllexport) DWORD get_index() { return _tls_index; }
