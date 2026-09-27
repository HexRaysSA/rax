#include "common.h"
extern DWORD GrowStackSwitch(void *, DWORD, void *, UPTR);
static DWORD slot;
static void *root, *child;
static volatile DWORD entered, callbacks, resumed;
static UPTR value = COOKIE, allocation, growth_address;
static void WINAPI callback(void *data) {
    volatile unsigned char local[192];
    DWORD i;
    for (i = 0; i < 192; ++i) local[i] = (unsigned char)(i ^ 0x5a);
    check(data == &value && *(UPTR *)data == COOKIE, 151);
    for (i = 0; i < 192; ++i) check(local[i] == (unsigned char)(i ^ 0x5a), 152);
    stack_check(153);
    ++callbacks;
}
static void WINAPI body(void *data) {
    volatile UPTR local = COOKIE + 1;
    MBI info;
    check(data == &value && fiber_data() == data, 155);
    check(VirtualQuery((void *)&local, &info, sizeof(info)) == sizeof(info), 156);
    allocation = (UPTR)info.allocation;
    growth_address = ((UPTR)&local & ~(UPTR)4095) - 32 * 4096 + 512;
    check(VirtualQuery((void *)growth_address, &info, sizeof(info)) == sizeof(info), 170);
    check(info.state == MEM_RESERVE, 171);
    entered = 1;
    /* Descending stores perform actual CPU fault/retry, never host preflight. */
    check(GrowStackSwitch(root, slot, &value, COOKIE + 2) == 0, 157);
    check(callbacks == 1 && local == COOKIE + 1, 158);
    stack_check(159);
    resumed = 1;
    SwitchToFiber(root);
    ExitProcess(161);
}
void entry(void) {
    MBI info;
    slot = FlsAlloc(callback); check(slot != INFINITE, 162);
    root = ConvertThreadToFiberEx(0, FLOAT_SWITCH); check(root != 0, 163);
    child = CreateFiberEx(4096, 262144, FLOAT_SWITCH, body, &value);
    check(child && !entered, 164);
    SwitchToFiber(child);
    check(entered == 1 && callbacks == 1 && !resumed, 165);
    check(VirtualQuery((void *)growth_address, &info, sizeof(info)) == sizeof(info), 172);
    check(info.state == MEM_COMMIT, 173);
    SwitchToFiber(child);
    check(resumed == 1 && callbacks == 1, 166);
    DeleteFiber(child);
    check(callbacks == 1, 167);
    check(VirtualQuery((void *)allocation, &info, sizeof(info)) == sizeof(info), 168);
    check(info.state == MEM_FREE && ConvertFiberToThread(), 169);
    ExitProcess(0);
}
