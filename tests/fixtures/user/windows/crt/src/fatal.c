#include "common.h"
static DWORD marker;
static int WINAPI forbidden_veh(void *information) {
    (void)information; ExitProcess(176);
}
static void WINAPI forbidden_fls(void *value) {
    (void)value; ExitProcess(177);
}
void entry(void) {
    DWORD slot;
    check(AddVectoredExceptionHandler(1, forbidden_veh) != 0, 178);
    slot = FlsAlloc(forbidden_fls); check(slot != INFINITE, 179);
    check(FlsSetValue(slot, &marker), 180);
    /* No custom handler: the public contract requires termination, not return. */
    check(_get_invalid_parameter_handler() == 0, 174);
    (void)_get_errno(0);
    ExitProcess(175);
}
