#include "common.h"
#include "repair.h"
static char marker[] = "guest-marker";
static char *replacement[] = {marker, 0};
static WCHAR wmarker[] = L"guest-marker";
static WCHAR *wreplacement[] = {wmarker, 0};
static volatile int invalid_calls;
static void CRTCALL invalid(const WCHAR *expression, const WCHAR *function,
                           const WCHAR *file, unsigned int line, UPTR reserved) {
    (void)expression; (void)function; (void)file; (void)line;
    check(reserved == 0, 114);
    ++invalid_calls;
}
void entry(void) {
    InvalidHandler previous = _set_invalid_parameter_handler(invalid);
    check(_configure_narrow_argv(0) == 0 && *argc_cell() == 0 && *argv_cell() == 0, 100);
    void *handler = protect_and_register((void *)((UPTR)argc_cell() & ~(UPTR)4095), 1, 3);
    check(_configure_narrow_argv(1) == 0 && *argc_cell() == 3, 101);
    finish_repair(handler);
    check(invalid_calls == 0, 162); /* Saved formal mode3 did not replace captured mode1. */
    char **saved = *argv_cell();
    check(same_n(saved[0], "probe") && same_n(saved[1], "one") && same_n(saved[2], "two") && !saved[3], 102);
    check(_configure_narrow_argv(1) == 0 && *argv_cell() == saved, 103);
    *argc_cell() = 29;
    *argv_cell() = replacement;
    check(_configure_narrow_argv(1) == 0 && *argc_cell() == 29 && *argv_cell() == replacement, 104);
    check(_configure_narrow_argv(2) == 0 && *argc_cell() == 3 && !(*argv_cell())[3], 105);
    check(_configure_narrow_argv(0) == 0 && *argc_cell() == 0 && *argv_cell() == 0, 106);
    check(_configure_wide_argv(0) == 0 && *argc_cell() == 0 && *wargv_cell() == 0, 107);
    check(_configure_wide_argv(1) == 0 && *argc_cell() == 3, 108);
    WCHAR **wsaved = *wargv_cell();
    check(same_w(wsaved[0], L"probe") && same_w(wsaved[1], L"one") && same_w(wsaved[2], L"two") && !wsaved[3], 109);
    check(_configure_wide_argv(1) == 0 && *wargv_cell() == wsaved, 110);
    *argc_cell() = 31;
    *wargv_cell() = wreplacement;
    check(_configure_wide_argv(1) == 0 && *argc_cell() == 31 && *wargv_cell() == wreplacement, 111);
    check(_configure_wide_argv(2) == 0 && *argc_cell() == 3 && !(*wargv_cell())[3], 112);
    check(_configure_wide_argv(0) == 0 && *argc_cell() == 0 && *wargv_cell() == 0, 113);
    *_errno() = 71;
    check(_configure_narrow_argv(3) == 22 && *_errno() == 22 && invalid_calls == 1, 115);
    check(*argc_cell() == 0 && *argv_cell() == 0, 116);
    check(set_new_mode(2) == -1 && *_errno() == 22 && invalid_calls == 2, 117);
    check(query_new_mode() == 0, 118);
    _set_invalid_parameter_handler(previous);
    ExitProcess(0);
}
