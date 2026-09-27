#include "common.h"
#if defined(LEGACY_CRT)
#include "repair.h"
#endif
/* Independent raw-line/golden literals, not the CLI serializer or engine parser. */
static const char *const narrow[] = {
    "C:\\Program Files\\probe.exe", "", "ab\"c", "a\\\\\\b", "de fg", "caf\xe9", "x y"
};
static const WCHAR *const wide[] = {
    L"C:\\Program Files\\probe.exe", L"", L"ab\"c", L"a\\\\\\b", L"de fg", L"caf\u00e9", L"\uff02x", L"y\uff02"
};
static const WCHAR raw[] = L"\"C:\\Program Files\\probe.exe\" \"\" \"ab\\\"c\" a\\\\\\b d\"e f\"g \"caf\u00e9\" \uff02x y\uff02";
static const char raw_bestfit[] = "\"C:\\Program Files\\probe.exe\" \"\" \"ab\\\"c\" a\\\\\\b d\"e f\"g \"caf\xe9\" \"x y\"";
void entry(void) {
    STARTINFO info = {0};
    int argc = -1;
    char **argv = 0, **env = 0, **saved;
    WCHAR **wargv = 0, **wenv = 0, **wsaved;
    check(sizeof(int) == 4 && sizeof(WCHAR) == 2, 1);
    check(__getmainargs(&argc, &argv, &env, 0, &info) == 0 && argc == 7, 2);
    for (int i = 0; i < argc; ++i) check(same_n(argv[i], narrow[i]), 3 + i);
    check(argv[argc] == 0 && argv == *argv_cell() && argc == *argc_cell(), 11);
    saved = argv;
    for (int repeat = 0; repeat < 32; ++repeat)
        check(__getmainargs(&argc, &argv, &env, 0, &info) == 0 && argc == 7 && argv == saved, 12);
    check(__wgetmainargs(&argc, &wargv, &wenv, 0, &info) == 0 && argc == 8, 13);
    for (int i = 0; i < argc; ++i) check(same_w(wargv[i], wide[i]), 14 + i);
    check(wargv[argc] == 0 && wargv == *wargv_cell() && argc == *argc_cell(), 23);
    wsaved = wargv;
    for (int repeat = 0; repeat < 32; ++repeat)
        check(__wgetmainargs(&argc, &wargv, &wenv, 0, &info) == 0 && argc == 8 && wargv == wsaved, 24);
    /* Re-establish argc/vector consistency on each active-width transition.
       Pointer identity across these transitions is deliberately not asserted. */
    for (int repeat = 0; repeat < 4; ++repeat) {
        check(__getmainargs(&argc, &argv, &env, 0, &info) == 0 && argc == 7 && !argv[7], 34);
        for (int i = 0; i < argc; ++i) check(same_n(argv[i], narrow[i]), 35);
        check(__wgetmainargs(&argc, &wargv, &wenv, 0, &info) == 0 && argc == 8 && !wargv[8], 36);
        for (int i = 0; i < argc; ++i) check(same_w(wargv[i], wide[i]), 37);
    }
    check(same_w(raw_w(), raw) && same_n(raw_n(), raw_bestfit), 25);
    check(program_n() && ends_n(program_n(), "\\arguments.exe"), 26);
    check(same_n(program_n(), "C:\\arguments.exe") && same_w(program_w(), L"C:\\arguments.exe"), 27);
    check(!same_w(program_w(), wide[0]), 28); /* Full image path is not raw argv0. */
#if !defined(LEGACY_CRT)
    char *pgm = 0;
    WCHAR *wpgm = 0;
    check(_get_pgmptr(&pgm) == 0 && pgm == program_n(), 29);
    check(_get_wpgmptr(&wpgm) == 0 && wpgm == program_w(), 30);
    check(same_n(_get_narrow_winmain_command_line(), raw_bestfit + 29), 31);
    check(same_w(_get_wide_winmain_command_line(), raw + 29), 32);
#elif defined(_M_IX86)
    check(__p___argc() == &__argc && __p___argv() == &__argv && __p___wargv() == &__wargv, 33);
#endif
#if defined(LEGACY_CRT)
    typedef struct { int argc; char **argv, **env; } Output;
    Output *out = (Output *)VirtualAlloc(0, 4096, 0x3000, 4);
    check(out != 0, 157);
    out->argc = -1; out->argv = 0; out->env = 0;
    void *handler = protect_and_register(out, 5, 0);
    check(__getmainargs(&out->argc, &out->argv, &out->env, 0, &info) == 0, 158);
    finish_repair(handler);
    check(out->argc == 7 && out->argv && !out->argv[7] && out->env && !out->env[0], 159);
    for (int i = 0; i < out->argc; ++i) check(same_n(out->argv[i], narrow[i]), 160);
    check(VirtualFree(out, 0, 0x8000), 161);
#endif
    ExitProcess(0);
}
