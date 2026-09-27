#include "common.h"
static char replacement[] = "OWN=replacement";
static char *current[] = {replacement, 0};
static WCHAR wreplacement[] = L"OWN=replacement";
static WCHAR *wcurrent[] = {wreplacement, 0};
static int matches_n(char **env, const char *expected) {
    int count = 0;
    for (int i = 0; env[i]; ++i) if (same_n(env[i], expected)) ++count;
    return count == 1;
}
static int matches_w(WCHAR **env, const WCHAR *expected) {
    int count = 0;
    for (int i = 0; env[i]; ++i) if (same_w(env[i], expected)) ++count;
    return count == 1;
}
void entry(void) {
    STARTINFO info = {0};
    int argc;
    char **argv, **env, **saved;
    WCHAR **wargv, **wenv, **wsaved;
    check(__getmainargs(&argc, &argv, &env, 0, &info) == 0, 40);
    if (argc == 2 && same_n(argv[1], "empty")) {
        check(env && !env[0], 59);
        check(__wgetmainargs(&argc, &wargv, &wenv, 0, &info) == 0 && wenv && !wenv[0], 59);
        ExitProcess(0);
    }
    saved = env;
    int count = 0;
    while (env[count]) { check(count < 4, 41); ++count; }
    check(count == 4 && matches_n(env, "alpha=last") && matches_n(env, "Beta=two") &&
          matches_n(env, "Mixed=caf\xe9") && matches_n(env, "EMPTY="), 42);
    check(__getmainargs(&argc, &argv, &env, 0, &info) == 0 && env == saved, 43);
    check(__wgetmainargs(&argc, &wargv, &wenv, 0, &info) == 0, 44);
    wsaved = wenv;
    count = 0;
    while (wenv[count]) { check(count < 4, 45); ++count; }
    check(count == 4 && matches_w(wenv, L"alpha=last") && matches_w(wenv, L"Beta=two") &&
          matches_w(wenv, L"Mixed=caf\u00e9") && matches_w(wenv, L"EMPTY="), 46);
    check(__wgetmainargs(&argc, &wargv, &wenv, 0, &info) == 0 && wenv == wsaved, 47);
#if defined(HAVE_ENV_CELLS)
    check(*environ_cell() == saved && initial_n() == saved, 48);
    check(*wenviron_cell() == wsaved && initial_w() == wsaved, 49);
    *environ_cell() = current;
    *wenviron_cell() = wcurrent;
    check(__getmainargs(&argc, &argv, &env, 0, &info) == 0 && env == current, 50);
    check(__wgetmainargs(&argc, &wargv, &wenv, 0, &info) == 0 && wenv == wcurrent, 51);
    check(initial_n() == saved && initial_w() == wsaved, 52);
#if !defined(LEGACY_CRT)
    check(_initialize_narrow_environment() == 0 && _initialize_wide_environment() == 0, 53);
    check(*environ_cell() == current && *wenviron_cell() == wcurrent, 54);
#elif defined(_M_IX86)
    check(__p__environ() == &_environ && __p__wenviron() == &_wenviron, 55);
    check(__p___initenv() == &__initenv && __p___winitenv() == &__winitenv, 56);
#endif
    *environ_cell() = saved;
    *wenviron_cell() = wsaved;
#else
    /* ARM64 legacy has no admitted initial/current cell exports. Mutating a
       returned shared vector must survive the repeated getter instead. */
    char **observed = 0;
    WCHAR **wobserved = 0;
    _get_environ(&observed);
    _get_wenviron(&wobserved);
    check(observed == saved && wobserved == wsaved, 163);
    char *original = saved[0];
    WCHAR *woriginal = wsaved[0];
    saved[0] = replacement;
    wsaved[0] = wreplacement;
    check(__getmainargs(&argc, &argv, &env, 0, &info) == 0 && env == saved && env[0] == replacement, 57);
    check(__wgetmainargs(&argc, &wargv, &wenv, 0, &info) == 0 && wenv == wsaved && wenv[0] == wreplacement, 58);
    saved[0] = original;
    wsaved[0] = woriginal;
#endif
    ExitProcess(0);
}
