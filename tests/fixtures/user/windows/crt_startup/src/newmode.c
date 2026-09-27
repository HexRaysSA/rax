#include "common.h"
void entry(void) {
    check(set_new_mode(0) == 0, 80);
#if defined(HAVE_NEW_QUERY)
    check(query_new_mode() == 0, 81);
#endif
    check(set_new_mode(1) == 0, 82);
#if defined(HAVE_NEW_QUERY)
    check(query_new_mode() == 1, 83);
#endif
    void *memory = malloc(31);
    check(memory != 0, 84);
    free(memory);
    STARTINFO info = {0};
    int argc;
    char **argv, **env;
    check(__getmainargs(&argc, &argv, &env, 0, &info) == 0, 85);
    check(set_new_mode(1) == 0, 86); /* Actual getter/wrapper applied newmode0. */
    WCHAR **wargv, **wenv;
    check(__wgetmainargs(&argc, &wargv, &wenv, 0, &info) == 0, 87);
    check(set_new_mode(1) == 0, 88);
    info.newmode = 1;
    check(__getmainargs(&argc, &argv, &env, 0, &info) == 0, 89);
    check(set_new_mode(0) == 1, 90);
    check(__wgetmainargs(&argc, &wargv, &wenv, 0, &info) == 0, 91);
    check(set_new_mode(0) == 1, 92);
    ExitProcess(0);
}
