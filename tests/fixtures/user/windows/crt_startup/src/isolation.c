#include "common.h"
typedef int (CRTCALL *GetArgs)(int *, char ***, char ***, int, STARTINFO *);
typedef int (CRTCALL *SetMode)(int);
void entry(void) {
    void *legacy = LoadLibraryA("msvcrt.dll");
    void *universal = LoadLibraryA("ucrtbase.dll");
    check(legacy && universal && legacy != universal, 120);
    GetArgs get = (GetArgs)GetProcAddress(legacy, "__getmainargs");
    SetMode lmode = (SetMode)GetProcAddress(legacy, "?_set_new_mode@@YAHH@Z");
    int *argc_l = (int *)GetProcAddress(legacy, "__argc");
    char ***argv_l = (char ***)GetProcAddress(legacy, "__argv");
    check(_configure_narrow_argv(1) == 0 && *argc_cell() == 3, 123);
    check(get && lmode && argc_l && argv_l, 121);
    STARTINFO info = {0};
    int argc;
    char **argv, **env;
    check(get(&argc, &argv, &env, 0, &info) == 0 && argc == 3, 122);
    check(argc_l != argc_cell() && argv_l != argv_cell() && *argv_l != *argv_cell(), 124);
    check(same_n((*argv_l)[1], "one") && same_n((*argv_cell())[1], "one"), 125);
    *argc_l = 37;
    (*argv_l)[1][0] = 'L';
    check(*argc_cell() == 3 && same_n((*argv_cell())[1], "one"), 126);
    *argc_cell() = 41;
    (*argv_cell())[1][0] = 'U';
    check(*argc_l == 37 && same_n((*argv_l)[1], "Lne"), 127);
    check(lmode(1) == 0 && set_new_mode(0) == 0 && lmode(0) == 1 && set_new_mode(1) == 0, 128);
    check(set_new_mode(0) == 1, 129);
    ExitProcess(0);
}
