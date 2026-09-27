#include "common.h"
static const char *const plain[] = {"probe", "*.txt", "*.txt", "*.*", "sub\\?.bin", "absent*.q", "??.dat"};
static const char *const expanded[] = {
    "probe", "alpha.txt", "beta.txt", "*.txt", "README", "aa.dat", "alpha.txt",
    "bb.dat", "beta.txt", "sub", "sub\\q.bin", "absent*.q", "aa.dat", "bb.dat"
};
static const WCHAR *const wplain[] = {L"probe", L"*.txt", L"*.txt", L"*.*", L"sub\\?.bin", L"absent*.q", L"??.dat"};
static const WCHAR *const wexpanded[] = {
    L"probe", L"alpha.txt", L"beta.txt", L"*.txt", L"README", L"aa.dat", L"alpha.txt",
    L"bb.dat", L"beta.txt", L"sub", L"sub\\q.bin", L"absent*.q", L"aa.dat", L"bb.dat"
};
void entry(void) {
    STARTINFO info = {0};
    int argc;
    char **argv, **env;
    WCHAR **wargv, **wenv;
    check(__getmainargs(&argc, &argv, &env, 0, &info) == 0 && argc == 7, 60);
    for (int i = 0; i < argc; ++i) check(same_n(argv[i], plain[i]), 61);
    check(argv[argc] == 0, 62);
    check(__getmainargs(&argc, &argv, &env, 1, &info) == 0 && argc == 14, 63);
    for (int i = 0; i < argc; ++i) check(same_n(argv[i], expanded[i]), 64);
    check(argv[argc] == 0, 65);
    check(__wgetmainargs(&argc, &wargv, &wenv, 0, &info) == 0 && argc == 7, 66);
    for (int i = 0; i < argc; ++i) check(same_w(wargv[i], wplain[i]), 67);
    check(wargv[argc] == 0, 68);
    check(__wgetmainargs(&argc, &wargv, &wenv, 1, &info) == 0 && argc == 14, 69);
    for (int i = 0; i < argc; ++i) check(same_w(wargv[i], wexpanded[i]), 70);
    check(wargv[argc] == 0, 71);
    ExitProcess(0);
}
