#include "common.h"
void entry(void) {
    FILE *input = standard(0), *output = standard(1), *error = standard(2);
    check(input && output && error && input != output && output != error, 110);
    check(standard(0) == input && standard(1) == output && standard(2) == error, 111);
    check(_fileno(input) == 0 && _fileno(output) == 1 && _fileno(error) == 2, 112);
    check(_get_osfhandle(0) == (IPTR)GetStdHandle((DWORD)-10) &&
          _get_osfhandle(1) == (IPTR)GetStdHandle((DWORD)-11) &&
          _get_osfhandle(2) == (IPTR)GetStdHandle((DWORD)-12), 113);
    int *mode = fmode_cell(), *commit = commode_cell();
    check(mode && commit && mode != commit, 114);
    check(fmode_cell() == mode && commode_cell() == commit, 115);
    int saved_mode = *mode, saved_commit = *commit;
    *mode = O_BINARY; *commit = 0;
    check(*fmode_cell() == O_BINARY && *commode_cell() == 0, 116);
    *mode = saved_mode; *commit = saved_commit;
    SetLastError(0x12345678u);
    check(_fileno(output) == 1 && GetLastError() == 0x12345678u, 117);
    check(setvbuf(output, 0, IONBF, 0) == 0 && setvbuf(error, 0, IONBF, 0) == 0, 118);
    check(fwrite("stdio-out\n", 1, 10, output) == 10, 119);
    check(fwrite("stdio-err\n", 1, 10, error) == 10, 120);
    check(fflush(0) == 0 && !ferror(output) && !ferror(error), 121);
    ExitProcess(0);
}
