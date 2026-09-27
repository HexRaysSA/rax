#include "common.h"
void entry(void) {
    void *handle = file(L"descriptor.dat", 0xc0000000u, 2);
    int fd = descriptor(handle, O_BINARY | O_RDWR);
    check(_write(fd, "FD\n", 3) == 3, 150);
    check(_setmode(fd, O_TEXT) == O_BINARY, 151);
    check(_write(fd, "T\n", 2) == 2, 152);
    check(_setmode(fd, O_BINARY) == O_TEXT && length(handle) == 6, 153);
    check(_close(fd) == 0, 154); closed(handle);
    handle = file(L"descriptor.dat", 0x80000000u, 3);
    fd = descriptor(handle, O_RDONLY | O_BINARY);
    FILE *input = _wfdopen(fd, L"rb");
    check(input && _fileno(input) == fd, 155);
    unsigned char actual[8];
    check(fread(actual, 1, 8, input) == 6 && equal(actual, "FD\nT\r\n", 6), 156);
    check(feof(input) && !ferror(input) && fclose(input) == 0, 157);
    closed(handle);
    handle = file(L"descriptor.dat", 0x80000000u, 3);
    fd = descriptor(handle, O_RDONLY | O_BINARY);
    check(_read(fd, actual, 8) == 6 && equal(actual, "FD\nT\r\n", 6), 158);
    check(_read(fd, actual, 1) == 0 && _close(fd) == 0, 159);
    closed(handle);
    ExitProcess(0);
}
