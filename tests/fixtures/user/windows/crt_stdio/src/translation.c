#include "common.h"
void entry(void) {
    /* Runner supplies physical bytes; no expected bytes come from CRT output. */
    void *handle = file(L"text.dat", 0x80000000u, 3);
    int fd = descriptor(handle, O_RDONLY | O_TEXT);
    unsigned char actual[16]; SIZE count = 0;
    for (;;) { int n = _read(fd, actual + count, 1); check(n == 0 || n == 1, 160);
        if (!n) break; check(++count <= 8, 161); }
    check(count == 8 && equal(actual, "a\nb\rx\nYZ", 8), 162);
    check(_close(fd) == 0, 163); closed(handle);
    /* _read budgets physical bytes; CRLF contraction lowers returned count. */
    handle = file(L"text.dat", 0x80000000u, 3);
    fd = descriptor(handle, O_RDONLY | O_TEXT);
    check(_read(fd, actual, 3) == 2 && equal(actual, "a\n", 2), 180);
    check(_read(fd, actual, 3) == 3 && equal(actual, "b\rx", 3), 181);
    check(_read(fd, actual, 3) == 2 && equal(actual, "\nY", 2), 182);
    check(_read(fd, actual, 3) == 1 && actual[0] == 'Z', 183);
    check(_read(fd, actual, 3) == 0 && _close(fd) == 0, 184); closed(handle);
    /* Physical CR/LF at offsets 255/256 crosses the internal chunk boundary. */
    handle = file(L"edge.dat", 0x80000000u, 3);
    fd = descriptor(handle, O_RDONLY | O_TEXT);
    unsigned char chunk[768];
    check(_read(fd, chunk, sizeof(chunk)) == 767, 187);
    for (SIZE i = 0; i < 255; ++i) check(chunk[i] == 'a', 188);
    check(chunk[255] == '\n', 189);
    for (SIZE i = 256; i < 767; ++i) check(chunk[i] == 'b', 190);
    check(_read(fd, actual, 2) == 2 && equal(actual, "bZ", 2), 191);
    check(_read(fd, actual, 1) == 0 && _close(fd) == 0, 192); closed(handle);
    handle = file(L"text.dat", 0x80000000u, 3);
    fd = descriptor(handle, O_RDONLY | O_BINARY);
    check(_read(fd, actual, sizeof(actual)) == 12, 164);
    check(equal(actual, "a\r\nb\rx\r\nYZ\x1aQ", 12), 165);
    check(_close(fd) == 0, 166); closed(handle);
    handle = file(L"translate.dat", 0xc0000000u, 2);
    fd = descriptor(handle, O_TEXT | O_RDWR);
    FILE *output = stream(fd, "wt");
    char buffer[4]; check(setvbuf(output, buffer, IOFBF, 4) == 0, 167);
    check(fwrite("a\r", 1, 2, output) == 2 && fwrite("\nB\n", 1, 3, output) == 3, 168);
    check(fflush(output) == 0 && fclose(output) == 0, 169); closed(handle);
    /* _fmode is consulted when fdopen mode omits t/b. */
    int *mode = fmode_cell(), saved = *mode;
    *mode = O_BINARY;
    handle = file(L"default.dat", 0xc0000000u, 2);
    fd = descriptor(handle, O_TEXT | O_RDWR);
    output = stream(fd, "w");
    check(fwrite("D\n", 1, 2, output) == 2 && fclose(output) == 0, 170);
    *mode = saved; closed(handle);
    /* Checked profile: marker and suffix are excluded from this call's count. */
    handle = file(L"control.dat", 0xc0000000u, 2);
    fd = descriptor(handle, O_TEXT | O_RDWR);
    check(_write(fd, "A\x1a" "B", 3) == 1, 185);
    check(_write(fd, "C\n", 2) == 2 && _close(fd) == 0, 186); closed(handle);
    ExitProcess(0);
}
