#include "common.h"
void entry(void) {
    void *one = file(L"line.dat", 0xc0000000u, 2);
    void *two = file(L"flush.dat", 0xc0000000u, 2);
    FILE *a = stream(descriptor(one, O_BINARY | O_RDWR), "wb");
    FILE *b = stream(descriptor(two, O_BINARY | O_RDWR), "wb");
    char owned[8];
    /* Win32 IOLBF is documented as full buffering, not newline flushing. */
    check(setvbuf(a, owned, IOLBF, 7) == 0, 171);
    check(setvbuf(b, 0, IOFBF, 16) == 0, 172);
    check(fwrite("one\n", 1, 4, a) == 4 && fwrite("two", 1, 3, b) == 3, 173);
    check(length(one) == 0 && length(two) == 0, 174);
    check(fwrite("ab", 1, 2, a) == 2 && length(one) == 6, 179);
    check(fflush(0) == 0 && length(one) == 6 && length(two) == 3, 175);
    check(fwrite("!", 1, 1, a) == 1 && length(one) == 6, 176);
    check(fclose(a) == 0 && fclose(b) == 0, 177);
    closed(one); closed(two);
    *(volatile char *)(owned + 7) = 0x23;
    check(*(volatile char *)(owned + 7) == 0x23, 178);
    ExitProcess(0);
}
