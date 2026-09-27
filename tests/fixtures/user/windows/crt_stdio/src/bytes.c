#include "common.h"
static const unsigned char golden[7] = {'A', 0, 'B', '\n', 'C', '\r', 255};
void entry(void) {
    void *handle = file(L"bytes.dat", 0xc0000000u, 2);
    int fd = descriptor(handle, O_BINARY | O_RDWR);
    FILE *output = stream(fd, "wb");
    char owned[16]; for (SIZE i = 0; i < sizeof(owned); ++i) owned[i] = 0x5a;
    check(setvbuf(output, owned, IOFBF, sizeof(owned)) == 0, 130);
    check(fwrite(golden, 1, sizeof(golden), output) == sizeof(golden), 131);
    check(length(handle) == 0, 132); /* An incomplete full buffer is pending. */
    check(fflush(output) == 0 && length(handle) == sizeof(golden), 133);
    check(fclose(output) == 0, 134);
    closed(handle);
    /* Caller-owned memory remains caller-owned after fclose. */
    *(volatile char *)owned = 0x33; check(*(volatile char *)owned == 0x33, 135);
    handle = file(L"bytes.dat", 0x80000000u, 3);
    fd = descriptor(handle, O_BINARY | O_RDONLY);
    FILE *input = stream(fd, "rb");
    check(setvbuf(input, 0, IONBF, 0) == 0 && !feof(input) && !ferror(input), 136);
    unsigned char buffer[16]; for (SIZE i = 0; i < sizeof(buffer); ++i) buffer[i] = 0xa5;
    check(fread(buffer, 2, 3, input) == 3 && equal(buffer, golden, 6), 137);
    check(!feof(input), 138);
    check(fread(buffer + 6, 1, 4, input) == 1 && buffer[6] == golden[6], 139);
    check(feof(input) != 0 && ferror(input) == 0, 140);
    clearerr(input);
    check(feof(input) == 0 && ferror(input) == 0, 141);
    check(fread(buffer, 1, 1, input) == 0 && feof(input), 142);
    check(fclose(input) == 0, 143); closed(handle);
    ExitProcess(0);
}
