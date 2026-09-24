/* Reads standard input to end of file and reports a checksum. */
#include <stdio.h>
#include <unistd.h>

int main(void) {
    unsigned long total = 0, sum = 0;
    unsigned char buf[4096];
    ssize_t n;
    while ((n = read(0, buf, sizeof buf)) > 0) {
        for (ssize_t i = 0; i < n; i++)
            sum = sum * 31 + buf[i];
        total += (unsigned long)n;
    }
    printf("bytes=%lu sum=%lu last=%zd\n", total, sum, n);
    return n < 0;
}
