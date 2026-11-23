#define _DARWIN_C_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 2 || mkdir(argv[1], 0700) || chdir(argv[1])) return 1;
    int dir = open(".", O_RDONLY | O_DIRECTORY);
    int file = open("file", O_CREAT | O_RDWR, 0600);
    if (dir < 0 || file < 0 || symlink("file", "alias")) return 2;

    const int selectors[] = {
        _PC_NAME_MAX, _PC_PATH_MAX, _PC_REC_INCR_XFER_SIZE, _PC_REC_MAX_XFER_SIZE,
        _PC_REC_MIN_XFER_SIZE, _PC_REC_XFER_ALIGN
    };
    for (size_t i = 0; i < sizeof(selectors) / sizeof(*selectors); ++i) {
        int selector = selectors[i];
        long value = pathconf(".", selector);
        if (value <= 0 || fpathconf(dir, selector) != value ||
            fpathconf(file, selector) != value || pathconf("alias", selector) != value) return 3;
        printf("%d=%ld\n", selector, value);
    }
    if (fpathconf(file, -1) != -1 || errno != EINVAL ||
        pathconf(".", -1) != -1 || errno != EINVAL) return 4;
    if (unlink("file") || fpathconf(file, _PC_REC_XFER_ALIGN) <= 0 ||
        pathconf("alias", _PC_REC_XFER_ALIGN) != -1 || errno != ENOENT) return 5;
    if (close(file) || fpathconf(file, _PC_REC_XFER_ALIGN) != -1 || errno != EBADF ||
        close(dir) || unlink("alias") || chdir("/") || rmdir(argv[1])) return 6;
    return 0;
}
