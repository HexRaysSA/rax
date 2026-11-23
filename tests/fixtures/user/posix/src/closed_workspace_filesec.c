#define _DARWIN_C_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/acl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

static void property(filesec_t security, const char *label) {
    acl_t acl = NULL;
    int result = filesec_get_property(security, FILESEC_ACL, &acl);
    printf("%s ACL status=%d errno=%d\n", label, result, result < 0 ? errno : 0);
    if (result == 0) acl_free(acl);
}

int main(int argc, char **argv) {
    if (argc != 2 || mkdir(argv[1], 0700) || chdir(argv[1])) return 1;
    int file = open("file", O_RDWR | O_CREAT | O_EXCL, 0600);
    if (file < 0 || write(file, "ACL", 3) != 3 || symlink("file", "link")) return 2;
    filesec_t security = filesec_init();
    if (!security) return 3;
    struct stat st;
    if (fstatx_np(file, &st, security)) return 4;
    property(security, "descriptor");
    printf("descriptor is regular=%d size=%lld\n", S_ISREG(st.st_mode), (long long)st.st_size);
    if (statx_np("link", &st, security)) return 5;
    property(security, "follow");
    printf("follow is regular=%d\n", S_ISREG(st.st_mode));
    if (lstatx_np("link", &st, security)) return 6;
    property(security, "no follow");
    printf("no follow is link=%d\n", S_ISLNK(st.st_mode));

    unsigned char bytes[64];
    memset(bytes, 0xa5, sizeof(bytes));
    size_t size = sizeof(bytes);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    int status = syscall(SYS_fstat64_extended, file, &st, bytes, &size);
    if (status || size > sizeof(bytes)) return 8;
    printf("empty record size=%zu bytes=", size);
    for (size_t index = 0; index < size; index++) printf("%02x", bytes[index]);
    putchar('\n');
    size = 0;
    status = syscall(SYS_fstat64_extended, file, &st, (void *)1, &size);
    printf("zero capacity status=%d size=%zu\n", status, size);
    size = sizeof(bytes);
    status = syscall(SYS_fstat64_extended, file, &st, (void *)1, &size);
    printf("invalid buffer status=%d errno=%d size=%zu\n",
           status, status < 0 ? errno : 0, size);
    memset(&st, 0, sizeof(st));
    status = syscall(SYS_fstat64_extended, file, &st, bytes, NULL);
    printf("invalid size pointer status=%d errno=%d stat written=%d\n",
           status, status < 0 ? errno : 0, S_ISREG(st.st_mode));
    status = syscall(SYS_fstat64_extended, file, &st, NULL, NULL);
    printf("omitted ACL status=%d\n", status);
#pragma clang diagnostic pop

    if (unlink("file") || fstatx_np(file, &st, security)) return 7;
    property(security, "retained descriptor");
    printf("retained link count=%u\n", (unsigned)st.st_nlink);
    filesec_free(security);
    return close(file) || unlink("link") || chdir("/") || rmdir(argv[1]);
}
