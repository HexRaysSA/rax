#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    gid_t groups[64];
    errno = 0;
    int negative = syscall(SYS_getgroups, -1, groups);
    bool rejects_negative = negative == -1 && errno == EINVAL;

    errno = 0;
    int size = syscall(SYS_getgroups, 0, NULL);
    errno = 0;
    int invalid = syscall(SYS_getgroups, 64, NULL);
    bool rejects_null = invalid == -1 && errno == EFAULT;

    int read = syscall(SYS_getgroups, 64, groups);
    bool count_matches = size > 0 && size == read;
    bool first_is_effective_gid = count_matches && groups[0] == getegid();
    printf("query-and-read-agree=%d effective-gid-first=%d negative-size-EINVAL=%d null-list-EFAULT=%d\n",
           count_matches, first_is_effective_gid, rejects_negative, rejects_null);
    return !(count_matches && first_is_effective_gid && rejects_negative && rejects_null);
}
