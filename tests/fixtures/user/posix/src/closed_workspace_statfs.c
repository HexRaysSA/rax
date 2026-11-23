#define _DARWIN_C_SOURCE 1
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <sys/mount.h>
#else
#include <sys/vfs.h>
#endif

static int same_volume(const struct statfs *left, const struct statfs *right)
{
    return left->f_bsize == right->f_bsize && left->f_type == right->f_type &&
           memcmp(&left->f_fsid, &right->f_fsid, sizeof(left->f_fsid)) == 0;
}

static int writable(const struct statfs *volume)
{
#if defined(__APPLE__)
    return (volume->f_flags & MNT_RDONLY) == 0;
#else
    return (volume->f_flags & 1) == 0;
#endif
}

int main(int argc, char **argv)
{
    if (argc != 2 || mkdir(argv[1], 0700) || chdir(argv[1])) return 1;
    int fd = open("data", O_CREAT | O_RDWR, 0600);
    if (fd < 0 || symlink("data", "alias")) return 2;

    struct statfs directory, path, descriptor, alias;
    if (statfs(".", &directory) || statfs("data", &path) ||
        fstatfs(fd, &descriptor) || statfs("alias", &alias)) return 3;
    if (!same_volume(&directory, &path) || !same_volume(&path, &descriptor) ||
        !same_volume(&descriptor, &alias) || !writable(&descriptor) ||
        !writable(&path) || !descriptor.f_blocks || !descriptor.f_files ||
        descriptor.f_bavail > descriptor.f_bfree ||
        descriptor.f_bfree > descriptor.f_blocks ||
        descriptor.f_ffree > descriptor.f_files) return 4;

    if (unlink("data") || fstatfs(fd, &descriptor) || !same_volume(&descriptor, &path)) return 5;
    if (statfs("alias", &alias) != -1 || errno != ENOENT) return 6;
    if (close(fd) || unlink("alias") || chdir("/") || rmdir(argv[1])) return 7;
    puts("path, descriptor and symlink agree on the writable volume");
    return 0;
}
