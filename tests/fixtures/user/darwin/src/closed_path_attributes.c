#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/attr.h>
#include <sys/stat.h>
#include <unistd.h>

static uint32_t get_u32(const unsigned char *bytes) {
    uint32_t value;
    memcpy(&value, bytes, sizeof(value));
    return value;
}

static void check_record(const unsigned char *record, const struct stat *st) {
    assert(get_u32(record) == 36);
    assert(get_u32(record + 4) == 24);
    assert(get_u32(record + 8) == sizeof("uname"));
    assert(get_u32(record + 12) == (uint32_t)st->st_dev);
    assert(get_u32(record + 16) == 1); /* VREG */
    uint64_t object_id;
    memcpy(&object_id, record + 20, sizeof(object_id));
    assert(object_id == st->st_ino);
    assert(memcmp(record + 28, "uname", sizeof("uname")) == 0);
    assert(record[34] == 0 && record[35] == 0);
    assert(record[36] == 0xAB);
}

static void check_string(const unsigned char *record, size_t reference,
                         size_t payload, const char *expected) {
    const size_t length = strlen(expected) + 1;
    assert(get_u32(record + reference) == payload - reference);
    assert(get_u32(record + reference + 4) == length);
    assert(memcmp(record + payload, expected, length) == 0);
}

static void check_bulk_after_rename(void) {
    char parent[] = "/tmp/rax-attribute-path.XXXXXX";
    assert(mkdtemp(parent) != NULL);
    int root = open(parent, O_RDONLY | O_DIRECTORY);
    assert(root != -1 && mkdirat(root, "old", 0700) == 0);
    int dir = openat(root, "old", O_RDONLY | O_DIRECTORY);
    assert(dir != -1 && mkdirat(dir, "child", 0700) == 0);
    assert(renameat(root, "old", root, "new") == 0);

    struct attrlist request = {
        .bitmapcount = ATTR_BIT_MAP_COUNT,
        .commonattr = ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_NAME | ATTR_CMN_FULLPATH,
    };
    unsigned char record[PATH_MAX + 128];
    assert(getattrlistbulk(dir, &request, record, sizeof(record), FSOPT_ATTR_CMN_EXTENDED) == 1);
    assert(get_u32(record + 4) == request.commonattr);
    uint32_t fullpath = 32 + get_u32(record + 32);
    size_t fullpath_size = get_u32(record + 36);
    const char suffix[] = "/new/child";
    assert(fullpath_size >= sizeof(suffix));
    assert(fullpath <= get_u32(record) && fullpath_size <= get_u32(record) - fullpath);
    assert(get_u32(record) <= sizeof(record));
    assert(memcmp(record + fullpath + fullpath_size - sizeof(suffix), suffix, sizeof(suffix)) == 0);
    assert(getattrlistbulk(dir, &request, record, sizeof(record), FSOPT_ATTR_CMN_EXTENDED) == 0);

    assert(unlinkat(dir, "child", AT_REMOVEDIR) == 0 && close(dir) == 0);
    assert(unlinkat(root, "new", AT_REMOVEDIR) == 0 && close(root) == 0);
    assert(rmdir(parent) == 0);
}

int main(void) {
    const char path[] = "/usr/bin/uname";
    struct attrlist request = {
        .bitmapcount = ATTR_BIT_MAP_COUNT,
        .commonattr = ATTR_CMN_NAME | ATTR_CMN_DEVID | ATTR_CMN_OBJTYPE | ATTR_CMN_OBJID,
    };
    unsigned char record[96];
    struct stat st;
    int dir = open("/usr/bin", O_RDONLY | O_DIRECTORY);
    int fd = open(path, O_RDONLY);
    assert(dir != -1 && fd != -1 && fstat(fd, &st) == 0);
    memset(record, 0xAB, sizeof(record));
    assert(getattrlist(path, &request, record, sizeof(record), FSOPT_NOFOLLOW) == 0);
    check_record(record, &st);
    memset(record, 0xAB, sizeof(record));
    assert(getattrlistat(dir, "uname", &request, record, sizeof(record), 0) == 0);
    check_record(record, &st);
    memset(record, 0xAB, sizeof(record));
    assert(fgetattrlist(fd, &request, record, sizeof(record), 0) == 0);
    check_record(record, &st);

    memset(record, 0xAB, sizeof(record));
    assert(getattrlist(path, &request, record, 5, FSOPT_REPORT_FULLSIZE) == 0);
    assert(get_u32(record) == 36 && record[4] == 24 && record[5] == 0xAB);
    errno = 0;
    assert(getattrlist(path, &request, record, 3, 0) == -1 && errno == ERANGE);
    errno = 0;
    assert(fgetattrlist(-1, &request, record, sizeof(record), 0) == -1 && errno == EBADF);
    errno = 0;
    assert(getattrlistat(dir, "rax-missing-path", &request, record, sizeof(record), 0) == -1);
    assert(errno == ENOENT);

    request.commonattr = ATTR_CMN_FULLPATH;
    memset(record, 0xAB, sizeof(record));
    assert(getattrlist("/usr/bin/../bin/uname", &request, record, sizeof(record), 0) == 0);
    assert(get_u32(record) == 28);
    check_string(record, 4, 12, path);
    assert(record[27] == 0 && record[28] == 0xAB);
    memset(record, 0xAB, sizeof(record));
    assert(getattrlistat(dir, "./uname", &request, record, sizeof(record), 0) == 0);
    check_string(record, 4, 12, path);
    memset(record, 0xAB, sizeof(record));
    assert(fgetattrlist(fd, &request, record, sizeof(record), 0) == 0);
    check_string(record, 4, 12, path);

    request.commonattr |= ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_NAME | ATTR_CMN_FILEID;
    memset(record, 0xAB, sizeof(record));
    assert(getattrlist(path, &request, record, sizeof(record), 0) == 0);
    assert(get_u32(record) == 72);
    assert(get_u32(record + 4) == request.commonattr);
    check_string(record, 24, 48, "uname");
    uint64_t file_id;
    memcpy(&file_id, record + 32, sizeof(file_id));
    assert(file_id == st.st_ino);
    check_string(record, 40, 56, path);
    assert(record[71] == 0 && record[72] == 0xAB);

    char resolved[PATH_MAX];
    assert(realpath("/usr/bin/../bin/uname", resolved) != NULL);
    assert(strcmp(resolved, path) == 0);
    errno = 0;
    assert(realpath("/usr/bin/rax-missing-path", resolved) == NULL && errno == ENOENT);
    assert(close(fd) == 0 && close(dir) == 0);
    check_bulk_after_rename();
    puts("path attributes and realpath match");
    return 0;
}
