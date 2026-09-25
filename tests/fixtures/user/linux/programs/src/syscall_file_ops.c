/*
 * File System Operations
 *
 * Tests file I/O syscall patterns.
 * Exercises open, read, write, close, etc.
 *
 * Features exercised:
 *   - File open/close
 *   - Read/write operations
 *   - File positioning (seek)
 *   - File metadata (stat)
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */

volatile int64_t sink;
static int64_t rax_nondet; /* rax: fd numbers and st_blocks, excluded from the printed result */

#define BUFFER_SIZE 4096
#define TEST_FILE "/tmp/syscall_test_XXXXXX"

static char buffer[BUFFER_SIZE];
static char read_buffer[BUFFER_SIZE];

/* Basic file operations */
__attribute__((noinline))
int64_t test_basic_file_ops(void) {
    int64_t result = 0;
    char filename[32];

    /* Create temp filename */
    strcpy(filename, TEST_FILE);
    int fd = mkstemp(filename);
    if (fd < 0) return -1;

    result += fd;
    rax_nondet += fd; /* rax: print the result so that runs can be compared */

    /* Write data */
    for (int i = 0; i < BUFFER_SIZE; i++) {
        buffer[i] = (char)(i & 0xFF);
    }

    ssize_t written = write(fd, buffer, BUFFER_SIZE);
    result += written;

    /* Seek to beginning */
    off_t pos = lseek(fd, 0, SEEK_SET);
    result += pos;

    /* Read data back */
    ssize_t bytes_read = read(fd, read_buffer, BUFFER_SIZE);
    result += bytes_read;

    /* Verify */
    for (int i = 0; i < BUFFER_SIZE; i++) {
        if (read_buffer[i] != buffer[i]) {
            result -= 1;
        }
    }

    /* Close and cleanup */
    close(fd);
    unlink(filename);

    return result;
}

/* Partial reads and writes */
__attribute__((noinline))
int64_t test_partial_io(void) {
    int64_t result = 0;
    char filename[32];

    strcpy(filename, TEST_FILE);
    int fd = mkstemp(filename);
    if (fd < 0) return -1;

    /* Write in small chunks */
    for (int i = 0; i < 16; i++) {
        memset(buffer, 'A' + i, 256);
        ssize_t w = write(fd, buffer, 256);
        result += w;
    }

    /* Read in different chunk sizes */
    lseek(fd, 0, SEEK_SET);

    ssize_t total_read = 0;
    int chunk_sizes[] = {64, 128, 256, 512, 1024, 2048};
    int chunk_idx = 0;

    while (total_read < 4096) {
        ssize_t r = read(fd, read_buffer, chunk_sizes[chunk_idx % 6]);
        if (r <= 0) break;
        total_read += r;
        result += r;
        chunk_idx++;
    }

    close(fd);
    unlink(filename);

    return result;
}

/* File positioning */
__attribute__((noinline))
int64_t test_seek_operations(void) {
    int64_t result = 0;
    char filename[32];

    strcpy(filename, TEST_FILE);
    int fd = mkstemp(filename);
    if (fd < 0) return -1;

    /* Write test pattern */
    for (int i = 0; i < BUFFER_SIZE; i++) {
        buffer[i] = (char)i;
    }
    write(fd, buffer, BUFFER_SIZE);

    /* SEEK_SET - absolute positioning */
    for (int i = 0; i < 100; i++) {
        off_t target = (i * 37) % BUFFER_SIZE;
        off_t pos = lseek(fd, target, SEEK_SET);
        result += pos;

        char c;
        read(fd, &c, 1);
        result += c;
    }

    /* SEEK_CUR - relative positioning */
    lseek(fd, 0, SEEK_SET);
    for (int i = 0; i < 50; i++) {
        off_t pos = lseek(fd, 10, SEEK_CUR);
        result += pos;
    }

    /* SEEK_END - from end */
    off_t end_pos = lseek(fd, 0, SEEK_END);
    result += end_pos;

    off_t back_pos = lseek(fd, -100, SEEK_END);
    result += back_pos;

    close(fd);
    unlink(filename);

    return result;
}

/* File stat operations */
__attribute__((noinline))
int64_t test_stat_operations(void) {
    int64_t result = 0;
    char filename[32];

    strcpy(filename, TEST_FILE);
    int fd = mkstemp(filename);
    if (fd < 0) return -1;

    /* Write some data */
    write(fd, buffer, 1000);

    /* fstat on open file */
    struct stat st;
    if (fstat(fd, &st) == 0) {
        result += st.st_size;
        result += st.st_mode & 0777;
        result += st.st_nlink;
    }

    close(fd);

    /* stat on path */
    if (stat(filename, &st) == 0) {
        result += st.st_size;
        result += st.st_blocks;
        rax_nondet += st.st_blocks; /* rax: print the result so that runs can be compared */
    }

    /* lstat (for symlinks, but works on regular files too) */
    if (lstat(filename, &st) == 0) {
        result += st.st_size;
    }

    unlink(filename);

    return result;
}

/* Multiple file descriptors */
__attribute__((noinline))
int64_t test_multiple_fds(void) {
    int64_t result = 0;
    char filenames[4][32];
    int fds[4];

    /* Open multiple files */
    for (int i = 0; i < 4; i++) {
        strcpy(filenames[i], TEST_FILE);
        fds[i] = mkstemp(filenames[i]);
        if (fds[i] < 0) {
            /* Cleanup on error */
            for (int j = 0; j < i; j++) {
                close(fds[j]);
                unlink(filenames[j]);
            }
            return -1;
        }
        result += fds[i];
        rax_nondet += fds[i]; /* rax: print the result so that runs can be compared */
    }

    /* Write to all files */
    for (int round = 0; round < 10; round++) {
        for (int i = 0; i < 4; i++) {
            buffer[0] = (char)(round * 4 + i);
            write(fds[i], buffer, 100);
        }
    }

    /* Read from all files */
    for (int i = 0; i < 4; i++) {
        lseek(fds[i], 0, SEEK_SET);
        ssize_t r = read(fds[i], read_buffer, 1000);
        result += r;
    }

    /* Cleanup */
    for (int i = 0; i < 4; i++) {
        close(fds[i]);
        unlink(filenames[i]);
    }

    return result;
}

/* Truncate operations */
__attribute__((noinline))
int64_t test_truncate(void) {
    int64_t result = 0;
    char filename[32];

    strcpy(filename, TEST_FILE);
    int fd = mkstemp(filename);
    if (fd < 0) return -1;

    /* Write 4K */
    memset(buffer, 'X', BUFFER_SIZE);
    write(fd, buffer, BUFFER_SIZE);

    /* Truncate to 1K */
    ftruncate(fd, 1024);

    struct stat st;
    fstat(fd, &st);
    result += st.st_size;

    /* Extend to 2K (creates hole) */
    ftruncate(fd, 2048);
    fstat(fd, &st);
    result += st.st_size;

    close(fd);

    /* Truncate via path */
    truncate(filename, 512);
    stat(filename, &st);
    result += st.st_size;

    unlink(filename);

    return result;
}

/* pread/pwrite operations */
__attribute__((noinline))
int64_t test_pread_pwrite(void) {
    int64_t result = 0;
    char filename[32];

    strcpy(filename, TEST_FILE);
    int fd = mkstemp(filename);
    if (fd < 0) return -1;

    /* Write with pwrite at various offsets */
    for (int i = 0; i < 10; i++) {
        memset(buffer, 'A' + i, 100);
        ssize_t w = pwrite(fd, buffer, 100, i * 100);
        result += w;
    }

    /* Read with pread at various offsets */
    for (int i = 9; i >= 0; i--) {
        ssize_t r = pread(fd, read_buffer, 100, i * 100);
        result += r;
        result += read_buffer[0];
    }

    /* Current position should be unchanged */
    off_t pos = lseek(fd, 0, SEEK_CUR);
    result += pos;

    close(fd);
    unlink(filename);

    return result;
}

/* Directory operations */
__attribute__((noinline))
int64_t test_directory_ops(void) {
    int64_t result = 0;

    /* Create directory */
    char dirname[] = "/tmp/syscall_dir_XXXXXX";
    if (mkdtemp(dirname) == NULL) {
        return -1;
    }

    result += 1;

    /* Create files in directory */
    char filepath[64];
    for (int i = 0; i < 3; i++) {
        snprintf(filepath, sizeof(filepath), "%s/file%d", dirname, i);
        int fd = open(filepath, O_CREAT | O_WRONLY, 0644);
        if (fd >= 0) {
            write(fd, "test", 4);
            close(fd);
            result += 1;
        }
    }

    /* Stat directory */
    struct stat st;
    if (stat(dirname, &st) == 0) {
        result += (st.st_mode & S_IFDIR) ? 1 : 0;
    }

    /* Cleanup files */
    for (int i = 0; i < 3; i++) {
        snprintf(filepath, sizeof(filepath), "%s/file%d", dirname, i);
        unlink(filepath);
    }

    /* Remove directory */
    rmdir(dirname);

    return result;
}

int main(void) {
    int64_t result = 0;

    for (int iter = 0; iter < 1; iter++) { /* rax: was 100 */
        result += test_basic_file_ops();
        result += test_partial_io();
        result += test_seek_operations();
        result += test_stat_operations();
        result += test_multiple_fds();
        result += test_truncate();
        result += test_pread_pwrite();

        if (iter % 10 == 0) {
            result += test_directory_ops();
        }
    }

    sink = result;
    printf("result_det=%" PRId64 "\n", result - rax_nondet); /* rax: print the result so that runs can be compared */
    return 0;
}
