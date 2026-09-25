/*
 * Memory Mapping Operations
 *
 * Tests mmap/munmap syscall patterns.
 * Exercises virtual memory management.
 *
 * Features exercised:
 *   - Anonymous mapping
 *   - File-backed mapping
 *   - Memory protection changes
 *   - Shared vs private mappings
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdio.h>

volatile int64_t sink;

#define PAGE_SIZE 4096
#define TEST_FILE "/tmp/mmap_test_XXXXXX"

/* Anonymous mapping */
__attribute__((noinline))
int64_t test_anonymous_mmap(void) {
    int64_t result = 0;

    /* Map anonymous memory */
    void *addr = mmap(NULL, PAGE_SIZE * 4,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS,
                      -1, 0);

    if (addr == MAP_FAILED) {
        return -1;
    }

    result += (intptr_t)addr & 0xFFF; /* Should be page-aligned (0) */

    /* Use the memory */
    int32_t *arr = (int32_t *)addr;
    int count = (PAGE_SIZE * 4) / sizeof(int32_t);

    for (int i = 0; i < count; i++) {
        arr[i] = i * i;
    }

    for (int i = 0; i < count; i++) {
        result += arr[i];
    }

    /* Unmap */
    int ret = munmap(addr, PAGE_SIZE * 4);
    result += ret;

    return result;
}

/* File-backed mapping */
__attribute__((noinline))
int64_t test_file_mmap(void) {
    int64_t result = 0;
    char filename[32];

    strcpy(filename, TEST_FILE);
    int fd = mkstemp(filename);
    if (fd < 0) return -1;

    /* Extend file to desired size */
    ftruncate(fd, PAGE_SIZE * 2);

    /* Write some data directly */
    char buffer[PAGE_SIZE];
    for (int i = 0; i < PAGE_SIZE; i++) {
        buffer[i] = (char)i;
    }
    write(fd, buffer, PAGE_SIZE);

    /* Map the file */
    void *addr = mmap(NULL, PAGE_SIZE * 2,
                      PROT_READ | PROT_WRITE,
                      MAP_SHARED, fd, 0);

    if (addr == MAP_FAILED) {
        close(fd);
        unlink(filename);
        return -1;
    }

    /* Read through mapping */
    char *mapped = (char *)addr;
    for (int i = 0; i < PAGE_SIZE; i++) {
        result += mapped[i];
    }

    /* Write through mapping */
    for (int i = 0; i < PAGE_SIZE; i++) {
        mapped[PAGE_SIZE + i] = (char)(i * 2);
    }

    /* Sync to file */
    msync(addr, PAGE_SIZE * 2, MS_SYNC);

    /* Unmap and verify data persisted */
    munmap(addr, PAGE_SIZE * 2);

    lseek(fd, PAGE_SIZE, SEEK_SET);
    read(fd, buffer, PAGE_SIZE);
    for (int i = 0; i < PAGE_SIZE; i++) {
        result += buffer[i];
    }

    close(fd);
    unlink(filename);

    return result;
}

/* Private mapping (copy-on-write) */
__attribute__((noinline))
int64_t test_private_mmap(void) {
    int64_t result = 0;
    char filename[32];

    strcpy(filename, TEST_FILE);
    int fd = mkstemp(filename);
    if (fd < 0) return -1;

    /* Write initial data */
    char buffer[PAGE_SIZE];
    memset(buffer, 'A', PAGE_SIZE);
    ftruncate(fd, PAGE_SIZE);
    write(fd, buffer, PAGE_SIZE);
    lseek(fd, 0, SEEK_SET);

    /* Map as private */
    void *addr = mmap(NULL, PAGE_SIZE,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE, fd, 0);

    if (addr == MAP_FAILED) {
        close(fd);
        unlink(filename);
        return -1;
    }

    /* Modify mapping */
    char *mapped = (char *)addr;
    for (int i = 0; i < PAGE_SIZE; i++) {
        result += mapped[i];
        mapped[i] = 'B';
    }

    /* Verify mapping changed */
    for (int i = 0; i < PAGE_SIZE; i++) {
        result += mapped[i];
    }

    /* Verify file unchanged (private mapping) */
    lseek(fd, 0, SEEK_SET);
    read(fd, buffer, PAGE_SIZE);
    for (int i = 0; i < PAGE_SIZE; i++) {
        result += buffer[i]; /* Should still be 'A' */
    }

    munmap(addr, PAGE_SIZE);
    close(fd);
    unlink(filename);

    return result;
}

/* Memory protection changes */
__attribute__((noinline))
int64_t test_mprotect(void) {
    int64_t result = 0;

    /* Map with read/write */
    void *addr = mmap(NULL, PAGE_SIZE,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS,
                      -1, 0);

    if (addr == MAP_FAILED) {
        return -1;
    }

    /* Write data */
    int32_t *arr = (int32_t *)addr;
    for (int i = 0; i < PAGE_SIZE / 4; i++) {
        arr[i] = i;
    }

    /* Make read-only */
    int ret = mprotect(addr, PAGE_SIZE, PROT_READ);
    result += ret;

    /* Read should still work */
    for (int i = 0; i < PAGE_SIZE / 4; i++) {
        result += arr[i];
    }

    /* Make read/write again */
    ret = mprotect(addr, PAGE_SIZE, PROT_READ | PROT_WRITE);
    result += ret;

    /* Write should work now */
    for (int i = 0; i < PAGE_SIZE / 4; i++) {
        arr[i] = i * 2;
    }

    for (int i = 0; i < PAGE_SIZE / 4; i++) {
        result += arr[i];
    }

    munmap(addr, PAGE_SIZE);

    return result;
}

/* Multiple mappings */
__attribute__((noinline))
int64_t test_multiple_mappings(void) {
    int64_t result = 0;
    void *addrs[8];

    /* Create multiple anonymous mappings */
    for (int i = 0; i < 8; i++) {
        addrs[i] = mmap(NULL, PAGE_SIZE,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS,
                        -1, 0);
        if (addrs[i] == MAP_FAILED) {
            /* Cleanup on error */
            for (int j = 0; j < i; j++) {
                munmap(addrs[j], PAGE_SIZE);
            }
            return -1;
        }
    }

    /* Use all mappings */
    for (int i = 0; i < 8; i++) {
        int32_t *arr = (int32_t *)addrs[i];
        for (int j = 0; j < PAGE_SIZE / 4; j++) {
            arr[j] = i * 1000 + j;
        }
    }

    /* Read from all mappings */
    for (int i = 0; i < 8; i++) {
        int32_t *arr = (int32_t *)addrs[i];
        for (int j = 0; j < PAGE_SIZE / 4; j++) {
            result += arr[j];
        }
    }

    /* Unmap all */
    for (int i = 0; i < 8; i++) {
        munmap(addrs[i], PAGE_SIZE);
    }

    return result;
}

/* Large mapping */
__attribute__((noinline))
int64_t test_large_mapping(void) {
    int64_t result = 0;
    size_t size = PAGE_SIZE * 256; /* 1MB */

    void *addr = mmap(NULL, size,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS,
                      -1, 0);

    if (addr == MAP_FAILED) {
        return -1;
    }

    /* Touch pages (may trigger demand paging) */
    char *mem = (char *)addr;
    for (size_t i = 0; i < size; i += PAGE_SIZE) {
        mem[i] = (char)(i / PAGE_SIZE);
    }

    /* Read back */
    for (size_t i = 0; i < size; i += PAGE_SIZE) {
        result += mem[i];
    }

    /* Partial unmap (if supported) */
    munmap((char *)addr + PAGE_SIZE * 128, PAGE_SIZE * 128);

    /* Use remaining part */
    for (size_t i = 0; i < PAGE_SIZE * 128; i += PAGE_SIZE) {
        result += mem[i];
    }

    munmap(addr, PAGE_SIZE * 128);

    return result;
}

/* mremap for resizing (Linux-specific) */
#ifdef __linux__
__attribute__((noinline))
int64_t test_mremap(void) {
    int64_t result = 0;

    /* Initial mapping */
    void *addr = mmap(NULL, PAGE_SIZE,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS,
                      -1, 0);

    if (addr == MAP_FAILED) {
        return -1;
    }

    /* Write data */
    int32_t *arr = (int32_t *)addr;
    for (int i = 0; i < PAGE_SIZE / 4; i++) {
        arr[i] = i;
    }

    /* Expand mapping */
    void *new_addr = mremap(addr, PAGE_SIZE, PAGE_SIZE * 4, MREMAP_MAYMOVE);
    if (new_addr == MAP_FAILED) {
        munmap(addr, PAGE_SIZE);
        return -1;
    }

    /* Verify old data preserved */
    arr = (int32_t *)new_addr;
    for (int i = 0; i < PAGE_SIZE / 4; i++) {
        result += arr[i];
    }

    /* Use new space */
    for (int i = PAGE_SIZE / 4; i < PAGE_SIZE; i++) {
        arr[i] = i * 2;
    }

    for (int i = 0; i < PAGE_SIZE; i++) {
        result += arr[i];
    }

    munmap(new_addr, PAGE_SIZE * 4);

    return result;
}
#else
__attribute__((noinline))
int64_t test_mremap(void) {
    return 0; /* Not available on this platform */
}
#endif

/* madvise hints */
__attribute__((noinline))
int64_t test_madvise(void) {
    int64_t result = 0;
    size_t size = PAGE_SIZE * 16;

    void *addr = mmap(NULL, size,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS,
                      -1, 0);

    if (addr == MAP_FAILED) {
        return -1;
    }

    /* Sequential access hint */
    madvise(addr, size, MADV_SEQUENTIAL);

    /* Use sequentially */
    int32_t *arr = (int32_t *)addr;
    for (size_t i = 0; i < size / 4; i++) {
        arr[i] = (int32_t)i;
        result += arr[i];
    }

    /* Random access hint */
    madvise(addr, size, MADV_RANDOM);

    /* Use randomly */
    uint32_t seed = 12345;
    for (int i = 0; i < 1000; i++) {
        seed = seed * 1103515245 + 12345;
        size_t idx = (seed >> 16) % (size / 4);
        result += arr[idx];
    }

    /* Don't need hint */
    madvise(addr, size, MADV_DONTNEED);

    munmap(addr, size);

    return result;
}

int main(void) {
    int64_t result = 0;

    for (int iter = 0; iter < 1; iter++) { /* rax: was 100 */
        result += test_anonymous_mmap();
        result += test_file_mmap();
        result += test_private_mmap();
        result += test_mprotect();
        result += test_multiple_mappings();

        if (iter % 10 == 0) {
            result += test_large_mapping();
            result += test_mremap();
        }

        result += test_madvise();
    }

    sink = result;
    printf("sink=%" PRId64 "\n", (int64_t)sink); /* rax: print the result so that runs can be compared */
    return 0;
}
