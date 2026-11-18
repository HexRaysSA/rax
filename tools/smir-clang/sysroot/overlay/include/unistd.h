// The part of POSIX's <unistd.h> that is a runtime service under another
// name, or a fact about the runtime: reading, writing and positioning by
// handle, removing a name, pausing, and what the system is like. A file
// descriptor is a handle of the runtime; 0, 1 and 2 are the standard
// streams.
#ifndef SMIR_SYSROOT_UNISTD_H
#define SMIR_SYSROOT_UNISTD_H

#include <llvm-libc-types/off_t.h>
#include <llvm-libc-types/ssize_t.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

#ifndef SEEK_SET
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
#endif

typedef unsigned useconds_t;

// The names `sysconf` knows, with Linux's numbers.
#define _SC_PAGESIZE 30
#define _SC_PAGE_SIZE _SC_PAGESIZE
#define _SC_NPROCESSORS_CONF 83
#define _SC_NPROCESSORS_ONLN 84

// The size of a page, or how many threads can run at one time; -1 and
// EINVAL for any other name.
long sysconf(int name);

ssize_t read(int descriptor, void *buffer, size_t count);
ssize_t write(int descriptor, const void *buffer, size_t count);
off_t lseek(int descriptor, off_t offset, int whence);
int close(int descriptor);
int unlink(const char *path);

// The runtime does not say what is behind a stream: nothing is a terminal.
int isatty(int descriptor);

unsigned sleep(unsigned seconds);
int usleep(useconds_t microseconds);

#ifdef __cplusplus
}
#endif

#endif
