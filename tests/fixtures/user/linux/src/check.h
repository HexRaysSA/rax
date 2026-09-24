/* Shared helpers for rax-user Linux fixtures. Each check prints one line,
 * "ok <name>" or "FAIL <name>: <detail>", so a run's output is identical on a
 * real Linux kernel and under emulation when behavior matches. */
#ifndef RAX_FIXTURE_CHECK_H
#define RAX_FIXTURE_CHECK_H
#include <errno.h>
#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(name, cond)                                                     \
    do {                                                                      \
        if (cond) {                                                           \
            printf("ok %s\n", name);                                          \
        } else {                                                              \
            failures++;                                                       \
            printf("FAIL %s: %s (errno %d %s) at line %d\n", name, #cond,     \
                   errno, strerror(errno), __LINE__);                         \
        }                                                                     \
    } while (0)

/* Expect a call to fail with a specific errno. */
#define CHECK_ERR(name, expr, err)                                            \
    do {                                                                      \
        errno = 0;                                                            \
        long r_ = (long)(expr);                                               \
        if (r_ == -1 && errno == (err)) {                                     \
            printf("ok %s\n", name);                                          \
        } else {                                                              \
            failures++;                                                       \
            printf("FAIL %s: %s returned %ld errno %d, want errno %d\n",      \
                   name, #expr, r_, errno, (err));                            \
        }                                                                     \
    } while (0)

#define FINISH()                                                              \
    do {                                                                      \
        printf("%s\n", failures ? "FAILED" : "PASSED");                       \
        return failures ? 1 : 0;                                              \
    } while (0)

#endif
