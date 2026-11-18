// The time macros of this target: those LLVM libc has for a target without
// an operating system, and the clocks `clock_gettime` reads, which that
// configuration does not have. The numbers of the clocks are Linux's.
#ifndef LLVM_LIBC_MACROS_TIME_MACROS_H
#define LLVM_LIBC_MACROS_TIME_MACROS_H

#define CLOCKS_PER_SEC 1000000
#define CLK_TCK CLOCKS_PER_SEC

#define TIME_UTC 1
#define TIME_MONOTONIC 2
#define TIME_ACTIVE 3
#define TIME_THREAD_ACTIVE 4

#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1
#define CLOCK_PROCESS_CPUTIME_ID 2
#define CLOCK_THREAD_CPUTIME_ID 3

#endif // LLVM_LIBC_MACROS_TIME_MACROS_H
