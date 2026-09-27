/* Exact excerpt (lines 1-5 and 17-21) from installed mingw-w64 14.0.0_3:
 * toolchain-x86_64/x86_64-w64-mingw32/include/malloc.h.
 * This width profile is not claimed to pin a native Microsoft CRT build.
 */
/**
 * This file has no copyright assigned and is placed in the Public Domain.
 * This file is part of the mingw-w64 runtime package.
 * No warranty is given; refer to the file DISCLAIMER.PD within this package.
 */
#ifdef _WIN64
#define _HEAP_MAXREQ 0xFFFFFFFFFFFFFFE0
#else
#define _HEAP_MAXREQ 0xFFFFFFE0
#endif
