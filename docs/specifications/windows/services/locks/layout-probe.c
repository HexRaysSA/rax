#include <windows.h>
#include <stddef.h>

/* Public installed-header layout only: not a Microsoft runtime oracle. */
#if defined(_WIN64)
_Static_assert(sizeof(CRITICAL_SECTION) == 0x28, "critical-section size");
_Static_assert(offsetof(CRITICAL_SECTION, LockCount) == 0x08, "lock count");
_Static_assert(offsetof(CRITICAL_SECTION, RecursionCount) == 0x0c, "recursion count");
_Static_assert(offsetof(CRITICAL_SECTION, OwningThread) == 0x10, "owner");
_Static_assert(offsetof(CRITICAL_SECTION, LockSemaphore) == 0x18, "semaphore");
_Static_assert(offsetof(CRITICAL_SECTION, SpinCount) == 0x20, "spin count");
#else
_Static_assert(sizeof(CRITICAL_SECTION) == 0x18, "critical-section size");
_Static_assert(offsetof(CRITICAL_SECTION, LockCount) == 0x04, "lock count");
_Static_assert(offsetof(CRITICAL_SECTION, RecursionCount) == 0x08, "recursion count");
_Static_assert(offsetof(CRITICAL_SECTION, OwningThread) == 0x0c, "owner");
_Static_assert(offsetof(CRITICAL_SECTION, LockSemaphore) == 0x10, "semaphore");
_Static_assert(offsetof(CRITICAL_SECTION, SpinCount) == 0x14, "spin count");
#endif
_Static_assert(offsetof(CRITICAL_SECTION, DebugInfo) == 0, "debug-info pointer");
_Static_assert(sizeof(SRWLOCK) == sizeof(void *), "SRW size");
_Static_assert(sizeof(CONDITION_VARIABLE) == sizeof(void *), "CV size");
