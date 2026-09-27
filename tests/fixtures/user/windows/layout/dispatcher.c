/* Compile-only checks of named MinGW-w64 declarations; not a native oracle. */
#include <stddef.h>
#include <windows.h>

#define CHECK(expression) _Static_assert((expression), "rax-dispatcher: " #expression)

#if defined(__x86_64__) && !defined(__aarch64__)
CHECK(sizeof(DISPATCHER_CONTEXT) == 0x50);
CHECK(offsetof(DISPATCHER_CONTEXT, ScopeIndex) == 0x48);
CHECK(offsetof(DISPATCHER_CONTEXT, Fill0) == 0x4C);
#elif defined(__aarch64__)
CHECK(sizeof(DISPATCHER_CONTEXT) == 0x58);
CHECK(offsetof(DISPATCHER_CONTEXT, ScopeIndex) == 0x48);
CHECK(offsetof(DISPATCHER_CONTEXT, ControlPcIsUnwound) == 0x4C);
CHECK(offsetof(DISPATCHER_CONTEXT, NonVolatileRegisters) == 0x50);
#else
#error DISPATCHER_CONTEXT probe requires x64 or ARM64
#endif
