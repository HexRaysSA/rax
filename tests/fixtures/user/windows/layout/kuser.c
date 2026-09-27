/* Public ntddk.h fields used by src/user/windows/layout.rs::kuser.
 * NtBuildNumber and NativeProcessorArchitecture are absent from these
 * header revisions and are deliberately not asserted as named members. */
#define _WIN32_WINNT 0x0a00
#define NTDDI_VERSION 0x0a000000
#include <stddef.h>
#include <ddk/ntddk.h>

#define OFFSET(field, expected) \
    _Static_assert(offsetof(KUSER_SHARED_DATA, field) == (expected), "rax-layout:" #field)

_Static_assert(sizeof(KSYSTEM_TIME) == 0x0c, "rax-layout:sizeof(KSYSTEM_TIME)");
OFFSET(TickCountLowDeprecated, 0x000);
OFFSET(TickCountMultiplier, 0x004);
OFFSET(InterruptTime, 0x008);
OFFSET(SystemTime, 0x014);
OFFSET(TimeZoneBias, 0x020);
OFFSET(ImageNumberLow, 0x02c);
OFFSET(ImageNumberHigh, 0x02e);
OFFSET(NtSystemRoot, 0x030);
OFFSET(MaxStackTraceDepth, 0x238);
OFFSET(CryptoExponent, 0x23c);
OFFSET(TimeZoneId, 0x240);
OFFSET(LargePageMinimum, 0x244);
OFFSET(NtProductType, 0x264);
OFFSET(ProductTypeIsValid, 0x268);
OFFSET(NtMajorVersion, 0x26c);
OFFSET(NtMinorVersion, 0x270);
OFFSET(ProcessorFeatures, 0x274);
OFFSET(SuiteMask, 0x2d0);
OFFSET(KdDebuggerEnabled, 0x2d4);
OFFSET(ActiveConsoleId, 0x2d8);
OFFSET(NumberOfPhysicalPages, 0x2e8);
OFFSET(SafeBootMode, 0x2ec);
OFFSET(TickCount, 0x320);
OFFSET(Cookie, 0x330);
OFFSET(ActiveProcessorCount, 0x3c0);
OFFSET(ActiveGroupCount, 0x3c4);
