/*++ BUILD Version: 0072     Increment this if a change has global effects

Copyright (c) Microsoft Corporation. All rights reserved.

Module Name:

    winnt.h

Abstract:

    This module defines the 32-Bit Windows types and constants that are
    defined by NT, but exposed through the Win32 API.

Revision History:

--*/
#define PROTECTED_DACL_SECURITY_INFORMATION         (0x80000000L)
#define PROTECTED_SACL_SECURITY_INFORMATION         (0x40000000L)
#define UNPROTECTED_DACL_SECURITY_INFORMATION       (0x20000000L)
#define UNPROTECTED_SACL_SECURITY_INFORMATION       (0x10000000L)


//
// Base signing levels.
//

typedef BYTE  SE_SIGNING_LEVEL, *PSE_SIGNING_LEVEL;

#define SE_SIGNING_LEVEL_UNCHECKED         0x00000000
#define SE_SIGNING_LEVEL_UNSIGNED          0x00000001
#define SE_SIGNING_LEVEL_ENTERPRISE        0x00000002
#define SE_SIGNING_LEVEL_CUSTOM_1          0x00000003
#define SE_SIGNING_LEVEL_DEVELOPER         SE_SIGNING_LEVEL_CUSTOM_1
#define SE_SIGNING_LEVEL_AUTHENTICODE      0x00000004
#define SE_SIGNING_LEVEL_CUSTOM_2          0x00000005
#define SE_SIGNING_LEVEL_STORE             0x00000006
#define SE_SIGNING_LEVEL_CUSTOM_3          0x00000007
#define SE_SIGNING_LEVEL_ANTIMALWARE       SE_SIGNING_LEVEL_CUSTOM_3
#define SE_SIGNING_LEVEL_MICROSOFT         0x00000008
#define SE_SIGNING_LEVEL_CUSTOM_4          0x00000009
#define SE_SIGNING_LEVEL_CUSTOM_5          0x0000000A
#define SE_SIGNING_LEVEL_DYNAMIC_CODEGEN   0x0000000B
#define SE_SIGNING_LEVEL_WINDOWS           0x0000000C
#define SE_SIGNING_LEVEL_CUSTOM_7          0x0000000D
#define SE_SIGNING_LEVEL_WINDOWS_TCB       0x0000000E
#define SE_SIGNING_LEVEL_CUSTOM_6          0x0000000F

//
// Image signature types.
