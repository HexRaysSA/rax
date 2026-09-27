/**
 * This file is part of the mingw-w64 runtime package.
 * No warranty is given; refer to the file DISCLAIMER within this package.
 */

    typedef struct DECLSPEC_ALIGN (16) _M128A {
      ULONGLONG Low;
      LONGLONG High;
    } M128A,*PM128A;

#ifdef _AMD64_

#if !defined(RC_INVOKED)

#define CONTEXT_AMD64 0x100000

#define CONTEXT_CONTROL (CONTEXT_AMD64 | __MSABI_LONG(0x1))
#define CONTEXT_INTEGER (CONTEXT_AMD64 | __MSABI_LONG(0x2))
#define CONTEXT_SEGMENTS (CONTEXT_AMD64 | __MSABI_LONG(0x4))
#define CONTEXT_FLOATING_POINT (CONTEXT_AMD64 | __MSABI_LONG(0x8))
#define CONTEXT_DEBUG_REGISTERS (CONTEXT_AMD64 | __MSABI_LONG(0x10))

#define CONTEXT_FULL (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT)
#define CONTEXT_ALL (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS)

#define CONTEXT_XSTATE (CONTEXT_AMD64 | __MSABI_LONG(0x40))
#define CONTEXT_KERNEL_CET (CONTEXT_AMD64 | __MSABI_LONG(0x80))

#define CONTEXT_EXCEPTION_ACTIVE 0x8000000
#define CONTEXT_SERVICE_ACTIVE 0x10000000
#define CONTEXT_EXCEPTION_REQUEST 0x40000000
#define CONTEXT_EXCEPTION_REPORTING 0x80000000
#define CONTEXT_UNWOUND_TO_CALL 0x20000000

#endif /* !defined(RC_INVOKED) */

#define INITIAL_MXCSR 0x1f80
#define INITIAL_FPCSR 0x027f

  typedef struct _XMM_SAVE_AREA32 {
    WORD ControlWord;
    WORD StatusWord;
    BYTE TagWord;
    BYTE Reserved1;
    WORD ErrorOpcode;
    DWORD ErrorOffset;
    WORD ErrorSelector;
    WORD Reserved2;
    DWORD DataOffset;
    WORD DataSelector;
    WORD Reserved3;
    DWORD MxCsr;
    DWORD MxCsr_Mask;
    M128A FloatRegisters[8];
    M128A XmmRegisters[16];
    BYTE Reserved4[96];
  } XMM_SAVE_AREA32,*PXMM_SAVE_AREA32;

#define LEGACY_SAVE_AREA_LENGTH sizeof(XMM_SAVE_AREA32)

  typedef struct DECLSPEC_ALIGN(16) _CONTEXT {
    DWORD64 P1Home;
    DWORD64 P2Home;
    DWORD64 P3Home;
    DWORD64 P4Home;
    DWORD64 P5Home;
    DWORD64 P6Home;
    DWORD ContextFlags;
    DWORD MxCsr;
    WORD SegCs;
    WORD SegDs;
    WORD SegEs;
    WORD SegFs;
    WORD SegGs;
    WORD SegSs;
    DWORD EFlags;
    DWORD64 Dr0;
    DWORD64 Dr1;
    DWORD64 Dr2;
    DWORD64 Dr3;
    DWORD64 Dr6;
    DWORD64 Dr7;
    DWORD64 Rax;
    DWORD64 Rcx;
    DWORD64 Rdx;
    DWORD64 Rbx;
    DWORD64 Rsp;
    DWORD64 Rbp;
    DWORD64 Rsi;
    DWORD64 Rdi;
    DWORD64 R8;
    DWORD64 R9;
    DWORD64 R10;
    DWORD64 R11;
    DWORD64 R12;
    DWORD64 R13;
    DWORD64 R14;
    DWORD64 R15;
    DWORD64 Rip;
    __C89_NAMELESS union {
      XMM_SAVE_AREA32 FltSave;
      XMM_SAVE_AREA32 FloatSave;
      __C89_NAMELESS struct {
	M128A Header[2];
	M128A Legacy[8];
	M128A Xmm0;
	M128A Xmm1;
	M128A Xmm2;
	M128A Xmm3;
	M128A Xmm4;
	M128A Xmm5;
	M128A Xmm6;
	M128A Xmm7;
	M128A Xmm8;
	M128A Xmm9;
	M128A Xmm10;
	M128A Xmm11;
	M128A Xmm12;
	M128A Xmm13;
	M128A Xmm14;
	M128A Xmm15;
      };
    };
    M128A VectorRegister[26];
    DWORD64 VectorControl;
    DWORD64 DebugControl;
    DWORD64 LastBranchToRip;
    DWORD64 LastBranchFromRip;
    DWORD64 LastExceptionToRip;
    DWORD64 LastExceptionFromRip;
  } CONTEXT,*PCONTEXT;

#endif /* end of _AMD64_ */
#if !defined(RC_INVOKED)

#define CONTEXT_ARM64                 0x400000
#define CONTEXT_ARM64_CONTROL         (CONTEXT_ARM64 | 0x00000001)
#define CONTEXT_ARM64_INTEGER         (CONTEXT_ARM64 | 0x00000002)
#define CONTEXT_ARM64_FLOATING_POINT  (CONTEXT_ARM64 | 0x00000004)
#define CONTEXT_ARM64_DEBUG_REGISTERS (CONTEXT_ARM64 | 0x00000008)
#define CONTEXT_ARM64_X18             (CONTEXT_ARM64 | 0x00000010)


#define CONTEXT_ARM64_FULL (CONTEXT_ARM64_CONTROL | CONTEXT_ARM64_INTEGER | CONTEXT_ARM64_FLOATING_POINT)
#define CONTEXT_ARM64_ALL  (CONTEXT_ARM64_CONTROL | CONTEXT_ARM64_INTEGER | CONTEXT_ARM64_FLOATING_POINT | CONTEXT_ARM64_DEBUG_REGISTERS | CONTEXT_ARM64_X18)

#define CONTEXT_ARM64_UNWOUND_TO_CALL 0x20000000

#ifdef _ARM64_

#define CONTEXT_CONTROL         CONTEXT_ARM64_CONTROL
#define CONTEXT_INTEGER         CONTEXT_ARM64_INTEGER
#define CONTEXT_FLOATING_POINT  CONTEXT_ARM64_FLOATING_POINT
#define CONTEXT_DEBUG_REGISTERS CONTEXT_ARM64_DEBUG_REGISTERS
#define CONTEXT_FULL            CONTEXT_ARM64_FULL
#define CONTEXT_ALL             CONTEXT_ARM64_ALL
#define CONTEXT_UNWOUND_TO_CALL CONTEXT_ARM64_UNWOUND_TO_CALL

#define CONTEXT_EXCEPTION_ACTIVE    0x08000000
#define CONTEXT_SERVICE_ACTIVE      0x10000000
#define CONTEXT_EXCEPTION_REQUEST   0x40000000
#define CONTEXT_EXCEPTION_REPORTING 0x80000000

#endif /* _ARM64_ */

#endif /* !defined(RC_INVOKED) */

#define ARM64_MAX_BREAKPOINTS   8
#define ARM64_MAX_WATCHPOINTS   2

  typedef union _ARM64_NT_NEON128 {
    struct
    {
        ULONGLONG Low;
        LONGLONG High;
    } DUMMYSTRUCTNAME;
    double D[2];
    float S[4];
    WORD  H[8];
    BYTE  B[16];
  } ARM64_NT_NEON128, *PARM64_NT_NEON128;

#ifdef _ARM64_
  typedef ARM64_NT_NEON128 NEON128, *PNEON128;
#endif

  typedef struct DECLSPEC_ALIGN(16)
#ifdef _ARM64_
  _CONTEXT
#else
  _ARM64_NT_CONTEXT
#endif
  {
    ULONG ContextFlags;                 /* 000 */
    /* CONTEXT_INTEGER */
    ULONG Cpsr;                         /* 004 */
    union
    {
        struct
        {
            DWORD64 X0;                 /* 008 */
            DWORD64 X1;                 /* 010 */
            DWORD64 X2;                 /* 018 */
            DWORD64 X3;                 /* 020 */
            DWORD64 X4;                 /* 028 */
            DWORD64 X5;                 /* 030 */
            DWORD64 X6;                 /* 038 */
            DWORD64 X7;                 /* 040 */
            DWORD64 X8;                 /* 048 */
            DWORD64 X9;                 /* 050 */
            DWORD64 X10;                /* 058 */
            DWORD64 X11;                /* 060 */
            DWORD64 X12;                /* 068 */
            DWORD64 X13;                /* 070 */
            DWORD64 X14;                /* 078 */
            DWORD64 X15;                /* 080 */
            DWORD64 X16;                /* 088 */
            DWORD64 X17;                /* 090 */
            DWORD64 X18;                /* 098 */
            DWORD64 X19;                /* 0a0 */
            DWORD64 X20;                /* 0a8 */
            DWORD64 X21;                /* 0b0 */
            DWORD64 X22;                /* 0b8 */
            DWORD64 X23;                /* 0c0 */
            DWORD64 X24;                /* 0c8 */
            DWORD64 X25;                /* 0d0 */
            DWORD64 X26;                /* 0d8 */
            DWORD64 X27;                /* 0e0 */
            DWORD64 X28;                /* 0e8 */
            DWORD64 Fp;                 /* 0f0 */
            DWORD64 Lr;                 /* 0f8 */
        } DUMMYSTRUCTNAME;
        DWORD64 X[31];                  /* 008 */
    } DUMMYUNIONNAME;
    /* CONTEXT_CONTROL */
    DWORD64 Sp;                         /* 100 */
    DWORD64 Pc;                         /* 108 */
    /* CONTEXT_FLOATING_POINT */
    ARM64_NT_NEON128 V[32];             /* 110 */
    DWORD Fpcr;                         /* 310 */
    DWORD Fpsr;                         /* 314 */
    /* CONTEXT_DEBUG_REGISTERS */
    DWORD Bcr[ARM64_MAX_BREAKPOINTS];   /* 318 */
    DWORD64 Bvr[ARM64_MAX_BREAKPOINTS]; /* 338 */
    DWORD Wcr[ARM64_MAX_WATCHPOINTS];   /* 378 */
    DWORD64 Wvr[ARM64_MAX_WATCHPOINTS]; /* 380 */
  } ARM64_NT_CONTEXT, *PARM64_NT_CONTEXT;

#ifdef _ARM64_
  typedef ARM64_NT_CONTEXT CONTEXT, *PCONTEXT;
#endif
#ifdef _X86_
#define SIZE_OF_80387_REGISTERS 80

#if !defined(RC_INVOKED)

#define CONTEXT_i386 0x00010000
#define CONTEXT_i486 0x00010000

#define CONTEXT_CONTROL (CONTEXT_i386 | __MSABI_LONG(0x00000001))
#define CONTEXT_INTEGER (CONTEXT_i386 | __MSABI_LONG(0x00000002))
#define CONTEXT_SEGMENTS (CONTEXT_i386 | __MSABI_LONG(0x00000004))
#define CONTEXT_FLOATING_POINT (CONTEXT_i386 | __MSABI_LONG(0x00000008))
#define CONTEXT_DEBUG_REGISTERS (CONTEXT_i386 | __MSABI_LONG(0x00000010))
#define CONTEXT_EXTENDED_REGISTERS (CONTEXT_i386 | __MSABI_LONG(0x00000020))

#define CONTEXT_FULL (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS)

#define CONTEXT_ALL (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS)
#endif /* !defined(RC_INVOKED) */

#define MAXIMUM_SUPPORTED_EXTENSION 512

    typedef struct _FLOATING_SAVE_AREA {
      DWORD ControlWord;
      DWORD StatusWord;
      DWORD TagWord;
      DWORD ErrorOffset;
      DWORD ErrorSelector;
      DWORD DataOffset;
      DWORD DataSelector;
      BYTE RegisterArea[SIZE_OF_80387_REGISTERS];
      DWORD Cr0NpxState;
    } FLOATING_SAVE_AREA;

    typedef FLOATING_SAVE_AREA *PFLOATING_SAVE_AREA;

    typedef struct _CONTEXT {
      DWORD ContextFlags;
      DWORD Dr0;
      DWORD Dr1;
      DWORD Dr2;
      DWORD Dr3;
      DWORD Dr6;
      DWORD Dr7;
      FLOATING_SAVE_AREA FloatSave;
      DWORD SegGs;
      DWORD SegFs;
      DWORD SegEs;
      DWORD SegDs;

      DWORD Edi;
      DWORD Esi;
      DWORD Ebx;
      DWORD Edx;
      DWORD Ecx;
      DWORD Eax;
      DWORD Ebp;
      DWORD Eip;
      DWORD SegCs;
      DWORD EFlags;
      DWORD Esp;
      DWORD SegSs;
      BYTE ExtendedRegisters[MAXIMUM_SUPPORTED_EXTENSION];
    } CONTEXT;

    typedef CONTEXT *PCONTEXT;

#endif /* end of _X86_ */
#define EXCEPTION_MAXIMUM_PARAMETERS 15

    typedef struct _EXCEPTION_RECORD {
      DWORD ExceptionCode;
      DWORD ExceptionFlags;
      struct _EXCEPTION_RECORD *ExceptionRecord;
      PVOID ExceptionAddress;
      DWORD NumberParameters;
      ULONG_PTR ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
    } EXCEPTION_RECORD;

    typedef EXCEPTION_RECORD *PEXCEPTION_RECORD;

    typedef struct _EXCEPTION_RECORD32 {
      DWORD ExceptionCode;
      DWORD ExceptionFlags;
      DWORD ExceptionRecord;
      DWORD ExceptionAddress;
      DWORD NumberParameters;
      DWORD ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
    } EXCEPTION_RECORD32,*PEXCEPTION_RECORD32;

    typedef struct _EXCEPTION_RECORD64 {
      DWORD ExceptionCode;
      DWORD ExceptionFlags;
      DWORD64 ExceptionRecord;
      DWORD64 ExceptionAddress;
      DWORD NumberParameters;
      DWORD __unusedAlignment;
      DWORD64 ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
    } EXCEPTION_RECORD64,*PEXCEPTION_RECORD64;

    typedef struct _EXCEPTION_POINTERS {
      PEXCEPTION_RECORD ExceptionRecord;
      PCONTEXT ContextRecord;
    } EXCEPTION_POINTERS,*PEXCEPTION_POINTERS;
