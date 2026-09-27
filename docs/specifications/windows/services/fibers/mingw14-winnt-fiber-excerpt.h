/**
 * This file is part of the mingw-w64 runtime package.
 * No warranty is given; refer to the file DISCLAIMER within this package.
 */


#if !defined(GENUTIL) && !defined(_GENIA64_) && defined(_IA64_)

    void *_cdecl _rdteb(void);

#ifdef __ia64__
#define NtCurrentTeb() ((struct _TEB *)_rdteb())
#define GetCurrentFiber() (((PNT_TIB)NtCurrentTeb())->FiberData)
#define GetFiberData() (*(PVOID *)(GetCurrentFiber()))

#ifndef _NT_TIB_DEFINED
#define _NT_TIB_DEFINED
    __C89_NAMELESS typedef struct _NT_TIB {
      struct _EXCEPTION_REGISTRATION_RECORD *ExceptionList;
      PVOID StackBase;
      PVOID StackLimit;
      PVOID SubSystemTib;
      __C89_NAMELESS union {
	PVOID FiberData;
	DWORD Version;
      };
      PVOID ArbitraryUserPointer;
      struct _NT_TIB *Self;
    } NT_TIB;
    typedef NT_TIB *PNT_TIB;
#endif /* _NT_TIB_DEFINED */

    __C89_NAMELESS typedef struct _NT_TIB32 {
      DWORD ExceptionList;
      DWORD StackBase;
      DWORD StackLimit;
      DWORD SubSystemTib;
      __C89_NAMELESS union {
	DWORD FiberData;
	DWORD Version;
      };
      DWORD ArbitraryUserPointer;
      DWORD Self;
    } NT_TIB32,*PNT_TIB32;

    __C89_NAMELESS typedef struct _NT_TIB64 {
      DWORD64 ExceptionList;
      DWORD64 StackBase;
      DWORD64 StackLimit;
      DWORD64 SubSystemTib;
      __C89_NAMELESS union {
	DWORD64 FiberData;
	DWORD Version;
      };
      DWORD64 ArbitraryUserPointer;
      DWORD64 Self;
    } NT_TIB64,*PNT_TIB64;

#if !defined(__ia64__) && !defined (__WIDL__)
    struct _TEB *NtCurrentTeb(VOID);
    PVOID GetCurrentFiber(VOID);
    PVOID GetFiberData(VOID);

#if defined (__aarch64__) || defined(__arm64ec__)
    register struct _TEB *__mingw_current_teb __asm__("x18");
    FORCEINLINE struct _TEB *NtCurrentTeb(VOID)
    {
        return __mingw_current_teb;
    }
    FORCEINLINE PVOID GetCurrentFiber(VOID)
    {
        return (PVOID)(((PNT_TIB)NtCurrentTeb())->FiberData);
    }
#elif defined(__x86_64__)
    FORCEINLINE struct _TEB *NtCurrentTeb(VOID)
    {
        return (struct _TEB *)__readgsqword(FIELD_OFFSET(NT_TIB,Self));
    }
    FORCEINLINE PVOID GetCurrentFiber(VOID)
    {
        return (PVOID)__readgsqword(FIELD_OFFSET(NT_TIB,FiberData));
    }
#elif defined(__i386__)
#   define PcTeb 0x18
    FORCEINLINE struct _TEB *NtCurrentTeb(void)
    {
        return (struct _TEB *)__readfsdword(PcTeb);
    }
    FORCEINLINE PVOID GetCurrentFiber(void)
    {
        return (PVOID)__readfsdword(0x10);
    }
#elif defined (__arm__)
    FORCEINLINE struct _TEB *NtCurrentTeb(VOID)
    {
        struct _TEB *teb;
        __asm ("mrc p15, 0, %0, c13, c0, 2" : "=r" (teb));
        return teb;
    }
    FORCEINLINE PVOID GetCurrentFiber(VOID)
    {
        return (PVOID)(((PNT_TIB)NtCurrentTeb())->FiberData);
    }
#endif

    FORCEINLINE PVOID GetFiberData (VOID) { return *(void **)GetCurrentFiber (); }
#endif /* !defined(__ia64__) && !defined (__WIDL__) */

