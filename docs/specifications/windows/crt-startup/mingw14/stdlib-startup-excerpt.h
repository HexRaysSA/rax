/**
 * This file has no copyright assigned and is placed in the Public Domain.
 * This file is part of the mingw-w64 runtime package.
 * No warranty is given; refer to the file DISCLAIMER.PD within this package.
 */
  _CRTIMP char ***__cdecl __p___argv(void);
  _CRTIMP int *__cdecl __p__fmode(void);
  _CRTIMP int *__cdecl __p___argc(void);
  _CRTIMP wchar_t ***__cdecl __p___wargv(void);
  _CRTIMP char **__cdecl __p__pgmptr(void);
  _CRTIMP wchar_t **__cdecl __p__wpgmptr(void);

  errno_t __cdecl _get_pgmptr(char **_Value);
  errno_t __cdecl _get_wpgmptr(wchar_t **_Value);
  _CRTIMP errno_t __cdecl _set_fmode(int _Mode);
  _CRTIMP errno_t __cdecl _get_fmode(int *_PMode);

#ifndef _fmode
#define _fmode (* __p__fmode())
#endif

#ifndef __argc
#define __argc (* __p___argc())
#endif
#ifndef __argv
#define __argv (* __p___argv())
#endif
#ifndef __wargv
#define __wargv (* __p___wargv())
#endif

#ifndef _pgmptr
#define _pgmptr (* __p__pgmptr())
#endif

#ifndef _wpgmptr
#define _wpgmptr (* __p__wpgmptr())
#endif

#ifndef _POSIX_
#if (defined(_ARM_) || defined(__arm__) || defined(_ARM64_) || defined(__aarch64__) || defined(_ARM64EC_) || defined(__arm64ec__)) && !defined(_UCRT)
  /* The plain msvcrt.dll for arm/aarch64 lacks
   * _environ/_wenviron, but has these functions instead. */
  _CRTIMP void __cdecl _get_environ(char ***);
  _CRTIMP void __cdecl _get_wenviron(wchar_t ***);

  static __inline char **__get_environ_ptr(void) {
    char **__ptr;
    _get_environ(&__ptr);
    return __ptr;
  }

  static __inline wchar_t **__get_wenviron_ptr(void) {
    wchar_t **__ptr;
    _get_wenviron(&__ptr);
    return __ptr;
  }

#ifndef _environ
#define _environ (__get_environ_ptr())
#endif

#ifndef _wenviron
#define _wenviron (__get_wenviron_ptr())
#endif
#else /* UCRT or non-ARM/ARM64 msvcrt */
  _CRTIMP char ***__cdecl __p__environ(void);
  _CRTIMP wchar_t ***__cdecl __p__wenviron(void);

#ifndef _environ
#define _environ (* __p__environ())
#endif

#ifndef _wenviron
#define _wenviron (* __p__wenviron())
#endif
