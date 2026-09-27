/**
 * This file has no copyright assigned and is placed in the Public Domain.
 * This file is part of the mingw-w64 runtime package.
 * No warranty is given; refer to the file DISCLAIMER.PD within this package.
 */
#ifndef _CRT_TERMINATE_DEFINED
#define _CRT_TERMINATE_DEFINED
  void __cdecl __MINGW_NOTHROW exit(int _Code) __MINGW_ATTRIB_NORETURN;
  void __cdecl __MINGW_NOTHROW _exit(int _Code) __MINGW_ATTRIB_NORETURN;
#ifdef _UCRT
  void __cdecl __MINGW_NOTHROW quick_exit(int _Code) __MINGW_ATTRIB_NORETURN;
#endif

#if !defined __NO_ISOCEXT /* extern stub in static libmingwex.a */
  /* C99 function name */
  void __cdecl _Exit(int) __MINGW_ATTRIB_NORETURN;
#ifndef __CRT__NO_INLINE
  __CRT_INLINE __MINGW_ATTRIB_NORETURN void  __cdecl _Exit(int status)
  {  _exit(status); }
#endif /* !__CRT__NO_INLINE */
#endif /* Not  __NO_ISOCEXT */

#pragma push_macro("abort")
#undef abort
  void __cdecl __MINGW_ATTRIB_NORETURN abort(void);
#pragma pop_macro("abort")

#endif /* _CRT_TERMINATE_DEFINED */

  typedef void (__stdcall *_tls_callback_type)(void*,unsigned long,void*);
  _CRTIMP void __cdecl _register_thread_local_exe_atexit_callback(_tls_callback_type callback);

  void __cdecl __MINGW_NOTHROW _cexit(void);
  void __cdecl __MINGW_NOTHROW _c_exit(void);
#ifdef _CRT_USE_WINAPI_FAMILY_DESKTOP_APP
