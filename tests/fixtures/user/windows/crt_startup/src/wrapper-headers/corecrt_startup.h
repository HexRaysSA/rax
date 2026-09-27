/* Declaration-only bridge for unmodified retained MinGW UCRT wrapper sources.
   Exact semantic bodies stay in the primary archive; no startup implementation. */
#ifndef RAX_WRAPPER_CORECRT_H
#define RAX_WRAPPER_CORECRT_H
typedef __WCHAR_TYPE__ wchar_t;
#define __cdecl __attribute__((cdecl))
#define _CRTIMP __declspec(dllimport)
typedef enum { _crt_argv_no_arguments = 0, _crt_argv_unexpanded_arguments = 1,
               _crt_argv_expanded_arguments = 2 } _crt_argv_mode;
_CRTIMP int __cdecl _initialize_narrow_environment(void);
_CRTIMP int __cdecl _initialize_wide_environment(void);
_CRTIMP int __cdecl _configure_narrow_argv(_crt_argv_mode);
_CRTIMP int __cdecl _configure_wide_argv(_crt_argv_mode);
#endif
