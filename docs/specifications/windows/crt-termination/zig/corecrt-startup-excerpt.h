/**
 * This file has no copyright assigned and is placed in the Public Domain.
 * This file is part of the mingw-w64 runtime package.
 * No warranty is given; refer to the file DISCLAIMER.PD within this package.
 */
    _crt_console_app,
    _crt_gui_app
} _crt_app_type;

_CRTIMP _crt_app_type __cdecl _query_app_type(void);
_CRTIMP void __cdecl _set_app_type(_crt_app_type _Type);

typedef enum _crt_argv_mode {

typedef int (__cdecl *_onexit_t)(void);

_CRTIMP int __cdecl _initialize_onexit_table(_onexit_table_t*);
_CRTIMP int __cdecl _register_onexit_function(_onexit_table_t*,_onexit_t);
_CRTIMP int __cdecl _execute_onexit_table(_onexit_table_t*);
_CRTIMP int __cdecl _crt_atexit(_PVFV func);
_CRTIMP int __cdecl _crt_at_quick_exit(_PVFV func);
