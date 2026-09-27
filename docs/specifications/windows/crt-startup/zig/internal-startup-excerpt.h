/**
 * This file has no copyright assigned and is placed in the Public Domain.
 * This file is part of the mingw-w64 runtime package.
 * No warranty is given; refer to the file DISCLAIMER.PD within this package.
 */

  extern int _dowildcard;
  extern int _newmode;

  _CRTIMP wchar_t *** __cdecl __p___winitenv(void);
#define __winitenv (*__p___winitenv())

  _CRTIMP char *** __cdecl __p___initenv(void);
#define __initenv (*__p___initenv())

  _CRTIMP void __cdecl _amsg_exit(int) __MINGW_ATTRIB_NORETURN;

  int __CRTDECL _setargv(void);
  int __CRTDECL __setargv(void);
  int __CRTDECL _wsetargv(void);
  int __CRTDECL __wsetargv(void);

  int __CRTDECL main(int _Argc, char **_Argv, char **_Env);
  int __CRTDECL wmain(int _Argc, wchar_t **_Argv, wchar_t **_Env);

#ifndef _STARTUP_INFO_DEFINED
#define _STARTUP_INFO_DEFINED
  typedef struct {
    int newmode;
  } _startupinfo;
#endif

  _CRTIMP int __cdecl __getmainargs(int * _Argc, char *** _Argv, char ***_Env, int _DoWildCard, _startupinfo *_StartInfo);
  _CRTIMP int __cdecl __wgetmainargs(int * _Argc, wchar_t ***_Argv, wchar_t ***_Env, int _DoWildCard, _startupinfo *_StartInfo);

#define _CONSOLE_APP 1
#define _GUI_APP 2
