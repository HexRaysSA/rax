/**
 * This file has no copyright assigned and is placed in the Public Domain.
 * This file is part of the mingw-w64 runtime package.
 * No warranty is given; refer to the file DISCLAIMER.PD within this package.
 */
#define _NO_CONSOLE_FILENO (intptr_t)-2

#ifndef _FILE_DEFINED
#define _FILE_DEFINED
  struct _iobuf {
    char *_ptr;
    int _cnt;
    char *_base;
    int _flag;
    int _file;
    int _charbuf;
    int _bufsiz;
    char *_tmpfname;
  };
  typedef struct _iobuf FILE;
#endif

#if !defined (_FILEX_DEFINED) && defined (_WINDOWS_)
#define _FILEX_DEFINED
  typedef struct {
    FILE f;
    CRITICAL_SECTION lock;
  } _FILEX;
#endif
