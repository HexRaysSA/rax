/**
 * This file has no copyright assigned and is placed in the Public Domain.
 * This file is part of the mingw-w64 runtime package.
 * No warranty is given; refer to the file DISCLAIMER.PD within this package.
 */
#ifndef _IO_H_
#define _IO_H_

  _CRTIMP int __cdecl _close(int _FileHandle);
  _CRTIMP int __cdecl _setmode(int _FileHandle,int _Mode);
  _CRTIMP intptr_t __cdecl _get_osfhandle(int _FileHandle);
  _CRTIMP int __cdecl _open_osfhandle(intptr_t _OSFileHandle,int _Flags);
