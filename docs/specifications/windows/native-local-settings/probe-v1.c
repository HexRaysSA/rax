/* Read-only Local Settings controls. Complete data remains inside SHA-256. */
#define main retained_command_fixture_main
#include "../native-command-processor/absolute-v1.c"
#undef main
#include "digest-v1.h"
#include "opens-v1.h"
#include <sddl.h>

static int ls_hash(BYTE digest[32]) {
  DWORD bytes = 32;
  return CryptHashCertificate2(L"SHA256", 0, NULL, ls_wire, (DWORD)ls_used,
                               digest, &bytes) &&
         bytes == 32;
}

int wmain(int argc, WCHAR **argv) {
  if (argc != 1 && argc != 2)
    return 1;
  if (argc == 2) {
    FILE *stream = NULL;
    if (_wfreopen_s(&stream, argv[1], L"wb", stdout) != 0 || !stream)
      return 1;
  }
  BYTE digest[32], subject[68];
  DWORD needed = 0, subject_bytes = 0, before = 0, after = 0;
  HANDLE token = NULL;
  union {
    ULONGLONG alignment;
    BYTE bytes[256];
  } user;
  OSVERSIONINFOW version = {0};
  version.dwOSVersionInfoSize = sizeof version;
  if (RtlGetVersion(&version) != 0 ||
      !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    return 2;
  if (!GetTokenInformation(token, TokenUser, &user, sizeof user, &needed)) {
    CloseHandle(token);
    return 3;
  }
  PSID sid = ((TOKEN_USER *)user.bytes)->User.Sid;
  if (!IsValidSid(sid) ||
      (subject_bytes = GetLengthSid(sid)) > sizeof subject) {
    CloseHandle(token);
    return 4;
  }
  memcpy(subject, sid, subject_bytes);
  WCHAR *text = NULL;
  if (!ConvertSidToStringSidW(sid, &text)) {
    CloseHandle(token);
    return 5;
  }
  if (!CloseHandle(token)) {
    LocalFree(text);
    return 6;
  }
  WCHAR logical[512];
  int formatted = _snwprintf_s(
      logical, 512, _TRUNCATE,
      L"\\REGISTRY\\USER\\%ls\\Software\\Classes\\Local Settings", text);
  LocalFree(text);
  if (formatted < 0)
    return 7;
  ls_scratch = malloc(LS_SCRATCH);
  if (!ls_scratch || !ls_append("RAXLS1\0\0", 8) || !ls_hash(digest))
    return 8;
  if (!GetProcessHandleCount(GetCurrentProcess(), &before))
    return 9;
  const ULONG views[] = {0x100, 0x200};
  ULONG roots[2];
  for (unsigned int i = 0; i < 2; ++i) {
    HANDLE key = NULL;
    roots[i] = (ULONG)ls_open(NULL, logical, 0x02000000 | views[i], &key);
    if (!ls_u32(views[i]) || !ls_u32(roots[i]))
      return 10;
    if (roots[i] == 0) {
      if (!key || ls_reserved == LS_MAX_KEYS)
        return 11;
      ++ls_reserved;
      int result = ls_node(key, views[i], 0, NULL);
      if (NtClose(key) != 0)
        result = 12;
      if (result)
        return result;
    } else if (key) {
      NtClose(key);
      return 13;
    } else if (roots[i] != 0xc0000034 && roots[i] != 0xc000003a)
      return 14;
  }
  if (!ls_hash(digest))
    return 15;
  printf(
      "{\"pointer_bytes\":%zu,\"kernel\":[%lu,%lu,%lu],\"subject_sid_hex\":\"",
      sizeof(void *), version.dwMajorVersion, version.dwMinorVersion,
      version.dwBuildNumber);
  hex(subject, subject_bytes);
  printf("\",\"handles_before\":%lu,\"roots\":[%lu,%lu],"
         "\"wire_bytes\":%zu,\"nodes\":%lu,\"values\":%lu,"
         "\"path_bytes\":%zu,\"value_bytes\":%zu,\"child_entries\":%lu,"
         "\"child_bytes\":%zu,\"sha256\":\"",
         before, roots[0], roots[1], ls_used, ls_keys, ls_values, ls_paths,
         ls_value_bytes, ls_children, ls_child_bytes);
  hex(digest, 32);
  printf("\"");
  if (roots[0] == 0) {
    int result = ls_controls(logical);
    if (result)
      return result;
  }
  if (!GetProcessHandleCount(GetCurrentProcess(), &after))
    return 17;
  printf(",\"handles_after\":%lu}\n", after);
  free(ls_scratch);
  free(ls_wire);
  return before == after ? 0 : 16;
}
