/* Standalone output/runtime substrate; imports only the installed Kernel32/NTDLL. */
#include <stddef.h>
#include <stdarg.h>
static char control_output[16384];
static unsigned control_used;
__declspec(noinline) void *memset(void *p, int value, size_t n) {
  volatile unsigned char *out = (volatile unsigned char *)p;
  for (size_t i = 0; i < n; ++i) out[i] = (unsigned char)value;
  return p;
}
__declspec(noinline) void *memcpy(void *p, const void *q, size_t n) {
  volatile unsigned char *out = (volatile unsigned char *)p;
  const volatile unsigned char *in = (const volatile unsigned char *)q;
  for (size_t i = 0; i < n; ++i) out[i] = in[i];
  return p;
}
static void control_flush(void) {
  DWORD written = 0;
  if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), control_output, control_used, &written, NULL) || written != control_used) ExitProcess(90);
  control_used = 0;
}
static void control_char(char c) {
  if (control_used == sizeof control_output) control_flush();
  control_output[control_used++] = c;
}
static void control_text(const char *s) { while (*s) control_char(*s++); }
static void control_number(size_t value) {
  char digits[24]; unsigned at = sizeof digits;
  do { digits[--at] = (char)('0' + value % 10); value /= 10; } while (value);
  while (at < sizeof digits) control_char(digits[at++]);
}
static void control_print(const char *format, ...) {
  va_list args; va_start(args, format);
  while (*format) {
    if (*format++ != '%') { control_char(format[-1]); continue; }
    if (format[0] == '0' && format[1] == '2' && format[2] == 'x') {
      unsigned value = va_arg(args, unsigned); const char *hex = "0123456789abcdef";
      if (value > 255) ExitProcess(91);
      control_char(hex[value >> 4]); control_char(hex[value & 15]); format += 3;
    } else if (format[0] == 'z' && format[1] == 'u') {
      control_number(va_arg(args, size_t)); format += 2;
    } else if (format[0] == 'l' && format[1] == 'u') {
      control_number(va_arg(args, unsigned long)); format += 2;
    } else if (*format == 'u') {
      control_number(va_arg(args, unsigned)); ++format;
    } else if (*format == 's') {
      control_text(va_arg(args, const char *)); ++format;
    } else { ExitProcess(92); }
  }
  va_end(args);
}
static size_t control_wcslen(const WCHAR *p) { size_t n = 0; while (((const volatile WCHAR *)p)[n]) ++n; return n; }
typedef LONG (NTAPI *OpenKeyFn)(HANDLE *, ULONG, Attributes *);
typedef LONG (NTAPI *OpenKeyExFn)(HANDLE *, ULONG, Attributes *, ULONG);
typedef LONG (NTAPI *QueryKeyFn)(HANDLE, ULONG, void *, ULONG, ULONG *);
typedef LONG (NTAPI *QueryObjectFn)(HANDLE, ULONG, void *, ULONG, ULONG *);
typedef LONG (NTAPI *CloseFn)(HANDLE);
typedef LONG (NTAPI *VersionFn)(OSVERSIONINFOW *);
static OpenKeyFn control_open;
static OpenKeyExFn control_open_ex;
static QueryKeyFn control_query;
static QueryObjectFn control_object;
static CloseFn control_close;
static VersionFn control_version;
#define NtOpenKey control_open
#define NtOpenKeyEx control_open_ex
#define NtQueryKey control_query
#define NtQueryObject control_object
#define NtClose control_close
#define RtlGetVersion control_version
#define printf control_print
#define wcslen control_wcslen
static void control_load(void) {
  HMODULE module = GetModuleHandleW(L"ntdll.dll");
  control_open = (OpenKeyFn)(uintptr_t)GetProcAddress(module, "NtOpenKey");
  control_open_ex = (OpenKeyExFn)(uintptr_t)GetProcAddress(module, "NtOpenKeyEx");
  control_query = (QueryKeyFn)(uintptr_t)GetProcAddress(module, "NtQueryKey");
  control_object = (QueryObjectFn)(uintptr_t)GetProcAddress(module, "NtQueryObject");
  control_close = (CloseFn)(uintptr_t)GetProcAddress(module, "NtClose");
  control_version = (VersionFn)(uintptr_t)GetProcAddress(module, "RtlGetVersion");
  if (!control_open || !control_open_ex || !control_query || !control_object || !control_close || !control_version) ExitProcess(93);
}
