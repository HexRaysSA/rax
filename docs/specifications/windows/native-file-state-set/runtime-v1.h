/* Standalone output/runtime substrate; imports only the installed Kernel32/NTDLL. */
#include <stddef.h>
#include <stdarg.h>
static HANDLE control_sink;
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
  if (!WriteFile(control_sink, control_output, control_used, &written, NULL) || written != control_used) ExitProcess(90);
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
