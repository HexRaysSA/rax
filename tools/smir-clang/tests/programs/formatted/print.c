#include "print.h"

#include <smir/services.h>
#include <stdarg.h>

static char buffer[512];
static unsigned used;
static int total;

static void flush(void) {
  for (unsigned done = 0; done < used;) {
    uint64_t written;
    if (smir_file_write(SMIR_STANDARD_OUTPUT, buffer + done, used - done, &written) != 0 || written == 0)
      break;
    done += (unsigned)written;
  }
  used = 0;
}

static void put(char byte) {
  if (used == sizeof buffer)
    flush();
  buffer[used++] = byte;
  total++;
}

static void put_unsigned(uint64_t value, unsigned base, unsigned width, char padding, int negative) {
  char digits[24];
  unsigned count = 0;
  do {
    digits[count++] = "0123456789abcdef"[value % base];
    value /= base;
  } while (value);
  unsigned length = count + (negative ? 1 : 0);
  // Zeros go between the sign and the digits; spaces before the sign.
  if (negative && padding == '0')
    put('-');
  for (; length < width; length++)
    put(padding);
  if (negative && padding != '0')
    put('-');
  while (count)
    put(digits[--count]);
}

static void put_double(double value) {
  if (value != value) {
    for (const char *text = "nan"; *text; text++)
      put(*text);
    return;
  }
  if (value < 0) {
    put('-');
    value = -value;
  }
  if (value > 1.0e18) {
    for (const char *text = "inf"; *text; text++)
      put(*text);
    return;
  }
  uint64_t whole = (uint64_t)value;
  // Six digits, rounded half up.
  uint64_t fraction = (uint64_t)((value - (double)whole) * 1000000.0 + 0.5);
  if (fraction >= 1000000) {
    whole++;
    fraction -= 1000000;
  }
  put_unsigned(whole, 10, 0, ' ', 0);
  put('.');
  put_unsigned(fraction, 10, 6, '0', 0);
}

int print(const char *format, ...) {
  va_list arguments;
  va_start(arguments, format);
  total = 0;
  for (; *format; format++) {
    if (*format != '%') {
      put(*format);
      continue;
    }
    format++;
    char padding = ' ';
    unsigned width = 0;
    int wide = 0;
    if (*format == '0') {
      padding = '0';
      format++;
    }
    for (; *format >= '0' && *format <= '9'; format++)
      width = width * 10 + (unsigned)(*format - '0');
    if (*format == 'l') {
      wide = 1;
      format++;
    }
    switch (*format) {
    case 'd':
    case 'i': {
      int64_t value = wide ? va_arg(arguments, int64_t) : va_arg(arguments, int);
      put_unsigned(value < 0 ? 0 - (uint64_t)value : (uint64_t)value, 10, width, padding, value < 0);
      break;
    }
    case 'u':
    case 'x': {
      uint64_t value = wide ? va_arg(arguments, uint64_t) : va_arg(arguments, unsigned);
      put_unsigned(value, *format == 'x' ? 16 : 10, width, padding, 0);
      break;
    }
    case 'c':
      put((char)va_arg(arguments, int));
      break;
    case 's': {
      const char *text = va_arg(arguments, const char *);
      unsigned length = 0;
      while (text[length])
        length++;
      for (; length < width; length++)
        put(' ');
      while (*text)
        put(*text++);
      break;
    }
    case 'f':
      put_double(va_arg(arguments, double));
      break;
    case '%':
      put('%');
      break;
    default:
      // An unknown conversion is printed as it was written.
      put('%');
      if (*format)
        put(*format);
      else
        format--;
    }
  }
  va_end(arguments);
  flush();
  return total;
}
