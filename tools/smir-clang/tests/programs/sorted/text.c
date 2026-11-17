#include "text.h"

#include <smir/services.h>

uint64_t text_length(const char *text) {
  uint64_t length = 0;
  while (text[length])
    length++;
  return length;
}

int text_compare(const char *left, const char *right) {
  while (*left && *left == *right) {
    left++;
    right++;
  }
  return (int)(unsigned char)*left - (int)(unsigned char)*right;
}

int put_bytes(uint64_t stream, const char *bytes, uint64_t length) {
  // A write may take only part of what it is given.
  while (length) {
    uint64_t written;
    if (smir_file_write(stream, bytes, length, &written) != 0 || written == 0)
      return 1;
    bytes += written;
    length -= written;
  }
  return 0;
}

int put_text(uint64_t stream, const char *text) { return put_bytes(stream, text, text_length(text)); }

int put_number(uint64_t stream, int64_t value) {
  char digits[21];
  char *next = digits + sizeof digits;
  uint64_t magnitude = value < 0 ? 0 - (uint64_t)value : (uint64_t)value;
  do {
    *--next = (char)('0' + magnitude % 10);
    magnitude /= 10;
  } while (magnitude);
  if (value < 0)
    *--next = '-';
  return put_bytes(stream, next, (uint64_t)(digits + sizeof digits - next));
}

uint64_t read_all(char *buffer, uint64_t capacity) {
  uint64_t total = 0;
  while (total < capacity) {
    uint64_t count;
    // A small request, so that the input arrives over several reads.
    uint64_t request = capacity - total < 7 ? capacity - total : 7;
    if (smir_file_read(SMIR_STANDARD_INPUT, buffer + total, request, &count) != 0 || count == 0)
      break;
    total += count;
  }
  return total;
}
