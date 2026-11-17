// Text input and output over the runtime's streams.
#ifndef TEXT_H
#define TEXT_H
#include <stdint.h>

// Write all of `text`, a string, to a stream. Returns zero on success.
int put_text(uint64_t stream, const char *text);
int put_bytes(uint64_t stream, const char *bytes, uint64_t length);
int put_number(uint64_t stream, int64_t value);

// Read standard input to its end into `buffer` and return the byte count,
// which is `capacity` if the input did not fit.
uint64_t read_all(char *buffer, uint64_t capacity);

uint64_t text_length(const char *text);
int text_compare(const char *left, const char *right);

#endif
