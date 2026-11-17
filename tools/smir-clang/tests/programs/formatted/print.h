// A small formatted print over the runtime's output stream.
#ifndef PRINT_H
#define PRINT_H

// Supports %d %i %u %x %c %s %f %% with the length modifier l for the
// integers, a minimum field width, and zero padding. %f prints six digits
// after the point. Returns the number of bytes written.
int print(const char *format, ...);

#endif
