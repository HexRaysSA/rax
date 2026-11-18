// The C library's files: streams that are opened, written, read, moved in
// and closed, in text and in binary, and names that are removed and
// changed. Run in a directory of its own; what it leaves there is
// `kept.txt` and `table.bin`.
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void lines(void) {
  FILE *out = fopen("draft.txt", "w");
  if (!out) {
    puts("cannot make draft.txt");
    return;
  }
  fprintf(out, "%s %d %5.2f\n", "first", 1, 1.5);
  fputs("second 2 2.25\n", out);
  fputc('t', out);
  fwrite("hird 3 3.125\n", 1, 13, out);
  printf("position %ld\n", ftell(out));
  printf("close %d\n", fclose(out));

  FILE *in = fopen("draft.txt", "r");
  char word[16], line[64];
  int number;
  double real;
  while (fscanf(in, "%15s %d %lf", word, &number, &real) == 3)
    printf("%s|%d|%g\n", word, number, real);
  printf("end %d error %d\n", feof(in) != 0, ferror(in) != 0);
  rewind(in);
  printf("after rewind: end %d position %ld\n", feof(in) != 0, ftell(in));
  while (fgets(line, sizeof line, in))
    printf("%zu: %s", strlen(line), line);
  // A character read and put back is read again.
  fseek(in, 6, SEEK_SET);
  int c = fgetc(in);
  ungetc(c, in);
  printf("%c%c at %ld\n", c, fgetc(in), ftell(in));
  fseek(in, -6, SEEK_END);
  printf("%s", fgets(line, sizeof line, in));
  printf("past the end: %d %d\n", fgetc(in), feof(in) != 0);
  fclose(in);
}

static void updates(void) {
  // Appending adds; updating changes in place; both see the whole file.
  FILE *more = fopen("draft.txt", "a");
  fprintf(more, "fourth %d %g\n", 4, 4.0);
  fclose(more);
  FILE *both = fopen("draft.txt", "r+");
  fseek(both, 7, SEEK_SET);
  fputc('9', both);
  fflush(both);
  rewind(both);
  char line[64];
  int count = 0;
  while (fgets(line, sizeof line, both))
    printf("%d %s", ++count, line);
  fclose(both);
  // "w+" empties what is there and reads back what it writes.
  FILE *fresh = fopen("scratch.txt", "w+");
  fputs("abcdef", fresh);
  fseek(fresh, 2, SEEK_SET);
  char pair[3] = {0};
  printf("%zu %s\n", fread(pair, 1, 2, fresh), pair);
  fclose(fresh);
  fresh = fopen("scratch.txt", "w");
  fclose(fresh);
  fresh = fopen("scratch.txt", "r");
  printf("emptied: %d\n", fgetc(fresh) == EOF);
  fclose(fresh);
}

static void binary(void) {
  // More than any buffer holds, in pieces of odd sizes.
  enum { COUNT = 40000 };
  static uint32_t table[COUNT];
  for (uint32_t index = 0; index < COUNT; index++)
    table[index] = index * 2654435761u;
  FILE *out = fopen("table.bin", "wb");
  size_t written = 0;
  for (size_t piece = 1; written < COUNT; piece = piece * 3 + 1) {
    size_t take = piece < COUNT - written ? piece : COUNT - written;
    written += fwrite(table + written, sizeof table[0], take, out);
  }
  printf("wrote %zu, at %ld\n", written, ftell(out));
  fclose(out);
  FILE *in = fopen("table.bin", "rb");
  static uint32_t back[COUNT + 10];
  size_t got = fread(back, sizeof back[0], COUNT + 10, in);
  printf("read %zu, same %d, end %d\n", got, memcmp(table, back, sizeof table) == 0, feof(in) != 0);
  // One item from the middle.
  uint32_t item = 0;
  fseek(in, 12345 * (long)sizeof item, SEEK_SET);
  printf("%zu %d\n", fread(&item, sizeof item, 1, in), item == table[12345]);
  fseek(in, 0, SEEK_END);
  printf("size %ld\n", ftell(in));
  fclose(in);
  // With a buffer of the program's own, and with none.
  static char buffer[64];
  in = fopen("table.bin", "rb");
  setvbuf(in, buffer, _IOFBF, sizeof buffer);
  uint32_t sum = 0;
  while (fread(&item, sizeof item, 1, in) == 1)
    sum += item;
  fclose(in);
  in = fopen("table.bin", "rb");
  setvbuf(in, 0, _IONBF, 0);
  fseek(in, 4, SEEK_SET);
  fread(&item, sizeof item, 1, in);
  printf("sum %u, second %d\n", sum, item == table[1]);
  fclose(in);
}

static void names(void) {
  errno = 0;
  printf("missing: %d %d\n", fopen("nothing.txt", "r") == 0, errno == ENOENT);
  printf("bad mode: %d\n", fopen("draft.txt", "q") == 0);
  printf("rename %d\n", rename("draft.txt", "kept.txt"));
  printf("old name: %d\n", fopen("draft.txt", "r") == 0);
  FILE *kept = fopen("kept.txt", "r");
  char line[64];
  printf("%s", fgets(line, sizeof line, kept));
  fclose(kept);
  printf("remove %d\n", remove("scratch.txt"));
  errno = 0;
  printf("remove again: %d %d\n", remove("scratch.txt") != 0, errno == ENOENT);
  // A stream that goes on as another file.
  FILE *moved = fopen("kept.txt", "r");
  moved = freopen("table.bin", "rb", moved);
  uint32_t item;
  printf("%zu %u\n", fread(&item, sizeof item, 1, moved), item);
  fclose(moved);
}

static void standard(void) {
  printf("%d %d %d\n", fileno(stdin), fileno(stdout), fileno(stderr));
  // What is asked before input is read has been written by then.
  char line[32];
  printf("name? ");
  if (fgets(line, sizeof line, stdin)) {
    line[strcspn(line, "\n")] = 0;
    printf("hello, %s\n", line);
  }
  int sum = 0, number;
  while (scanf("%d", &number) == 1)
    sum += number;
  printf("sum %d, end %d\n", sum, feof(stdin) != 0);
  fprintf(stderr, "to the error stream\n");
  fputs("no line end", stdout);
}

int main(void) {
  lines();
  updates();
  binary();
  names();
  standard();
  return 0;
}
