// files [NAME]: the file services. A file is made and written, read back
// whole and from the middle, appended to, renamed and removed, and the
// requests the runtime refuses are refused. What is left in the directory
// is `kept.txt` and, if a name is given, a file of that name.
#include <smir/services.h>

static uint64_t length_of(const char *text) {
  uint64_t length = 0;
  while (text[length])
    length++;
  return length;
}

static void say(const char *text) {
  uint64_t written;
  smir_file_write(SMIR_STANDARD_OUTPUT, text, length_of(text), &written);
}

static void say_number(const char *label, uint64_t value) {
  char digits[24];
  int at = sizeof digits;
  digits[--at] = 0;
  digits[--at] = '\n';
  do
    digits[--at] = (char)('0' + value % 10);
  while ((value /= 10) != 0);
  say(label);
  say(digits + at);
}

static uint32_t open_named(const char *name, uint32_t flags, uint64_t *handle) {
  return smir_file_open(name, length_of(name), flags, 0644, handle);
}

// Write all of `text`; a write may take fewer bytes than it is given.
static uint32_t write_all(uint64_t handle, const char *text) {
  uint64_t length = length_of(text), done = 0;
  while (done < length) {
    uint64_t count;
    uint32_t status = smir_file_write(handle, text + done, length - done, &count);
    if (status != 0)
      return status;
    done += count;
  }
  return 0;
}

// Print what a file holds, from its position on.
static void show(uint64_t handle) {
  char buffer[16];
  for (;;) {
    uint64_t count, written;
    if (smir_file_read(handle, buffer, sizeof buffer, &count) != 0 || count == 0)
      break;
    smir_file_write(SMIR_STANDARD_OUTPUT, buffer, count, &written);
  }
}

int main(int argc, char **argv) {
  const uint32_t fresh = SMIR_OPEN_WRITE | SMIR_OPEN_CREATE | SMIR_OPEN_TRUNCATE;
  uint64_t file, other, position;
  say_number("create ", open_named("draft.txt", fresh | SMIR_OPEN_READ, &file));
  say_number("write ", write_all(file, "one\ntwo\nthree\nfour\n"));
  // Back to the start, and everything is there.
  say_number("rewind ", smir_file_seek(file, 0, SMIR_SEEK_START, &position));
  say_number("at ", position);
  show(file);
  // The third line, found from the end; then overwritten in place.
  say_number("seek ", smir_file_seek(file, -11, SMIR_SEEK_END, &position));
  say_number("at ", position);
  say_number("patch ", write_all(file, "THREE"));
  say_number("skip ", smir_file_seek(file, 1, SMIR_SEEK_CURRENT, &position));
  say_number("at ", position);
  show(file);
  say_number("before the start ", smir_file_seek(file, -1, SMIR_SEEK_START, &position) != 0);
  say_number("close ", smir_file_close(file));
  say_number("closed twice ", smir_file_close(file) != 0);
  say_number("read when closed ", smir_file_read(file, &position, 1, &position) != 0);

  // A second handle is another number, and appending goes to the end
  // wherever the position is.
  say_number("append ", open_named("draft.txt", SMIR_OPEN_WRITE | SMIR_OPEN_APPEND, &other));
  say_number("fresh handle ", other != file && other > SMIR_STANDARD_ERROR);
  smir_file_seek(other, 0, SMIR_SEEK_START, &position);
  say_number("write ", write_all(other, "five\n"));
  say_number("close ", smir_file_close(other));

  // Under a new name the file is the same, and the old name is gone.
  say_number("rename ", smir_file_rename("draft.txt", 9, "kept.txt", 8));
  say_number("old name ", open_named("draft.txt", SMIR_OPEN_READ, &file) != 0);
  say_number("new name ", open_named("kept.txt", SMIR_OPEN_READ, &file));
  show(file);
  // A file opened for reading is not written.
  say_number("write to a reader ", write_all(file, "x") != 0);
  say_number("close ", smir_file_close(file));

  // A file made and removed leaves nothing.
  say_number("create ", open_named("scratch.bin", fresh, &file));
  say_number("close ", smir_file_close(file));
  say_number("unlink ", smir_file_unlink("scratch.bin", 11));
  say_number("unlink again ", smir_file_unlink("scratch.bin", 11) != 0);
  say_number("gone ", open_named("scratch.bin", SMIR_OPEN_READ, &file) != 0);

  // What is refused: no way of access, emptying without writing, a name of
  // no bytes, and moving in a stream.
  say_number("no access ", open_named("kept.txt", 0, &file) != 0);
  say_number("truncate a reader ", open_named("kept.txt", SMIR_OPEN_READ | SMIR_OPEN_TRUNCATE, &file) != 0);
  say_number("empty name ", smir_file_open("kept.txt", 0, SMIR_OPEN_READ, 0, &file) != 0);
  say_number("seek a stream ", smir_file_seek(SMIR_STANDARD_OUTPUT, 0, SMIR_SEEK_CURRENT, &position) != 0);

  if (argc > 1) {
    say_number("named ", open_named(argv[1], fresh, &file));
    say_number("write ", write_all(file, argv[1]));
    say_number("close ", smir_file_close(file));
  }
  return 0;
}
