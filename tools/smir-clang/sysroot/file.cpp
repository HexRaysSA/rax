// Files and the standard streams of the C library, over the runtime's file
// services: what LLVM libc's `File`, which buffers and locks, asks a
// platform for.
#include "src/__support/File/file.h"

#include "hdr/errno_macros.h"
#include "hdr/stdio_macros.h"
#include "hdr/types/FILE.h"
#include "hdr/types/off_t.h"
#include "src/__support/CPP/new.h"
#include "src/__support/CPP/string_view.h"
#include "src/__support/File/file_mode.h"
#include "src/__support/OSUtil/io.h"
#include "src/__support/alloc-checker.h"
#include "src/__support/common.h"
#include "src/__support/libc_errno.h"
#include "src/__support/macros/config.h"
#include "src/stdio/fdopen.h"
#include "src/stdio/remove.h"
#include "src/stdio/rename.h"
#include "src/stdio/stderr.h"
#include "src/stdio/stdin.h"
#include "src/stdio/stdout.h"

#include <smir/services.h>

namespace LIBC_NAMESPACE_DECL {

namespace {

FileIOResult write_file(File *, const void *, size_t);
FileIOResult read_file(File *, void *, size_t);
ErrorOr<off_t> seek_file(File *, off_t, int);
int close_file(File *);

// A stream is a handle of the runtime; none once it is closed.
class Stream : public File {
public:
  static constexpr uint64_t CLOSED = ~uint64_t(0);

  uint64_t handle;
  // Whether `fopen` made it. The standard streams are objects with static
  // storage, which closing does not release.
  bool opened;

  constexpr Stream(uint64_t handle, uint8_t *buffer, size_t buffer_size, int buffer_mode, bool opened,
                   FileMode mode)
      : File(&write_file, &read_file, &seek_file, &close_file, buffer, buffer_size, buffer_mode, opened, mode),
        handle(handle), opened(opened) {}

  int reopen_unlocked(const char *path, const char *mode);
};

extern Stream standard_input, standard_output;
constexpr size_t INPUT_BUFFER = 512, OUTPUT_BUFFER = 1024;

// One service call may take only part of the bytes; a stream writes all.
FileIOResult write_file(File *file, const void *data, size_t size) {
  uint64_t handle = static_cast<Stream *>(file)->handle;
  size_t done = 0;
  while (done < size) {
    uint64_t count;
    uint32_t status = smir_file_write(handle, static_cast<const char *>(data) + done, size - done, &count);
    if (status != 0)
      return {done, static_cast<int>(status)};
    if (count == 0)
      break;
    done += count;
  }
  return done;
}

// `File` takes fewer bytes than it asked for as the end of the file, so a
// read goes on until it has them all or there are no more: one service
// call transfers a limited number. Standard input is the exception when
// `File` fills its buffer: there a read returns what has arrived, so that a
// program at a terminal or a pipe gets each line as it comes.
FileIOResult read_file(File *file, void *buffer, size_t size) {
  bool arriving = file == &standard_input && size <= INPUT_BUFFER;
  // Whoever is asked for input has seen what was printed before.
  if (file == &standard_input)
    standard_output.flush();
  uint64_t handle = static_cast<Stream *>(file)->handle;
  size_t done = 0;
  while (done < size) {
    uint64_t count;
    uint32_t status = smir_file_read(handle, static_cast<char *>(buffer) + done, size - done, &count);
    if (status != 0)
      return {done, static_cast<int>(status)};
    done += count;
    if (count == 0 || arriving)
      break;
  }
  return done;
}

ErrorOr<off_t> seek_file(File *file, off_t offset, int whence) {
  // SEEK_SET, SEEK_CUR and SEEK_END are the runtime's 0, 1 and 2.
  uint64_t position;
  uint32_t status =
      smir_file_seek(static_cast<Stream *>(file)->handle, offset, static_cast<uint32_t>(whence), &position);
  if (status != 0)
    return Error(static_cast<int>(status));
  return static_cast<off_t>(position);
}

int close_file(File *file) {
  auto *stream = static_cast<Stream *>(file);
  if (!stream->opened) {
    // A standard stream: the program has done with it, the runtime has not.
    stream->handle = Stream::CLOSED;
    return 0;
  }
  File::remove_file(stream);
  int status = stream->handle == Stream::CLOSED ? EBADF : static_cast<int>(smir_file_close(stream->handle));
  delete stream;
  return status;
}

size_t length_of(const char *text) {
  size_t length = 0;
  while (text[length])
    ++length;
  return length;
}

// What a mode of `fopen` asks of `smir_file_open`.
uint32_t open_flags(const FileMode &mode) {
  uint32_t flags = mode.is_update() ? SMIR_OPEN_READ | SMIR_OPEN_WRITE
                   : mode.is_append() || mode.is_write() ? SMIR_OPEN_WRITE
                                                          : SMIR_OPEN_READ;
  if (mode.is_append())
    flags |= SMIR_OPEN_CREATE | SMIR_OPEN_APPEND;
  else if (mode.is_write())
    flags |= SMIR_OPEN_CREATE | SMIR_OPEN_TRUNCATE;
  return flags;
}

ErrorOr<uint64_t> open_handle(const char *path, const FileMode &mode) {
  uint64_t handle;
  // rw-rw-rw-, as `fopen` makes a file anywhere.
  uint32_t status = smir_file_open(path, length_of(path), open_flags(mode), 0666, &handle);
  if (status != 0)
    return Error(static_cast<int>(status));
  return handle;
}

// The standard streams. Standard output is written line by line, so that
// what a program has printed is there when it stops for input or stops
// altogether; standard error at once.
uint8_t input_buffer[INPUT_BUFFER], output_buffer[OUTPUT_BUFFER];
Stream standard_input(SMIR_STANDARD_INPUT, input_buffer, INPUT_BUFFER, _IOFBF, false, FileMode::READ_MODE);
Stream standard_output(SMIR_STANDARD_OUTPUT, output_buffer, OUTPUT_BUFFER, _IOLBF, false, FileMode::APPEND_MODE);
Stream standard_error(SMIR_STANDARD_ERROR, nullptr, 0, _IONBF, false, FileMode::APPEND_MODE);

// When the program ends in good order, after everything else that runs
// then: what the streams still hold is written.
[[gnu::destructor(0)]] void flush_streams() {
  standard_output.flush();
  File::lock_list();
  for (File *file = File::get_first_file(); file; file = file->get_next())
    file->flush();
  File::unlock_list();
}

} // namespace

// A stream with a buffer for an open handle; null if there is no storage.
static Stream *make_stream(uint64_t handle, const FileMode &mode) {
  AllocChecker buffered;
  auto *buffer = new (buffered) uint8_t[File::DEFAULT_BUFFER_SIZE];
  if (!buffered)
    return nullptr;
  AllocChecker made;
  auto *stream = new (made) Stream(handle, buffer, File::DEFAULT_BUFFER_SIZE, _IOFBF, true, mode);
  if (!made) {
    delete[] buffer;
    return nullptr;
  }
  File::add_file(stream);
  return stream;
}

ErrorOr<File *> openfile(const char *path, const char *mode) {
  const FileMode file_mode(mode);
  if (!file_mode.is_valid())
    return Error(EINVAL);
  ErrorOr<uint64_t> handle = open_handle(path, file_mode);
  if (!handle)
    return Error(handle.error());
  Stream *stream = make_stream(handle.value(), file_mode);
  if (!stream) {
    smir_file_close(handle.value());
    return Error(ENOMEM);
  }
  return stream;
}

// `freopen`: the stream goes on as another file. Without a path it would
// change how its file is open, which the runtime has no service for.
int Stream::reopen_unlocked(const char *path, const char *mode) {
  flush_unlocked();
  const FileMode file_mode(mode);
  if (path == nullptr)
    return EINVAL;
  // A standard stream's handle stays open for the runtime.
  if (opened && handle != CLOSED)
    smir_file_close(handle);
  handle = CLOSED;
  reset_stream_state_unlocked(file_mode);
  if (!file_mode.is_valid())
    return EINVAL;
  ErrorOr<uint64_t> next = open_handle(path, file_mode);
  if (!next)
    return next.error();
  handle = next.value();
  return 0;
}

int reopenfile_unlocked(File *file, const char *path, const char *mode) {
  return static_cast<Stream *>(file)->reopen_unlocked(path, mode);
}

int reopenfile(File *file, const char *path, const char *mode) {
  File::FileLock lock(file);
  return reopenfile_unlocked(file, path, mode);
}

// A handle is a file descriptor to whoever asks for one, as far as it fits.
int get_fileno(File *file) {
  uint64_t handle = static_cast<Stream *>(file)->handle;
  return handle <= 0x7fffffff ? static_cast<int>(handle) : -1;
}

// What the library says when it gives up goes out at once.
void write_to_stderr(cpp::string_view message) {
  uint64_t count;
  smir_file_write(SMIR_STANDARD_ERROR, message.data(), message.size(), &count);
}

LLVM_LIBC_VARIABLE(FILE *, stdin) = reinterpret_cast<FILE *>(&standard_input);
LLVM_LIBC_VARIABLE(FILE *, stdout) = reinterpret_cast<FILE *>(&standard_output);
LLVM_LIBC_VARIABLE(FILE *, stderr) = reinterpret_cast<FILE *>(&standard_error);

// A stream for a handle that is open already. Whether the handle can do
// what the mode says shows when it is used.
LLVM_LIBC_FUNCTION(::FILE *, fdopen, (int handle, const char *mode)) {
  const FileMode file_mode(mode);
  Stream *stream = handle >= 0 && file_mode.is_valid() ? make_stream(static_cast<uint64_t>(handle), file_mode)
                                                        : nullptr;
  if (!stream)
    libc_errno = handle < 0 ? EBADF : file_mode.is_valid() ? ENOMEM : EINVAL;
  return reinterpret_cast<::FILE *>(stream);
}

LLVM_LIBC_FUNCTION(int, remove, (const char *path)) {
  uint32_t status = smir_file_unlink(path, length_of(path));
  if (status == 0)
    return 0;
  libc_errno = static_cast<int>(status);
  return -1;
}

LLVM_LIBC_FUNCTION(int, rename, (const char *from, const char *to)) {
  uint32_t status = smir_file_rename(from, length_of(from), to, length_of(to));
  if (status == 0)
    return 0;
  libc_errno = static_cast<int>(status);
  return -1;
}

} // namespace LIBC_NAMESPACE_DECL
