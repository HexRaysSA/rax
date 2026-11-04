# Native FIFO readiness and fixture inheritance

The FIFO unit-test fixture opens both endpoints with `O_CLOEXEC`, preventing
an unrelated child exec from retaining its writer and delaying EOF. The
`named_fifo_writer_does_not_survive_an_unrelated_child_exec` regression holds
a real Rust child at a stdin barrier while the parent closes its writer. It
checks readiness and EOF before releasing that child. Its watchdog reaps only
its own child if the regression fails.

`native-readiness-v1.c` links no RAX code. It creates one private nonblocking
FIFO, closes the writer, samples `select`, reads EOF, and samples `select`
again. `profile-v1.json` binds the source, executable and measured hosts.

| Measured host | select before EOF read | read return (bytes) | select after EOF read |
|---|---:|---:|---:|
| macOS | 1 | 0 | 0 |
| Linux | 1 | 0 | 1 |

Blocking fixture waits also retry native `EINTR` with the original absolute
deadline. Their readiness and elapsed-time assertions remain intact. Same-image
Linux diagnostics observed interruptions; blocking only `SIGCHLD` did not
eliminate them, so the particular signal is unknown.

The test therefore checks readiness before consuming EOF. This preserves both
assertions without imposing Linux's post-read behavior on macOS. These finite
observations do not establish every OS release's FIFO behavior. The specific
inheriting process in the earlier broad-suite failure remains unknown.

From the repository root, use an in-tree build and temporary directory:

```sh
mkdir -p target/fifo-readiness-control/tmp
cc -std=c11 -Wall -Wextra -Werror \
  docs/specifications/posix-fifo-readiness/native-readiness-v1.c \
  -o target/fifo-readiness-control/probe
TMPDIR="$PWD/target/fifo-readiness-control/tmp" \
  target/fifo-readiness-control/probe
```

On macOS, use `xcrun --sdk macosx clang` as the compiler if `cc` is not the
system compiler. The program removes its FIFO; remove the generated binary
and empty build directories after collecting its output. The control uses
POSIX FIFOs and is compiled only for Unix hosts; it introduces no Windows
runtime capability or API change.
