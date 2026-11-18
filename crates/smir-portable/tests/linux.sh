#!/bin/sh
# Run the runtime's tests on Linux from a machine that is not Linux and has
# a container engine: the lanes of the six hosts that such a machine can run
# itself.
#
#     sh crates/smir-portable/tests/linux.sh [glibc] [musl-x86_64] [musl-aarch64] [pack] [foreign]
#
# With no argument, the first three.
#
# glibc         The crates are built and tested inside a container of
#               BUILD_IMAGE, for the architecture the engine runs natively:
#               the unit tests, the interpreter and native-code tests, and
#               the host C interface with its C program.
# musl-x86_64   The tests are built here, for x86_64-unknown-linux-musl,
# musl-aarch64  or aarch64, as programs that need nothing of the system they
#               run on, and are run in a container of RUN_IMAGE. An engine
#               on a machine of the other architecture emulates the one it
#               is not. The host C interface is tested without its C
#               program, which wants a C compiler for that system.
# pack          The tests of executables (tools/smir-clang/test_pack.py),
#               inside a container of BUILD_IMAGE: ELF executables that
#               carry the runtime or find it installed, linked by that
#               system's compiler and started there. The objects of their
#               programs are compiled here first, since the compiler is
#               here: this lane needs what tools/smir-clang needs.
# foreign       The processor for foreign code (crates/smir-portable-foreign)
#               and its tests, inside a container of BUILD_IMAGE: x86-64 and
#               AArch64 machine code under the emulator's cores. It builds
#               the emulator, which takes some minutes and some gigabytes.
#
# Nothing is written to the repository: it is mounted for reading only, at
# the path it has here, since the tests know their files by that path.
# What is built inside a container goes to SCRATCH. The crates the build
# needs come from this machine's registry; nothing is fetched.
#
# Some tests run the Python tools of the repository, which want Python 3.11.
# Where the image has an older one those tests are left out and the script
# says so.
#
# Environment:
#   SMIR_LINUX_BUILD_IMAGE  an image with cargo and a C compiler
#                           (rust:1.95-bullseye)
#   SMIR_LINUX_RUN_IMAGE    an image to run programs in (the build image)
#   SMIR_LINUX_SCRATCH      where the container's builds go
#   SMIR_LINUX_ENGINE       the container engine's command (docker)
#
# The musl lanes need the Rust targets (`rustup target add
# x86_64-unknown-linux-musl aarch64-unknown-linux-musl`); they are linked
# with the linker the toolchain has, so no C toolchain for Linux is needed.
set -eu

ROOT=$(cd "$(dirname "$0")/../../.." && pwd -P)
ENGINE=${SMIR_LINUX_ENGINE:-docker}
BUILD_IMAGE=${SMIR_LINUX_BUILD_IMAGE:-rust:1.95-bullseye}
RUN_IMAGE=${SMIR_LINUX_RUN_IMAGE:-$BUILD_IMAGE}
SCRATCH=${SMIR_LINUX_SCRATCH:-${TMPDIR:-/tmp}/smir-linux}
REGISTRY=${CARGO_HOME:-$HOME/.cargo}/registry
# What cargo has of the dependencies that come from git: the emulator has one.
SOURCES=${CARGO_HOME:-$HOME/.cargo}/git
RUNTIME=$ROOT/crates/smir-portable
INTERFACE=$ROOT/crates/smir-portable-capi
FOREIGN=$ROOT/crates/smir-portable-foreign

# The tests that run the repository's Python tools, by the names `cargo
# test` leaves out: of the unit tests, and of the interpreter tests.
UNIT_PYTHON="--skip pointer_generator --skip all_owned_generated"
INTERP_PYTHON="--skip reference --skip committed --skip command_line_runner --skip batch_mode --skip data_that_exceeds"
# Sets `unit` and `interp` to those, or to nothing if the Python will do.
PYTHON_CHECK='if python3 -c "import sys; sys.exit(sys.version_info < (3, 11))" 2>/dev/null; then unit=; interp=;
else echo "linux.sh: no Python 3.11 in this image: the tests that run the Python tools are left out" >&2; fi'

glibc() {
  mkdir -p "$SCRATCH/glibc"
  "$ENGINE" run --rm -v "$ROOT:$ROOT:ro" -v "$REGISTRY:/cargo/registry:ro" -v "$SCRATCH/glibc:/target" \
    -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/target -e unit="$UNIT_PYTHON" -e interp="$INTERP_PYTHON" \
    "$BUILD_IMAGE" sh -euc "$PYTHON_CHECK"'
      echo "linux.sh: glibc, $(uname -m)" >&2
      tested() { cargo test --offline --locked --quiet --manifest-path "$@"; }
      tested '"$RUNTIME"'/Cargo.toml --lib -- $unit
      tested '"$RUNTIME"'/Cargo.toml --test interp -- $interp
      # The static library, which the C program of the tests links.
      cargo build --offline --locked --quiet --manifest-path '"$INTERFACE"'/Cargo.toml
      tested '"$INTERFACE"'/Cargo.toml'
}

# The test programs `cargo test --no-run` built, one path on a line.
built() {
  if ! log=$(RUSTFLAGS="-C linker-flavor=ld.lld -C linker=rust-lld -C link-self-contained=yes" \
    cargo test --offline --locked --no-run --target "$1" --manifest-path "$2" $3 2>&1); then
    printf '%s\n' "$log" | tail -n 30 >&2
    echo "linux.sh: the tests do not build for $1" >&2
    exit 1
  fi
  printf '%s\n' "$log" | sed -n 's/^ *Executable .*(\(.*\))$/\1/p'
}

musl() {
  target=$1-unknown-linux-musl
  cd "$ROOT"
  unit=$(built "$target" "$RUNTIME/Cargo.toml" --lib)
  interp=$(built "$target" "$RUNTIME/Cargo.toml" "--test interp")
  host=$(built "$target" "$INTERFACE/Cargo.toml" "--test host")
  for program in "$unit" "$interp" "$host"; do
    [ -n "$program" ] && [ -f "$ROOT/$program" ] || {
      echo "linux.sh: the tests were not built for $target; run cargo test --no-run to see why" >&2
      exit 1
    }
  done
  "$ENGINE" run --rm -v "$ROOT:$ROOT:ro" -w "$RUNTIME" -e unit="$UNIT_PYTHON" -e interp="$INTERP_PYTHON" \
    "$RUN_IMAGE" sh -euc "$PYTHON_CHECK"'
      echo "linux.sh: musl, '"$1"', on $(uname -m)" >&2
      '"$ROOT/$unit"' --quiet $unit
      '"$ROOT/$interp"' --quiet $interp
      cd '"$INTERFACE"'
      '"$ROOT/$host"' --quiet --skip a_c_program'
}

pack() {
  objects=$SCRATCH/objects
  mkdir -p "$objects" "$SCRATCH/glibc"
  # The objects of the tests' programs, compiled where the compiler is; the
  # tests in the container find them there and compile nothing.
  SMIR_PACK_OBJECTS=$objects python3 -B -c \
    'import sys; sys.path.insert(0, sys.argv[1]); import test_pack; test_pack.objects()' "$ROOT/tools/smir-clang"
  "$ENGINE" run --rm -v "$ROOT:$ROOT:ro" -v "$objects:$objects:ro" -v "$REGISTRY:/cargo/registry:ro" \
    -v "$SCRATCH/glibc:/target" -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/target \
    -e SMIR_PACK_OBJECTS="$objects" "$BUILD_IMAGE" sh -euc '
      echo "linux.sh: pack, $(uname -m)" >&2
      python3 -B -m unittest discover -s '"$ROOT"'/tools/smir-clang -p test_pack.py'
}

foreign() {
  mkdir -p "$SCRATCH/foreign"
  "$ENGINE" run --rm -v "$ROOT:$ROOT:ro" -v "$REGISTRY:/cargo/registry:ro" -v "$SOURCES:/cargo/git:ro" \
    -v "$SCRATCH/foreign:/target" -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/target "$BUILD_IMAGE" sh -euc '
      echo "linux.sh: foreign, $(uname -m)" >&2
      cargo test --offline --locked --quiet --manifest-path '"$FOREIGN"'/Cargo.toml'
}

[ $# -gt 0 ] || set -- glibc musl-x86_64 musl-aarch64
for lane; do
  case $lane in
  glibc) glibc ;;
  musl-x86_64) musl x86_64 ;;
  musl-aarch64) musl aarch64 ;;
  pack) pack ;;
  foreign) foreign ;;
  *)
    echo "usage: linux.sh [glibc] [musl-x86_64] [musl-aarch64] [pack] [foreign]" >&2
    exit 2
    ;;
  esac
done
