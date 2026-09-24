#!/usr/bin/env bash
# Records expected fixture results on a real Linux kernel through Docker.
#
#     tests/fixtures/user/linux/record-expected.sh [image]
#
# Each case in cases.txt runs in a container (default image alpine:latest,
# `--init` so the program is not the namespace init, which ignores
# default-action signals). stdout and the exit status are written to
# expected/<arch>/<case>.{stdout,status}; the container kernel and the
# binfmt handler used for non-native architectures are recorded in
# expected/ORACLE. Containers run without Docker's default seccomp profile,
# which refuses some valid arguments (for example personality(2) flags) with
# EPERM. oracle-overrides.txt names the cases a binfmt handler cannot run
# faithfully and the oracle used instead (QEMU user mode, installed in the
# container with apk, which needs network access, or another
# architecture's result).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"
image="${1:-alpine:latest}"
mkdir -p expected

{
    echo "image: $image"
    echo "kernel: $(docker run --rm "$image" uname -srvm)"
    echo "docker: $(docker version --format '{{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}')"
    echo "recorded: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    native="$(docker run --rm "$image" uname -m)"
    echo "native-arch: $native"
    echo "translated: every other architecture runs through the Docker host's binfmt_misc handler"
    # The registered handlers (name, state, interpreter), for reviewing which
    # translator ran each architecture. `cat -v` shows non-ASCII bytes in
    # handler names (OrbStack registers names differing by U+200B).
    docker run --rm --privileged "$image" sh -c \
        'mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc 2>/dev/null
         cd /proc/sys/fs/binfmt_misc &&
         for f in *; do
             case "$f" in register|status) continue ;; esac
             echo "binfmt: $f $(sed -n 1,2p "$f" | tr "\n" " ")"
         done' | LC_ALL=C sort | LC_ALL=C cat -v || echo "binfmt: unavailable"
    echo "seccomp: unconfined"
} > expected/ORACLE

# run_case ARCH PROG INPUT RUNNER ARGS...: runs one case in a container,
# directly (RUNNER "-") or under a QEMU user-mode binary installed with apk,
# and prints its standard output; the exit status is the program's.
run_case() {
    local arch="$1" prog="$2" input="$3" runner="$4"
    shift 4
    local stdin=/dev/null
    [[ "$input" != "-" ]] && stdin="$input"
    local cmd=(/w/"$arch"/"$prog" "$@")
    if [[ "$runner" != "-" ]]; then
        cmd=(sh -c 'apk add -q "$0" >/dev/null 2>&1 && exec "$@"' "$runner" "$runner" "${cmd[@]}")
    fi
    timeout 300 docker run -i --rm --init --security-opt seccomp=unconfined \
        -e RAX_FIXTURE_VAR=set -v "$here/bin:/w:ro" "$image" "${cmd[@]}" \
        2>/dev/null < "$stdin"
}

# override ARCH CASE: the source oracle-overrides.txt gives, if any.
override() {
    grep -v '^#' oracle-overrides.txt | awk -v a="$1" -v c="$2" '$1 == a && $2 == c { print $3 }'
}

grep -v '^#' cases.txt | while read -r name prog input args; do
    [[ -z "$name" ]] && continue
    for arch in x86_64 aarch64 riscv64; do
        mkdir -p "expected/$arch"
        out="expected/$arch/$name"
        runner=-
        source="$(override "$arch" "$name")"
        [[ "$source" == qemu-* ]] && runner="$source"
        status=0
        # shellcheck disable=SC2086
        run_case "$arch" "$prog" "$input" "$runner" $args > "$out.stdout" || status=$?
        echo "$status" > "$out.status"
        echo "$arch $name -> $status${source:+ ($source)}"
    done
done

# Overrides: a QEMU user-mode run (recorded above, with its version noted
# here) or a copy of another architecture's result.
grep -v '^#' oracle-overrides.txt | while read -r arch name source reason; do
    [[ -z "$arch" ]] && continue
    case "$source" in
        qemu-*)
            version="$(docker run --rm "$image" sh -c \
                "apk add -q $source >/dev/null 2>&1 && $source --version" | head -1)"
            echo "override: $arch/$name run under $version ($reason)" >> expected/ORACLE
            ;;
        *)
            cp "expected/$source/$name.stdout" "expected/$arch/$name.stdout"
            cp "expected/$source/$name.status" "expected/$arch/$name.status"
            echo "override: $arch/$name from $source ($reason)" >> expected/ORACLE
            echo "$arch $name <- $source"
            ;;
    esac
done
