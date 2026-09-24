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
# EPERM. oracle-overrides.txt then replaces results a system-call-emulating
# binfmt handler cannot provide faithfully.
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
         done' | LC_ALL=C sort | cat -v || echo "binfmt: unavailable"
    echo "seccomp: unconfined"
} > expected/ORACLE

grep -v '^#' cases.txt | while read -r name prog input args; do
    [[ -z "$name" ]] && continue
    for arch in x86_64 aarch64 riscv64; do
        mkdir -p "expected/$arch"
        out="expected/$arch/$name"
        # shellcheck disable=SC2086
        if [[ "$input" == "-" ]]; then
            status=0
            timeout 120 docker run --rm --init --security-opt seccomp=unconfined \
                -e RAX_FIXTURE_VAR=set \
                -v "$here/bin:/w:ro" "$image" /w/"$arch"/"$prog" $args \
                > "$out.stdout" 2>/dev/null < /dev/null || status=$?
        else
            status=0
            timeout 120 docker run -i --rm --init --security-opt seccomp=unconfined \
                -e RAX_FIXTURE_VAR=set \
                -v "$here/bin:/w:ro" "$image" /w/"$arch"/"$prog" $args \
                > "$out.stdout" 2>/dev/null < "$input" || status=$?
        fi
        echo "$status" > "$out.status"
        echo "$arch $name -> $status"
    done
done

grep -v '^#' oracle-overrides.txt | while read -r arch name source reason; do
    [[ -z "$arch" ]] && continue
    cp "expected/$source/$name.stdout" "expected/$arch/$name.stdout"
    cp "expected/$source/$name.status" "expected/$arch/$name.status"
    echo "override: $arch/$name from $source ($reason)" >> expected/ORACLE
    echo "$arch $name <- $source"
done
