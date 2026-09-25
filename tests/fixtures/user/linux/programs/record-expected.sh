#!/usr/bin/env bash
# Records expected/ for the morok program corpus on a real Linux kernel
# through Docker.
#
#     tests/fixtures/user/linux/programs/record-expected.sh [image]
#
# Every program in cases.txt runs twice per architecture in one container per
# architecture (default image alpine:latest), each run in a fresh working
# directory with standard input from /dev/null. The first run's stdout and
# exit status are written to expected/<arch>/<program>.{stdout,status}; a
# program whose two runs differ outside its noise.txt filters is reported,
# since its expectation would not be reproducible. Containers run
#
# - with `--init`, so the program is not the namespace init;
# - without Docker's default seccomp profile, which refuses some valid
#   arguments with EPERM;
# - on one CPU (`--cpuset-cpus 0`): rax-user runs every guest thread on one
#   host thread and reports one CPU, and programs that size thread pools by
#   the CPU count print it.
#
# Non-native architectures run through the Docker host's binfmt_misc handler
# (recorded in expected/ORACLE). The x86-64 results are cross-checked under
# qemu-x86_64 user mode (installed in a container with apk, which needs
# network access); disagreements are listed in expected/ORACLE. Entries of
# oracle-overrides.txt replace a recording: `qemu-<arch>` runs the program
# under QEMU user mode, another architecture's name copies its recording,
# and `kernel` keeps the committed expectation, derived from the kernel
# source named in the reason.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"
image="${1:-alpine:latest}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

grep -v '^#' cases.txt | awk 'NF' > "$work/cases"

# Runs every case in /cases under $RUNNER (empty: directly) twice, writing
# /o/<name>.<run>.{stdout,status}.
cat > "$work/run.sh" <<'EOF'
set -u
[ -n "$RUNNER" ] && { apk add -q "$RUNNER" >/dev/null 2>&1 || exit 90; }
while read -r name args; do
    [ -n "$ONLY" ] && ! printf '%s\n' $ONLY | grep -qx "$name" && continue
    for run in 1 2; do
        d=$(mktemp -d)
        (cd "$d" && timeout 300 $RUNNER "/w/$name" $args </dev/null >"/o/$name.$run.stdout" 2>/dev/null
         echo $? >"/o/$name.$run.status")
        rm -rf "$d"
    done
done < /cases
EOF

# record ARCH OUTDIR RUNNER [ONLY...]: runs the corpus for ARCH into OUTDIR.
record() {
    local arch="$1" out="$2" runner="$3"
    shift 3
    mkdir -p "$out"
    docker run --rm --init --security-opt seccomp=unconfined --cpuset-cpus 0 \
        -e RUNNER="$runner" -e ONLY="$*" \
        -v "$here/bin/$arch:/w:ro" -v "$out:/o" \
        -v "$work/cases:/cases:ro" -v "$work/run.sh:/run.sh:ro" \
        "$image" sh /run.sh
}

# The noise.txt filters of ARCH/PROGRAM applied to stdin, as the test
# applies them: `addresses` masks hexadecimal addresses (0x and six or more
# digits), `number-before:WORD` masks the number just before " WORD",
# `line:WORD` masks a line containing WORD, `drop:WORD` drops a line
# containing WORD, and `ignore-stdout` drops the output.
denoise() {
    local filters
    filters="$(grep -v '^#' noise.txt |
        awk -v a="$1" -v p="$2" '($1 == a || $1 == "*") && $2 == p { print $3 }' | tr '\n' ' ')"
    perl -e '
        my @f = split " ", shift;
        my $all = join "", <STDIN>;
        exit 0 if grep { $_ eq "ignore-stdout" } @f;
        for my $l (split /(?<=\n)/, $all) {
            for (@f) {
                if ($_ eq "addresses") { $l =~ s/0x[0-9a-fA-F]{6,}/0x?/g }
                elsif (/^number-before:(.*)$/) { my $w = quotemeta $1; $l =~ s/[0-9][0-9.]*(?= $w)/?/g }
                elsif (/^line:(.*)$/) { $l = ($l =~ /\n$/ ? "<masked>\n" : "<masked>") if index($l, $1) >= 0 }
                elsif (/^drop:(.*)$/) { $l = "" if index($l, $1) >= 0 }
            }
            print $l;
        }' "$filters"
}

override() {
    grep -v '^#' oracle-overrides.txt | awk -v a="$1" -v c="$2" '$1 == a && $2 == c { print $3 }'
}

native="$(docker run --rm "$image" uname -m)"
{
    echo "image: $image"
    echo "kernel: $(docker run --rm "$image" uname -srvm)"
    echo "docker: $(docker version --format '{{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}')"
    echo "recorded: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "native-arch: $native"
    echo "cpus: 1 (--cpuset-cpus 0)"
    echo "seccomp: unconfined"
} > "$work/ORACLE"

for arch in x86_64 aarch64 riscv64; do
    echo "recording $arch"
    record "$arch" "$work/$arch" ""
    mkdir -p "expected/$arch"
    while read -r name _; do
        source="$(override "$arch" "$name")"
        case "$source" in
            kernel) continue ;;
            qemu-*) continue ;;
        esac
        r="$work/$arch/$name"
        if ! cmp -s <(denoise "$arch" "$name" < "$r.1.stdout") <(denoise "$arch" "$name" < "$r.2.stdout") ||
            ! cmp -s "$r.1.status" "$r.2.status"; then
            echo "nondeterministic: $arch/$name" | tee -a "$work/ORACLE"
        fi
        cp "$r.1.stdout" "expected/$arch/$name.stdout"
        cp "$r.1.status" "expected/$arch/$name.status"
    done < "$work/cases"
done

# The x86-64 translator cross-check.
qemu_version="$(docker run --rm "$image" sh -c \
    'apk add -q qemu-x86_64 >/dev/null 2>&1 && qemu-x86_64 --version' | head -1)"
record x86_64 "$work/qemu-x86_64" qemu-x86_64
same=0
differ=""
while read -r name _; do
    r="$work/qemu-x86_64/$name.1"
    if cmp -s <(denoise x86_64 "$name" < "$r.stdout") <(denoise x86_64 "$name" < "expected/x86_64/$name.stdout") &&
        cmp -s "$r.status" "expected/x86_64/$name.status"; then
        same=$((same + 1))
    else
        differ="$differ $name"
    fi
done < "$work/cases"
echo "cross-check: x86_64 under $qemu_version agrees on $same of $(awk 'END { print NR }' "$work/cases") programs${differ:+; differs:$differ}" >> "$work/ORACLE"

grep -v '^#' oracle-overrides.txt | while read -r arch name source reason; do
    [[ -z "$arch" ]] && continue
    case "$source" in
        kernel)
            echo "override: $arch/$name from the kernel source ($reason)" >> "$work/ORACLE"
            ;;
        qemu-*)
            version="$(docker run --rm "$image" sh -c \
                "apk add -q $source >/dev/null 2>&1 && $source --version" | head -1)"
            record "$arch" "$work/$source-$arch" "$source" "$name"
            cp "$work/$source-$arch/$name.1.stdout" "expected/$arch/$name.stdout"
            cp "$work/$source-$arch/$name.1.status" "expected/$arch/$name.status"
            echo "override: $arch/$name run under $version ($reason)" >> "$work/ORACLE"
            ;;
        *)
            cp "expected/$source/$name.stdout" "expected/$arch/$name.stdout"
            cp "expected/$source/$name.status" "expected/$arch/$name.status"
            echo "override: $arch/$name from $source ($reason)" >> "$work/ORACLE"
            ;;
    esac
done
cp "$work/ORACLE" expected/ORACLE
echo "recorded; see expected/ORACLE"
