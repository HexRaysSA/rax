#!/bin/sh
# Run inside the digest-pinned Rust/Debian container from capi-release.yml.
set -eu
apt-get update
apt-get install -y --no-install-recommends "gcc-$TOOLCHAIN" "g++-$TOOLCHAIN" \
    qemu-user cmake make pkg-config python3 git ca-certificates
rustup target add "$SDK_TARGET"
git config --global --add safe.directory /source
export PYTHONDONTWRITEBYTECODE=1
python3 -m unittest discover -s tools/capi -p 'test_*.py' -v
set --
if [ -n "${RELEASE_TAG:-}" ]; then set -- --tag "$RELEASE_TAG"; fi
python3 tools/capi/package.py --target "$SDK_TARGET" --cross-linux \
    --work-dir /tmp/rax-sdk --output-dir /dist "$@"
