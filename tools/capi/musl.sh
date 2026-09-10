#!/bin/sh
# Run inside the digest-pinned native Rust/Alpine container from capi-release.yml.
set -eu
apk add --no-cache python3 cmake make g++ musl-dev pkgconf binutils git
# The checkout is read-only and may be owned by the runner rather than root.
git config --global --add safe.directory /source
export PYTHONDONTWRITEBYTECODE=1
python3 -m unittest discover -s tools/capi -p 'test_*.py' -v
set --
if [ -n "${RELEASE_TAG:-}" ]; then set -- --tag "$RELEASE_TAG"; fi
python3 tools/capi/package.py --target "$SDK_TARGET" \
    --work-dir /tmp/rax-sdk --output-dir /dist "$@"
