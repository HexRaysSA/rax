#!/bin/sh
# Mechanical primary-source acquisition only; no fixture/code generation.
set -eu
out=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
revision=f2355df9f7136d8a2097193fc507882a7caeb5f5
root=https://raw.githubusercontent.com/MicrosoftDocs/cpp-docs/$revision
for page in malloc calloc realloc free expand msize strdup-wcsdup-mbsdup get-errno set-errno get-doserrno set-doserrno get-heap-handle invalid-parameter-functions set-invalid-parameter-handler-set-thread-local-invalid-parameter-handler get-invalid-parameter-handler-get-thread-local-invalid-parameter-handler
do
    curl --fail --silent --show-error "$root/docs/c-runtime-library/reference/$page.md" -o "$out/$page.md"
done
for page in heap-maxreq errno-doserrno-sys-errlist-and-sys-nerr errno-constants parameter-validation potential-errors-passing-crt-objects-across-dll-boundaries
do
    curl --fail --silent --show-error "$root/docs/c-runtime-library/$page.md" -o "$out/$page.md"
done
curl --fail --silent --show-error "$root/docs/intrinsics/fastfail.md" -o "$out/fastfail.md"
curl --fail --silent --show-error "$root/LICENSE" -o "$out/LICENSE"
curl --fail --silent --show-error "$root/LICENSE-CODE" -o "$out/LICENSE-CODE"
