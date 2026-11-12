#!/usr/bin/env bash
# Builds the embedded WireGuard engine as a C archive for a target whose own
# CMake build cannot run Go (Windows: MinGW/CMake/Ninja run under Wine).
# Pass the result to CMake as -DAOWIS_NETWORK_WIREGUARD_ARCHIVE=<dir>/libaowis_wireguard.a
#
# Usage: GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc-posix \
#            tools/build_wireguard_engine.sh <output-dir>
#
# GOOS, GOARCH and CC select the target exactly as for `go build`. The Go
# version is the one installed (GOTOOLCHAIN=local): no silent downloads.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    printf 'Usage: %s <output-dir>\n' "$0" >&2
    exit 2
fi
bridge="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../bridge" && pwd)"
mkdir -p -- "$1"
out="$(cd -- "$1" && pwd)"
archive="$out/libaowis_wireguard.a"

printf 'Building WireGuard engine for %s/%s with %s (CC=%s)\n' \
    "$(go env GOOS)" "$(go env GOARCH)" "$(go env GOVERSION)" "$(go env CC)"
rm -f -- "$archive" "$out/libaowis_wireguard.h"
(
    cd -- "$bridge"
    CGO_ENABLED=1 GOWORK=off GOTOOLCHAIN=local \
        go build -mod=readonly -trimpath -buildmode=c-archive -o "$archive" .
)
if [[ ! -s "$archive" ]]; then
    printf 'Engine archive was not produced: %s\n' "$archive" >&2
    exit 1
fi
printf 'Engine archive: %s\n' "$archive"
