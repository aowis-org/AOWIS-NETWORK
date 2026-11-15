#!/usr/bin/env bash
# Builds the embedded WireGuard engine for a target whose own CMake build
# cannot run Go (Windows: MinGW/CMake/Ninja run under Wine; Android: Qt's
# NDK cross build). Pass the result to CMake as
# -DAOWIS_NETWORK_WIREGUARD_ARCHIVE=<dir>/libaowis_wireguard.{a,so}
#
# Usage: GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc-posix \
#            tools/build_wireguard_engine.sh <output-dir>
#        GOOS=android GOARCH=arm64 CC=<ndk>/aarch64-linux-android28-clang \
#            tools/build_wireguard_engine.sh <output-dir>
#
# GOOS, GOARCH and CC select the target exactly as for `go build`. The Go
# version is the one installed (GOTOOLCHAIN=local): no silent downloads.
#
# Android gets a shared library (c-shared): a Go c-archive for android uses
# local-exec TLS and cannot be linked into the app's own shared library.
# The .so is packaged next to the app (QT_ANDROID_EXTRA_LIBS), 16 KiB page
# aligned as Android 15+ requires. Override with AOWIS_WIREGUARD_BUILDMODE.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    printf 'Usage: %s <output-dir>\n' "$0" >&2
    exit 2
fi
bridge="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../bridge" && pwd)"
mkdir -p -- "$1"
out="$(cd -- "$1" && pwd)"
goos="$(go env GOOS)"

buildmode="${AOWIS_WIREGUARD_BUILDMODE:-}"
if [[ -z "$buildmode" ]]; then
    buildmode=c-archive
    [[ "$goos" != android ]] || buildmode=c-shared
fi
ldflags=()
case "$buildmode" in
    c-archive) library="$out/libaowis_wireguard.a" ;;
    c-shared)
        [[ "$goos" != windows ]] || { printf 'c-shared is not supported for Windows here\n' >&2; exit 2; }
        library="$out/libaowis_wireguard.so"
        if [[ "$goos" == android ]]; then
            ldflags=(-ldflags '-extldflags=-Wl,-z,max-page-size=16384')
        fi
        ;;
    *) printf 'Unsupported AOWIS_WIREGUARD_BUILDMODE: %s\n' "$buildmode" >&2; exit 2 ;;
esac

printf 'Building WireGuard engine (%s) for %s/%s with %s (CC=%s)\n' \
    "$buildmode" "$goos" "$(go env GOARCH)" "$(go env GOVERSION)" "$(go env CC)"
rm -f -- "$out/libaowis_wireguard.a" "$out/libaowis_wireguard.so" "$out/libaowis_wireguard.h"
(
    cd -- "$bridge"
    CGO_ENABLED=1 GOWORK=off GOTOOLCHAIN=local \
        go build -mod=readonly -trimpath -buildmode="$buildmode" "${ldflags[@]}" -o "$library" .
)
if [[ ! -s "$library" ]]; then
    printf 'Engine library was not produced: %s\n' "$library" >&2
    exit 1
fi
printf 'Engine library: %s\n' "$library"
