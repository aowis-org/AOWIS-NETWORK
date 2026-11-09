#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
cmake -S "$root" -B "$root/build-linux-tests" -G Ninja \
    -DAOWIS_NETWORK_WITH_WIREGUARD=ON -DBUILD_TESTING=ON
cmake --build "$root/build-linux-tests" --parallel "${AOWIS_BUILD_JOBS:-8}"
ctest --test-dir "$root/build-linux-tests" --output-on-failure
