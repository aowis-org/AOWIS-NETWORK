#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
cmake -S "$root" -B "$root/build-linux" -G Ninja \
    -DAOWIS_NETWORK_WITH_WIREGUARD=ON -DBUILD_TESTING=OFF
cmake --build "$root/build-linux" --parallel "${AOWIS_BUILD_JOBS:-8}"
