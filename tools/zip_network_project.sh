#!/usr/bin/env bash
set -euo pipefail

if ! command -v zip >/dev/null 2>&1; then
    printf "Error: 'zip' is not installed.\n" >&2
    exit 1
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
project_dir="$(cd -- "$script_dir/.." && pwd -P)"
project_parent="$(dirname -- "$project_dir")"
project_name="$(basename -- "$project_dir")"
archive_path="$project_parent/network.zip"

if [[ "$project_name" != 'AOWIS-NETWORK' ]]; then
    printf 'Error: expected checkout directory AOWIS-NETWORK, got: %s\n' "$project_name" >&2
    exit 1
fi

# Build a new snapshot first so a failed zip cannot destroy the previous one.
temporary_dir="$(mktemp -d -- "$project_parent/.network-snapshot.XXXXXXXX")"
temporary_archive="$temporary_dir/network.zip"
trap 'rm -rf -- "$temporary_dir"' EXIT
cd -- "$project_parent"

find "$project_name" \
    \( -type d \( \
        -name 'build' -o -name 'build-*' -o -name 'build_*' -o \
        -name '.git' -o -name '.idea' -o -name '.vscode' -o \
        -name '.vs' -o -name '.qtcreator' -o -name '.cache' -o \
        -name 'CMakeFiles' -o -name 'Testing' -o \
        -name '_deps' -o -name '__pycache__' -o -name '*.dSYM' \
    \) \) -prune -o \
    \( -type f \( \
        -name '.git' -o -name '*.user' -o -name '*.user.*' -o \
        -name 'CMakeCache.txt' -o -name 'cmake_install.cmake' -o \
        -name 'install_manifest.txt' -o -name 'compile_commands.json' -o \
        -name 'build.ninja' -o -name 'rules.ninja' -o \
        -name '.ninja_deps' -o -name '.ninja_log' -o \
        -name '*.o' -o -name '*.obj' -o -name '*.a' -o \
        -name '*.so' -o -name '*.so.*' -o -name '*.dll' -o \
        -name '*.dylib' -o -name '*.exe' -o -name '*.pdb' -o \
        -name '*.ilk' -o -name '*.wasm' -o -name '*.log' -o \
        -name 'core' -o -name 'core.*' -o \
        -name '*.tmp' -o -name '*.temp' -o \
        -name '*.swp' -o -name '*.swo' -o -name '*~' -o \
        -name '.DS_Store' -o -name 'Thumbs.db' -o \
        -name '.aowis-patch-delete.txt' \
    \) \) -prune -o \
    -print | zip -q -y "$temporary_archive" -@

mv -f -- "$temporary_archive" "$archive_path"
printf 'Created: %s\n' "$archive_path"
