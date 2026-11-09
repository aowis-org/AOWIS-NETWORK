#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    printf 'Usage: %s /path/to/aowis-network-description.zip\n' "${0##*/}" >&2
    exit 2
fi

patch_name="${1##*/}"
case "$patch_name" in
    aowis-network-?*.zip) ;;
    *)
        printf 'Error: expected aowis-network-*.zip, got: %s\n' "$patch_name" >&2
        exit 2
        ;;
esac

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
project_root="$(cd -- "$script_dir/.." && pwd -P)"
project_name="$(basename -- "$project_root")"

if [[ "$project_name" != 'AOWIS-NETWORK' ]]; then
    printf 'Error: expected checkout directory AOWIS-NETWORK, got: %s\n' "$project_name" >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    printf 'Error: python3 is required to validate and apply patch ZIPs.\n' >&2
    exit 1
fi
if [[ ! -f "$1" ]]; then
    printf 'Error: patch file not found: %s\n' "$1" >&2
    exit 1
fi

# Validate the entire archive before writing, including any optional deletion
# manifest. Stage replacements in the checkout parent and atomically rename files
# into place; refresh mtimes so incremental build tools notice every change.
python3 - "$project_root" "$1" <<'PY'
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import zipfile

root = Path(sys.argv[1])
archive_path = Path(sys.argv[2])
manifest_name = '.aowis-patch-delete.txt'


def invalid(message):
    raise ValueError(message)


def relative_path(name, is_directory=False):
    prefix = root.name + '/'
    if not name.startswith(prefix):
        invalid(f'Invalid patch path (must start with {prefix}): {name!r}')
    relative = name[len(prefix):]
    if not relative and is_directory:
        return None
    if not relative or '\\' in relative or '\x00' in relative or '\r' in relative or '\n' in relative:
        invalid(f'Invalid patch path: {name!r}')
    if is_directory:
        if not relative.endswith('/'):
            invalid(f'Invalid directory path: {name!r}')
        relative = relative[:-1]
    elif relative.endswith('/'):
        invalid(f'Invalid file path: {name!r}')
    parts = relative.split('/')
    if any(part in ('', '.', '..', '.git') for part in parts):
        invalid(f'Unsafe patch path: {name!r}')
    return Path(*parts)


def check_worktree_path(relative, expect_file=False):
    target = root / relative
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            invalid(f'Refusing to follow symlink: {relative.as_posix()}')
    if expect_file and target.is_dir():
        invalid(f'File path is an existing directory: {relative.as_posix()}')
    for parent in target.parents:
        if parent == root:
            break
        if parent.is_file():
            invalid(f'Parent is an existing file: {relative.as_posix()}')
    return target


try:
    with zipfile.ZipFile(archive_path) as archive:
        if archive.testzip() is not None:
            invalid('Patch ZIP failed its integrity check')

        files = {}
        directories = set()
        for info in archive.infolist():
            relative = relative_path(info.filename, info.is_dir())
            if relative is None:
                continue
            mode = info.external_attr >> 16
            file_type = stat.S_IFMT(mode)
            if file_type not in (0, stat.S_IFDIR if info.is_dir() else stat.S_IFREG):
                invalid(f'Unsupported ZIP entry (e.g. symlink): {info.filename!r}')
            if info.is_dir():
                if relative in directories:
                    invalid(f'Duplicate ZIP directory: {info.filename!r}')
                directories.add(relative)
            else:
                if relative in files:
                    invalid(f'Duplicate ZIP file: {info.filename!r}')
                files[relative] = info

        if not files:
            invalid('Patch ZIP contains no files')
        for relative in files:
            if relative in directories or any(parent in files for parent in relative.parents if parent != Path('.')):
                invalid(f'Conflicting ZIP file paths: {relative.as_posix()}')
            if relative != Path(manifest_name):
                check_worktree_path(relative, expect_file=True)
        for relative in directories:
            if relative in files or any(parent in files for parent in relative.parents if parent != Path('.')):
                invalid(f'Conflicting ZIP directory: {relative.as_posix()}')
            check_worktree_path(relative)

        deletions = []
        if Path(manifest_name) in files:
            data = archive.read(files[Path(manifest_name)]).decode('utf-8')
            for name in data.splitlines():
                if not name:
                    continue
                relative = relative_path(root.name + '/' + name)
                if relative == Path(manifest_name) or relative in files:
                    invalid(f'Deletion conflicts with patch addition: {name!r}')
                target = check_worktree_path(relative, expect_file=True)
                if target not in deletions:
                    deletions.append(target)

        # Copy the validated data into a temporary tree before modifying the checkout.
        with tempfile.TemporaryDirectory(prefix='.aowis-network-patch-', dir=root.parent) as temporary:
            staging_root = Path(temporary)
            for relative, info in files.items():
                if relative == Path(manifest_name):
                    continue
                staged = staging_root / relative
                staged.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as source, staged.open('wb') as destination:
                    while chunk := source.read(1024 * 1024):
                        destination.write(chunk)
                permissions = (info.external_attr >> 16) & 0o777
                if permissions:
                    staged.chmod(permissions)

            changed_directories = set()
            for relative in files:
                if relative == Path(manifest_name):
                    continue
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                os.replace(staging_root / relative, destination)
                now = time.time_ns()
                os.utime(destination, ns=(now, now))
                changed_directories.update(p for p in destination.parents if p == root or root in p.parents)
            for target in deletions:
                target.unlink(missing_ok=True)
                changed_directories.update(p for p in target.parents if p == root or root in p.parents)
            for directory in sorted(changed_directories, key=lambda p: len(p.parts), reverse=True):
                now = time.time_ns()
                os.utime(directory, ns=(now, now))

    print(f'Applied {archive_path} with current file and directory timestamps.')
except (OSError, ValueError, zipfile.BadZipFile, UnicodeError) as error:
    print(f'Error: {error}', file=sys.stderr)
    sys.exit(1)
PY

# The snapshot script may itself have been updated by the patch.
printf 'Refreshing network.zip...\n'
if ! bash "$project_root/tools/zip_network_project.sh"; then
    printf 'Error: patch was applied, but refreshing network.zip failed.\n' >&2
    exit 1
fi
