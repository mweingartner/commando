#!/usr/bin/env bash
# Copy one already-built, content-bound artifact. This script never builds,
# downloads, elevates, mutates PATH, or runs the installed executable.
set -euo pipefail
IFS=$'\n\t'

fail() {
  printf 'install-local: %s\n' "$*" >&2
  exit 1
}

reject_symlink_or_parent_escape() {
  local path="$1" label="$2" current component remainder
  [[ -n "$path" ]] || fail "$label path is empty"
  if [[ "$path" == /* ]]; then
    current=/
    remainder="${path#/}"
  else
    current=.
    remainder="$path"
  fi
  local -a components=()
  IFS=/ read -r -a components <<<"$remainder"
  for component in "${components[@]}"; do
    [[ -n "$component" && "$component" != . && "$component" != .. ]] \
      || fail "$label path contains an unsafe component"
    if [[ "$current" == / ]]; then
      current="/$component"
    else
      current="$current/$component"
    fi
    [[ ! -L "$current" ]] || fail "$label path traverses a symlink: $current"
  done
}

if [[ $# -ne 3 ]]; then
  fail "usage: scripts/install-local.sh <artifact> <sha256> <installed-path>"
fi

artifact=$1
expected_sha256=$2
installed_path=$3

[[ "$expected_sha256" =~ ^[0-9a-f]{64}$ ]] || fail "expected SHA-256 must be 64 lowercase hexadecimal characters"
reject_symlink_or_parent_escape "$artifact" artifact
reject_symlink_or_parent_escape "$installed_path" installed
[[ -f "$artifact" && ! -L "$artifact" ]] || fail "artifact must be a non-symlink regular file"
[[ ! -L "$installed_path" ]] || fail "installed path must not be a symlink"
[[ ! -e "$installed_path" || -f "$installed_path" ]] || fail "installed path must be absent or a regular file"

actual_sha256=$(shasum -a 256 -- "$artifact" | awk '{print $1}')
[[ "$actual_sha256" == "$expected_sha256" ]] || fail "artifact SHA-256 differs from the Build receipt"

install_parent=$(dirname -- "$installed_path")
mkdir -p -- "$install_parent"
reject_symlink_or_parent_escape "$install_parent" 'installed parent'
temporary=$(mktemp "$install_parent/.mpd-install.XXXXXX")
cleanup() {
  rm -f -- "$temporary"
}
trap cleanup EXIT HUP INT TERM

if source_mode=$(stat -f '%Lp' -- "$artifact" 2>/dev/null); then
  :
elif source_mode=$(stat -c '%a' -- "$artifact" 2>/dev/null); then
  :
else
  fail "cannot determine artifact mode"
fi
cp -- "$artifact" "$temporary"
chmod "$source_mode" "$temporary"
copied_sha256=$(shasum -a 256 -- "$temporary" | awk '{print $1}')
[[ "$copied_sha256" == "$expected_sha256" ]] || fail "copied artifact SHA-256 differs from the Build receipt"
mv -f -- "$temporary" "$installed_path"
trap - EXIT HUP INT TERM

installed_sha256=$(shasum -a 256 -- "$installed_path" | awk '{print $1}')
[[ "$installed_sha256" == "$expected_sha256" ]] || fail "installed artifact SHA-256 differs after atomic replacement"
printf 'install-local: copied verified artifact to %s\n' "$installed_path"
