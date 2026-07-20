#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
umask 077

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck source=bootstrap-helpers.sh
source "$repo_root/scripts/bootstrap-helpers.sh"

fixture="$(mktemp -d "${TMPDIR:-/tmp}/mpd-bootstrap-test.XXXXXX")"
cleanup() {
  case "$fixture" in "${TMPDIR:-/tmp}"/mpd-bootstrap-test.??????) rm -rf -- "$fixture" ;; *) exit 70 ;; esac
}
trap cleanup EXIT HUP INT TERM

git -C "$fixture" init -q
git -C "$fixture" config user.email bootstrap-test@example.invalid
git -C "$fixture" config user.name bootstrap-test
mkdir -p "$fixture/.githooks" "$fixture/publish"
printf '#!/bin/sh\nexit 0\n' >"$fixture/.githooks/pre-commit"
printf '#!/bin/sh\nexit 0\n' >"$fixture/.githooks/pre-push"
printf 'baseline\n' >"$fixture/baseline.txt"
git -C "$fixture" add baseline.txt .githooks
git -C "$fixture" commit -qm baseline

git_snapshot() {
  {
    git -C "$fixture" rev-parse HEAD
    git -C "$fixture" for-each-ref --format='%(refname)%00%(objectname)%00%(objecttype)'
    git -C "$fixture" config --local --null --list
    find "$fixture/.git/hooks" "$fixture/.githooks" -type f -print0 | sort -z | xargs -0 shasum -a 256
  } | shasum -a 256 | awk '{print $1}'
}

payload="$fixture/payload.crate"
printf 'reviewed payload\n' >"$payload"
payload_sha="$(bootstrap_sha256_file "$payload")"
callback_marker="$fixture/callback-started"
installer_canary() {
  printf 'started\n' >"$callback_marker"
}

# A bad payload digest blocks before the installer callback can begin.
if bootstrap_run_verified_installer "$payload" "$(printf '0%.0s' {1..64})" installer_canary; then
  printf 'bootstrap test: tampered payload unexpectedly reached installer\n' >&2
  exit 1
fi
[[ ! -e "$callback_marker" ]] || {
  printf 'bootstrap test: installer callback began before hash verification\n' >&2
  exit 1
}
bootstrap_run_verified_installer "$payload" "$payload_sha" installer_canary
[[ -f "$callback_marker" ]]

make_stage() {
  local stage="$1"
  mkdir -p "$stage/bin"
  printf '#!/bin/sh\nprintf "fixture-tool 1.2.3\\n"\n' >"$stage/bin/fixture-tool"
  chmod 700 "$stage/bin/fixture-tool"
}

before_git="$(git_snapshot)"
stage_one="$fixture/stage-one"
target="$fixture/publish/fixture-tool"
make_stage "$stage_one"
bootstrap_publish_tool "$stage_one" "$target" "bin/fixture-tool" "1.2.3" "$payload_sha"
[[ ! -e "$stage_one" ]]
bootstrap_verify_installed_tool "$target" "bin/fixture-tool" "1.2.3" "$payload_sha"
installed_digest="$(bootstrap_sha256_file "$target/bin/fixture-tool")"

# Response-loss retry verifies the existing winner and never replaces it.
stage_retry="$fixture/stage-retry"
make_stage "$stage_retry"
bootstrap_publish_tool "$stage_retry" "$target" "bin/fixture-tool" "1.2.3" "$payload_sha"
[[ -d "$stage_retry" ]]
[[ "$(bootstrap_sha256_file "$target/bin/fixture-tool")" == "$installed_digest" ]]

# Existing-target tamper and source-identity mismatch both fail closed.
printf 'tampered\n' >>"$target/bin/fixture-tool"
if bootstrap_verify_installed_tool "$target" "bin/fixture-tool" "1.2.3" "$payload_sha"; then
  printf 'bootstrap test: tampered installed executable was accepted\n' >&2
  exit 1
fi
make_stage "$fixture/stage-clean"
rm -rf -- "$target"
bootstrap_publish_tool "$fixture/stage-clean" "$target" "bin/fixture-tool" "1.2.3" "$payload_sha"
if bootstrap_verify_installed_tool "$target" "bin/fixture-tool" "1.2.3" "$(printf 'f%.0s' {1..64})"; then
  printf 'bootstrap test: wrong reviewed source identity was accepted\n' >&2
  exit 1
fi

[[ "$(git_snapshot)" == "$before_git" ]] || {
  printf 'bootstrap test: helper changed Git refs, config, or hooks\n' >&2
  exit 1
}

# The production bootstrap must use the tested hash-before-callback seam and
# must not contain any elevation or Git trust-state mutation escape.
rg -Fq 'bootstrap_run_verified_installer "$archive" "$package_sha"' "$repo_root/scripts/bootstrap-local-ci.sh"
if rg -n '^[[:space:]]*(sudo|doas)([[:space:]]|$)|git[[:space:]]+config|update-ref|core\.hooksPath' "$repo_root/scripts/bootstrap-local-ci.sh"; then
  printf 'bootstrap test: production bootstrap contains elevation or Git trust mutation\n' >&2
  exit 1
fi

printf 'bootstrap local-CI test: PASS\n'
