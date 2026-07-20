#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
umask 077

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
installer="$repo_root/scripts/install-local.sh"
fixture_parent="$(cd "${TMPDIR:-/tmp}" && pwd -P)"
fixture="$(mktemp -d "$fixture_parent/mpd-install-test.XXXXXX")"
cleanup() {
  case "$fixture" in "$fixture_parent"/mpd-install-test.??????) rm -rf -- "$fixture" ;; *) exit 70 ;; esac
}
trap cleanup EXIT HUP INT TERM

artifact="$fixture/artifact"
target="$fixture/install/bin/mpd"
printf '#!/bin/sh\nprintf "mpd fixture\\n"\n' >"$artifact"
chmod 755 "$artifact"
digest="$(shasum -a 256 "$artifact" | awk '{print $1}')"

"$installer" "$artifact" "$digest" "$target" >/dev/null
[[ -f "$target" && ! -L "$target" ]]
[[ "$(shasum -a 256 "$target" | awk '{print $1}')" == "$digest" ]]
[[ "$("$target")" == 'mpd fixture' ]]

# Exact-input retry is idempotent in content and leaves no temporary sibling.
"$installer" "$artifact" "$digest" "$target" >/dev/null
[[ "$(shasum -a 256 "$target" | awk '{print $1}')" == "$digest" ]]
if find "$(dirname "$target")" -maxdepth 1 -name '.mpd-install.*' -print -quit | grep -q .; then
  printf 'install-local test: retry leaked a temporary file\n' >&2
  exit 1
fi

# A bad digest refuses before replacing the prior installed winner.
before="$(shasum -a 256 "$target" | awk '{print $1}')"
if "$installer" "$artifact" "$(printf '0%.0s' {1..64})" "$target" >/dev/null 2>&1; then
  printf 'install-local test: digest mismatch unexpectedly succeeded\n' >&2
  exit 1
fi
[[ "$(shasum -a 256 "$target" | awk '{print $1}')" == "$before" ]]

# Leaf and intermediate symlinks are both rejected without touching targets.
ln -s "$artifact" "$fixture/artifact-link"
if "$installer" "$fixture/artifact-link" "$digest" "$fixture/link-source-target" >/dev/null 2>&1; then
  printf 'install-local test: symlinked artifact was accepted\n' >&2
  exit 1
fi
outside="$fixture/outside"
mkdir "$outside"
ln -s "$outside" "$fixture/install-link"
if "$installer" "$artifact" "$digest" "$fixture/install-link/escaped" >/dev/null 2>&1; then
  printf 'install-local test: symlinked installed parent was accepted\n' >&2
  exit 1
fi
[[ ! -e "$outside/escaped" ]]
printf 'external\n' >"$outside/external"
ln -s "$outside/external" "$fixture/installed-leaf-link"
if "$installer" "$artifact" "$digest" "$fixture/installed-leaf-link" >/dev/null 2>&1; then
  printf 'install-local test: symlinked installed leaf was accepted\n' >&2
  exit 1
fi
[[ "$(cat "$outside/external")" == external ]]

if (cd "$fixture" && "$installer" artifact "$digest" ../escaped-install) >/dev/null 2>&1; then
  printf 'install-local test: parent traversal was accepted\n' >&2
  exit 1
fi
[[ ! -e "$(dirname "$fixture")/escaped-install" ]]

# The exact-copy leaf has no build, download, elevation, or execution path.
if rg -n --fixed-strings -e 'cargo build' -e 'cargo install' -e 'curl ' -e 'wget ' \
  -e 'sudo ' -e 'doas ' "$installer"; then
  printf 'install-local test: installer contains a rebuild/download/elevation path\n' >&2
  exit 1
fi

printf 'install-local test: PASS\n'
