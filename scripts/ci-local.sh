#!/usr/bin/env bash
# Thin local-CI entry point. The activated, digest-reviewed clone-private MPD
# coordinator owns exact-subject materialization, locked tools, sandboxing,
# receipts, and offline policy. This wrapper never reimplements those checks.
set -euo pipefail
IFS=$'\n\t'

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$repo_root"

fail() {
  printf 'ci-local: %s\n' "$*" >&2
  exit 1
}

git_common="$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null)" || fail "not a Git worktree"
coordinator="$git_common/mpd/trusted-hooks/mpd-coordinator"
[[ -f "$coordinator" && ! -L "$coordinator" && -x "$coordinator" ]] || fail "approved clone-private coordinator is inactive; complete the reviewed policy activation"

if [[ "${1:-}" == "--staged" && "$#" -eq 1 ]]; then
  exec "$coordinator" hook pre-commit
fi

profile="test"
commit="HEAD"
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --profile)
      [[ "$#" -ge 2 ]] || fail "--profile requires a value"
      profile="$2"
      shift 2
      ;;
    --commit)
      [[ "$#" -ge 2 ]] || fail "--commit requires a value"
      commit="$2"
      shift 2
      ;;
    *) fail "usage: bash scripts/ci-local.sh [--staged] [--profile NAME] [--commit OID]" ;;
  esac
done

exec "$coordinator" validate --commit "$commit" --profile "$profile"
