#!/usr/bin/env bash
# Validate current operator-facing doctrine. Preserved OpenSpec review history is
# excluded because rejected decisions must remain verbatim evidence.
set -euo pipefail
IFS=$'\n\t'

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
if [[ $# -gt 0 ]]; then
  [[ $# -eq 2 && "$1" == --root && "$2" == /* && -d "$2" && ! -L "$2" ]] || {
    printf 'check-doc-staleness: usage: check-doc-staleness.sh [--root /absolute/path]\n' >&2
    exit 2
  }
  root="$2"
fi

declare -a files=()
for relative in README.md AGENTS.md ARCHITECTURE.md SECURITY.md CONTRIBUTING.md \
  openspec/changes/local-first-verification-hardening/documentation.md \
  openspec/changes/local-first-verification-hardening/closure-runbook.md; do
  [[ ! -f "$root/$relative" ]] || files+=("$root/$relative")
done
for directory in "$root/.mpd/directives" "$root/crates/mpd/assets/directives"; do
  [[ ! -d "$directory" ]] || while IFS= read -r -d '' path; do
    files+=("$path")
  done < <(find "$directory" -type f -name '*.md' -print0)
done
if [[ ${#files[@]} -eq 0 ]]; then
  while IFS= read -r -d '' path; do files+=("$path"); done \
    < <(find "$root" -type f -name '*.md' -print0)
fi
[[ ${#files[@]} -gt 0 ]] || {
  printf 'check-doc-staleness: no current Markdown files found\n' >&2
  exit 2
}

reject_fixed() {
  local label="$1" needle="$2"
  if rg -n -F -- "$needle" "${files[@]}"; then
    printf 'check-doc-staleness: stale %s claim: %s\n' "$label" "$needle" >&2
    exit 1
  fi
}

for stale in \
  'GitHub Actions is validation authority' \
  'GitHub Actions are validation authority' \
  'hosted CI is validation authority' \
  'hosted CI is gate evidence' \
  'hosted checks are required' \
  'CI with required checks is stronger'; do
  reject_fixed hosted-authority "$stale"
done
for stale in \
  '--waive-artifact' \
  'mpd first-adoption' \
  'run-pretrust.sh' \
  'PostimageEqualityV2' \
  'ValidationPolicyV2' \
  'BrokerRepositoryReceiveTransaction' \
  'NON-EXECUTABLE SUPERSESSION NOTICE' \
  '.mpd/bin/mpd' \
  'local-ref remote-ref local-oid remote-oid' \
  'local-ref remote-ref local-sha remote-sha' \
  '--skip-deploy' \
  'Deploy may be skipped' \
  'Deploy is optional'; do
  reject_fixed stale-interface "$stale"
done
for stale in \
  'doctor runs validation' \
  'doctor invokes validation' \
  'doctor recursively validates' \
  'mpd doctor --scope all'; do
  reject_fixed recursive-doctor "$stale"
done

if rg -n -e '(^|[^A-Za-z])(TODO|TBD|FIXME)([^A-Za-z]|$)|<placeholder>|<!--[[:space:]]*(TODO|TBD|FIXME)' "${files[@]}"; then
  printf 'check-doc-staleness: unresolved placeholder in current operator documentation\n' >&2
  exit 1
fi

if [[ -f "$root/.mpd/directives/protocol.md" && -f "$root/crates/mpd/assets/directives/protocol.md" ]]; then
  cmp -s "$root/.mpd/directives/protocol.md" "$root/crates/mpd/assets/directives/protocol.md" || {
    printf 'check-doc-staleness: project and bundled protocol doctrine differ\n' >&2
    exit 1
  }
fi

for required in \
  'Commando has no artifact-waiver flag' \
  'GitHub Actions' \
  'mpd policy activate' \
  'same-user process isolation'; do
  rg -Fq -- "$required" "$root/README.md" || {
    printf 'check-doc-staleness: README omits required current doctrine: %s\n' "$required" >&2
    exit 1
  }
done

printf 'check-doc-staleness: PASS (%s current Markdown files)\n' "${#files[@]}"
