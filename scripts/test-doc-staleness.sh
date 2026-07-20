#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
checker="$repo_root/scripts/check-doc-staleness.sh"
fixture="$(mktemp -d "${TMPDIR:-/tmp}/mpd-doc-staleness-test.XXXXXX")"
cleanup() {
  case "$fixture" in "${TMPDIR:-/tmp}"/mpd-doc-staleness-test.??????) rm -rf -- "$fixture" ;; *) exit 70 ;; esac
}
trap cleanup EXIT HUP INT TERM

assert_rejected() {
  local text="$1"
  printf '%s\n' "$text" >"$fixture/README.md"
  if bash "$checker" --root "$fixture" >/dev/null 2>&1; then
    printf 'doc-staleness test: stale text was accepted: %s\n' "$text" >&2
    exit 1
  fi
}

for stale in \
  'GitHub Actions is validation authority' \
  'doctor runs validation' \
  '--waive-artifact bypasses review' \
  'Deploy may be skipped' \
  'install to .mpd/bin/mpd' \
  'mpd first-adoption reconcile' \
  'PostimageEqualityV2 is current' \
  'pre-push order: local-ref remote-ref local-oid remote-oid' \
  'TODO: finish this operator contract'; do
  assert_rejected "$stale"
done

printf '%s\n' \
  '# Current doctrine' \
  'Commando has no artifact-waiver flag.' \
  'GitHub Actions and hosted checks are not validation authority.' \
  'Use mpd policy activate for reviewed local authority.' \
  'Doctor is read-only and never validates, installs, or deploys.' \
  'Pre-push order is local-ref local-oid remote-ref remote-oid.' \
  'The adapter does not claim same-user process isolation.' \
  >"$fixture/README.md"
bash "$checker" --root "$fixture" >/dev/null

bash "$checker" >/dev/null
printf 'doc-staleness test: PASS\n'
