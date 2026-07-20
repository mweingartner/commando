#!/usr/bin/env bash
# Static guard for local validation entry points plus their focused script tests.
set -euo pipefail
IFS=$'\n\t'

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly -a validation_files=(
  "$repo_root/scripts/ci-local.sh"
  "$repo_root/scripts/install-local.sh"
  "$repo_root/scripts/bootstrap-helpers.sh"
  "$repo_root/scripts/check-doc-staleness.sh"
  "$repo_root/scripts/test-bootstrap-local-ci.sh"
  "$repo_root/scripts/test-install-local.sh"
  "$repo_root/scripts/test-doc-staleness.sh"
  "$repo_root/.githooks/pre-commit"
  "$repo_root/.githooks/pre-push"
)

fail() {
  printf 'verify-network-denied: %s\n' "$*" >&2
  exit 1
}

for file in "${validation_files[@]}"; do
  [[ -f "$file" && ! -L "$file" ]] || fail "required regular entry point is missing: $file"
done

if rg -n --fixed-strings --glob '*.sh' -e 'curl ' -e 'wget ' -e 'sudo ' -e 'doas ' \
  "$repo_root/scripts/ci-local.sh" "$repo_root/scripts/install-local.sh"; then
  fail "validation/install wrappers contain a prohibited network or elevation command"
fi

bootstrap="$repo_root/scripts/bootstrap-local-ci.sh"
[[ -f "$bootstrap" && ! -L "$bootstrap" ]] || fail "explicit bootstrap is missing"
rg -Fq 'curl --fail' "$bootstrap" || fail "bootstrap omits reviewed HTTPS acquisition"
if rg -n '^[[:space:]]*(sudo|doas)([[:space:]]|$)|git[[:space:]]+config|update-ref|core\.hooksPath' "$bootstrap"; then
  fail "bootstrap contains elevation or Git trust-state mutation"
fi
network_users="$(rg -l '^[[:space:]]*curl[[:space:]]' "$repo_root/scripts" --glob '*.sh' --glob '!verify-network-denied.sh' | sort || true)"
[[ "$network_users" == "$bootstrap" ]] || fail "a script other than bootstrap contains a curl acquisition path"

rg -Fq -- 'trusted-hooks/mpd-coordinator' "$repo_root/scripts/ci-local.sh" || fail "local CI omits the activated coordinator"
rg -Fq -- 'validate --commit' "$repo_root/scripts/ci-local.sh" || fail "local CI omits exact-subject validation"
if rg -n --fixed-strings -e 'cargo test' -e 'cargo clippy' -e 'cargo audit' -e 'semgrep ' -e 'gitleaks ' "$repo_root/scripts/ci-local.sh"; then
  fail "thin local-CI wrapper duplicates validation lanes"
fi

rg -Fq 'bytes != FIXED_PROFILE.as_bytes()' "$repo_root/crates/mpd/src/sandbox_macos.rs" || \
  fail "compiled adapter omits exact reviewed-profile byte comparison"

bash "$repo_root/scripts/test-bootstrap-local-ci.sh"
bash "$repo_root/scripts/test-install-local.sh"
bash "$repo_root/scripts/test-doc-staleness.sh"

printf 'verify-network-denied: PASS (offline validation wrappers, sole explicit bootstrap, fixed profile parity)\n'
