#!/usr/bin/env bash
# Explicit, network-enabled bootstrap. Validation and hooks never invoke this file.
# Cargo inputs and cargo-audit are clone-private. Semgrep uses the explicitly
# reviewed external Homebrew package-manager root and mutates that local root.
# The script never uses sudo or mutates PATH, hooks, Git refs, or repository settings.
set -euo pipefail
IFS=$'\n\t'
umask 077

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$repo_root"
# shellcheck source=bootstrap-helpers.sh
source "$repo_root/scripts/bootstrap-helpers.sh"

fail() {
  printf 'bootstrap-local-ci: %s\n' "$*" >&2
  exit 1
}

for command_name in git jq curl shasum brew; do
  command -v "$command_name" >/dev/null 2>&1 || fail "required bootstrap command is unavailable: $command_name"
done

git_common="$(git rev-parse --path-format=absolute --git-common-dir)"
[[ -d "$git_common" && ! -L "$git_common" ]] || fail "unsafe Git common directory"
private_root="$git_common/mpd"
mkdir -p "$private_root/tools"
chmod 700 "$private_root" "$private_root/tools"

locked_cargo="/opt/homebrew/bin/cargo"
locked_rustc="/opt/homebrew/bin/rustc"
locked_rustfmt="/opt/homebrew/bin/rustfmt"
locked_clippy="/opt/homebrew/bin/cargo-clippy"
[[ -x "$locked_cargo" && -x "$locked_rustc" && -x "$locked_rustfmt" && -x "$locked_clippy" ]] || fail "reviewed Homebrew Rust 1.91.0 tools/components are unavailable"
verify_system_tool() {
  local name="$1" path="$2" expected actual canonical package_root
  expected="$(jq -er --arg name "$name" '.tools[] | select(.name == "rust-toolchain") | .executables[$name]' security/tool-lock.json)"
  package_root="$(jq -er '.tools[] | select(.name == "rust-toolchain") | .package_root' security/tool-lock.json)"
  canonical="$(cd "$(dirname "$path")" && pwd -P)/$(basename "$path")"
  canonical="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$canonical")"
  [[ "$canonical" == "$package_root"/* ]] || fail "$name escaped its reviewed package root"
  actual="$(shasum -a 256 "$canonical" | awk '{print $1}')"
  [[ "$actual" == "$expected" ]] || fail "$name executable digest differs from security/tool-lock.json"
}
command -v python3 >/dev/null 2>&1 || fail "python3 is required to canonicalize reviewed bootstrap paths"
verify_system_tool cargo "$locked_cargo"
verify_system_tool rustc "$locked_rustc"
verify_system_tool rustfmt "$locked_rustfmt"
verify_system_tool cargo-clippy "$locked_clippy"
host="$($locked_rustc -vV | sed -n 's/^host: //p')"
[[ "$host" == "aarch64-apple-darwin" ]] || fail "this reviewed bootstrap lock supports only aarch64-apple-darwin; observed $host"

verify_gitleaks() {
  local expected_root expected_digest expected_version binary canonical observed
  expected_root="$(jq -er '.tools[] | select(.name == "gitleaks") | .package_root' security/tool-lock.json)"
  expected_digest="$(jq -er '.tools[] | select(.name == "gitleaks") | .executable_sha256' security/tool-lock.json)"
  expected_version="$(jq -er '.tools[] | select(.name == "gitleaks") | .version' security/tool-lock.json)"
  binary="/opt/homebrew/bin/gitleaks"
  [[ -x "$binary" ]] || fail "reviewed Homebrew gitleaks is unavailable"
  canonical="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$binary")"
  [[ "$canonical" == "$expected_root"/* ]] || fail "gitleaks escaped its reviewed package root"
  observed="$(shasum -a 256 "$canonical" | awk '{print $1}')"
  [[ "$observed" == "$expected_digest" ]] || fail "gitleaks executable digest differs from security/tool-lock.json"
  "$canonical" version | grep -Fq "$expected_version" || fail "gitleaks version probe failed"
}
verify_gitleaks

tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/mpd-local-ci.XXXXXX")"
cleanup() {
  [[ "$tmp_root" == "${TMPDIR:-/tmp}"/mpd-local-ci.* ]] && rm -rf -- "$tmp_root"
}
trap cleanup EXIT HUP INT TERM

sha256_file() {
  bootstrap_sha256_file "$1"
}

verify_sha256() {
  bootstrap_verify_sha256 "$1" "$2" || fail "reviewed payload hash verification failed: $1"
}

install_verified_cargo_audit_archive() {
  local archive="$1" version="$2" package_sha="$3"
  local source_dir stage target binary
  mkdir "$tmp_root/cargo-audit-source"
  tar -xzf "$archive" -C "$tmp_root/cargo-audit-source"
  source_dir="$tmp_root/cargo-audit-source/cargo-audit-$version"
  [[ -f "$source_dir/Cargo.lock" ]] || fail "verified cargo-audit archive has no Cargo.lock"
  stage="$tmp_root/cargo-audit-install"
  CARGO_HOME="$private_root/cargo-home" "$locked_cargo" install --path "$source_dir" --locked --root "$stage"
  binary="$stage/bin/cargo-audit"
  [[ -x "$binary" ]] || fail "cargo-audit install produced no executable"
  "$binary" --version | grep -Fq "cargo-audit $version" || fail "cargo-audit version probe failed"
  target="$private_root/tools/cargo-audit"
  bootstrap_publish_tool "$stage" "$target" "bin/cargo-audit" "$version" "$package_sha" \
    || fail "cargo-audit publish or post-install verification failed"
}

install_cargo_audit() {
  local version package_sha archive
  version="$(jq -er '.tools[] | select(.name == "cargo-audit") | .version' security/tool-lock.json)"
  package_sha="$(jq -er '.tools[] | select(.name == "cargo-audit") | .package_sha256' security/tool-lock.json)"
  archive="$tmp_root/cargo-audit-$version.crate"
  curl --fail --location --proto '=https' --tlsv1.2 \
    "https://static.crates.io/crates/cargo-audit/cargo-audit-$version.crate" \
    --output "$archive"
  bootstrap_run_verified_installer "$archive" "$package_sha" \
    install_verified_cargo_audit_archive "$version" "$package_sha" \
    || fail "cargo-audit archive verification or installation failed"
}

install_semgrep() {
  local version package_sha package_root inventory binary formula_json installed_version observed_bottle receipt_sha
  version="$(jq -er '.tools[] | select(.name == "semgrep") | .version' security/tool-lock.json)"
  package_sha="$(jq -er '.tools[] | select(.name == "semgrep") | .bottle_sha256' security/tool-lock.json)"
  package_root="$(jq -er '.tools[] | select(.name == "semgrep") | .package_root' security/tool-lock.json)"
  inventory="$git_common/$(jq -er '.tools[] | select(.name == "semgrep") | .inventory' security/tool-lock.json)"
  formula_json="$(brew info --json=v2 semgrep)"
  [[ "$(jq -r '.formulae[0].versions.stable' <<<"$formula_json")" == "$version" ]] || fail "Homebrew Semgrep formula version differs from the reviewed lock"
  observed_bottle="$(jq -er --arg digest "$package_sha" '[.formulae[0].bottle.stable.files[].sha256 | select(. == $digest)][0]' <<<"$formula_json")"
  [[ "$observed_bottle" == "$package_sha" ]] || fail "Homebrew Semgrep bottle digest differs from the reviewed lock"
  if ! brew list --versions semgrep 2>/dev/null | grep -Eq "^semgrep ${version}([[:space:]]|$)"; then
    HOMEBREW_NO_AUTO_UPDATE=1 brew install --force-bottle semgrep
  fi
  installed_version="$(brew list --versions semgrep | awk '{print $2}')"
  [[ "$installed_version" == "$version" ]] || fail "installed Homebrew Semgrep version differs from the reviewed lock"
  binary="$(brew --prefix semgrep)/bin/semgrep"
  binary="$(cd "$(dirname "$binary")" && pwd -P)/$(basename "$binary")"
  [[ -x "$binary" && "$binary" == "$package_root"/* ]] || fail "Semgrep executable escaped the reviewed Homebrew package root"
  "$binary" --version | grep -Fq "$version" || fail "Semgrep version probe failed"
  [[ -f "$package_root/INSTALL_RECEIPT.json" ]] || fail "Homebrew Semgrep install receipt is missing"
  receipt_sha="$(sha256_file "$package_root/INSTALL_RECEIPT.json")"
  mkdir -p "$(dirname "$inventory")"
  jq -n --arg version "$version" --arg source "$package_sha" \
    --arg executable "$(sha256_file "$binary")" --arg receipt "$receipt_sha" \
    '{schema:1,name:"semgrep",version:$version,source_package_sha256:$source,executable_sha256:$executable,install_receipt_sha256:$receipt,package_manager_root:"/opt/homebrew"}' \
    > "$inventory.tmp.$$"
  chmod 600 "$inventory.tmp.$$"
  mv "$inventory.tmp.$$" "$inventory"
}

install_advisory_db() {
  local repository commit expected_tree expected_listing target stage observed_tree observed_listing
  repository="$(jq -er '.repository' security/advisory-db.lock.json)"
  commit="$(jq -er '.commit' security/advisory-db.lock.json)"
  expected_tree="$(jq -er '.git_tree_oid' security/advisory-db.lock.json)"
  expected_listing="$(jq -er '.tree_listing_sha256' security/advisory-db.lock.json)"
  target="$private_root/advisory-db"
  if [[ ! -e "$target" ]]; then
    stage="$tmp_root/advisory-db"
    git -c protocol.file.allow=never clone --quiet --no-checkout "$repository" "$stage"
    git -C "$stage" checkout --quiet --detach "$commit"
    mv "$stage" "$target"
  fi
  [[ -d "$target/.git" && ! -L "$target" ]] || fail "unsafe advisory database root"
  [[ "$(git -C "$target" rev-parse HEAD^{commit})" == "$commit" ]] || fail "advisory database commit mismatch"
  observed_tree="$(git -C "$target" rev-parse HEAD^{tree})"
  [[ "$observed_tree" == "$expected_tree" ]] || fail "advisory database tree OID mismatch"
  observed_listing="$(git -C "$target" ls-tree -r -z --full-tree "$commit" | shasum -a 256 | awk '{print $1}')"
  [[ "$observed_listing" == "$expected_listing" ]] || fail "advisory database listing digest mismatch"
  commit_epoch="$(git -C "$target" show -s --format=%ct "$commit")"
  max_age_days="$(jq -er '.max_age_days' security/advisory-db.lock.json)"
  now_epoch="$(date +%s)"
  (( commit_epoch <= now_epoch + 300 )) || fail "advisory database commit time is in the future"
  (( now_epoch - commit_epoch <= max_age_days * 86400 )) || fail "advisory database snapshot exceeds max_age_days"
}

# Prime the complete project dependency graph for later --offline/--locked runs.
# No --target filter: the validation preflight runs `cargo metadata --offline`,
# which resolves the full cross-platform lockfile graph, so every locked crate
# must be present in the clone-private cache — not just the host platform's.
CARGO_HOME="$private_root/cargo-home" "$locked_cargo" fetch --locked
install_cargo_audit
install_semgrep
install_advisory_db

printf 'bootstrap-local-ci: PASS (clone-private Cargo/cargo-audit/advisory inputs under %s; Semgrep bound to reviewed Homebrew root)\n' "$private_root"
printf 'bootstrap-local-ci: no hooks, trusted refs, policy state, or global PATH were changed\n'
