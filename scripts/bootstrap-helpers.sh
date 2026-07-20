#!/usr/bin/env bash
# Pure bootstrap verification/publish helpers. This file is safe to source from
# isolated tests: it performs no work until a function is called and never
# changes Git configuration, refs, hooks, or external package-manager state.

bootstrap_sha256_file() {
  /usr/bin/shasum -a 256 -- "$1" | /usr/bin/awk '{print $1}'
}

bootstrap_verify_sha256() {
  local path="$1" expected="$2" actual
  [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || {
    printf 'bootstrap helper: invalid expected SHA-256 for %s\n' "$path" >&2
    return 1
  }
  [[ -f "$path" && ! -L "$path" ]] || {
    printf 'bootstrap helper: payload is not a non-symlink regular file: %s\n' "$path" >&2
    return 1
  }
  actual="$(bootstrap_sha256_file "$path")"
  [[ "$actual" == "$expected" ]] || {
    printf 'bootstrap helper: SHA-256 mismatch for %s\n' "$path" >&2
    return 1
  }
}

# The callback cannot begin until the payload hash has matched. Keeping this
# ordering in one helper makes the security boundary directly testable.
bootstrap_run_verified_installer() {
  local payload="$1" expected="$2" installer="$3"
  shift 3
  bootstrap_verify_sha256 "$payload" "$expected" || return
  "$installer" "$payload" "$@"
}

bootstrap_safe_relative_path() {
  local path="$1"
  [[ -n "$path" && "$path" != /* && "$path" != *//* && "$path" != '..' && "$path" != ../* && "$path" != */../* && "$path" != */.. ]]
}

bootstrap_verify_installed_tool() {
  local root="$1" binary_relative="$2" version="$3" source_sha="$4"
  local inventory binary root_real binary_real recorded_source recorded_binary actual output
  bootstrap_safe_relative_path "$binary_relative" || {
    printf 'bootstrap helper: unsafe installed binary path\n' >&2
    return 1
  }
  [[ -d "$root" && ! -L "$root" ]] || {
    printf 'bootstrap helper: installed root is unsafe: %s\n' "$root" >&2
    return 1
  }
  inventory="$root/installed.json"
  binary="$root/$binary_relative"
  [[ -f "$inventory" && ! -L "$inventory" && -x "$binary" && ! -L "$binary" ]] || {
    printf 'bootstrap helper: installed inventory or executable is unavailable\n' >&2
    return 1
  }
  root_real="$(cd "$root" && pwd -P)"
  binary_real="$(cd "$(dirname "$binary")" && pwd -P)/$(basename "$binary")"
  case "$binary_real" in
    "$root_real"/*) ;;
    *) printf 'bootstrap helper: installed executable escaped its canonical root\n' >&2; return 1 ;;
  esac
  recorded_source="$(jq -er '.source_package_sha256' "$inventory")" || return
  recorded_binary="$(jq -er '.executable_sha256' "$inventory")" || return
  [[ "$recorded_source" == "$source_sha" ]] || {
    printf 'bootstrap helper: installed source identity differs from the reviewed payload\n' >&2
    return 1
  }
  actual="$(bootstrap_sha256_file "$binary_real")"
  [[ "$actual" == "$recorded_binary" ]] || {
    printf 'bootstrap helper: installed executable digest differs from its inventory\n' >&2
    return 1
  }
  output="$("$binary_real" --version)" || return
  [[ "$output" == *"$version"* ]] || {
    printf 'bootstrap helper: installed executable version probe failed\n' >&2
    return 1
  }
}

# Publish an already-built stage exactly once. A response-loss retry verifies
# the existing winner and performs no second replacement.
bootstrap_publish_tool() {
  local stage="$1" target="$2" binary_relative="$3" version="$4" source_sha="$5"
  local binary executable_sha target_parent
  if [[ -e "$target" || -L "$target" ]]; then
    bootstrap_verify_installed_tool "$target" "$binary_relative" "$version" "$source_sha"
    return
  fi
  [[ -d "$stage" && ! -L "$stage" ]] || {
    printf 'bootstrap helper: install stage is unsafe\n' >&2
    return 1
  }
  bootstrap_safe_relative_path "$binary_relative" || return
  binary="$stage/$binary_relative"
  [[ -x "$binary" && -f "$binary" && ! -L "$binary" ]] || {
    printf 'bootstrap helper: staged executable is unavailable\n' >&2
    return 1
  }
  executable_sha="$(bootstrap_sha256_file "$binary")"
  jq -n --arg version "$version" --arg source "$source_sha" --arg executable "$executable_sha" \
    '{schema:1,version:$version,source_package_sha256:$source,executable_sha256:$executable}' \
    >"$stage/installed.json"
  chmod 600 "$stage/installed.json"
  target_parent="$(dirname "$target")"
  [[ -d "$target_parent" && ! -L "$target_parent" ]] || {
    printf 'bootstrap helper: install target parent is unsafe\n' >&2
    return 1
  }
  mv "$stage" "$target"
  bootstrap_verify_installed_tool "$target" "$binary_relative" "$version" "$source_sha"
}
