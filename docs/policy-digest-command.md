# `mpd policy digest`

## Purpose
`mpd policy activate --confirm-policy-digest <hex>` requires a value that could not be
obtained through any supported command. The digest is SHA-256 over the exact serialized
`local_validation` policy read from the immutable subject commit, so it depends on
serde's own serialization of the parsed struct and cannot be reproduced by hashing the
file or with `jq`. Recovering it meant compiling a throwaway probe test against private
internals and reverting it afterwards. `mpd policy digest` prints that value directly.

## Value
Activation after any `.mpd/config.json` change becomes a documented two-step recipe
instead of an internals-patching ritual. The confirmation flag keeps its meaning — the
operator still states which reviewed policy they are binding — but can now obtain that
statement honestly and auditably.

## Scope
**Covers:** printing the canonical policy digest for the subject `policy activate` would
bind — the current preflight subject by default, or a named commit with `--commit`.

**Does NOT cover:** it does not activate anything, write to the ledger, produce a receipt,
or change trust state; it is strictly read-only. It does not alter `activate`'s mismatch
behavior, which still refuses without revealing the expected digest — so the flag remains
a statement of intent rather than a retry loop. The `#[cfg(test)]` `policy status` and
`policy bootstrap` arms stay test-only.

**Disclosure:** the digest is a hash of a repository-tracked file. It reveals nothing a
reader of the repository could not already compute by building the crate.

## Functional details
- `mpd policy digest` — resolves the current preflight subject and prints its commit and
  canonical policy digest.
- `mpd policy digest --commit <ref>` — reads `.mpd/config.json` from that immutable commit
  instead, which is the value `activate --commit <ref>` will require.
- `--json` — emits exactly one document: `schema`, `commit`, `tree`, `policy_digest`.
- The digest is derived through the same `subject_local_validation` +
  `canonical_policy_bytes` path activation uses, and the policy is validated before
  digesting, so a malformed policy reports the parse/validation error rather than a digest
  of something unusable.
- A repository with no structured `local_validation` errors rather than printing a digest
  derived from defaults — there is no policy to confirm.

## Usage
After changing `.mpd/config.json` and committing it, reactivate in two steps:

```sh
# 1. Read the digest for the commit you reviewed.
mpd policy digest --commit "$(git rev-parse HEAD)"

# 2. Bind it, together with the rebuilt coordinator.
mpd policy activate \
  --commit "$(git rev-parse HEAD)" \
  --confirm-policy-digest <digest from step 1> \
  --coordinator "$(pwd)/target/release/mpd" \
  --confirm-executable-digest "$(shasum -a 256 target/release/mpd | awk '{print $1}')" \
  --hooks .githooks --yes
```

Scripted:

```sh
mpd policy digest --json | jq -r .policy_digest
```
