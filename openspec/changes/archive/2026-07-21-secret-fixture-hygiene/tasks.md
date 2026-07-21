
## 1. Guard first (red)

- [x] 1.1 Add `first_party_source_is_scanner_clean` to the `checks::secrets`
      test module: walk `<repo>/crates` (skip `target/` components, symlinks,
      non-regular files; sorted order), scan via the production `scan_paths`,
      filter through the empty `SOURCE_HYGIENE_ALLOW` const, assert zero
      findings with `path:line rule` + remediation output.
- [x] 1.2 Run it and record the red baseline: exactly the 13 findings
      enumerated in `design.md` (4× class A, 2× class B, 7× class C), nothing
      else. — Evidence: first run reported exactly `secrets.rs:107
      private-key-block`, `secrets.rs:113 slack-token`, `secrets.rs:357/374/378
      generic-secret-assignment`, `local_validation.rs:6519/6520
      generic-secret-assignment`, `local_validation.rs:11813/11814/11820/11821
      aws-access-key-id`/`slack-token`, `local_validation.rs:13104/13130
      generic-secret-assignment` — 13 total, nothing else.

## 2. Split-literal conversion (green)

- [x] 2.1 `crates/mpd/src/local_validation.rs:11813-11821` — assemble the
      redaction fixture from split parts per design D3; reuse the bindings in
      the assertions; runtime bytes and every assertion unchanged.
- [x] 2.2 `crates/mpd/src/local_validation.rs:6519-6520` — hoist the two
      push-authorization digest tags to `concat!`-built consts; add the
      pinned-digest-hex assertion proving both values unchanged. — Evidence:
      `push_authorization_digest_tags_are_pinned_to_their_pre_refactor_bytes`
      pins to hex values computed via `shasum -a 256` from the pre-change
      literal bytes before any refactor (Condition 15); test passes.
- [x] 2.3 `crates/mpd/src/local_validation.rs:13104,13130` — build the
      tag/commit message fixtures via `format!` split; the
      `outgoing-secret-scan-failed` assertions still hold. — Evidence:
      `outgoing_scan_catches_secrets_fresh_despite_preexisting_receipt` passes.
- [x] 2.4 `crates/mpd/src/checks/secrets.rs:107,113` — `concat!`-split the
      private-key-block and Slack-prefix rule literals; compiled strings
      identical; no rule logic change. — Evidence: `detects_private_key_block`,
      `detects_aws_key`, and new `detects_slack_tokens_for_every_prefix`
      (Condition 11) all pass.
- [x] 2.5 `crates/mpd/src/checks/secrets.rs:357,374,378` — split the three
      generic-rule test fixtures; assertion outcomes unchanged. — Evidence:
      `ignores_ordinary_code` and `detects_unquoted_env_assignment` pass
      unmodified in outcome.
- [x] 2.6 Extend the doctrine comment at the top of the `checks::secrets` test
      module: name the invariant, the meta-test, and the split recipes.
- [x] 2.7 Meta-test green with `SOURCE_HYGIENE_ALLOW` empty. — Evidence:
      `cargo test -p mpd first_party_source_is_scanner_clean` → `test result:
      ok. 1 passed`.

## 3. Narrow the suppressions (only after 2.7)

- [x] 3.1 `.mpd/secret-allowlist.json` — remove the whole-file `paths` entries
      for `crates/mpd/src/checks/secrets.rs`,
      `crates/mpd/src/local_validation.rs`, and `.claude/pipeline-gates.json`;
      keep only `openspec/changes/archive/**`.
- [x] 3.2 `.claude/pipeline-gates.json` — remove the now-dead `secretAllow`
      array.
- [x] 3.3 Verify the commit gate passes on the final tree with the narrowed
      allowlist (built-in scan and gitleaks both clean, suppressed-count
      reporting reflects the narrowing). — Evidence: `mpd check` reports
      exactly 2 findings suppressed by the allowlist, both confirmed (via
      temporary instrumentation, reverted) to be inside
      `openspec/changes/archive/**` — the retained, deliberate blind spot;
      zero unsuppressed findings. `gitleaks detect` with the same
      extend-default+target-exclusion config `run_gitleaks` uses reports
      "no leaks found" over the whole tree.

## 4. Verification

- [x] 4.1 `cargo test --workspace` green with a real, non-zero test count;
      meta-test included. — Evidence: mpd unit 473 (472 passed + 1
      pre-existing unrelated ignored), mpd e2e 106, openspec-core unit 58 +
      integration suites 5+15+2+16+20+9+5 — all `0 failed`.
- [x] 4.2 Repo-wide provider-shaped token sweep (outside
      `openspec/changes/archive/**`) comes back empty. — Evidence: `git grep`
      for the AWS/Slack/digest-tag/token fixture shapes across the tracked
      tree (excluding archive) returns nothing; the two remaining plain-prose
      mentions of the digest tag names in a pre-existing, unrelated doc
      (`docs/closure-defects-and-measurement.md`, committed in an earlier
      change) don't trigger the rule (no `=`/`:`/quote separator on those
      lines) and are outside this change's scope.
- [x] 4.3 Digest-stability assertion (2.2) demonstrates push-authorization
      identity is unchanged. — Evidence: see 2.2.
