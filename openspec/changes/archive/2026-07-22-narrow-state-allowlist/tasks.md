## 1. Narrow the allowlist (.mpd/secret-allowlist.json)
- [ ] 1.1 Move `.mpd/state/**` from `paths` to `allow` as `{path:".mpd/state/**", rule:"generic-secret-assignment"}`; keep `openspec/changes/archive/**` in `paths`.
- [ ] 1.2 Confirm valid JSON that `Allowlist::load` round-trips.

## 2. Verify (config-only; manual, the rule-scoped mechanism is already unit-tested)
- [ ] 2.1 Built-in scanner over `.mpd/state/**` still yields 0 findings under the narrowed allowlist.
- [ ] 2.2 A planted branded-token shape (assembled `ghp_`+36) in a temp `.mpd/state/*.json` is NOT suppressed (curated `github-token` survives the filter).

## 3. Verification & landing
- [ ] 3.1 Full suite green (unchanged binary); commit-gate secret scan passes under the narrowed allowlist.
- [ ] 3.2 No coordinator rebuild (config-only; allowlist not in the policy digest).
