# Security (code) review

## Actor
Security (claude-code harness, deep tier). Focused code-stage audit.

## Findings
No critical/high/medium. The new check is a pure, read-only, refuse-only predicate.

## Conditions verified
- **Refuse-only, no bypass (Cond 1):** the hook (cli.rs:3311-3327) runs only in the
  strict Build arm, before `execute_strict_candidate_build`; non-empty → early
  `gate_blocked` (never a PASS); absent from load_ready_manifest/capture/reopen
  (grep). No mutation of manifest/candidate/overlay/digest.
- **No false-refusal (Cond 2):** `manifest_declares` (closure.rs:1694-1700) is
  logic-identical to `declared()`/`validate_documentation_postimage` (same
  `glob_match` over paths ∪ shared_paths); supersets (`**`) pass; the nested-spec
  probe faithfully reports a single-star change-dir pattern as incomplete
  (pathmatch: `*` doesn't cross `/`); self-healing property test confirms adding
  the reported entries always clears the check.
- **No auto-seed / no ledger (Cond 3):** `ChangeManifest::seed()` still empty; the
  NoDeclaredScope seed contract test intact; predicate never probes
  `.mpd/state/<change>.json`; `cmd_manifest` change is print-only guidance using
  `docs_dir()`.
- **Error integrity (Cond 4):** "retained manifest" / "durable-doc path" substrings
  preserved; NotFound hint gated on the NotFound variant only.
- **Scope (Cond 10):** git diff = closure.rs, cli.rs, e2e.rs only; no secret-shaped
  literals; test assertions real (exact vectors + non-vacuous e2e).

## Independent review
Deep-tier re-grep of the real code confirmed exactly one production call site
(cli.rs:3321), the reused `glob_match` matcher (closure.rs:38), the intact seed
contract test (closure.rs:4583-4597), and the pathmatch `*`-doesn't-cross-`/`
semantics behind the nested-spec probe. Dogfood: #19's OWN ledger-less manifest
(change-dir `/**` + docs, no `.mpd/state`) passed the new check at its own Build
gate — validating the design end to end.

## Refutation
Strongest attacks: (1) can the check produce or contribute to a PASS? Refuted —
it is an early-return refusal in front of the build path; the empty-gap case falls
through to the identical pre-existing path. (2) can it false-refuse a legitimate
superset, pushing an author toward a bypass? Refuted — superset matching + the
self-healing property test guarantee the gate never demands an entry it won't then
recognize. (3) does it weaken the empty-seed forcing function or require the
ledger? Refuted — seed untouched, ledger never probed.

## Verdict
PASS — code may proceed to Test. Advisory (non-blocking): the reviewer had no
shell, so the 3-file diff was corroborated not mechanically run; the orchestrator
confirmed `git diff --name-only` = closure.rs/cli.rs/e2e.rs, and mpd's strict
candidate refuses out-of-scope edits.
