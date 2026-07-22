# Doc validation

## Actor

Architect (claude-code harness, deep tier). Designer lens N/A — pure backend
scanner-rule change, no UI/UX surface.

## Architect lens

Validated every factual claim in `documentation.md` against the shipped code.
Accurate: the rule mechanics (`MIN_TOKEN_RUN = 16` at secrets.rs:88;
`is_token_char` = ASCII alphanumeric + `+`; `has_contiguous_token_run` single
O(len) pass, letter+digit within one run; the gate slot-in at `generic_secret_assignment`);
the strict-tightening claim (backed by `new_gate_implies_old_gate` over
`any::<String>()`); the unchanged keyword/length(≥20)/placeholder conditions and
curated rules; the accepted-miss classes (UUID + grouped-keys pinned by
`generic_rule_ignores_hyphenated_dictionary_values` and
`generic_rule_ignores_grouped_keys` with the matching `AAAA-1111-BBBB-2222-CCCC-3333`
fixture; Azure/GitLab/slash-base64 probabilistic); the Usage examples (all trace
to real test fixtures); `.mpd/secret-allowlist.json` unchanged with the follow-up
(task_a098de26) real.

**One accuracy defect found (initial verdict FAIL):** documentation.md said "The
**nine** curated detections (private-key armor, AWS, Slack, GitHub, Google,
Stripe, OpenAI, JWT) …" — but `scan_line` (secrets.rs:141-182) has exactly
**eight** curated matchers before the generic backstop; the parenthetical lists
eight names, self-contradicting "nine." The ninth rule is
`generic-secret-assignment` itself, the backstop this change modifies —
definitionally not one of the untouched curated set. (The miscount originated in
design.md and propagated to the security artifacts, which are historical pipeline
records; only `documentation.md` folds into `docs/` and must be correct.)

## Designer lens

N/A — no UI/UX surface in this change.

## Verdict

**PASS (after correction).** Initial validation returned FAIL on the "nine" →
"eight" miscount; corrected in `documentation.md` (the curated count is now eight,
with a note that `generic-secret-assignment` is the ninth, backstop rule).
Re-validation confirmed the corrected doc is accurate with no remaining overclaim
or phantom pins. (Gate history: the FAIL precedes this PASS.)
