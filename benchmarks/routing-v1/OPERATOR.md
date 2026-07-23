# Routing v1 operator procedure

1. Run every task in `tasks.json` through actual configured harness sessions for each listed seed. Do not synthesize Luna samples; current Codex comparisons cover the configured Sol and Terra routes.
2. Keep task/model identities blinded from scorers until each score is recorded. Preserve only the bounded metrics described in `rubric.md`.
3. Emit a `routing-evidence-v1` envelope, hash this manifest and rubric into its digest fields, and evaluate it offline.
4. Treat fixtures and unit tests as evaluator tests, never adoption evidence. Missing, stale, unblinded, undersampled, mixed-currency, or unavailable evidence is `MISSING`/`INSUFFICIENT` and leaves mappings unchanged.
5. Review the read-only preview. A later integration layer may apply it only after explicit confirmation and concurrent config/evidence digest revalidation; it may update existing reviewed routing targets only.

The latest actual-session coverage result is recorded in `run-status.json`. It is a
coverage/readiness record, not a `routing-evidence-v1` adoption envelope and cannot be
passed to `mpd routing apply`.
