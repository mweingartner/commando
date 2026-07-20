# Closure and Recovery Runbook

This runbook preserves the separation between engineering completion, archive closure, commit coherence, push authorization, Git transfer, remote parity, and installation.

## Before archive

1. Run `mpd status --json` and require all gates current, all conditions closed, and all canonical Builder tasks complete or validly deferred.
2. Run the full exact Candidate profile and record its nonzero test counts, receipt ID, exact host, and containment state.
3. Run `mpd archive` as a preview. It must end with `No state changed.` and report no uncovered transient path or closure mismatch.
4. Run `mpd archive --yes` once. Do not stage or commit around a failed archive.

## Interrupted archive

Inspect the pending transaction and current status. `mpd archive --recover` is completion-only and revalidates owned state before completing. `mpd archive --abandon` is allowed only at its named safe stage and removes owned transaction metadata without fabricating completion. Both support `--json`. If identity or scope is ambiguous, stop and repair the earliest affected phase.

## Commit and exact-Commit validation

After archive, stage explicit files only and commit normally. Candidate receipts do not become Commit receipts. Run the activated exact Commit profile:

```sh
bash scripts/ci-local.sh --profile high-risk-test --commit HEAD
```

`mpd doctor --scope runtime-health --enforce` is a read-only recheck after the exact-HEAD receipt and typed Deploy/install record exist. It does not create either one.

## Push

Push with ordinary `git push`; never use `--no-verify` or force. The pre-push hook authorizes only the exact invocation and never transports. For a non-main branch deletion, create one exact one-use approval only after reviewing the remote/ref/old OID:

```sh
mpd hook approve-deletion <remote-name> <remote-location> \
  --remote-ref refs/heads/<branch> --old-oid <full-oid> --yes
```

Main and tag deletion are denied. A failed or changed batch needs a new authorization/approval.

## Remote parity and installation

After Git returns successfully, run `mpd publish --verify`. Treat authorization, observed transfer, and parity as separate facts. If parity is unavailable, behind, diverged, rewritten, or unstable, do not claim publication.

Final typed Deploy consumes the Build output, copies and reopens it, and records either readiness-only or installed-and-verified truth. It does not execute the installed candidate. Any later source, policy, Build output, commit, or installed-byte change invalidates the affected evidence and requires the appropriate rewind/rerun.

