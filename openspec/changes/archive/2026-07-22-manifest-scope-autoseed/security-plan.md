# Security (plan) review

## Actor
Security (claude-code harness). Lean self-review: low threat surface — the change
adds a read-only completeness check at the Build gate that can only ADD refusals.

## Threat model
Trust boundary: the cooperative change author (no untrusted-input/credential/egress
surface). The only security-relevant questions are (1) can the new check be a
BYPASS that weakens the candidate/gate, and (2) does it weaken any existing
forcing function.
- (1) No: the check is a pure read-only predicate over the already-loaded manifest
  + config, hooked in the strict Build-gate arm (cli.rs ~:3311) BEFORE the
  candidate build; on gaps it returns `gate_blocked` (a refusal). It cannot make a
  gate PASS that would otherwise fail — it can only refuse. It does not touch the
  candidate materialization, the overlay plan, or any digest.
- (2) No, by construction (design D3): it does NOT auto-seed and does NOT touch
  `ChangeManifest::seed()`, so `is_ready()`/`NoDeclaredScope`/the `mpd next`
  INCOMPLETE nudge/the seed contract test are all preserved. It correctly does NOT
  require the ledger (folded via SystemScope regardless; requiring it would
  needlessly trip the `.mpd/` sensitive-path risk signal).
- The glob probe mirrors the enforcement sites' `declared()` semantics (paths ∪
  shared_paths), so a legitimate superset (`**`) passes — no false refusal that
  would push authors toward `--no-verify`-style bypasses.

## Conditions for Builder
Inherits design.md Conditions for Builder 1-6. Security-relevant emphasis: the
check must live ONLY in the Build-gate arm (never in capture/reopen — else it
would break pre-fix in-flight candidates), and must never auto-seed or require the
ledger.

## Verdict
PASS — no threat-model gap. The change strictly surfaces an existing
late-validation earlier; it weakens no gate and opens no bypass. Security (code)
will verify the hook location and glob semantics against the real implementation.
