# commando — `mpd`

**Model-Paired Development as a self-contained motion, over the OpenSpec format.**

`mpd` is a single Rust binary that a **coding agent (or you) drives to run a
model-paired development pipeline** — Architecture → Security → Build → Security →
Test → Documentation → Deploy → Doc Validation — as durable, machine-checkable
state that outlives any single session, enforced deterministically at `git commit`.
It speaks the [OpenSpec](https://github.com/Fission-AI/OpenSpec) on-disk format
natively, with **no runtime dependencies**: no Node, no OpenSpec CLI. The
macOS/Linux binary links only against the system C library.

```
$ otool -L target/release/mpd
    /usr/lib/libSystem.B.dylib
```

## What you get

A pipeline your **harness coordinates** and that **survives session death**. mpd
turns each adversarial phase into durable gate state on disk, so:

- **The harness leads; mpd keeps it honest.** Your agent drives the loop — mpd
  tells it exactly what to do next (persona, model, task, gate command) and
  refuses to advance on a gate it can *verify*: a real test run, a clean secret
  scan, a retained review artifact. The agent coordinates the work; mpd is the
  adversarial spine it can't talk its way past.
- **The adversarial record can't evaporate.** Under the self-enforcing tier, a
  Security or Test PASS requires its judgment artifact on disk — so a later
  session, another agent, or a human can read *why* each gate passed, not just
  that it did.
- **Each persona is its own model, tunable per project.** Architect ≠ Security ≠
  Tester; deep-cognition vs standard tier; retargeted by editing config, and
  tunable in behavior (rigor, test depth, project instructions) without ever being
  able to *silently* weaken a review.
- **Content-addressed evidence + verified publication.** Every PASS carries a
  SHA-256 receipt over exactly what it reviewed; `mpd publish --verify` proves
  exact remote parity. One static binary — format-compatible with OpenSpec, zero
  runtime coupling.

## Drive it from your harness

This is the intended way to use `mpd`: your agent is the coordinator, and `mpd` is
the pipeline it drives. To make the motion automatic, paste the block below into
the file your agent reads — `AGENTS.md` (Codex, and the emerging standard) or
`CLAUDE.md` (Claude Code). It tells any harness the full loop, including the
self-enforcing gates and the persona-tuning interview:

> **Drive all non-trivial changes through `mpd` (a local binary; run `mpd --help`).**
>
> **Start:** `mpd conduct <name> [--ui] [--fix|--chore] [--risk low|medium|high]
> [--threat-profile <p>]` — this begins the change under the strict, self-enforcing
> tier. (`--ui` adds the Design phases; `--fix`/`--chore` skip Documentation.) Then
> edit `openspec/changes/<name>/manifest.json` to declare the change's path scope.
>
> **Loop, every phase:** run `mpd next --harness <your-harness> --context`. It names
> the persona, the model to run it on, the task, the required judgment-artifact path,
> and the exact gate command. Do EXACTLY what the brief says as that persona (Claude
> Code: spawn a subagent on the named model; Codex: adopt the persona, or a fresh
> `codex --model <tier>`). Author the artifact it names under
> `openspec/changes/<name>/` (use `mpd brief <phase>` to scaffold a template). Then
> record the verdict: `mpd gate <phase> --pass --evidence <artifact>` (or
> `--conditional --condition "…"`, or `--fail --class <c>` — a Security FAIL also
> needs `--exploit "attacker|capability|boundary|harm|fix"`). Repeat until
> `mpd status` shows ready-to-archive.
>
> **Rules:** Never bypass a FAIL gate, never commit around the pre-commit hook,
> never edit a gate ledger by hand. A material change re-enters at the earliest
> affected phase. **Novel/risky surface** (auth, credentials, network egress, file
> I/O on untrusted input, crypto, a feature with no analog shipped): raise
> `--risk high`, run the Security phases at full depth, and do NOT fix Security
> findings inline — re-run the Security gate after each fix. Apply the brief's
> persona-tuning fields (`effort`, `reviewers`, `directive_append`) as emitted;
> never re-read `.mpd/config.json` yourself.
>
> **Finish:** `mpd resolve --all` (close CONDITIONAL conditions) → `mpd archive
> --yes` → commit + push with normal Git → `mpd publish --verify` (confirms exact
> remote parity).
>
> **Persona-tuning interview** — when the user asks to tune how the personas behave:
> for each persona (`Architect, Designer, Security, Builder, Tester, Documenter,
> DocValidation`) read `mpd persona show <persona> --json` — it returns each field's
> current value, allowed range, baseline, and a `dangerous` flag. Ask the user,
> showing the current value and the range, and a clear ⚠ warning whenever they pick
> the un-rankable `directive-append`. Record each answer with `mpd persona set
> <persona> <field> <value>` (it validates the name + term and warns on the
> dangerous knob) or `mpd persona reset <persona> [field]`. Then move on.

The motion is always the same three beats — `mpd next` → do the work → `mpd gate
<phase>` — so a human, Claude Code, or Codex all drive it identically. `mpd next`
supplies each phase's persona, model, task, artifact, and gate command; the git
pre-commit hook enforces the secret gate regardless of which harness — or human —
drives the commit, so the guarantee holds even for a harness that ignores mpd
entirely.

## The self-enforcing tier (why the harness can't cheat)

`mpd` runs at one of two tiers on the same phase machine. A harness should use the
**self-enforcing (strict)** tier — it is what makes "the harness coordinates" safe:

- **Self-enforcing / strict** (`mpd conduct`, or `mpd begin --strict`, or `mpd
  strict <name>` to promote later). The judgment gates (Security plan/code, Design
  review/sign-off, Test, Doc Validation) will not PASS unless their **judgment
  artifact** exists on disk and covers its required sections — the adversarial
  record can't evaporate after the gate. `mpd next --context` tells the harness the
  exact artifact path and gate command; `mpd brief <phase>` scaffolds a template to
  fill. The one escape is `mpd gate <phase> --pass --waive-artifact "reason"` — an
  audited, attempt-scoped waiver that never converts a FAIL, never skips an
  objective check (tests/secret scan), and is surfaced loudly in `status` and the
  archive summary. `mpd archive` re-checks every retained judgment artifact, so a
  strict change is archived **with** its adversarial record or not at all.
- **Manual** (`mpd begin`) — the raw verbs, lenient; a judgment `gate --pass` takes
  your word. For full control in a terminal against a local model (see
  [Manual usage](#manual-usage-terminal--local-model)).

The `strict` bit is write-once and monotonic — there is no strict→manual path — so
a resumed session keeps the enforcement it opted into. An untuned manual change is
byte-identical to pre-strict `mpd`.

## Per-persona tuning (behavior, not just model)

Beyond the model, each persona's *behavior* is tunable in `.mpd/config.json`
(`personas`), carried into the `mpd next` brief. The knobs are **strengthen-only**:

- `rigor` (`standard | deep | paranoid`) — raises reasoning effort and, for review
  personas, reviewer count. At `risk=high` the adversarial set (Security, Tester,
  Doc Validation) is floored to deep effort regardless of any custom model pin.
- `depth` (`examples | property | fuzz`) — the **Tester** only; a strengthen-only
  test-emphasis overlay.
- `directive_append` — a project instruction appended *after* the bundled directive
  (never replacing it); the one **un-rankable** knob.

```bash
mpd persona show Security --json       # current value, range, baseline, danger — per field
mpd persona set Security rigor paranoid
mpd persona set Tester depth fuzz
mpd persona set Security directive-append "Always check for IMAP cleartext."   # ⚠ warned + recorded
mpd persona reset Security             # back to baseline (or `… reset Security rigor` for one field)
```

**Integrity by construction.** The ordinal menus have no sub-baseline term, so they
cannot dial a persona weaker. The one un-rankable vector (a `directive_append`, or a
hand-edited base directive) can't be proven rigor-preserving, so it is **recorded,
never blocked**: a `weakened` flag on the brief and a `persona_tuning` stamp on the
gate receipt, so a tuned PASS is never indistinguishable in the ledger from a
full-rigor one. mpd never runs the model, so the stamp is a best-effort audit signal
— the structural knobs and the retained strict artifact are the real teeth. An
absent `personas` block is fully inert (byte-identical brief, `--json`, and ledger).

## Why this exists

Two ideas, composed:

- **OpenSpec** keeps AI honest with a durable, machine-readable *spec* — change
  folders with ADDED/MODIFIED/REMOVED deltas and GIVEN/WHEN/THEN scenarios that
  survive session death.
- **Model-Paired Development** keeps AI honest with a sequence of *adversarial
  personas* (Architect ≠ Security ≠ Tester, each on its own model) gating each
  other, backed by deterministic tooling.

`mpd` is the connective tissue: the OpenSpec artifacts become the contract the
personas verify against, and the personas' verdicts become durable gate state the
next session (or agent, or human) can read.

## Commands

The everyday loop is six verbs; the rest are author-support or rare recovery
(`mpd --help` prints the same grouping):

```
Core loop
  mpd conduct <name> [--ui] [--fix|--chore] [--risk low|medium|high] [--threat-profile <p>]  # start (strict tier)
  mpd next [--harness generic|claude-code|codex] [--context] [--full] [--json]  # the next persona's brief
  mpd gate <phase> --pass|--conditional|--fail [--evidence P] [--condition C] [--reuse R] \
           [--exploit "attacker|capability|boundary|harm|fix"] [--waive-artifact "reason"]   # record a verdict
  mpd status [--change N] [--json] [--brief]     # current phase, verdicts, tasks, readiness
  mpd archive [--yes] [--skip-specs]             # fold specs + docs into the record & archive
        (also: --recover / --abandon an interrupted archive closure)
  mpd publish [--verify] [--json]                # observe exact remote/ref parity; never push/fetch/deploy

Author & govern
  mpd brief <phase> [--change N]                 # scaffold a phase's judgment-artifact template
  mpd resolve <n> | --all                        # close open CONDITIONAL-PASS conditions
  mpd reconcile --continue "reason"              # authorize one excess attempt; also --narrow/--risk/--threat-profile
  mpd persona list|show|set|reset ...            # inspect/tune per-persona behavior (the interview primitives)
  mpd manifest [--change N]                      # seed a change's manifest.json (declare its path scope)
  mpd use <name>                                 # point .mpd/current at an existing change

Setup & recovery
  mpd init [--test <cmd>]                         # scaffold openspec/ + mpd schema + install the commit gate
  mpd strict <name>                              # promote an already-begun change to the strict tier (monotonic)
  mpd check [--staged]                           # run the secret scan now (+ external scanners/tests unless --staged)
  mpd doctor [--json] [--fix]                    # diagnose setup; --fix heals .mpd/.gitignore
```

`mpd begin` (the manual-tier start) and `mpd closure recover|abandon` remain as
hidden, still-functional aliases (`archive --recover|--abandon` is the documented
form). `--fix` (defect) and `--chore` (refactor/tooling/perf) skip the two
Documentation phases; `--ui` adds the three Design phases. Neither bypasses a gate —
they only change *which optional phases apply*.

### Proportional governance

Every change records a risk level and threat profile. Without flags, UI changes
default to medium risk, other changes to low risk, and the threat profile is
`local-trusted-user`; project defaults may be set under `governance` in
`.mpd/config.json`. Other profiles are `local-untrusted-input`, `network-client`,
`network-server`, `credential-bearing`, and `high-assurance`.

Every FAIL requires one class: `product`, `test`, `infrastructure`, `environment`,
or `policy`. A Security FAIL additionally requires a structured
`--exploit "attacker|capability|boundary|harm|fix"` (five `|`-delimited fields) so a
blocker states a credible exploit path inside or into the declared profile.
Out-of-profile defense in depth remains advisory.

Low, medium, and high risk allow one, two, and three attempts per phase before an
explicit `mpd reconcile` decision is required. Reconciliation authorizes one attempt
and never advances or erases a failed gate. Changing risk or threat profile retains
history and rewinds Security plan and downstream gates. Artifact guidance is advisory
(about two pages for low and eight for medium; unbounded for high) across canonical
proposal/design/tasks. Superseded prose belongs in `history/`.

### Content-addressed closure

Every new gate PASS carries a SHA-256 receipt over the inputs that phase actually
reviewed: declared scope, source content, governance, relevant config, tool/scanner
identity, and applicable artifacts. Status reports receipt content as `valid`,
`stale`, or `absent` separately from reuse eligibility. Reuse is never implicit:
`mpd gate <phase> --pass --reuse <receipt>` appends a distinct provenance event.
Build, Test, and Security(code) continue to execute unless a complete versioned
hermetic policy is configured; Deploy is never reusable.

`manifest.json` declares the change's path scope and optional publication target.
Architecture cannot pass until scope is explicit. Out-of-scope staged paths block
checks and archive without changing the index. Archive is a durable, journaled
transaction with staged postimages and completion-only recovery; it leaves an
ignored pending pointer until the exact archived result is committed and remotely
verified (`mpd archive --recover` to complete it, or `--abandon` to drop the
metadata).

After the operator commits and pushes normally, `mpd publish --verify` proves a
clean linear closure commit and observes the configured branch twice around a stable
local snapshot. Exact OID equality is `verified`; ahead, behind, diverged, rewritten,
unstable, offline, unavailable, and ancestry-unavailable remain distinct. MPD never
pushes, force-pushes, creates refs, fetches, stages, commits, or deploys as part of
publication verification.

Publication may be declared per change in `manifest.json`. If it is absent, MPD
resolves `closure.default_remote` plus `closure.default_ref` from `.mpd/config.json`,
then the current branch's configured upstream. It never invents a target for
detached HEAD or an unconfigured branch. Remote reads are bounded (15 seconds by
default; `closure.remote_timeout_secs` accepts 1–300), and human path lists can be
capped with `closure.human_path_list_limit`. Hermetic execution reuse is opt-in under
`closure.hermetic_reuse`; the former top-level `hermetic_reuse` spelling remains
readable for migration.

## The gates are real, not self-reported

- **`mpd gate build|test --pass`** re-runs the configured test command itself and
  refuses PASS unless it exits zero **and** a non-zero pass count is observed — it
  cannot accept the caller's word.
- **`mpd gate security-code --pass`** refuses PASS on any secret finding.
- **`mpd gate documentation --pass`** refuses PASS unless `documentation.md` exists
  and covers every required section (Purpose/Value/Scope/Functional/Usage) with no
  unfilled placeholders — an empty stub can't pass.
- **`mpd gate deploy --pass`** runs the configured `deploy` command (when set) and
  refuses PASS if it exits non-zero, so deploy is a machine-enforced step rather than
  a checkbox.
- **`mpd archive`** refuses on any non-PASS gate, open condition, incomplete
  manifest, or mixed staging. `--yes` uses a journaled transaction and retains
  recovery data until the archived result is committed and closed.
- **`mpd publish --verify`** requires a coherent closure commit and compares its
  exact OID with the configured remote branch without pushing or fetching.
- The **git `pre-commit` hook** re-runs the checks independently, so enforcement
  holds even when a harness that ignores `mpd` drives the commit. Bypass one commit
  with `MPD_GATE_SKIP=1`.

External best-of-breed scanners (gitleaks, Semgrep) are used when present as
*additional* passes; a built-in scanner is the always-available floor, and the ledger
records which scanners actually backed each PASS. Degraded coverage is reported by
`mpd doctor`, never silently treated as clean.

### Secret allowlist

Real repos have intentional fixture secrets (fake API keys in tests). To acknowledge
them without weakening the gate, add `.mpd/secret-allowlist.json`:

```json
{
  "paths": ["Tests/**", "scripts/fixtures/**"],
  "allow": [
    { "path": "Sources/AI/Context.swift", "rule": "private-key-block", "line": 324 }
  ]
}
```

`paths` are repo-relative globs (`*` within a segment, `**` across segments); `allow`
entries narrow by `rule` and/or `line`. Two guarantees: suppressions are **always
counted and reported** (never silent), and a missing or malformed allowlist
suppresses **nothing** (fail-closed). The file is version-controlled trust —
committing an entry is a reviewable statement that a finding is a verified false
positive. When gitleaks is the active scanner it honors its own `.gitleaksignore`
independently.

## Trust boundaries

- **`.mpd/config.json` is executable trust.** Its `test` value is run via `sh -c` by
  the Build/Test gates and the pre-commit hook. Because `.mpd/` is version-controlled
  (it is the durable spec-of-record), **merging a change that edits `.mpd/config.json`
  is equivalent to granting arbitrary code execution** on the next gate run — treat it
  like a `Makefile` or `package.json` script in review.
- **The engine refuses to follow symlinks out of `openspec/`.** Reads, writes, and
  the archive merge validate that every path component stays within the tree and is
  not a symlink, so a committed symlink cannot redirect a spec or config write to
  `~/.ssh/authorized_keys` or read an arbitrary file. The same guard applies to
  `.mpd/directives/` and `.mpd/config.json` reads/writes.
- **A project directive is untrusted instruction text.** `mpd next --full` inlines a
  persona directive verbatim as that persona's operating instructions, so a project
  copy that diverges from the bundled default is flagged with a visible warning — a
  malicious edit to a directive is surfaced for review, not trusted silently.
- **Change and capability names are validated at every use**, not just at creation —
  a tampered `.mpd/current` or a `--change ../../x` flag is rejected before it becomes
  a path.
- **Network egress:** when Semgrep is installed, the security-code gate runs it with
  `--config auto`, which fetches its ruleset from Semgrep's registry over the network.
  Absent Semgrep, no egress occurs; the built-in scanner is fully offline.
- **Remote observation is explicit egress.** Only `mpd publish --verify` invokes
  `git ls-remote`, and only for a syntactically safe name found in the repository's
  configured remote set. MPD stores no URL, credentials, raw remote output, source
  bytes, or environment values in its bounded local observation cache.

## Phase → persona → model

The persona (role) is fixed; the **model is harness-specific**. The judgment/creative
planning and validation phases — **Design, Architecture, and Doc Validation** — are
the deep-cognition tier; the execution/synthesis/review phases are standard.
`mpd next --harness <h>` resolves the concrete model:

| Phase | Persona | Tier | Claude Code | Codex |
|---|---|---|---|---|
| **Design Mock / Review / Sign-off**¹ | Designer | **deep** | **Fable** (→ Opus if unavailable) | **Sol** |
| **Architecture** | Architect | **deep** | **Fable** (→ Opus if unavailable) | **Sol** |
| Security (plan / code) | Security | standard | Sonnet | Terra |
| Build | Builder | standard | Sonnet | Terra |
| Test | Tester | standard | Sonnet | Terra |
| Documentation² | Documenter | standard | Sonnet | Terra |
| Deploy | main session | — | — | — |
| **Doc Validation**² | Architect & Designer | **deep** | **Fable** (→ Opus if unavailable) | **Sol** |

¹ Design phases run only for `--ui` changes. ² Documentation phases run only for
feature changes (a `--fix` or `--chore` skips them). The Documenter *synthesizes* the
doc cheaply; the Architect + Designer *validate* it (both spawned) at the deep tier.
Codex tiers are GPT-5.6 Sol / Terra / Luna (deepest → lightest); Luna is unassigned by
default. The `generic` harness reports the *tier* (`deep-cognition` / `standard`)
rather than a concrete model.

### Models are configuration, not code

The table above is the **default**, seeded into `.mpd/config.json` at `mpd init` as a
per-harness, per-persona map. As models evolve you retarget a persona by editing data
— no rebuild, no release:

```json
{
  "test": "cargo test --workspace",
  "models": {
    "claude-code": {
      "Architect": "fable", "Designer": "fable",
      "Builder": "sonnet", "Documenter": "sonnet",
      "Security": "sonnet", "Tester": "sonnet"
    },
    "codex": {
      "Architect": "sol", "Designer": "sol",
      "Builder": "terra", "Documenter": "terra",
      "Security": "terra", "Tester": "terra"
    }
  },
  "model_fallbacks": { "fable": "opus" }
}
```

Point Security at a stronger model for one project — `"Security": "opus"` — and
`mpd next --harness claude-code` reports it immediately. An absent entry falls back to
the built-in tier default, so a partial map never breaks resolution; `model_fallbacks`
surfaces as a note (`fable (fall back to opus if unavailable)`). Model ids are
charset-validated (`[A-Za-z0-9._-]`, ≤64) so a configured value can never smuggle
shell metacharacters into a rendered `--model` string.

## Documentation

Feature changes carry documentation through the pipeline as first-class, gated work:

- **Documentation** (after Test) — the **Documenter** (cheap, standard tier)
  *passively synthesizes* a durable doc from everything the prior phases produced
  (proposal, design + Conditions for Builder, spec scenarios, security findings,
  tasks, test results) covering **Purpose · Value · Scope · Functional details ·
  Usage**. Its gate is a **deterministic structural check** — the doc must exist and
  cover every section with no unfilled placeholders — so an empty stub can't pass.
- **Doc Validation** (after Deploy) — the **Architect** (functional/scope accuracy)
  and **Designer** (purpose/value/representation) *both* validate the doc against what
  shipped, at the deep tier. A FAIL sends it back to the Documenter to revise.

At archive, the doc folds into a project subdirectory (default `docs/<name>.md`,
configurable via `docs_dir`). Defect fixes (`--fix`) and non-functional chores
(`--chore`) skip both phases — only changes that alter functional behavior are
documented.

## The doctrine ships in the binary

The Model-Paired Development doctrine — the protocol plus one directive per persona —
is **compiled into `mpd`** (`include_str!`), not read from a file on your machine.
`mpd init` installs it to `.mpd/directives/` so each project can customize it, and
every `mpd next` surfaces the active phase's persona directive:

```bash
mpd next --harness claude-code          # names the persona + directive
mpd next --harness claude-code --full   # inlines the FULL directive text
```

With `--full`, a harness that has **no** `CLAUDE.md`/`AGENTS.md` at all is still
self-sufficient — the brief carries the persona's complete operating instructions
inline. Resolution is **project-first**: the `.mpd/directives/` copy wins when
present, otherwise the bundled default is used, so a fresh clone always resolves.

Because a directive is inlined *verbatim as that persona's instructions* and lives in
the branch under review, an edited project copy is untrusted until seen: `mpd next
--full` prepends a **divergence warning** when a project directive differs from the
bundled default, flagging it for review rather than trusting it silently — the
mitigation for directive-content prompt-injection (a PR that quietly edits
`personas/security.md` to "PASS without scanning"). Directive reads are
symlink-refusing and size-capped, so a planted symlink can't redirect a read to an
arbitrary file. `mpd doctor` reports whether directives are installed.

## Manual usage (terminal / local model)

The harness flow above is the recommended path. For full manual control — a terminal
against a local model — install once and drive the raw verbs yourself. `mpd begin` is
the lenient **manual tier** (a judgment `gate --pass` takes your word; add `--strict`,
or use `mpd conduct`, for the self-enforcing tier):

```bash
# 1. Install (from a clone of this repo)
cargo install --path crates/mpd          # → ~/.cargo/bin/mpd  (put it on PATH)

# 2. Initialize a project (from its repo root)
cd ~/my/project
mpd init --test "cargo test"             # scaffolds openspec/, installs directives + the commit gate,
                                         # seeds the per-persona model map in .mpd/config.json
# optionally set a deploy command:  edit .mpd/config.json → {"test": "...", "deploy": "scripts/deploy.sh"}

# 3. Start a change (manual tier) and declare its scope
mpd begin add-rate-limiter               # a feature (documented). --fix/--chore skip docs; --strict = self-enforcing.
mpd manifest --change add-rate-limiter   # seed manifest.json, then edit it to declare paths + publish target

# 4. Walk the loop: next → work → gate, until archive-ready
mpd next --harness claude-code           # prints the phase's persona, model, task, gate cmd
mpd next --harness claude-code --full    # …and inlines the persona's full directive
#   … do the work the brief describes …
mpd gate architecture --pass --evidence design.md#conditions
mpd status                               # where am I? what's blocking archive?
mpd gate build --pass                    # re-runs `cargo test`; refuses without a real pass
# …security-code, test, documentation, deploy, doc-validation…
mpd resolve --all                        # close any CONDITIONAL-PASS conditions
mpd archive --yes                        # fold specs → openspec/specs/, doc → docs/
# commit + push using normal Git, then:
mpd publish --verify                     # observe exact remote/ref parity; never pushes or fetches
```

## How it's built

`mpd` does **not** shell out to the Node OpenSpec CLI — that would reintroduce the
dependency it exists to remove. Instead it treats the OpenSpec **on-disk format as
the integration contract** and implements a native engine (`openspec-core`) that
reads and writes the same files. Directories written by `mpd` remain readable by the
reference OpenSpec implementation and vice versa — **format compatibility with zero
runtime coupling**.

A Cargo workspace of two crates:

```
crates/
  openspec-core/   # the format engine — the ONLY code that knows the on-disk layout
    model          #   Spec, Requirement, Scenario, Delta{Added,Modified,Removed,Renamed}
    parse          #   fence-aware markdown → model
    render         #   model → canonical markdown (idempotent form)
    merge          #   apply deltas → spec (RENAMED→REMOVED→MODIFIED→ADDED)
    validate       #   structural + convention checks
    schema         #   schema.yaml / .openspec.yaml
    project        #   filesystem layout, discovery, status, archive
  mpd/             # the overlay + CLI
    phase          #   the pipeline state machine (pure)
    ledger         #   durable gate verdicts + evidence  (.mpd/state/<change>.json)
    checks         #   secret scan + test-count verification
    digest         #   canonical, domain-separated SHA-256 content identities
    git            #   bounded, argument-array-only Git plumbing
    closure        #   manifests, evidence receipts, commit coherence, remote parity
    personas       #   per-phase briefs + model assignments
    harness        #   `next` adapters (generic / claude-code / codex) + model policy
    directives     #   bundled MPD doctrine (include_str!) + project-first resolution
    config         #   .mpd/config.json — test/deploy cmds + per-persona model + tuning
    githooks       #   the pre-commit enforcement floor
    scaffold       #   init / begin
```

The boundary is an **anticorruption layer**: `mpd` talks to the format only through
`openspec-core`'s typed API, never raw markdown. If the OpenSpec format evolves, the
change is contained to one crate.

**The parser** is the one non-trivial algorithm — fence-aware, because real spec
bodies embed structural markers (`## RENAMED Requirements`, `### Requirement:`) as
*examples* inside code fences. `mpd`'s parser treats a `#`-prefixed line as a heading
only at column 0 and outside a code fence, so a fenced example is preserved verbatim
as body text. This is verified against the real OpenSpec fixtures and a fence-torture
case.

## Build & test

```
cargo test --workspace       # unit + fidelity + property/metamorphic + e2e
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release -p mpd  # the encased binary at target/release/mpd
```

## License

MIT.
