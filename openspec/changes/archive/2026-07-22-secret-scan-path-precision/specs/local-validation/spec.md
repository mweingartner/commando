## ADDED Requirements

### Requirement: Path-precise generic secret detection

The built-in scanner's generic secret-assignment rule SHALL flag a
keyword-bearing assignment value only when the value contains contiguous
credential-token material: a run of at least 16 consecutive characters drawn
from `[A-Za-z0-9+]` that itself contains at least one ASCII letter and one ASCII
digit. A value that decomposes entirely into shorter runs separated by path and
word separators (`/`, `-`, `_`, `.`, whitespace) — filesystem paths, dated
archive names, hyphenated identifiers, UUID-shaped strings — SHALL NOT be
reported by the generic rule. This constraint SHALL apply only to the generic
rule: the curated detections (private-key armor, AWS, Slack, GitHub, Google,
Stripe, OpenAI, JWT) SHALL be unaffected, and the generic rule's existing
length, placeholder, and keyword conditions SHALL remain in force so the rule
only ever becomes stricter.

#### Scenario: Keyword-bearing filesystem path is not a secret

- **WHEN** a scanned line contains a secret keyword and a quoted or assigned
  filesystem path such as a dated archive change path whose name contains
  "secret"
- **THEN** the built-in scan SHALL report no generic-secret-assignment finding
  for that line

#### Scenario: Contiguous high-entropy token is still a secret

- **WHEN** a scanned line assigns a keyword-named key a non-placeholder value of
  at least 20 characters containing a contiguous run of 16 or more
  letters-and-digits token characters, such as a 64-hex digest or a 24-char
  alphanumeric token
- **THEN** the built-in scan SHALL report a generic-secret-assignment finding
