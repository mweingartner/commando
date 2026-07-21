# Process Governance Delta

## ADDED Requirements

### Requirement: Ledger version-skew diagnosis

Saved ledgers SHALL carry a numeric format marker, and a failed ledger
deserialization SHALL be diagnosed with a bounded version probe: when the probed
format exceeds what the running binary supports, the error SHALL state that the ledger
requires a newer MPD with both format numbers; otherwise the original parse error SHALL
be preserved with the ledger's path context. The probe SHALL run only after full
deserialization has failed and SHALL never alter the result of a successful load.

#### Scenario: Newer ledger meets an older binary

- **WHEN** a ledger's probed format number exceeds the binary's supported format
- **THEN** the load error SHALL say the ledger requires a newer MPD and name the found
  and supported format numbers

#### Scenario: Corrupt ledger is not misattributed

- **WHEN** a ledger fails to parse and its probed format is absent or not greater than
  the supported format
- **THEN** the original parse error SHALL be reported with path context and SHALL NOT
  claim a version mismatch

#### Scenario: Valid ledger is untouched by the guard

- **WHEN** a ledger deserializes successfully
- **THEN** the load SHALL behave identically to a build without the version guard
