# Fence Torture Specification

## Purpose

This spec embeds structural markers inside fenced code to prove the parser
ignores them.

## Requirements

### Requirement: Only real structure is parsed

The parser SHALL treat `#`-prefixed lines inside fenced code blocks as body
text, not structure.

#### Scenario: Fenced example with fake headers

- **WHEN** a scenario body contains a fenced example
- **THEN** the following markers MUST be preserved verbatim and ignored:

```markdown
### Requirement: FAKE — should not be parsed
#### Scenario: FAKE — should not be parsed
## ADDED Requirements
## RENAMED Requirements
- FROM: `### Requirement: Old`
- TO: `### Requirement: New`
```

- **AND** parsing yields exactly one requirement with one scenario
