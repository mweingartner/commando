# Fix maturity assessment links

## Why

The archive exporter copied archive-relative links into a root `docs/` file, where they
resolve outside the repository and one points back to the same document.

## What Changes

- Replace the two broken links with paths correct from `docs/`.
- Leave assessment content, runtime, policy, configuration, and archived evidence intact.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

None; this is a mechanical documentation correction.

## Impact

One durable Markdown file and the required change records. No executable or policy impact.
