# Doc validation: Fix maturity assessment links

## Actor

DocValidator-Terra-64

## Architect lens

Verified both targets are tracked files, the canonical target contains `## Assessment`,
the root-document path arithmetic is correct, and the durable diff changes only the two
link lines. Doc staleness and whitespace checks pass.

## Designer lens

Link labels distinguish the canonical assessment from archived test evidence and no
self-link remains. The correction is discoverable without adding commands or external
navigation.

## Verdict

PASS
