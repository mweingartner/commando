# Gate Evidence Delta

## ADDED Requirements

### Requirement: Adversarial actor separation

Strict gates SHALL enforce cooperative actor separation on two axes over the change's
current attempt cycle: the gate actor SHALL differ from the actor of the latest
applicable upstream gate record, and a judgment gate with a defined review subject —
Design Review and Security (plan) reviewing Architecture; Security (code), Design
Sign-off, and Test reviewing Build; Doc Validation reviewing Documentation — SHALL also
differ from the actor recorded on that subject phase. Authoring and execution phases
(Design Mock, Architecture, Build, Documentation, Deploy) carry only the
adjacent-upstream rule. The documented persona-reuse patterns (Designer at the three
Design gates, Security at both Security gates, Architect at Architecture and Doc
Validation) SHALL remain valid. Actor labels remain recorded cooperative provenance,
not authenticated identity.

#### Scenario: Alternating labels attempt self-review

- **WHEN** the actor who recorded Build later attempts the Design Sign-off, Security
  (code), or Test gate under the same label, with a different label recorded in between
- **THEN** the gate SHALL be refused with a message naming the review-subject rule and
  both actors

#### Scenario: Documented persona reuse proceeds

- **WHEN** one Designer label records Design Mock, Design Review, and Design Sign-off,
  one Security label records both Security gates, and the Architect label records
  Architecture and Doc Validation, with each gate actor distinct from its adjacent
  upstream actor and its review subject's actor
- **THEN** every gate SHALL proceed

#### Scenario: Rewound subject leaves nothing to compare

- **WHEN** a judgment gate runs while its review-subject phase has no gate record in
  the current attempt cycle
- **THEN** only the adjacent-upstream comparison SHALL apply
