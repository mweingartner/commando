# Routing v1 blind rubric

Score each completed, blinded sample before its harness/model identity is revealed.

- `quality_bps`: 0–10,000, based on explicit task acceptance criteria.
- `escaped_defects`: confirmed defects discovered after the first submitted result.
- `rework_steps`: bounded correction cycles required to meet the rubric.
- `latency_ms`, `tokens`, `cost_micros`, and `currency`: observed structured usage facts only.

Do not include prompts, source content, raw model output, API keys, provider credentials, or model names in blind scoring material. An evaluator may report only Pareto eligibility; it must not claim a globally optimal model.
