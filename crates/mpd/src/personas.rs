//! Per-phase persona briefs: what each adversarial persona must do, which
//! OpenSpec artifacts it produces, and what its gate verifies.
//!
//! Briefs are bundled at compile time so the binary is self-contained.

use crate::phase::Phase;

/// The task guidance surfaced to the persona for a phase.
pub fn guidance(phase: Phase) -> &'static str {
    match phase {
        Phase::DesignMock => {
            "Produce the design for this change in the context of the existing design work: \
             which established patterns and components it must reuse, how the new surface fits \
             the whole, and concrete acceptance criteria the Architect will build against."
        }
        Phase::Architecture => {
            "Produce the implementation plan built against the proposal and specs. Author the \
             OpenSpec artifacts (proposal, specs, design, tasks). The design MUST end with a \
             'Conditions for Builder' section enumerating the security/correctness invariants \
             discovered while planning."
        }
        Phase::DesignReview => {
            "Review the plan against the design intent: does the planned implementation still \
             realize the mock, is every feature properly represented, was anything quietly \
             degraded to fit? Revise the mock or send the plan back before any code is written."
        }
        Phase::SecurityPlan => {
            "Review the plan for threat-model gaps, trust boundaries, and credential handling. \
             Verify each 'Condition for Builder' is sound and complete. Return PASS / \
             CONDITIONAL PASS / FAIL."
        }
        Phase::Build => {
            "Implement the plan faithfully AND write the initial tests in the same pass. Match \
             existing patterns; leave the tree building. Mark tasks complete as you go."
        }
        Phase::SecurityCode => {
            "Review the real code on disk (not the plan) against the Conditions for Builder. \
             Grep for the actual patterns. Novel threat surface must re-run Security after any \
             fix. Return PASS / CONDITIONAL PASS / FAIL."
        }
        Phase::DesignSignoff => {
            "Verify the built implementation against the mock and intent: it is what was \
             designed, every feature is properly represented, nothing regressed. No sign-off, \
             no Test."
        }
        Phase::Test => {
            "Run functional AND non-functional testing (performance, load/stress, resource, \
             accessibility) plus fuzz/property/metamorphic tests for any parser/serializer/ \
             codec/protocol. The full suite must be green with a real, non-zero count."
        }
        Phase::Documentation => {
            "Passively synthesize the durable documentation from everything the prior phases \
             produced (proposal, design + Conditions for Builder, specs/scenarios, security \
             findings, tasks, test results). Write documentation.md covering Purpose, Value, \
             Scope, Functional details, and Usage — turn spec scenarios into concrete usage \
             examples. Clean and concise; no placeholders left."
        }
        Phase::DocValidation => {
            "Validate the documentation for accuracy from two lenses — spawn BOTH: the \
             Architect verifies functional/scope/technical accuracy against the built code and \
             specs; the Designer verifies the purpose, value, and user-facing representation. \
             PASS only if both confirm; on inaccuracy, FAIL (or CONDITIONAL PASS with a \
             condition) and have the Documenter revise before re-validating."
        }
        Phase::Deploy => {
            "Readiness / real-target gate. Confirm all gates passed and conditions closed. \
             Deploy only when explicitly authorized; otherwise deliver deploy-ready evidence."
        }
        Phase::Done => "All phases complete. Archive the change to fold specs into the record.",
    }
}

/// The OpenSpec artifact ids a phase is responsible for producing.
pub fn artifacts_for(phase: Phase) -> &'static [&'static str] {
    match phase {
        Phase::Architecture => &["proposal", "specs", "design", "tasks"],
        Phase::Documentation => &["documentation"],
        _ => &[],
    }
}

/// A one-line description of what the phase's gate verifies.
pub fn gate_hint(phase: Phase) -> &'static str {
    match phase {
        Phase::Build => {
            "runs the configured test command; PASS requires a real non-zero pass count"
        }
        Phase::Test => "full suite green with a non-zero count; fuzz/property passes present",
        Phase::SecurityCode => "secret scan clean; Conditions for Builder verified against code",
        Phase::SecurityPlan => "threat model reviewed; conditions sound",
        Phase::Documentation => {
            "documentation.md exists and covers Purpose/Value/Scope/Functional/Usage (checked)"
        }
        Phase::DocValidation => "Architect and Designer both confirm the doc is accurate",
        _ => "persona sign-off recorded with evidence",
    }
}
