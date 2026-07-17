//! The Model-Paired Development phase state machine.
//!
//! The pipeline is a fixed sequence of adversarial-persona phases. Two axes of
//! [`Applicability`] gate which phases run: the **Design** phases (Mock, Review,
//! Sign-off) run only for UI/UX changes, and the **Documentation** phases
//! (Documentation, Doc Validation) run only for feature changes that alter
//! functional behavior (defect fixes and non-functional chores skip them).
//! Everything else is mandatory. This module is pure — no I/O — so the ordering
//! and skip rules are unit-testable in isolation.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A pipeline phase. Ordering follows the canonical Model-Paired Development
/// sequence; [`Phase::Done`] is the terminal state after Doc Validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    /// Designer produces the design mock (UI/UX changes only).
    DesignMock,
    /// Architect produces the implementation plan + Conditions for Builder.
    Architecture,
    /// Designer reviews the plan against the mock (UI/UX changes only).
    DesignReview,
    /// Security reviews the plan for threat-model gaps.
    SecurityPlan,
    /// Builder implements the plan and writes initial tests.
    Build,
    /// Security reviews the real code on disk.
    SecurityCode,
    /// Designer verifies the built UI against intent (UI/UX changes only).
    DesignSignoff,
    /// Tester runs functional + non-functional + fuzz/property passes.
    Test,
    /// Documenter synthesizes the durable doc (feature changes only).
    Documentation,
    /// Deploy / readiness gate.
    Deploy,
    /// Architect + Designer validate the doc for accuracy (feature changes only).
    DocValidation,
    /// All phases complete.
    Done,
}

use Phase::*;

/// The canonical phase order, excluding the terminal [`Phase::Done`].
pub const PIPELINE: [Phase; 11] = [
    DesignMock,
    Architecture,
    DesignReview,
    SecurityPlan,
    Build,
    SecurityCode,
    DesignSignoff,
    Test,
    Documentation,
    Deploy,
    DocValidation,
];

/// Which optional phase groups apply to a change. Derived from the change's
/// UI/UX flag and its kind (see [`crate::ledger::ChangeKind`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Applicability {
    /// The change has a UI/UX surface → the Design phases run.
    pub ui: bool,
    /// The change alters functional behavior worth documenting → the
    /// Documentation phases run.
    pub docs: bool,
}

/// The persona responsible for a phase. The *model* it runs under is
/// harness-specific (Claude uses Fable/Sonnet, Codex uses Sol/Terra), so it is
/// resolved by [`crate::harness::model_for`], not fixed here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Persona {
    /// Persona name (e.g. `Architect`).
    pub name: &'static str,
}

impl Phase {
    /// The Doc Validation phase — validated by two personas (Architect +
    /// Designer), so the harness spawns both.
    pub fn is_doc_validation(self) -> bool {
        matches!(self, DocValidation)
    }

    /// Whether this phase is active for a change with the given applicability.
    pub fn is_active(self, a: Applicability) -> bool {
        match self {
            DesignMock | DesignReview | DesignSignoff => a.ui,
            Documentation | DocValidation => a.docs,
            _ => true,
        }
    }

    /// Phases whose PASS verdict must be backed by a real test run.
    pub fn requires_tests(self) -> bool {
        matches!(self, Build | Test)
    }

    /// Phases whose PASS verdict must be backed by a secret scan.
    pub fn requires_secret_scan(self) -> bool {
        matches!(self, SecurityCode)
    }

    /// Phases whose PASS verdict must be backed by a documentation structural
    /// check (the doc exists and covers every required section).
    pub fn requires_doc_check(self) -> bool {
        matches!(self, Documentation)
    }

    /// The judgment artifact this phase must produce under the strict tier, as
    /// `(filename, required "##" sections)`. A judgment phase whose adversarial
    /// record would otherwise evaporate maps to its own durable artifact; every
    /// non-judgment phase returns `None` (design.md D4/D6). Architecture is a
    /// special case: it keeps the core `design.md` artifact, and the strict check
    /// only requires the `Conditions for Builder` section be present. The
    /// high-risk Security (code) additions (`Independent review`, `Refutation`)
    /// are layered on at the gate, not here.
    // Consumed by the strict gate + archive re-check (later stages); exercised
    // now by the mapping unit test.
    #[allow(dead_code)]
    pub fn judgment_artifact(self) -> Option<(&'static str, &'static [&'static str])> {
        match self {
            SecurityPlan => Some((
                "security-plan.md",
                &["Threat model", "Conditions for Builder", "Verdict"],
            )),
            SecurityCode => Some((
                "security-code.md",
                &["Findings", "Conditions verified", "Verdict"],
            )),
            DesignReview => Some(("design-review.md", &["Intent check", "Verdict"])),
            DesignSignoff => Some((
                "design-signoff.md",
                &["Implementation vs intent", "Verdict"],
            )),
            Test => Some(("test.md", &["Coverage", "Results", "Verdict"])),
            DocValidation => Some((
                "doc-validation.md",
                &["Architect lens", "Designer lens", "Verdict"],
            )),
            // design.md is a core artifact; strict only demands the Conditions.
            Architecture => Some(("design.md", &["Conditions for Builder"])),
            _ => None,
        }
    }

    /// The one or two upstream phases whose artifact this phase's persona needs,
    /// for the strict-mode context pack (`mpd next --context`). Every entry
    /// precedes `self` in the pipeline; the consumer resolves each to its
    /// [`Phase::judgment_artifact`] and skips phases (or applicability-excluded
    /// phases) that have none.
    // Consumed by `mpd next --context` (a later stage); exercised now by the
    // ordering unit test.
    #[allow(dead_code)]
    pub fn upstream_context(self) -> &'static [Phase] {
        match self {
            // The Architect builds against the design mock.
            Architecture => &[DesignMock],
            // The Designer reviews the plan against the mock.
            DesignReview => &[DesignMock, Architecture],
            // Security reviews the plan.
            SecurityPlan => &[Architecture],
            // The Builder implements the plan under the security conditions.
            Build => &[Architecture, SecurityPlan],
            // Security (code) verifies the plan's conditions against the code.
            SecurityCode => &[SecurityPlan],
            // The Designer verifies the build against the mock and the review.
            DesignSignoff => &[DesignMock, DesignReview],
            // The Tester tests against the plan and the code review.
            Test => &[Architecture, SecurityCode],
            // The Documenter synthesizes from the plan and the test results.
            Documentation => &[Architecture, Test],
            // The Architect + Designer validate the doc.
            DocValidation => &[Documentation],
            // No upstream artifact is needed.
            DesignMock | Deploy | Done => &[],
        }
    }

    /// The persona-tuning key for this phase (`.mpd/config.json` `personas` map):
    /// the composite Doc-Validation phase normalizes to `"DocValidation"`, every
    /// other phase keys on its persona display name. So a persona serving multiple
    /// phases (e.g. Designer over Mock/Review/Sign-off) is tuned once for all of
    /// them (design.md D3/Cond 9).
    pub fn tuning_key(self) -> &'static str {
        if self.is_doc_validation() {
            "DocValidation"
        } else {
            self.persona().name
        }
    }

    /// The persona display name(s) whose base directive backs this phase — the two
    /// parts for the composite Doc-Validation persona (`for_persona` returns `None`
    /// for the composite name, so it MUST be resolved from the parts), else the
    /// single persona. Used to compute `base_modified` and the persona-tuning
    /// dependency digest (design.md Cond 9).
    pub fn tuning_personas(self) -> Vec<&'static str> {
        if self.is_doc_validation() {
            vec!["Architect", "Designer"]
        } else {
            vec![self.persona().name]
        }
    }

    /// The persona responsible for this phase.
    pub fn persona(self) -> Persona {
        let name = match self {
            DesignMock | DesignReview | DesignSignoff => "Designer",
            Architecture => "Architect",
            SecurityPlan | SecurityCode => "Security",
            Build => "Builder",
            Test => "Tester",
            Documentation => "Documenter",
            DocValidation => "Architect & Designer",
            Deploy => "main-session",
            Done => "-",
        };
        Persona { name }
    }

    /// Whether this phase is the deep-cognition tier — the judgment/creative
    /// planning and validation phases (Design, Architecture, and Doc
    /// Validation). Deep phases get the strongest model per harness; the
    /// execution/synthesis/review phases (Security, Build, Test, Documentation)
    /// get the standard model.
    pub fn is_deep(self) -> bool {
        matches!(
            self,
            Architecture | DesignMock | DesignReview | DesignSignoff | DocValidation
        )
    }

    /// The CLI/serde slug (kebab-case) for this phase.
    pub fn slug(self) -> &'static str {
        match self {
            DesignMock => "design-mock",
            Architecture => "architecture",
            DesignReview => "design-review",
            SecurityPlan => "security-plan",
            Build => "build",
            SecurityCode => "security-code",
            DesignSignoff => "design-signoff",
            Test => "test",
            Documentation => "documentation",
            Deploy => "deploy",
            DocValidation => "doc-validation",
            Done => "done",
        }
    }

    /// Parse a phase from its slug.
    pub fn from_slug(s: &str) -> Option<Phase> {
        PIPELINE
            .iter()
            .copied()
            .chain(std::iter::once(Done))
            .find(|p| p.slug() == s)
    }

    /// A short human label.
    pub fn label(self) -> &'static str {
        match self {
            DesignMock => "Design Mock",
            Architecture => "Architecture",
            DesignReview => "Design Review",
            SecurityPlan => "Security (plan)",
            Build => "Build",
            SecurityCode => "Security (code)",
            DesignSignoff => "Design Sign-off",
            Test => "Test",
            Documentation => "Documentation",
            Deploy => "Deploy",
            DocValidation => "Doc Validation",
            Done => "Done",
        }
    }

    /// The first phase for a change, honoring the applicability skip rules.
    pub fn first(a: Applicability) -> Phase {
        Self::skip_forward(DesignMock, a)
    }

    /// The next phase after `self`, skipping inapplicable phases. Returns
    /// [`Phase::Done`] after the last applicable phase.
    pub fn next(self, a: Applicability) -> Phase {
        if self == Done {
            return Done;
        }
        let idx = PIPELINE.iter().position(|&p| p == self);
        match idx {
            Some(i) if i + 1 < PIPELINE.len() => Self::skip_forward(PIPELINE[i + 1], a),
            _ => Done,
        }
    }

    /// From `start`, advance past any inapplicable phases to the first active
    /// phase (or [`Phase::Done`]).
    fn skip_forward(start: Phase, a: Applicability) -> Phase {
        let mut idx = PIPELINE.iter().position(|&p| p == start).unwrap_or(0);
        while idx < PIPELINE.len() {
            let p = PIPELINE[idx];
            if !p.is_active(a) {
                idx += 1;
                continue;
            }
            return p;
        }
        Done
    }

    /// The ordered phases that actually apply to a change.
    pub fn applicable(a: Applicability) -> Vec<Phase> {
        PIPELINE
            .iter()
            .copied()
            .filter(|p| p.is_active(a))
            .collect()
    }
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FEATURE: Applicability = Applicability {
        ui: false,
        docs: true,
    };
    const UI_FEATURE: Applicability = Applicability {
        ui: true,
        docs: true,
    };
    const FIX: Applicability = Applicability {
        ui: false,
        docs: false,
    };

    #[test]
    fn non_ui_feature_skips_design_but_keeps_docs() {
        assert_eq!(Phase::first(FEATURE), Architecture);
        assert_eq!(Architecture.next(FEATURE), SecurityPlan);
        assert_eq!(Build.next(FEATURE), SecurityCode);
        // Security (code) skips Design Sign-off straight to Test.
        assert_eq!(SecurityCode.next(FEATURE), Test);
        // Test → Documentation → Deploy → Doc Validation → Done.
        assert_eq!(Test.next(FEATURE), Documentation);
        assert_eq!(Documentation.next(FEATURE), Deploy);
        assert_eq!(Deploy.next(FEATURE), DocValidation);
        assert_eq!(DocValidation.next(FEATURE), Done);
        let applicable = Phase::applicable(FEATURE);
        assert!(!applicable.contains(&DesignMock) && !applicable.contains(&DesignReview));
        assert!(applicable.contains(&Documentation));
        assert_eq!(applicable.len(), 8);
    }

    #[test]
    fn ui_feature_includes_everything() {
        assert_eq!(Phase::first(UI_FEATURE), DesignMock);
        assert_eq!(DesignSignoff.next(UI_FEATURE), Test);
        assert_eq!(Test.next(UI_FEATURE), Documentation);
        assert_eq!(Phase::applicable(UI_FEATURE).len(), 11);
    }

    #[test]
    fn fix_skips_documentation_phases() {
        assert_eq!(Phase::first(FIX), Architecture);
        // Test → Deploy (Documentation skipped) → Done (Doc Validation skipped).
        assert_eq!(Test.next(FIX), Deploy);
        assert_eq!(Deploy.next(FIX), Done);
        let applicable = Phase::applicable(FIX);
        assert!(!applicable.contains(&Documentation) && !applicable.contains(&DocValidation));
        assert_eq!(applicable.len(), 6);
    }

    #[test]
    fn judgment_artifacts_map_judgment_phases_only() {
        // Each judgment phase maps to its own durable artifact + required
        // sections; non-judgment phases return None.
        let (file, secs) = SecurityPlan.judgment_artifact().unwrap();
        assert_eq!(file, "security-plan.md");
        assert_eq!(
            secs,
            &["Threat model", "Conditions for Builder", "Verdict"][..]
        );
        let (file, secs) = SecurityCode.judgment_artifact().unwrap();
        assert_eq!(file, "security-code.md");
        assert_eq!(secs, &["Findings", "Conditions verified", "Verdict"][..]);
        assert_eq!(
            DesignReview.judgment_artifact().unwrap().0,
            "design-review.md"
        );
        assert_eq!(
            DesignSignoff.judgment_artifact().unwrap().0,
            "design-signoff.md"
        );
        assert_eq!(Test.judgment_artifact().unwrap().0, "test.md");
        assert_eq!(
            DocValidation.judgment_artifact().unwrap().0,
            "doc-validation.md"
        );
        // Architecture keeps the core design.md, with only Conditions required.
        assert_eq!(
            Architecture.judgment_artifact(),
            Some(("design.md", &["Conditions for Builder"][..]))
        );
        // Non-judgment phases carry no artifact requirement.
        for p in [DesignMock, Build, Documentation, Deploy, Done] {
            assert!(p.judgment_artifact().is_none(), "{p:?} should be None");
        }
    }

    #[test]
    fn upstream_context_points_only_at_prior_phases() {
        assert_eq!(SecurityPlan.upstream_context(), &[Architecture][..]);
        assert_eq!(Build.upstream_context(), &[Architecture, SecurityPlan][..]);
        assert_eq!(DocValidation.upstream_context(), &[Documentation][..]);
        assert!(DesignMock.upstream_context().is_empty());
        assert!(Deploy.upstream_context().is_empty());
        // Every referenced upstream phase strictly precedes the phase itself.
        for &p in PIPELINE.iter().chain(std::iter::once(&Done)) {
            for &up in p.upstream_context() {
                assert!(up < p, "{up:?} must precede {p:?}");
            }
        }
    }

    #[test]
    fn persona_and_tier_assignments() {
        assert_eq!(Documentation.persona().name, "Documenter");
        assert_eq!(DocValidation.persona().name, "Architect & Designer");
        // Documenter is standard tier (cheap synthesis); Doc Validation is deep.
        assert!(!Documentation.is_deep());
        assert!(DocValidation.is_deep());
        assert!(Documentation.requires_doc_check());
        assert!(DocValidation.is_doc_validation());
    }
}
