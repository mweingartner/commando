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
