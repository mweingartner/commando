//! The Model-Paired Development phase state machine.
//!
//! The pipeline is a fixed sequence of adversarial-persona phases. Design
//! phases (Mock, Review, Sign-off) are skipped for changes with no UI/UX
//! surface. Everything else is mandatory. This module is pure — no I/O — so the
//! ordering and skip rules are unit-testable in isolation.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A pipeline phase. Ordering follows the canonical Model-Paired Development
/// sequence; [`Phase::Done`] is the terminal state after Deploy.
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
    /// Deploy / readiness gate (main session).
    Deploy,
    /// All phases complete.
    Done,
}

use Phase::*;

/// The canonical phase order, excluding the terminal [`Phase::Done`].
pub const PIPELINE: [Phase; 9] = [
    DesignMock,
    Architecture,
    DesignReview,
    SecurityPlan,
    Build,
    SecurityCode,
    DesignSignoff,
    Test,
    Deploy,
];

/// The persona responsible for a phase. The *model* it runs under is
/// harness-specific (Claude uses Fable/Sonnet, Codex uses Sol/Terra), so it is
/// resolved by [`crate::harness::model_for`], not fixed here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Persona {
    /// Persona name (e.g. `Architect`).
    pub name: &'static str,
}

impl Phase {
    /// A design phase (skipped when the change has no UI/UX component).
    pub fn is_design(self) -> bool {
        matches!(self, DesignMock | DesignReview | DesignSignoff)
    }

    /// Phases whose PASS verdict must be backed by a real test run.
    pub fn requires_tests(self) -> bool {
        matches!(self, Build | Test)
    }

    /// Phases whose PASS verdict must be backed by a secret scan.
    pub fn requires_secret_scan(self) -> bool {
        matches!(self, SecurityCode)
    }

    /// The persona responsible for this phase.
    pub fn persona(self) -> Persona {
        let name = match self {
            DesignMock | DesignReview | DesignSignoff => "Designer",
            Architecture => "Architect",
            SecurityPlan | SecurityCode => "Security",
            Build => "Builder",
            Test => "Tester",
            Deploy => "main-session",
            Done => "-",
        };
        Persona { name }
    }

    /// Whether this phase is the deep-cognition "heavy lifting" tier (only
    /// Architecture). Deep phases get the strongest model per harness; all other
    /// phases get the standard model.
    pub fn is_deep(self) -> bool {
        matches!(self, Architecture)
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
            Deploy => "deploy",
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
            Deploy => "Deploy",
            Done => "Done",
        }
    }

    /// The first phase for a change, honoring the UI/UX skip rule.
    pub fn first(ui: bool) -> Phase {
        Self::skip_forward(DesignMock, ui)
    }

    /// The next phase after `self`, skipping design phases when `!ui`. Returns
    /// [`Phase::Done`] after Deploy.
    pub fn next(self, ui: bool) -> Phase {
        if self == Done {
            return Done;
        }
        let idx = PIPELINE.iter().position(|&p| p == self);
        match idx {
            Some(i) if i + 1 < PIPELINE.len() => Self::skip_forward(PIPELINE[i + 1], ui),
            _ => Done,
        }
    }

    /// From `start`, advance past any skipped design phases to the first
    /// applicable phase (or [`Phase::Done`]).
    fn skip_forward(start: Phase, ui: bool) -> Phase {
        let mut idx = PIPELINE.iter().position(|&p| p == start).unwrap_or(0);
        while idx < PIPELINE.len() {
            let p = PIPELINE[idx];
            if p.is_design() && !ui {
                idx += 1;
                continue;
            }
            return p;
        }
        Done
    }

    /// The ordered phases that actually apply to a change with the given UI flag.
    pub fn applicable(ui: bool) -> Vec<Phase> {
        PIPELINE
            .iter()
            .copied()
            .filter(|p| ui || !p.is_design())
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

    #[test]
    fn non_ui_change_skips_design_phases() {
        assert_eq!(Phase::first(false), Architecture);
        assert_eq!(Architecture.next(false), SecurityPlan);
        assert_eq!(SecurityPlan.next(false), Build);
        assert_eq!(Build.next(false), SecurityCode);
        // Security (code) skips Design Sign-off straight to Test.
        assert_eq!(SecurityCode.next(false), Test);
        assert_eq!(Test.next(false), Deploy);
        assert_eq!(Deploy.next(false), Done);
        let applicable = Phase::applicable(false);
        assert!(!applicable.iter().any(|p| p.is_design()));
        assert_eq!(applicable.len(), 6);
    }

    #[test]
    fn ui_change_includes_all_design_phases() {
        assert_eq!(Phase::first(true), DesignMock);
        assert_eq!(DesignMock.next(true), Architecture);
        assert_eq!(Architecture.next(true), DesignReview);
        assert_eq!(DesignReview.next(true), SecurityPlan);
        assert_eq!(SecurityCode.next(true), DesignSignoff);
        assert_eq!(DesignSignoff.next(true), Test);
        assert_eq!(Phase::applicable(true).len(), 9);
    }

    #[test]
    fn persona_and_tier_assignments() {
        assert_eq!(Architecture.persona().name, "Architect");
        assert_eq!(SecurityPlan.persona().name, "Security");
        assert_eq!(Build.persona().name, "Builder");
        assert_eq!(Test.persona().name, "Tester");
        assert_eq!(DesignMock.persona().name, "Designer");
        // Only Architecture is the deep-cognition tier.
        assert!(Architecture.is_deep());
        assert!(!Build.is_deep());
        assert!(!SecurityPlan.is_deep());
        assert!(!DesignMock.is_deep());
    }
}
