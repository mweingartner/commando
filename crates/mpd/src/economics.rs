//! Pure, coverage-aware accounting for bounded model work.

#![allow(dead_code)] // Public integration seam; next/gate wiring lands separately.

use crate::attestation::UsageRecord;
use crate::config::{AntiStallPolicy, BudgetLimits};
use crate::phase::Phase;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoverageState {
    #[default]
    Unreported,
    Complete,
    Partial,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LimitState {
    #[default]
    Within,
    SoftLimit,
    HardLimit,
    Unavailable,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Coverage {
    pub applicable_attempts: u64,
    pub reported_attempts: u64,
}
impl Coverage {
    pub fn state(self) -> CoverageState {
        if self.applicable_attempts == 0 || self.reported_attempts == 0 {
            CoverageState::Unreported
        } else if self.applicable_attempts == self.reported_attempts {
            CoverageState::Complete
        } else {
            CoverageState::Partial
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MetricReport {
    pub value: u64,
    pub coverage: Coverage,
    pub state: LimitState,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct EconomicsReport {
    pub tokens: MetricReport,
    pub active_millis: MetricReport,
    pub wall_millis: MetricReport,
    pub costs: BTreeMap<String, MetricReport>,
    pub block_reason: Option<String>,
}

/// Aggregate without inferring any missing evidence. Wall time is independently
/// observable and can therefore be complete while provider usage is partial.
pub fn aggregate<'a>(
    attempts: impl IntoIterator<Item = (Option<&'a UsageRecord>, u64)>,
) -> EconomicsReport {
    let mut report = EconomicsReport::default();
    for (usage, wall) in attempts {
        report.tokens.coverage.applicable_attempts =
            report.tokens.coverage.applicable_attempts.saturating_add(1);
        report.active_millis.coverage.applicable_attempts = report
            .active_millis
            .coverage
            .applicable_attempts
            .saturating_add(1);
        report.wall_millis.coverage.applicable_attempts = report
            .wall_millis
            .coverage
            .applicable_attempts
            .saturating_add(1);
        report.wall_millis.coverage.reported_attempts = report
            .wall_millis
            .coverage
            .reported_attempts
            .saturating_add(1);
        report.wall_millis.value = report.wall_millis.value.saturating_add(wall);
        if let Some(usage) = usage.filter(|u| u.reported) {
            report.tokens.coverage.reported_attempts =
                report.tokens.coverage.reported_attempts.saturating_add(1);
            report.active_millis.coverage.reported_attempts = report
                .active_millis
                .coverage
                .reported_attempts
                .saturating_add(1);
            report.tokens.value = report
                .tokens
                .value
                .saturating_add(usage.input_tokens)
                .saturating_add(usage.output_tokens)
                .saturating_add(usage.cached_tokens);
            report.active_millis.value = report
                .active_millis
                .value
                .saturating_add(usage.active_millis);
            if let (Some(currency), Some(cost)) = (&usage.currency, usage.cost_micros) {
                let cost_report = report.costs.entry(currency.clone()).or_default();
                cost_report.coverage.applicable_attempts =
                    cost_report.coverage.applicable_attempts.saturating_add(1);
                cost_report.coverage.reported_attempts =
                    cost_report.coverage.reported_attempts.saturating_add(1);
                cost_report.value = cost_report.value.saturating_add(cost);
            }
        }
    }
    // A reported currency never makes omitted cost evidence from the other
    // applicable attempts look like a known zero.  We cannot invent a metric
    // for a currency that was never reported, but every observed currency is
    // accountable across the complete attempt set.
    for metric in report.costs.values_mut() {
        metric.coverage.applicable_attempts = report.tokens.coverage.applicable_attempts;
    }
    report
}

pub fn evaluate(mut report: EconomicsReport, limits: &BudgetLimits) -> EconomicsReport {
    report.tokens.state = metric_state(&report.tokens, limits.soft_tokens, limits.hard_tokens);
    report.active_millis.state = metric_state(
        &report.active_millis,
        limits.soft_active_millis,
        limits.hard_active_millis,
    );
    report.wall_millis.state = metric_state(
        &report.wall_millis,
        limits.soft_wall_millis,
        limits.hard_wall_millis,
    );
    for (currency, metric) in &mut report.costs {
        metric.state = metric_state(
            metric,
            limits.soft_cost_micros.get(currency).copied(),
            limits.hard_cost_micros.get(currency).copied(),
        );
    }
    let hard = report.tokens.state == LimitState::HardLimit
        || report.active_millis.state == LimitState::HardLimit
        || report.wall_millis.state == LimitState::HardLimit
        || report
            .costs
            .values()
            .any(|m| m.state == LimitState::HardLimit);
    if hard {
        report.block_reason = Some("budget.hard-limit".into());
    }
    report
}

fn metric_state(metric: &MetricReport, soft: Option<u64>, hard: Option<u64>) -> LimitState {
    if metric.coverage.state() != CoverageState::Complete && hard.is_none() && soft.is_none() {
        return LimitState::Within;
    }
    if hard.is_some_and(|limit| metric.value >= limit) {
        return LimitState::HardLimit;
    }
    if metric.coverage.state() != CoverageState::Complete {
        return LimitState::Unavailable;
    }
    if soft.is_some_and(|limit| metric.value >= limit) {
        LimitState::SoftLimit
    } else {
        LimitState::Within
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BlockerClass {
    Infrastructure,
    Environment,
    Policy,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BlockerOutcome {
    pub class: BlockerClass,
    pub at_epoch_millis: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Continuation {
    pub change: String,
    pub phase: Phase,
    pub attempt: usize,
    pub reason: String,
    pub totals_digest: String,
    pub consumed: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum BriefDecision {
    Issue,
    Warn(String),
    Block(String),
}

pub fn anti_stall_decision(
    policy: &AntiStallPolicy,
    now_epoch_millis: u64,
    last_advancement_epoch_millis: u64,
    blockers: &[BlockerOutcome],
    continuation: Option<&Continuation>,
) -> BriefDecision {
    if now_epoch_millis < last_advancement_epoch_millis {
        return BriefDecision::Block("anti-stall.clock-regression".into());
    }
    if continuation.is_some_and(|c| !c.consumed) {
        return BriefDecision::Issue;
    }
    if now_epoch_millis.saturating_sub(last_advancement_epoch_millis)
        >= policy.no_advancement_millis
    {
        return BriefDecision::Block("anti-stall.no-advancement".into());
    }
    let consecutive = blockers
        .iter()
        .rev()
        .take_while(|b| b.at_epoch_millis >= last_advancement_epoch_millis)
        .count();
    if consecutive >= policy.consecutive_blockers as usize {
        BriefDecision::Block("anti-stall.consecutive-blockers".into())
    } else {
        BriefDecision::Issue
    }
}

pub fn continuation_matches(
    c: &Continuation,
    change: &str,
    phase: Phase,
    attempt: usize,
    totals_digest: &str,
) -> bool {
    !c.consumed
        && c.change == change
        && c.phase == phase
        && c.attempt == attempt
        && c.totals_digest == totals_digest
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn usage(
        input_tokens: u64,
        output_tokens: u64,
        cached_tokens: u64,
        active_millis: u64,
        reported: bool,
        currency: Option<&str>,
        cost_micros: Option<u64>,
    ) -> UsageRecord {
        UsageRecord {
            schema: 1,
            evidence_digest: "x".into(),
            input_tokens,
            output_tokens,
            cached_tokens,
            active_millis,
            currency: currency.map(str::to_string),
            cost_micros,
            reported,
        }
    }

    #[test]
    fn missing_usage_is_not_zero_and_known_hard_limit_still_blocks() {
        let usage = UsageRecord {
            schema: 1,
            evidence_digest: "x".into(),
            input_tokens: 10,
            output_tokens: 0,
            cached_tokens: 0,
            active_millis: 0,
            currency: None,
            cost_micros: None,
            reported: true,
        };
        let report = evaluate(
            aggregate([(Some(&usage), 1), (None, 2)]),
            &BudgetLimits {
                hard_tokens: Some(10),
                ..Default::default()
            },
        );
        assert_eq!(report.tokens.state, LimitState::HardLimit);
        assert_eq!(report.wall_millis.coverage.state(), CoverageState::Complete);
    }
    #[test]
    fn partial_coverage_is_unavailable_when_not_known_over_limit() {
        let report = evaluate(
            aggregate([(None, 1)]),
            &BudgetLimits {
                hard_tokens: Some(10),
                ..Default::default()
            },
        );
        assert_eq!(report.tokens.state, LimitState::Unavailable);
    }
    #[test]
    fn clock_regression_blocks_but_read_only_report_is_pure() {
        assert!(matches!(
            anti_stall_decision(&AntiStallPolicy::default(), 1, 2, &[], None),
            BriefDecision::Block(_)
        ));
    }

    #[test]
    fn observed_currency_remains_partial_when_another_attempt_omits_cost() {
        let usd = usage(1, 2, 3, 4, true, Some("USD"), Some(5));
        let no_cost = usage(6, 7, 8, 9, true, None, None);
        let mut limits = BudgetLimits::default();
        limits.soft_cost_micros.insert("USD".into(), 10);
        let report = evaluate(aggregate([(Some(&usd), 10), (Some(&no_cost), 11)]), &limits);
        let cost = &report.costs["USD"];
        assert_eq!(cost.value, 5);
        assert_eq!(cost.coverage.applicable_attempts, 2);
        assert_eq!(cost.coverage.reported_attempts, 1);
        assert_eq!(cost.coverage.state(), CoverageState::Partial);
        assert_eq!(cost.state, LimitState::Unavailable);
    }

    proptest! {
        #[test]
        fn aggregation_saturates_and_never_wraps(
            tokens in any::<u64>(),
            active in any::<u64>(),
            wall in any::<u64>(),
            cost in any::<u64>(),
        ) {
            let evidence = usage(tokens, tokens, tokens, active, true, Some("USD"), Some(cost));
            let report = aggregate([(Some(&evidence), wall), (Some(&evidence), wall)]);
            prop_assert_eq!(report.tokens.value, tokens.saturating_mul(6));
            prop_assert_eq!(report.active_millis.value, active.saturating_mul(2));
            prop_assert_eq!(report.wall_millis.value, wall.saturating_mul(2));
            prop_assert_eq!(report.costs["USD"].value, cost.saturating_mul(2));
            prop_assert_eq!(report.tokens.coverage.state(), CoverageState::Complete);
        }

        #[test]
        fn clock_and_continuation_decisions_are_monotonic_for_fixed_inputs(
            last in any::<u64>(),
            elapsed in any::<u64>(),
            blockers in 0usize..8,
        ) {
            let policy = AntiStallPolicy {
                consecutive_blockers: 2,
                no_advancement_millis: 30,
            };
            let now = last.saturating_add(elapsed);
            let outcomes = (0..blockers)
                .map(|_| BlockerOutcome { class: BlockerClass::Infrastructure, at_epoch_millis: last })
                .collect::<Vec<_>>();
            let first = anti_stall_decision(&policy, now, last, &outcomes, None);
            let second = anti_stall_decision(&policy, now, last, &outcomes, None);
            prop_assert_eq!(first, second);
        }
    }
}
