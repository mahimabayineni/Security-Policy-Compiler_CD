"""
Phase 4: Rule Analysis (rule_analyzer.py)

Detects policy anomalies under FIRST-MATCH semantics with a DEFAULT-DENY
fallback, following the anomaly classification of Al-Shaer & Hamed
("Firewall Policy Advisor", IEEE INFOCOM 2004).

For rules Ri before Rj (i < j), using the set relations in policy_semantics.py:

  Rj equivalent to Ri, same action      -> EXACT_DUPLICATE     (Rj unreachable)
  Rj equivalent to Ri, different action -> CONFLICT            (Rj unreachable, contradictory intent)
  Ri covers Rj, same action             -> REDUNDANT_SUBSUMED  (Rj unreachable)
  Ri covers Rj, different action        -> SHADOWED_RULE       (Rj unreachable, its action never applies)
  Rj covers Ri, same action, and no rule
     between them overlaps Ri with a
     different action                   -> REDUNDANT_PRECEDING (Ri can be removed safely)
  Rj covers Ri, different action        -> GENERALIZATION      (Ri is an exception to Rj; usually intended)
  partial overlap, different actions    -> CORRELATION         (outcome depends on rule order)

Unreachable rules are reported once, against the first live rule that covers
them, and are then excluded from further comparisons so they cannot generate
misleading follow-on reports.

Limitation: reachability is checked pairwise. A rule covered only by the
UNION of several earlier rules is not reported as unreachable.
"""

from enum import Enum
from typing import List, Optional, Set

from src.parser import PolicyNode, RuleNode
from src.policy_semantics import describe, rule_covers, rule_equivalent, rule_overlaps


class AnomalyType(Enum):
    EXACT_DUPLICATE = "Exact Duplicate"
    CONFLICT = "Direct Conflict"
    SHADOWED_RULE = "Shadowed Rule"
    REDUNDANT_SUBSUMED = "Redundant Subsumed Rule"
    REDUNDANT_PRECEDING = "Redundant Preceding Rule"
    GENERALIZATION = "Generalization"
    CORRELATION = "Correlation"


class AnomalySeverity(Enum):
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"


class RuleAnomaly:
    """A detected anomaly between two rules."""

    def __init__(
        self,
        anomaly_type: AnomalyType,
        severity: AnomalySeverity,
        prior_rule: RuleNode,
        later_rule: RuleNode,
        explanation: str,
        affected_rule: Optional[RuleNode] = None,
    ):
        self.anomaly_type = anomaly_type
        self.severity = severity
        self.prior_rule = prior_rule
        self.later_rule = later_rule
        self.explanation = explanation
        # The rule the finding is about (usually the later one).
        self.affected_rule = affected_rule or later_rule

    def __repr__(self) -> str:
        return (f"RuleAnomaly({self.anomaly_type.name}, {self.severity.name}, "
                f"{self.prior_rule.name} <-> {self.later_rule.name})")


class AnalysisReport:
    """All anomalies found in a policy."""

    def __init__(self):
        self.anomalies: List[RuleAnomaly] = []
        self.unreachable_rules: List[RuleNode] = []

    def add(self, anomaly: RuleAnomaly) -> None:
        self.anomalies.append(anomaly)

    def has_errors(self) -> bool:
        return any(a.severity == AnomalySeverity.ERROR for a in self.anomalies)

    def count(self, severity: AnomalySeverity) -> int:
        return sum(1 for a in self.anomalies if a.severity == severity)

    def format_report(self) -> str:
        lines = ["=" * 70, "RULE ANALYSIS REPORT (First-Match Semantics, Default BLOCK)", "=" * 70]
        if not self.anomalies:
            lines.append("No rule anomalies or conflicts detected.")
            lines.append("All rules are distinct, reachable, and logically consistent.")
            return "\n".join(lines)

        lines.append(
            f"{len(self.anomalies)} finding(s): {self.count(AnomalySeverity.ERROR)} error, "
            f"{self.count(AnomalySeverity.WARNING)} warning, {self.count(AnomalySeverity.INFO)} info"
        )
        for i, a in enumerate(self.anomalies, 1):
            lines.append("")
            lines.append(f"[{a.severity.value}] Issue #{i}: {a.anomaly_type.value}")
            lines.append(f"  Affects     : '{a.affected_rule.name}' (Line {a.affected_rule.line})")
            lines.append(f"  Prior Rule  : '{a.prior_rule.name}' (Line {a.prior_rule.line}) {describe(a.prior_rule)} -> {a.prior_rule.action}")
            lines.append(f"  Later Rule  : '{a.later_rule.name}' (Line {a.later_rule.line}) {describe(a.later_rule)} -> {a.later_rule.action}")
            lines.append(f"  Explanation : {a.explanation}")
        if self.unreachable_rules:
            names = ", ".join(r.name for r in self.unreachable_rules)
            lines.append("")
            lines.append(f"Unreachable rules (never fire): {names}")
        return "\n".join(lines)


class RuleAnalyzer:
    """Pairwise anomaly detection over an ordered rule list."""

    def __init__(self, policy: PolicyNode):
        self.policy = policy
        self.report = AnalysisReport()

    def analyze(self) -> AnalysisReport:
        rules = self.policy.rules
        dead: Set[int] = set()
        reported_redundant: Set[int] = set()

        for j, later in enumerate(rules):
            # 1) Is the later rule unreachable? Report against the first live rule covering it.
            for i in range(j):
                if i in dead:
                    continue
                prior = rules[i]
                if rule_covers(prior, later):
                    self.report.add(self._unreachable_anomaly(prior, later))
                    self.report.unreachable_rules.append(later)
                    dead.add(j)
                    break
            if j in dead:
                continue

            # 2) Relations between two reachable rules.
            for i in range(j):
                if i in dead:
                    continue
                prior = rules[i]
                if rule_covers(later, prior):
                    if prior.action == later.action:
                        if i not in reported_redundant and not self._conflicting_rule_between(rules, dead, i, j):
                            reported_redundant.add(i)
                            self.report.add(RuleAnomaly(
                                AnomalyType.REDUNDANT_PRECEDING, AnomalySeverity.INFO, prior, later,
                                f"'{prior.name}' is redundant: '{later.name}' is broader with the same action "
                                f"({later.action}) and no rule between them overrides it, so removing "
                                f"'{prior.name}' changes no packet's outcome.",
                                affected_rule=prior,
                            ))
                    else:
                        self.report.add(RuleAnomaly(
                            AnomalyType.GENERALIZATION, AnomalySeverity.INFO, prior, later,
                            f"'{prior.name}' ({prior.action}) is an exception carved out of the broader rule "
                            f"'{later.name}' ({later.action}). This is usually intentional, but the two rules "
                            "must never be reordered.",
                            affected_rule=prior,
                        ))
                elif prior.action != later.action and rule_overlaps(prior, later):
                    self.report.add(RuleAnomaly(
                        AnomalyType.CORRELATION, AnomalySeverity.WARNING, prior, later,
                        f"'{prior.name}' and '{later.name}' partially overlap with different actions. "
                        f"Packets in the overlap get {prior.action} only because '{prior.name}' comes first; "
                        "swapping the rules would change the policy.",
                    ))
        return self.report

    @staticmethod
    def _unreachable_anomaly(prior: RuleNode, later: RuleNode) -> RuleAnomaly:
        if rule_equivalent(prior, later):
            if prior.action == later.action:
                return RuleAnomaly(
                    AnomalyType.EXACT_DUPLICATE, AnomalySeverity.WARNING, prior, later,
                    f"'{later.name}' matches exactly the same traffic as '{prior.name}' with the same "
                    f"action ({prior.action}). It is redundant and never evaluated.",
                )
            return RuleAnomaly(
                AnomalyType.CONFLICT, AnomalySeverity.ERROR, prior, later,
                f"Contradictory actions for identical traffic: '{prior.name}' says {prior.action}, "
                f"'{later.name}' says {later.action}. Under first-match semantics '{prior.name}' always "
                f"wins, so '{later.name}' is unreachable.",
            )
        if prior.action == later.action:
            return RuleAnomaly(
                AnomalyType.REDUNDANT_SUBSUMED, AnomalySeverity.INFO, prior, later,
                f"'{later.name}' is a subset of the broader earlier rule '{prior.name}' with the same "
                f"action ({prior.action}). It can never be reached.",
            )
        return RuleAnomaly(
            AnomalyType.SHADOWED_RULE, AnomalySeverity.ERROR, prior, later,
            f"'{later.name}' ({later.action}) is completely shadowed by the broader earlier rule "
            f"'{prior.name}' ({prior.action}). Its action can never take effect; if it is meant as "
            "an exception, move it above the broader rule.",
        )

    @staticmethod
    def _conflicting_rule_between(rules: List[RuleNode], dead: Set[int], i: int, j: int) -> bool:
        target = rules[i]
        return any(
            k not in dead and rules[k].action != target.action and rule_overlaps(rules[k], target)
            for k in range(i + 1, j)
        )


def analyze_rules(policy: PolicyNode) -> AnalysisReport:
    """Helper function to run rule anomaly analysis."""
    return RuleAnalyzer(policy).analyze()
