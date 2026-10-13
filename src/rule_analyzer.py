"""
Phase 5: Rule Analysis (rule_analyzer.py)

Performs static policy anomaly analysis under First-Match Semantics:
1. Exact Duplicate Rules: Same condition, same action (redundant).
2. Direct Conflicting Rules: Same condition, opposite action (the second is shadowed).
3. Shadowed / Subsumed Rules: An earlier broader rule supersedes a later narrower rule.

Provides detailed diagnostic explanations without falsely flagging distinct ports or protocols.
"""

from enum import Enum
import ipaddress
from typing import List, Optional
from src.parser import PolicyNode, RuleNode


class AnomalyType(Enum):
    EXACT_DUPLICATE = "Exact Duplicate"
    CONFLICT = "Conflicting Rule"
    SHADOWED_RULE = "Shadowed Rule"
    REDUNDANT_SUBSUMED = "Redundant Subsumed Rule"


class AnomalySeverity(Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class RuleAnomaly:
    """Represents a detected anomaly between two rules."""

    def __init__(
        self,
        anomaly_type: AnomalyType,
        severity: AnomalySeverity,
        prior_rule: RuleNode,
        later_rule: RuleNode,
        explanation: str,
    ):
        self.anomaly_type = anomaly_type
        self.severity = severity
        self.prior_rule = prior_rule
        self.later_rule = later_rule
        self.explanation = explanation

    def __repr__(self) -> str:
        return (
            f"[{self.severity.value}] {self.anomaly_type.value}: "
            f"'{self.later_rule.name}' [Line {self.later_rule.line}] affected by "
            f"'{self.prior_rule.name}' [Line {self.prior_rule.line}] - {self.explanation}"
        )


class AnalysisReport:
    """Container for all rule anomalies detected across a security policy."""

    def __init__(self, policy: PolicyNode):
        self.policy = policy
        self.anomalies: List[RuleAnomaly] = []

    def add_anomaly(self, anomaly: RuleAnomaly) -> None:
        self.anomalies.append(anomaly)

    def has_errors(self) -> bool:
        return any(a.severity == AnomalySeverity.ERROR for a in self.anomalies)

    def has_warnings(self) -> bool:
        return any(a.severity == AnomalySeverity.WARNING for a in self.anomalies)

    def format(self) -> str:
        """Formats the analysis report into a readable presentation."""
        lines = [
            "=" * 70,
            "RULE ANALYSIS REPORT (First-Match Semantics)",
            "=" * 70,
        ]
        if not self.anomalies:
            lines.append("No rule anomalies or conflicts detected.")
            lines.append("All rules are distinct, reachable, and logically consistent.")
            lines.append("=" * 70)
            return "\n".join(lines)

        lines.append(f"Detected {len(self.anomalies)} issue(s):\n")
        for idx, a in enumerate(self.anomalies, 1):
            lines.append(f"Issue {idx}: [{a.severity.value}] {a.anomaly_type.value}")
            lines.append(f"  Affects Rule   : '{a.later_rule.name}' [Line {a.later_rule.line}]")
            lines.append(f"  Preceding Rule : '{a.prior_rule.name}' [Line {a.prior_rule.line}]")
            lines.append(f"  Explanation    : {a.explanation}")
            lines.append("-" * 70)
        return "\n".join(lines)


class RuleAnalyzer:
    """Analyzes a security policy AST for anomalies under first-match semantics."""

    def __init__(self, policy: PolicyNode):
        self.policy = policy

    def analyze(self) -> AnalysisReport:
        report = AnalysisReport(self.policy)
        rules = self.policy.rules

        for i in range(len(rules)):
            r_first = rules[i]
            for j in range(i + 1, len(rules)):
                r_second = rules[j]
                self._compare_rules(r_first, r_second, report)

        return report

    def _compare_rules(self, r1: RuleNode, r2: RuleNode, report: AnalysisReport) -> None:
        # Check exact condition match
        same_protocol = (r1.protocol == r2.protocol)
        same_port = (r1.port == r2.port)
        same_source = (r1.source == r2.source)
        same_action = (r1.action == r2.action)

        # 1. Exact Duplicate (Identical conditions AND identical action)
        if same_protocol and same_port and same_source and same_action:
            report.add_anomaly(
                RuleAnomaly(
                    anomaly_type=AnomalyType.EXACT_DUPLICATE,
                    severity=AnomalySeverity.WARNING,
                    prior_rule=r1,
                    later_rule=r2,
                    explanation=(
                        f"Rule '{r2.name}' has identical match conditions and action ({r1.action}) "
                        f"as preceding rule '{r1.name}'. Under first-match semantics, '{r2.name}' is redundant."
                    ),
                )
            )
            return

        # 2. Direct Conflict (Identical conditions BUT opposite action)
        if same_protocol and same_port and same_source and not same_action:
            report.add_anomaly(
                RuleAnomaly(
                    anomaly_type=AnomalyType.CONFLICT,
                    severity=AnomalySeverity.ERROR,
                    prior_rule=r1,
                    later_rule=r2,
                    explanation=(
                        f"Rule '{r2.name}' specifies action {r2.action}, but preceding rule '{r1.name}' "
                        f"specifies action {r1.action} for the exact same traffic "
                        f"({r1.protocol} PORT {r1.port} FROM {r1.source}). "
                        f"Under first-match semantics, '{r2.name}' will NEVER be executed."
                    ),
                )
            )
            return

        # 3. Subsumption and Shadowing (r1 is broader than r2)
        if self._is_superset(r1, r2):
            if r1.action == r2.action:
                report.add_anomaly(
                    RuleAnomaly(
                        anomaly_type=AnomalyType.REDUNDANT_SUBSUMED,
                        severity=AnomalySeverity.INFO,
                        prior_rule=r1,
                        later_rule=r2,
                        explanation=(
                            f"Rule '{r1.name}' ({r1.protocol} PORT {r1.port} SRC {r1.source} -> {r1.action}) "
                            f"matches a broader superset of traffic than rule '{r2.name}' "
                            f"({r2.protocol} PORT {r2.port} SRC {r2.source} -> {r2.action}) with the same action. "
                            f"Rule '{r2.name}' is subsumed and can be safely eliminated."
                        ),
                    )
                )
            else:
                report.add_anomaly(
                    RuleAnomaly(
                        anomaly_type=AnomalyType.SHADOWED_RULE,
                        severity=AnomalySeverity.WARNING,
                        prior_rule=r1,
                        later_rule=r2,
                        explanation=(
                            f"Preceding rule '{r1.name}' matches a superset of traffic with action {r1.action}, "
                            f"preventing rule '{r2.name}' ({r2.action}) from ever matching. "
                            f"Rule '{r2.name}' is completely shadowed."
                        ),
                    )
                )

    def _is_superset(self, r_broad: RuleNode, r_narrow: RuleNode) -> bool:
        """Determines if r_broad matches a strict superset of r_narrow's traffic."""
        # Protocol: 'ANY' matches any specific protocol
        proto_superset = (r_broad.protocol == "ANY" and r_narrow.protocol != "ANY") or (r_broad.protocol == r_narrow.protocol)
        if not proto_superset:
            return False

        # Port: 'ANY' matches any specific port
        port_superset = (r_broad.port == "ANY" and r_narrow.port != "ANY") or (r_broad.port == r_narrow.port)
        if not port_superset:
            return False

        # Source: 'ANY' matches everything
        src_superset = self._is_source_superset(r_broad.source, r_narrow.source)
        if not src_superset:
            return False

        # Must be strictly broader in at least one attribute to be a superset
        is_strictly_broader = (
            (r_broad.protocol == "ANY" and r_narrow.protocol != "ANY")
            or (r_broad.port == "ANY" and r_narrow.port != "ANY")
            or (r_broad.source == "ANY" and r_narrow.source != "ANY")
            or self._is_strict_cidr_superset(r_broad.source, r_narrow.source)
        )
        return is_strictly_broader

    def _is_source_superset(self, broad_src: str, narrow_src: str) -> bool:
        if broad_src == "ANY":
            return True
        if broad_src == narrow_src:
            return True
        # Check CIDR containment
        if "/" in broad_src:
            try:
                net_broad = ipaddress.ip_network(broad_src, strict=False)
                if "/" in narrow_src:
                    net_narrow = ipaddress.ip_network(narrow_src, strict=False)
                    return net_broad.supernet_of(net_narrow)
                else:
                    ip_narrow = ipaddress.ip_address(narrow_src)
                    return ip_narrow in net_broad
            except ValueError:
                pass
        return False

    def _is_strict_cidr_superset(self, broad_src: str, narrow_src: str) -> bool:
        if "/" in broad_src:
            try:
                net_broad = ipaddress.ip_network(broad_src, strict=False)
                if "/" in narrow_src:
                    net_narrow = ipaddress.ip_network(narrow_src, strict=False)
                    return net_broad.supernet_of(net_narrow) and net_broad != net_narrow
                else:
                    ip_narrow = ipaddress.ip_address(narrow_src)
                    return ip_narrow in net_broad
            except ValueError:
                pass
        return False


def analyze_rules(policy: PolicyNode) -> AnalysisReport:
    """Helper function to analyze a policy AST."""
    analyzer = RuleAnalyzer(policy)
    return analyzer.analyze()
