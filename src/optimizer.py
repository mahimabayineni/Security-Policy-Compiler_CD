"""
Phase 6: Policy Optimizer (optimizer.py)

Applies safe optimization passes on the Policy AST:
1. Exact Duplicate Elimination: Prunes subsequent rules with identical criteria & action.
2. Redundant Subsumption Pruning: Prunes narrower rules completely covered by an earlier rule
   with the identical action.
3. Dead Code Elimination: Prunes completely shadowed unreachable rules while strictly preserving
   first-match behavior.

Generates an Optimization Report detailing every change made and rule count delta.
"""

from typing import List, Tuple
from src.parser import PolicyNode, RuleNode
from src.rule_analyzer import RuleAnalyzer


class OptimizationAction:
    """Records an individual optimization decision made by the optimizer."""

    def __init__(self, rule_name: str, line: int, action_type: str, explanation: str):
        self.rule_name = rule_name
        self.line = line
        self.action_type = action_type
        self.explanation = explanation

    def __repr__(self) -> str:
        return f"[{self.action_type}] Rule '{self.rule_name}' (Line {self.line}): {self.explanation}"


class OptimizationResult:
    """Contains the optimized AST, statistics, and audit log of optimizations performed."""

    def __init__(
        self,
        original_policy: PolicyNode,
        optimized_policy: PolicyNode,
        actions: List[OptimizationAction],
    ):
        self.original_policy = original_policy
        self.optimized_policy = optimized_policy
        self.actions = actions
        self.original_count = len(original_policy.rules)
        self.optimized_count = len(optimized_policy.rules)

    def rules_removed_count(self) -> int:
        return self.original_count - self.optimized_count

    def format(self) -> str:
        lines = [
            "=" * 70,
            "OPTIMIZATION REPORT",
            "=" * 70,
            f"Original Rule Count  : {self.original_count}",
            f"Optimized Rule Count : {self.optimized_count}",
            f"Rules Eliminated     : {self.rules_removed_count()}",
            "-" * 70,
        ]
        if not self.actions:
            lines.append("No optimizations needed. Policy is already minimal.")
        else:
            lines.append("Optimizations Performed:")
            for idx, act in enumerate(self.actions, 1):
                lines.append(f"  {idx}. [{act.action_type}] Rule '{act.rule_name}' [Line {act.line}]")
                lines.append(f"     Reason: {act.explanation}")
        lines.append("=" * 70)
        return "\n".join(lines)


class PolicyOptimizer:
    """Optimizes a security policy AST while rigorously preserving first-match semantics."""

    def __init__(self, policy: PolicyNode):
        self.policy = policy
        self.analyzer = RuleAnalyzer(policy)

    def optimize(self) -> OptimizationResult:
        actions: List[OptimizationAction] = []
        current_rules: List[RuleNode] = list(self.policy.rules)

        retained_rules: List[RuleNode] = []

        for i, candidate in enumerate(current_rules):
            redundancy_found = False

            # Check candidate against already retained preceding rules
            for prior in retained_rules:
                # 1. Exact Duplicate
                if (
                    prior.protocol == candidate.protocol
                    and prior.port == candidate.port
                    and prior.source == candidate.source
                    and prior.action == candidate.action
                ):
                    actions.append(
                        OptimizationAction(
                            rule_name=candidate.name,
                            line=candidate.line,
                            action_type="ELIMINATE_EXACT_DUPLICATE",
                            explanation=(
                                f"Rule '{candidate.name}' is an exact duplicate of prior rule '{prior.name}'. "
                                f"Eliminated to reduce rule table traversal without altering policy behavior."
                            ),
                        )
                    )
                    redundancy_found = True
                    break

                # 2. Redundant Subsumed (Prior is broader with SAME action)
                if self.analyzer._is_superset(prior, candidate) and prior.action == candidate.action:
                    actions.append(
                        OptimizationAction(
                            rule_name=candidate.name,
                            line=candidate.line,
                            action_type="ELIMINATE_SUBSUMED",
                            explanation=(
                                f"Rule '{candidate.name}' ({candidate.protocol}:{candidate.port} "
                                f"SRC {candidate.source} -> {candidate.action}) is completely covered by broader "
                                f"prior rule '{prior.name}' ({prior.protocol}:{prior.port} "
                                f"SRC {prior.source} -> {prior.action}). Safely pruned."
                            ),
                        )
                    )
                    redundancy_found = True
                    break

                # 3. Unreachable Dead Code (Prior is exact match or broader with OPPOSITE action)
                if (
                    prior.protocol == candidate.protocol
                    and prior.port == candidate.port
                    and prior.source == candidate.source
                    and prior.action != candidate.action
                ):
                    actions.append(
                        OptimizationAction(
                            rule_name=candidate.name,
                            line=candidate.line,
                            action_type="ELIMINATE_DEAD_CONFLICT",
                            explanation=(
                                f"Rule '{candidate.name}' ({candidate.action}) matches the exact condition as "
                                f"prior rule '{prior.name}' ({prior.action}). Under first-match semantics, "
                                f"'{candidate.name}' is unreachable dead code and was safely pruned."
                            ),
                        )
                    )
                    redundancy_found = True
                    break

            if not redundancy_found:
                retained_rules.append(candidate)

        optimized_ast = PolicyNode(retained_rules)
        return OptimizationResult(self.policy, optimized_ast, actions)


def optimize_policy(policy: PolicyNode) -> OptimizationResult:
    """Helper function to optimize a policy AST."""
    opt = PolicyOptimizer(policy)
    return opt.optimize()
