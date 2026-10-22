"""
Phase 5: Policy Optimization (optimizer.py)

Removes rules whose removal provably changes no packet's outcome under
first-match, default-deny semantics. Passes run to a fixed point:

  Pass 1  Unreachable-rule elimination (dead code):
          a rule covered by an earlier rule never fires, whatever its action.
            ELIMINATE_EXACT_DUPLICATE   identical match, same action
            ELIMINATE_DEAD_CONFLICT     identical match, different action
            ELIMINATE_SUBSUMED          strict subset, same action
            ELIMINATE_SHADOWED          strict subset, different action
  Pass 2  Redundant-preceding elimination:
          Ri is removed if a later Rj covers it with the same action and no rule
          between them overlaps Ri with a different action (packets that used to
          hit Ri now fall through to Rj and get the same action).
  Pass 3  (only with aggressive=True, the -O2 level)
          Default-deny elimination: a BLOCK rule that no later ALLOW rule overlaps
          is redundant with the default BLOCK. Off by default because explicit
          BLOCK rules usually serve as documentation.

Correctness is checked independently by verifier.py, which compares the
original and optimized policies on every packet equivalence class.
"""

from typing import List, Optional

from src.parser import PolicyNode, RuleNode
from src.policy_semantics import rule_covers, rule_equivalent, rule_overlaps


class OptimizationAction:
    """Audit record of a single eliminated rule."""

    def __init__(self, action_type: str, removed_rule: RuleNode, reason: str, primary_rule: Optional[RuleNode] = None):
        self.action_type = action_type
        self.removed_rule = removed_rule
        self.reason = reason
        self.primary_rule = primary_rule

    def __repr__(self) -> str:
        return f"OptimizationAction({self.action_type}, removed='{self.removed_rule.name}')"


class OptimizationResult:
    """Optimized policy plus statistics and an audit trail."""

    def __init__(self, original_policy: PolicyNode, optimized_policy: PolicyNode,
                 actions: List[OptimizationAction], aggressive: bool = False):
        self.original_policy = original_policy
        self.optimized_policy = optimized_policy
        self.actions = actions
        self.aggressive = aggressive

    @property
    def original_count(self) -> int:
        return len(self.original_policy.rules)

    @property
    def optimized_count(self) -> int:
        return len(self.optimized_policy.rules)

    def rules_removed_count(self) -> int:
        return self.original_count - self.optimized_count

    def format_report(self) -> str:
        level = "O2 (aggressive)" if self.aggressive else "O1 (default)"
        lines = [
            "=" * 70, "POLICY OPTIMIZATION REPORT", "=" * 70,
            f"Optimization Level   : {level}",
            f"Original Rule Count  : {self.original_count}",
            f"Optimized Rule Count : {self.optimized_count}",
            f"Rules Eliminated     : {self.rules_removed_count()}",
        ]
        if not self.actions:
            lines.append("No optimizations needed. Policy is already minimal.")
        else:
            lines.append("")
            lines.append("Optimization Audit Trail:")
            for i, act in enumerate(self.actions, 1):
                lines.append(f"  {i}. [{act.action_type}] Removed '{act.removed_rule.name}' (Line {act.removed_rule.line})")
                lines.append(f"     Reason: {act.reason}")
        lines.append("")
        lines.append("Optimized rule order: " + (" -> ".join(r.name for r in self.optimized_policy.rules) or "(none)")
                     + " -> DEFAULT BLOCK")
        return "\n".join(lines)


class PolicyOptimizer:
    """Semantics-preserving rule elimination."""

    def __init__(self, policy: PolicyNode):
        self.policy = policy

    def optimize(self, aggressive: bool = False) -> OptimizationResult:
        rules = list(self.policy.rules)
        actions: List[OptimizationAction] = []

        changed = True
        while changed:
            rules, removed_dead = self._eliminate_unreachable(rules, actions)
            rules, removed_prec = self._eliminate_redundant_preceding(rules, actions)
            removed_default = False
            if aggressive:
                rules, removed_default = self._eliminate_default_redundant(rules, actions)
            changed = removed_dead or removed_prec or removed_default

        return OptimizationResult(self.policy, PolicyNode(rules), actions, aggressive)

    # ---- Pass 1 ----------------------------------------------------------------------
    @staticmethod
    def _eliminate_unreachable(rules: List[RuleNode], actions: List[OptimizationAction]):
        kept: List[RuleNode] = []
        removed = False
        for cand in rules:
            prior = next((p for p in kept if rule_covers(p, cand)), None)
            if prior is None:
                kept.append(cand)
                continue
            removed = True
            same = prior.action == cand.action
            if rule_equivalent(prior, cand):
                kind = "ELIMINATE_EXACT_DUPLICATE" if same else "ELIMINATE_DEAD_CONFLICT"
                why = (f"Identical to earlier rule '{prior.name}'" +
                       ("." if same else f"; '{prior.name}' ({prior.action}) always wins over {cand.action}."))
            else:
                kind = "ELIMINATE_SUBSUMED" if same else "ELIMINATE_SHADOWED"
                why = (f"Fully covered by earlier broader rule '{prior.name}' ({prior.action}); "
                       "this rule can never be reached.")
            actions.append(OptimizationAction(kind, cand, why, prior))
        return kept, removed

    # ---- Pass 2 ----------------------------------------------------------------------
    @staticmethod
    def _eliminate_redundant_preceding(rules: List[RuleNode], actions: List[OptimizationAction]):
        for i, ri in enumerate(rules):
            for j in range(i + 1, len(rules)):
                rj = rules[j]
                if rj.action != ri.action or not rule_covers(rj, ri):
                    continue
                blocked = any(rules[k].action != ri.action and rule_overlaps(rules[k], ri) for k in range(i + 1, j))
                if not blocked:
                    actions.append(OptimizationAction(
                        "ELIMINATE_REDUNDANT_PRECEDING", ri,
                        f"Later rule '{rj.name}' covers it with the same action ({rj.action}) and no rule "
                        "in between overrides it.", rj,
                    ))
                    return rules[:i] + rules[i + 1:], True
        return rules, False

    # ---- Pass 3 (O2) ------------------------------------------------------------------
    @staticmethod
    def _eliminate_default_redundant(rules: List[RuleNode], actions: List[OptimizationAction]):
        for i, ri in enumerate(rules):
            if ri.action != "BLOCK":
                continue
            if not any(r.action == "ALLOW" and rule_overlaps(r, ri) for r in rules[i + 1:]):
                actions.append(OptimizationAction(
                    "ELIMINATE_DEFAULT_REDUNDANT", ri,
                    "No later ALLOW rule overlaps it, so the default BLOCK already gives the same result.",
                ))
                return rules[:i] + rules[i + 1:], True
        return rules, False


def optimize_policy(policy: PolicyNode, aggressive: bool = False) -> OptimizationResult:
    """Helper function to optimize a policy."""
    return PolicyOptimizer(policy).optimize(aggressive=aggressive)
