"""Unit tests for the set-based match semantics (policy_semantics.py) and runtime.py."""

import unittest

from src.lexer import tokenize
from src.parser import parse
from src.policy_semantics import rule_covers, rule_equivalent, rule_overlaps, source_covers, source_overlaps
from src.runtime import match_source


def R(text):
    return parse(tokenize(f"RULE X {text}")).rules[0]


class TestSourceSemantics(unittest.TestCase):

    def test_any_covers_everything(self):
        for s in ("INTERNAL", "EXTERNAL", "UNKNOWN", "10.0.0.0/8", "1.2.3.4"):
            self.assertTrue(source_covers("ANY", s))
            self.assertFalse(source_covers(s, "ANY"))

    def test_cidr_containment(self):
        self.assertTrue(source_covers("10.0.0.0/8", "10.1.0.0/16"))
        self.assertTrue(source_covers("10.1.0.0/16", "10.1.2.3"))
        self.assertFalse(source_covers("10.1.0.0/16", "10.0.0.0/8"))

    def test_internal_and_external_regions(self):
        self.assertTrue(source_covers("INTERNAL", "172.16.5.0/24"))
        self.assertFalse(source_covers("INTERNAL", "8.8.8.0/24"))
        self.assertTrue(source_covers("EXTERNAL", "8.8.8.0/24"))
        self.assertFalse(source_covers("EXTERNAL", "10.0.0.0/7"))  # straddles 10/8
        self.assertTrue(source_overlaps("EXTERNAL", "10.0.0.0/7"))
        self.assertFalse(source_overlaps("UNKNOWN", "10.0.0.0/8"))

    def test_ip_equals_slash_32(self):
        self.assertTrue(source_covers("1.2.3.4", "1.2.3.4/32"))
        self.assertTrue(source_covers("1.2.3.4/32", "1.2.3.4"))

    def test_rule_relations(self):
        broad = R("WHEN ANY PORT ANY IF SOURCE INTERNAL THEN ALLOW")
        narrow = R("WHEN TCP PORT 22 IF SOURCE 10.0.0.0/24 THEN ALLOW")
        other = R("WHEN UDP PORT 22 IF SOURCE ANY THEN BLOCK")
        self.assertTrue(rule_covers(broad, narrow))
        self.assertFalse(rule_covers(narrow, broad))
        self.assertFalse(rule_overlaps(narrow, other))
        self.assertTrue(rule_overlaps(broad, other))
        self.assertTrue(rule_equivalent(R("WHEN ICMP PORT 0 IF SOURCE ANY THEN ALLOW"),
                                        R("WHEN ICMP PORT ANY IF SOURCE ANY THEN ALLOW")))


class TestRuntime(unittest.TestCase):

    def test_match_source(self):
        self.assertTrue(match_source("192.168.1.5", "INTERNAL"))
        self.assertFalse(match_source("8.8.8.8", "INTERNAL"))
        self.assertTrue(match_source("8.8.8.8", "EXTERNAL"))
        self.assertTrue(match_source("unknown", "UNKNOWN"))
        self.assertFalse(match_source("INTERNAL", "10.0.0.0/8"))
        self.assertTrue(match_source("10.9.9.9", "10.0.0.0/8"))
        self.assertTrue(match_source("anything", "ANY"))


if __name__ == "__main__":
    unittest.main()
