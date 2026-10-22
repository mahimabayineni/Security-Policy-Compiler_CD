"""
Policy Match-Space Semantics (policy_semantics.py)

Set-theoretic reasoning over the traffic a rule matches. Every rule condition
denotes a set of packets; the analyzer and optimizer reason about these sets:

  covers(A, B)      every packet matched by B is also matched by A   (B is a subset of A)
  overlaps(A, B)    at least one packet is matched by both
  equivalent(A, B)  A and B match exactly the same packets

Sources are compared semantically, not textually: INTERNAL is the union of the
RFC 1918 ranges, EXTERNAL is its complement, and an IP address is a /32 block.
So `10.0.0.1` and `10.0.0.1/32` are equivalent, and INTERNAL covers 192.168.1.0/24.

Unparseable values are treated conservatively: they cover nothing and are
assumed to overlap everything, so the optimizer never removes a rule on the
strength of a value it does not understand.
"""

import ipaddress
from typing import Optional, Union

from src.runtime import INTERNAL_NETWORKS

NAMED_SOURCES = ("ANY", "UNKNOWN", "INTERNAL", "EXTERNAL")

SourceValue = Union[str, ipaddress.IPv4Network]


def effective_port(rule) -> Union[int, str]:
    """ICMP has no ports, so `ICMP PORT 0` means the same as `ICMP PORT ANY`."""
    port = rule.port
    if isinstance(port, str):
        return port.upper()
    if rule.protocol == "ICMP" and port == 0:
        return "ANY"
    return port


def source_value(src: str) -> Optional[SourceValue]:
    text = str(src).strip()
    if text.upper() in NAMED_SOURCES:
        return text.upper()
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None
    return net if net.version == 4 else None


def _inside_internal(net: ipaddress.IPv4Network) -> bool:
    return any(net.subnet_of(block) for block in INTERNAL_NETWORKS)


def _touches_internal(net: ipaddress.IPv4Network) -> bool:
    return any(net.overlaps(block) for block in INTERNAL_NETWORKS)


def source_covers(broad: str, narrow: str) -> bool:
    b, n = source_value(broad), source_value(narrow)
    if b is None or n is None:
        return False
    if b == "ANY":
        return True
    if n == "ANY":
        return False
    if isinstance(b, str) and isinstance(n, str):
        return b == n
    if isinstance(b, str):  # named broad, network narrow
        if b == "INTERNAL":
            return _inside_internal(n)
        if b == "EXTERNAL":
            return not _touches_internal(n)
        return False  # UNKNOWN contains no addresses
    if isinstance(n, str):  # network broad, named narrow: labels never match networks
        return False
    return n.subnet_of(b)


def source_overlaps(a: str, b: str) -> bool:
    x, y = source_value(a), source_value(b)
    if x is None or y is None:
        return True
    if x == "ANY" or y == "ANY":
        return True
    if isinstance(x, str) and isinstance(y, str):
        return x == y
    if isinstance(x, str) or isinstance(y, str):
        named, net = (x, y) if isinstance(x, str) else (y, x)
        if named == "INTERNAL":
            return _touches_internal(net)
        if named == "EXTERNAL":
            return not _inside_internal(net)
        return False
    return x.overlaps(y)


def _field_covers(broad, narrow) -> bool:
    return broad == "ANY" or broad == narrow


def _field_overlaps(a, b) -> bool:
    return a == "ANY" or b == "ANY" or a == b


def rule_covers(broad, narrow) -> bool:
    """True if `broad` matches every packet that `narrow` matches."""
    return (
        _field_covers(broad.protocol, narrow.protocol)
        and _field_covers(effective_port(broad), effective_port(narrow))
        and source_covers(broad.source, narrow.source)
    )


def rule_overlaps(a, b) -> bool:
    return (
        _field_overlaps(a.protocol, b.protocol)
        and _field_overlaps(effective_port(a), effective_port(b))
        and source_overlaps(a.source, b.source)
    )


def rule_equivalent(a, b) -> bool:
    return rule_covers(a, b) and rule_covers(b, a)


def describe(rule) -> str:
    return f"{rule.protocol} PORT {effective_port(rule)} SRC {rule.source}"
