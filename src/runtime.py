"""
Packet-Matching Runtime (runtime.py)

The single definition of how a rule's SOURCE condition matches a packet.
It is used by three consumers, which therefore can never disagree:
  1. the reference AST interpreter (code_generator.evaluate_packet),
  2. the IR virtual machine (ir_vm.py),
  3. every generated Python policy (the code generator copies the block
     below the marker into the output file verbatim).

Everything below the marker must stay self-contained (standard library only).
"""

# --- runtime begin ---
import ipaddress

# INTERNAL means the RFC 1918 private ranges; EXTERNAL is every other IPv4 address.
INTERNAL_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)

SOURCE_LABELS = ("UNKNOWN", "INTERNAL", "EXTERNAL")


def _parse_ipv4(text):
    try:
        return ipaddress.IPv4Address(text)
    except ValueError:
        return None


def match_source(packet_source, rule_source):
    """Return True if a packet's source satisfies a rule's SOURCE condition.

    A packet source is either an IPv4 address or one of the labels
    UNKNOWN / INTERNAL / EXTERNAL (used when the address is not known).
    """
    pkt = str(packet_source).strip()
    pkt_label = pkt.upper()
    rule = str(rule_source).strip()
    rule_label = rule.upper()

    if rule_label == "ANY":
        return True

    pkt_ip = _parse_ipv4(pkt)

    if rule_label in SOURCE_LABELS:
        if pkt_label == rule_label:
            return True
        if pkt_ip is None:
            # A different label (or an unparseable source) never matches.
            return False
        is_internal = any(pkt_ip in net for net in INTERNAL_NETWORKS)
        if rule_label == "INTERNAL":
            return is_internal
        if rule_label == "EXTERNAL":
            return not is_internal
        return False  # UNKNOWN only matches packets labelled UNKNOWN

    # Rule source is an IPv4 address or CIDR block; labels never match it.
    if pkt_ip is None:
        return False
    try:
        return pkt_ip in ipaddress.ip_network(rule, strict=False)
    except ValueError:
        return False
