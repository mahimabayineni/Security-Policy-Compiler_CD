"""
Phase 7: Code Generation & Safe Simulation (code_generator.py)

Generates standalone, readable Python code that implements the compiled policy.
Provides an in-memory packet evaluator for safe simulation.

Academic Note: Evaluates purely simulated packet records (Python dictionaries).
Never accesses OS networking, sockets, or real firewall components.
"""

import ipaddress
from typing import Any, Dict, List, Optional
from src.parser import PolicyNode, RuleNode


class SimulatedPacket:
    """Represents a simulated packet data record."""

    def __init__(self, protocol: str, port: int, source: str):
        self.protocol = protocol.upper()
        self.port = int(port)
        self.source = source.strip()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol": self.protocol,
            "port": self.port,
            "source": self.source,
        }

    def __repr__(self) -> str:
        return f"Packet({self.protocol}:{self.port}, src='{self.source}')"


def match_source_condition(packet_source: str, rule_source: str) -> bool:
    """Safely checks if packet source matches a rule's source criteria."""
    rule_src = rule_source.strip().upper()
    pkt_src = packet_source.strip()
    pkt_src_upper = pkt_src.upper()

    # Rule matches ANY
    if rule_src == "ANY":
        return True

    # Exact named match (e.g. UNKNOWN == UNKNOWN, INTERNAL == INTERNAL)
    if pkt_src_upper == rule_src:
        return True

    # Named categories vs IP addresses
    if rule_src == "INTERNAL":
        try:
            ip = ipaddress.ip_address(pkt_src)
            return ip.is_private
        except ValueError:
            return False

    if rule_src == "EXTERNAL":
        try:
            ip = ipaddress.ip_address(pkt_src)
            return not ip.is_private
        except ValueError:
            return True  # Non-internal or external label

    if rule_src == "UNKNOWN":
        return pkt_src_upper == "UNKNOWN"

    # CIDR subnet match (e.g., rule specifies 192.168.1.0/24)
    if "/" in rule_source:
        try:
            network = ipaddress.ip_network(rule_source, strict=False)
            ip = ipaddress.ip_address(pkt_src)
            return ip in network
        except ValueError:
            return False

    # Exact IP address match
    try:
        rule_ip = ipaddress.ip_address(rule_source)
        pkt_ip = ipaddress.ip_address(pkt_src)
        return rule_ip == pkt_ip
    except ValueError:
        return rule_source.lower() == pkt_src.lower()


def evaluate_packet(policy: PolicyNode, packet: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluates a single simulated packet against the policy AST using First-Match semantics.
    Returns: {"action": "ALLOW"|"BLOCK", "matched_rule": str, "packet": dict}
    """
    pkt_proto = str(packet.get("protocol", "")).upper()
    pkt_port = int(packet.get("port", 0))
    pkt_src = str(packet.get("source", ""))

    for rule in policy.rules:
        # 1. Protocol check
        if rule.protocol != "ANY" and rule.protocol != pkt_proto:
            continue

        # 2. Port check
        if rule.port != "ANY" and int(rule.port) != pkt_port:
            continue

        # 3. Source check
        if not match_source_condition(pkt_src, rule.source):
            continue

        # First match found!
        return {
            "action": rule.action,
            "matched_rule": rule.name,
            "matched_line": rule.line,
            "packet": packet,
            "reason": f"Matched rule '{rule.name}' ({rule.protocol}:{rule.port} from {rule.source})",
        }

    # Default-Deny Fallback
    return {
        "action": "BLOCK",
        "matched_rule": "DEFAULT_FALLBACK",
        "matched_line": -1,
        "packet": packet,
        "reason": "No policy rule matched. Default policy is BLOCK.",
    }


def simulate_packets(policy: PolicyNode, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Evaluates a batch of simulated packets against the policy."""
    return [evaluate_packet(policy, pkt) for pkt in packets]


def generate_python_code(policy: PolicyNode) -> str:
    """
    Generates standalone, readable Python target code that executes the compiled policy.
    """
    code_lines = [
        '"""',
        'Auto-Generated Security Policy Evaluator',
        'Compiled by: Domain-Specific Security Policy Compiler',
        'Semantics  : First-Match with Default-Deny (BLOCK)',
        '"""',
        '',
        'import ipaddress',
        'from typing import Any, Dict',
        '',
        '',
        'def _match_source(pkt_src: str, rule_src: str) -> bool:',
        '    rule_src_u = rule_src.strip().upper()',
        '    pkt_src_u = pkt_src.strip().upper()',
        '    if rule_src_u == "ANY":',
        '        return True',
        '    if pkt_src_u == rule_src_u:',
        '        return True',
        '    if rule_src_u == "INTERNAL":',
        '        try:',
        '            return ipaddress.ip_address(pkt_src).is_private',
        '        except ValueError:',
        '            return False',
        '    if rule_src_u == "EXTERNAL":',
        '        try:',
        '            return not ipaddress.ip_address(pkt_src).is_private',
        '        except ValueError:',
        '            return True',
        '    if rule_src_u == "UNKNOWN":',
        '        return pkt_src_u == "UNKNOWN"',
        '    if "/" in rule_src:',
        '        try:',
        '            net = ipaddress.ip_network(rule_src, strict=False)',
        '            return ipaddress.ip_address(pkt_src) in net',
        '        except ValueError:',
        '            return False',
        '    try:',
        '        return ipaddress.ip_address(rule_src) == ipaddress.ip_address(pkt_src)',
        '    except ValueError:',
        '        return rule_src.lower() == pkt_src.lower()',
        '',
        '',
        'def evaluate_packet(packet: Dict[str, Any]) -> Dict[str, Any]:',
        '    """Evaluates an incoming packet dictionary against compiled policy rules."""',
        '    proto = str(packet.get("protocol", "")).upper()',
        '    port = int(packet.get("port", 0))',
        '    src = str(packet.get("source", ""))',
        '',
    ]

    for idx, rule in enumerate(policy.rules, 1):
        conditions = []
        if rule.protocol != "ANY":
            conditions.append(f'proto == "{rule.protocol}"')
        if rule.port != "ANY":
            conditions.append(f'port == {rule.port}')
        if rule.source.upper() != "ANY":
            conditions.append(f'_match_source(src, "{rule.source}")')

        cond_expr = " and ".join(conditions) if conditions else "True"

        code_lines.append(f'    # Rule {idx}: {rule.name} [Line {rule.line}]')
        code_lines.append(f'    if {cond_expr}:')
        code_lines.append('        return {')
        code_lines.append(f'            "action": "{rule.action}",')
        code_lines.append(f'            "matched_rule": "{rule.name}",')
        code_lines.append(f'            "reason": "Matched Rule {rule.name} (action: {rule.action})"')
        code_lines.append('        }')
        code_lines.append('')

    # Default fallback
    code_lines.extend([
        '    # Default Fallback (First-Match Default Deny)',
        '    return {',
        '        "action": "BLOCK",',
        '        "matched_rule": "DEFAULT_FALLBACK",',
        '        "reason": "No policy rule matched. Default policy is BLOCK."',
        '    }',
        '',
        '',
        'if __name__ == "__main__":',
        '    # Demonstration with sample packets',
        '    sample_packets = [',
        '        {"protocol": "TCP", "port": 22, "source": "UNKNOWN"},',
        '        {"protocol": "TCP", "port": 443, "source": "192.168.1.50"},',
        '        {"protocol": "TCP", "port": 80, "source": "10.0.0.1"},',
        '        {"protocol": "UDP", "port": 53, "source": "8.8.8.8"},',
        '    ]',
        '    print("=" * 60)',
        '    print("EXECUTING COMPILED SECURITY POLICY SIMULATION")',
        '    print("=" * 60)',
        '    for p in sample_packets:',
        '        res = evaluate_packet(p)',
        '        print(f"Packet: {p} -> ACTION: {res[\'action\']} ({res[\'reason\']})")',
        '    print("=" * 60)',
    ])

    return "\n".join(code_lines)


def format_simulation_table(results: List[Dict[str, Any]]) -> str:
    """Formats simulation outcomes into an ASCII presentation table."""
    col_pkt = 34
    col_rule = 18
    col_action = 10
    total_len = col_pkt + col_rule + col_action + 10
    sep = "+" + "-" * (total_len - 2) + "+"

    lines = [
        sep,
        f"| {'PACKET (Proto:Port From Source)':<{col_pkt}} | {'MATCHED RULE':<{col_rule}} | {'ACTION':<{col_action}} |",
        sep,
    ]
    for r in results:
        pkt = r["packet"]
        pkt_str = f"{pkt.get('protocol')}:{pkt.get('port')} src={pkt.get('source')}"
        rule_str = r.get("matched_rule", "")
        action_str = r.get("action", "")
        lines.append(f"| {pkt_str:<{col_pkt}} | {rule_str:<{col_rule}} | {action_str:<{col_action}} |")
    lines.append(sep)
    return "\n".join(lines)
