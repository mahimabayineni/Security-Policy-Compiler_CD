# Domain-Specific Security Policy Language Grammar Specification

## 1. Overview

The **Security Policy DSL (Domain-Specific Language)** is a declarative, line-oriented language designed for defining network packet filtering and access control policies. It provides a human-readable syntax that compiles down to machine-independent intermediate representations and simulated execution programs.

---

## 2. Formal Grammar in Extended Backus-Naur Form (EBNF)

```ebnf
(* Root program structure *)
Policy          ::= Rule+ EOF

(* Individual rule definition *)
Rule            ::= "RULE" RuleIdentifier
                    MatchClause
                    ConditionClause
                    ActionClause

(* Clauses *)
MatchClause     ::= "WHEN" Protocol "PORT" PortSpec
ConditionClause ::= "IF" "SOURCE" SourceSpec
ActionClause    ::= "THEN" Action

(* Protocol specifications *)
Protocol        ::= "TCP" | "UDP" | "ICMP" | "ANY"

(* Port specification *)
PortSpec        ::= Integer | "ANY"

(* Source criteria *)
SourceSpec      ::= NamedSource | IPv4Address | CIDRSubnet
NamedSource     ::= "ANY" | "UNKNOWN" | "INTERNAL" | "EXTERNAL"

(* Filtering action *)
Action          ::= "ALLOW" | "BLOCK" | "DENY"

(* Terminals and Lexical Elements *)
RuleIdentifier  ::= [a-zA-Z_][a-zA-Z0-9_-]*
Integer         ::= [0-9]+
IPv4Address     ::= Octet "." Octet "." Octet "." Octet
CIDRSubnet      ::= IPv4Address "/" PrefixLength
Octet           ::= [0-9]{1,3}         (* Semantically constrained to 0-255 *)
PrefixLength    ::= [0-9]{1,2}         (* Semantically constrained to 0-32 *)
```

---

## 3. Lexical Tokens and Keywords

### Reserved Keywords
| Keyword | Token Type | Description |
|---|---|---|
| `RULE` | `KW_RULE` | Introduces a rule declaration block |
| `WHEN` | `KW_WHEN` | Introduces the protocol/port matching clause |
| `PORT` | `KW_PORT` | Precedes the destination port specification |
| `IF` | `KW_IF` | Introduces condition qualification clause |
| `SOURCE` | `KW_SOURCE` | Specifies packet origin / client source address |
| `THEN` | `KW_THEN` | Introduces final policy decision action |
| `ALLOW` | `KW_ALLOW` | Permits the packet to pass |
| `BLOCK` | `KW_BLOCK` | Rejects/drops the packet |
| `DENY` | `KW_DENY` | Synonym for `BLOCK` |
| `TCP` | `KW_TCP` | Transmission Control Protocol |
| `UDP` | `KW_UDP` | User Datagram Protocol |
| `ICMP` | `KW_ICMP` | Internet Control Message Protocol |
| `ANY` | `KW_ANY` | Wildcard match (protocol, port, or source) |
| `UNKNOWN` | `KW_UNKNOWN` | Packets from unrecognized or untrusted sources |
| `INTERNAL` | `KW_INTERNAL` | Packets from private IP subnets (RFC 1918) |
| `EXTERNAL` | `KW_EXTERNAL` | Packets from public / WAN addresses |

### Comments & Whitespace
- **Comments**: Start with `#` and continue until the end of the line.
- **Whitespace**: Spaces, tabs, and newlines serve as token delimiters and are skipped by the lexer, except for line and column count tracking.

---

## 4. Semantic Constraints

Even if a policy conforms to the syntactic EBNF grammar, the semantic analyzer applies the following semantic rules:

1. **Unique Rule Identifiers**: Every rule name in a policy must be unique. Duplicate names cause a fatal semantic error.
2. **Valid Port Range**: Port numbers must satisfy \( 1 \le \text{port} \le 65535 \) or be `ANY`.
3. **Protocol-Port Compatibility**: ICMP is a network-layer protocol that does not use transport port numbers. ICMP rules must specify port `ANY` or `0`.
4. **Valid IPv4 / CIDR**: IP addresses must consist of valid 4-octet values (0–255 each) and CIDR prefixes between 0 and 32.
5. **Supported Actions**: Only `ALLOW` and `BLOCK` are valid target actions.

---

## 5. Example Policy Snippet

```spol
RULE BLOCK_SSH
WHEN TCP PORT 22
IF SOURCE UNKNOWN
THEN BLOCK

RULE ALLOW_INTERNAL_WEB
WHEN TCP PORT 443
IF SOURCE 192.168.1.0/24
THEN ALLOW

RULE DEFAULT_WEB
WHEN TCP PORT 80
IF SOURCE ANY
THEN ALLOW
```
