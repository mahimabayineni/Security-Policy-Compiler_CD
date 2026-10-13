# Domain-Specific Security Policy Compiler for Automated Rule Analysis and Optimization

An educational, modular implementation of a college Compiler Design project demonstrating the translation, validation, intermediate code generation, anomaly analysis, safe optimization, and code generation for a domain-specific security policy language.

> [!NOTE]
> **Academic Project Notice**: This compiler is designed for educational and demonstration purposes. It performs simulation on synthetic packet dictionaries and **does not** configure real OS firewalls, bind raw sockets, or alter actual network security settings.

---

## 1. Project Overview

In network security and cloud infrastructure, firewall and access control rules often grow into thousands of policy statements. Over time, human administrators introduce duplicate rules, contradictory/conflicting actions, and shadowed rules that waste hardware memory and lead to severe security misconfigurations.

This project implements a **Domain-Specific Language (DSL) Compiler** for security policies. By treating security rules as formal language statements, the compiler parses policies through standard compiler phases, builds intermediate representations, detects logical anomalies, eliminates safe redundancies, and emits optimized, executable policy evaluation programs.

---

## 2. Key Objectives & Features

- **Formal Compiler Pipeline**: Implements all classic compiler phases (Lexing, LL(1) Parsing, Semantic Validation, Three-Address Intermediate Code, Static Analysis, Optimization, and Target Code Generation).
- **Rule Anomaly Detection**:
  - Exact duplicate rule detection.
  - Policy conflict detection (opposite actions for identical traffic).
  - Rule shadowing and subsumption identification.
- **Formally Defined Semantics**: Explicit **First-Match Semantics** with **Default-Deny (BLOCK)** fallback.
- **Safe Semantics-Preserving Optimization**: Prunes dead code, exact duplicates, and redundant subsumed rules without altering the evaluation decision for any packet.
- **Executable Target Output**: Generates standalone Python evaluator programs and includes an in-memory packet simulation engine.
- **Zero Heavy Dependencies**: Built entirely using the Python 3 standard library; tests run out of the box with standard `unittest` or `pytest`.

---

## 3. Compiler Pipeline Overview

```
Source File (.spol)
       │
       ▼
[Phase 1: Lexical Analysis]        ──► Token Stream (Line & Column tracking)
       │
       ▼
[Phase 2: Syntax Analysis]         ──► Abstract Syntax Tree (AST)
       │
       ▼
[Phase 3: Semantic Analysis]       ──► Type, Range, Identifier & Protocol Checks
       │
       ▼
[Phase 4: Intermediate Code]       ──► Three-Address Code (TAC) & Quadruples Table
       │
       ▼
[Phase 5: Rule Analysis]           ──► Redundancy, Shadowing & Conflict Report
       │
       ▼
[Phase 6: Policy Optimization]     ──► Pruned Minimal AST (Equivalent Semantics)
       │
       ▼
[Phase 7: Code Generation]         ──► Standalone Python Evaluator & Simulated Packets
```

---

## 4. Project Directory Structure

```
Security-Policy-Compiler/
├── src/
│   ├── __init__.py               # Package metadata
│   ├── lexer.py                  # Phase 1: Tokenizer and line/column tracker
│   ├── parser.py                 # Phase 2: Recursive-descent AST parser
│   ├── semantic_analyzer.py      # Phase 3: Semantic checks (ports, protocols, scopes)
│   ├── intermediate_code.py      # Phase 4: TAC & Quadruples generator
│   ├── rule_analyzer.py          # Phase 5: Duplicate, conflict, and shadow analyzer
│   ├── optimizer.py              # Phase 6: Semantics-preserving rule optimizer
│   ├── code_generator.py         # Phase 7: Target Python generator & simulator
│   └── main.py                   # Phase 8: Compiler CLI driver
├── examples/
│   ├── sample_policy.spol        # Standard multi-rule production policy
│   ├── duplicate_rules.spol      # Demonstrates duplicate and subsumed rules
│   ├── conflicting_rules.spol    # Demonstrates conflicting and shadowed rules
│   └── invalid_policy.spol       # Demonstrates lexical, syntactic & semantic errors
├── tests/
│   ├── __init__.py
│   ├── test_lexer.py             # Unit tests for tokenization & errors
│   ├── test_parser.py            # Unit tests for grammar parsing & AST
│   ├── test_semantic_analyzer.py # Unit tests for ports, protocols, uniqueness
│   ├── test_rule_analyzer.py     # Unit tests for anomaly detection algorithms
│   ├── test_optimizer.py         # Unit tests for pruning & behavior preservation
│   └── test_code_generator.py    # Unit tests for code generation & simulation
├── docs/
│   ├── grammar.md                # Formal EBNF and token dictionary
│   └── compiler_architecture.md  # Detailed system architecture & algorithms
├── requirements.txt              # Optional pytest dependency
├── .gitignore                    # Git exclusions
└── README.md                     # Comprehensive project documentation
```

---

## 5. Domain-Specific Language (DSL) Specification

### Grammar Summary
Each policy consists of one or more rules structured as:
```spol
RULE <identifier>
WHEN <protocol> PORT <port_number | ANY>
IF SOURCE <source_condition>
THEN <ALLOW | BLOCK>
```

### Supported Elements:
- **Protocols**: `TCP`, `UDP`, `ICMP`, `ANY`
- **Ports**: Integers `1` to `65535`, or wildcard `ANY`
- **Source Conditions**:
  - Named identifiers: `ANY`, `UNKNOWN`, `INTERNAL`, `EXTERNAL`
  - Explicit IPv4 Address: e.g., `192.168.1.50`
  - IPv4 CIDR Subnet: e.g., `10.0.0.0/24`
- **Actions**: `ALLOW`, `BLOCK` (or `DENY`)

### Example Policy:
```spol
# Block untrusted SSH
RULE BLOCK_SSH
WHEN TCP PORT 22
IF SOURCE UNKNOWN
THEN BLOCK

# Allow public web access
RULE ALLOW_WEB
WHEN TCP PORT 443
IF SOURCE ANY
THEN ALLOW

# Allow internal DNS
RULE ALLOW_DNS
WHEN UDP PORT 53
IF SOURCE INTERNAL
THEN ALLOW
```

---

## 6. Installation & Prerequisites

The project requires **Python 3.8+** (tested on Python 3.14). No external third-party dependencies are required to run the compiler.

### Setup:
```powershell
# Clone or navigate to the repository directory
cd Security-Policy-Compiler_CD_Project

# (Optional) Install pytest if you wish to run tests with pytest
pip install -r requirements.txt
```

---

## 7. How to Run the Compiler

### 1. Full Pipeline Demonstration (Recommended for Faculty Review)
Compiles a policy and displays all 7 phases end-to-end:
```powershell
python src/main.py examples/sample_policy.spol
```

### 2. Demonstrating Redundancy Detection & Optimization
Compiles a policy with redundant rules and shows rule reduction:
```powershell
python src/main.py examples/duplicate_rules.spol
```

### 3. Demonstrating Conflict & Shadowed Rule Detection
Compiles a policy with conflicting actions and displays the anomaly report:
```powershell
python src/main.py examples/conflicting_rules.spol
```

### 4. Demonstrating Error Diagnostics
Runs the compiler on an invalid policy to verify graceful error handling:
```powershell
python src/main.py examples/invalid_policy.spol
```

### 5. Emitting Generated Python Code to File
```powershell
python src/main.py --output output/compiled_firewall.py examples/sample_policy.spol
```

### Command-Line Options:
| Flag | Description |
|---|---|
| `--tokens` | Display token table only |
| `--ast` | Display Abstract Syntax Tree only |
| `--ir` | Display Intermediate Three-Address Code and Quadruples table only |
| `--analysis` | Display rule conflict and anomaly findings only |
| `--optimize` | Run optimization pass and show optimized rule statistics |
| `-o`, `--output <file>` | Save generated target Python policy script to a file |
| `--simulate` | Run packet simulation test suite |
| `--all` | Display all pipeline phases in detail |

---

## 8. Automated Testing

All phases are backed by a comprehensive unit test suite covering:
- Lexer tokenization, comments, and invalid character diagnostics.
- Recursive-descent parser AST creation and syntax error detection.
- Semantic validation of ports (1-65535), protocols, rule names, and ICMP compatibility.
- Duplicate, conflict, and shadowing anomaly detection algorithms.
- **Semantic equivalence preservation**: Verifies that evaluating packets against the original AST and the optimized AST produces identical decisions across all tests.
- Syntactic validity and execution of generated Python code.

### Run Tests with Python standard `unittest`:
```powershell
python -m unittest discover tests
```

### Or with `pytest` (if installed):
```powershell
pytest -v
```

---

## 9. Expected Demonstration Output

When executing `python src/main.py examples/sample_policy.spol`, the compiler outputs:

```text
======================================================================
 COMPILING: examples/sample_policy.spol
======================================================================

[*] Phase 1: Lexical Analysis...
    [+] Success: 67 tokens generated.
+------------+------------------+--------------------------+
| LINE:COL   | TOKEN TYPE       | VALUE                    |
+------------+------------------+--------------------------+
| 7:1        | KW_RULE          | RULE                     |
| 7:6        | IDENTIFIER       | BLOCK_SSH_UNKNOWN        |
...

[*] Phase 2: Syntax Analysis (Parser)...
    [+] Success: AST constructed with 6 rule node(s).
Policy AST Root
+-- Rule: BLOCK_SSH_UNKNOWN [Line 7]
|   +-- Protocol : TCP
|   +-- Port     : 22
|   +-- Source   : UNKNOWN
|   \-- Action   : BLOCK
...

[*] Phase 3: Semantic Analysis...
[PASS] Semantic Analysis: 0 errors detected. Policy is semantically valid.

[*] Phase 4: Intermediate Representation (IR)...
    [+] Generated 51 IR Quadruples.
# --- Three-Address Code (TAC) Representation ---
LABEL_BLOCK_SSH_UNKNOWN:
    t0 = (packet.protocol == 'TCP')
    t1 = (packet.port == 22)
    t2 = t0 AND t1
    t3 = MATCH_SOURCE(packet.source, 'UNKNOWN')
    t4 = t2 AND t3
    IF NOT t4 GOTO LABEL_RULE_1
    RETURN ACTION(BLOCK) [Rule: BLOCK_SSH_UNKNOWN]
...

[*] Phase 5: Rule Analysis (First-Match Semantics)...
======================================================================
RULE ANALYSIS REPORT (First-Match Semantics)
======================================================================
No rule anomalies or conflicts detected.
All rules are distinct, reachable, and logically consistent.

[*] Phase 6: Policy Optimization...
======================================================================
OPTIMIZATION REPORT
======================================================================
Original Rule Count  : 6
Optimized Rule Count : 6
Rules Eliminated     : 0
No optimizations needed. Policy is already minimal.

[*] Phase 7: Code Generation (Target: Executable Python Policy)...
[+] Standalone Python policy generated.

[*] Safe Policy Simulation Demo (Testing Sample Packets):
+----------------------------------------------------------------------+
| PACKET (Proto:Port From Source)    | MATCHED RULE       | ACTION     |
+----------------------------------------------------------------------+
| TCP:22 src=UNKNOWN                 | BLOCK_SSH_UNKNOWN  | BLOCK      |
| TCP:443 src=192.168.1.100          | ALLOW_HTTPS        | ALLOW      |
| TCP:80 src=ANY                     | ALLOW_HTTP         | ALLOW      |
| UDP:53 src=8.8.8.8                 | DEFAULT_FALLBACK   | BLOCK      |
| ICMP:0 src=INTERNAL                | ALLOW_PING         | ALLOW      |
+----------------------------------------------------------------------+
======================================================================
 COMPILATION COMPLETED SUCCESSFULLY
======================================================================
```

---

## 10. Guide for Faculty Review / Viva

When demonstrating this project to your faculty, highlight these fundamental **Compiler Design** concepts:

1. **Front-End Design**:
   - **Lexer**: Point out the stateful scanner in `src/lexer.py` that computes token categories, string values, and `line:column` offsets.
   - **Parser**: Show `src/parser.py`, explaining that it is a **Recursive-Descent Parser** enforcing the context-free grammar defined in `docs/grammar.md` and producing a typed AST (`PolicyNode`, `RuleNode`).
2. **Static Semantics**:
   - Explain how `src/semantic_analyzer.py` catches contextual violations that grammars cannot detect (such as port ranges $1..65535$, rule name duplicate collisions, and transport port incompatibilities with ICMP).
3. **Intermediate Code**:
   - Show `src/intermediate_code.py`. Explain how declarative high-level rules are lowered into **Three-Address Code (TAC)** quadruples `(Op, Arg1, Arg2, Result)` with temporary variables (`t0`, `t1`, ...) and jump labels.
4. **Policy Semantics & Optimization**:
   - Clarify the difference between compile-time anomaly detection (`src/rule_analyzer.py`) and optimizer dead-code elimination (`src/optimizer.py`).
   - Emphasize that **First-Match Semantics** guarantees that optimizations never alter the policy's outcome on any packet.
5. **Back-End (Code Generation)**:
   - Show `src/code_generator.py`, which generates a production-ready Python packet evaluator function `evaluate_packet()`.

---

## 11. Current Limitations & Future Enhancements

### Current Limitations:
- Supports IPv4 address matching and standard CIDR notation; IPv6 notation is not currently implemented.
- Evaluates individual packets independently; does not maintain stateful connection tracking (e.g. TCP handshakes).
- Filtering criteria are limited to protocol, destination port, and source address.

### Future Enhancements:
- **Port Ranges**: Support continuous port ranges in syntax (e.g., `PORT 8000-8080`).
- **Destination Address & Stateful Inspection**: Support destination subnets and state tracking (`ESTABLISHED`, `RELATED`).
- **Binary / BPF Target Generation**: Extend the code generator back-end to compile policies into eBPF byte code or iptables scripts.
