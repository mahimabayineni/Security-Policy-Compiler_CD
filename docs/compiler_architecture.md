# Compiler Architecture & Pipeline Design

This document details the internal design and phase-by-phase execution of the **Domain-Specific Security Policy Compiler**.

---

## 1. High-Level Compiler Pipeline

The compiler follows classic compiler design principles, structured into distinct, decoupled modular phases:

```
DSL Source Code (.spol)
        |
        v
[ Phase 1: Lexical Analyzer (lexer.py) ]
        |   Stream of Tokens
        v
[ Phase 2: Syntax Analyzer (parser.py) ]
        |   Abstract Syntax Tree (AST)
        v
[ Phase 3: Semantic Analyzer (semantic_analyzer.py) ]
        |   Validated AST
        v
[ Phase 4: Intermediate Code Generator (intermediate_code.py) ]
        |   Three-Address Code (TAC) & Quadruples
        v
[ Phase 5: Rule Analyzer (rule_analyzer.py) ]
        |   Anomaly & Conflict Report
        v
[ Phase 6: Optimizer (optimizer.py) ]
        |   Optimized AST (pruned duplicates & dead rules)
        v
[ Phase 7: Code Generator (code_generator.py) ]
        |   Executable Python Policy Script / Simulated Packet Evaluation
        v
Target Output / Simulation Results
```

---

## 2. Phase-by-Phase Architecture

### Phase 1: Lexical Analysis (`lexer.py`)
- **Input**: Raw text from a `.spol` file.
- **Process**: Iterates character by character through source code. Matches keywords, identifiers, port numbers, IPv4 addresses, and CIDR blocks. Skips comments (`#`) and whitespace.
- **Diagnostics**: Tracks 1-based `line` and `column` for every token. Throws `LexerError` on unrecognized characters or malformed numeric inputs.
- **Output**: List of `Token(type, value, line, column)` objects terminated by `EOF`.

### Phase 2: Syntax Analysis (`parser.py`)
- **Technique**: Recursive-Descent LL(1) parsing.
- **AST Nodes**:
  - `PolicyNode`: Root node containing an ordered list of `RuleNode` instances.
  - `RuleNode`: Represents `RULE <name> WHEN <protocol> PORT <port> IF SOURCE <source> THEN <action>`.
- **Diagnostics**: Validates mandatory keyword sequence (`RULE -> WHEN -> PORT -> IF -> SOURCE -> THEN`). Raises `ParserError` with line and column information if syntax expectations are unmet.
- **Output**: `PolicyNode` Abstract Syntax Tree.

### Phase 3: Semantic Analysis (`semantic_analyzer.py`)
- **Scope**: Static context-sensitive checks not enforceable by context-free grammar alone.
- **Validation Rules**:
  1. **Identifier Uniqueness**: Ensures rule names are unique across the policy namespace.
  2. **Protocol Validation**: Verifies transport protocols belong to `{TCP, UDP, ICMP, ANY}`.
  3. **Port Bounds**: Checks that numerical ports are in the valid range \(1 \le \text{port} \le 65535\) or `ANY`.
  4. **Protocol Compatibility**: Flags invalid configurations like assigning transport ports to `ICMP`.
  5. **Source Format**: Validates IPv4 octet bounds (0-255) and CIDR netmasks (0-32).
  6. **Action Verification**: Enforces valid actions (`ALLOW`, `BLOCK`).
- **Diagnostics**: Accumulates all semantic errors and halts compilation if any violations exist.

### Phase 4: Intermediate Code Generation (`intermediate_code.py`)
- **Purpose**: Lowers high-level declarative security rules into machine-independent, linear instruction sequences.
- **Representations Provided**:
  1. **Three-Address Code (TAC)**:
     ```
     LABEL_BLOCK_SSH:
         t0 = (packet.protocol == 'TCP')
         t1 = (packet.port == 22)
         t2 = t0 AND t1
         t3 = MATCH_SOURCE(packet.source, 'UNKNOWN')
         t4 = t2 AND t3
         IF NOT t4 GOTO LABEL_RULE_2
         RETURN ACTION(BLOCK) [Rule: BLOCK_SSH]
     ```
  2. **Quadruple Table**: Standard compiler 4-tuples: `(Operator, Arg1, Arg2, Result)`.

### Phase 5: Rule Analysis (`rule_analyzer.py`)
- **Policy Semantics**: Defines **First-Match Semantics with Default Deny (BLOCK)**.
  Packets evaluate against rules top-to-bottom. The first rule whose condition matches triggers its action.
- **Anomaly Detection Algorithms**:
  1. **Exact Duplicates**:
     - Conditions: \( \text{Rule}_A.\text{criteria} = \text{Rule}_B.\text{criteria} \) and \( \text{Action}_A = \text{Action}_B \).
     - Impact: Second rule is completely redundant.
  2. **Direct Conflicts**:
     - Conditions: \( \text{Rule}_A.\text{criteria} = \text{Rule}_B.\text{criteria} \) but \( \text{Action}_A \ne \text{Action}_B \).
     - Impact: Under first-match semantics, Rule B is unreachable and represents a contradictory policy intention.
  3. **Shadowing**:
     - Preceding rule \( \text{Rule}_A \) matches a strict superset of traffic covered by \( \text{Rule}_B \), but with different actions. Rule B can never match.
  4. **Subsumption**:
     - Preceding rule \( \text{Rule}_A \) matches a strict superset of traffic covered by \( \text{Rule}_B \) with the *same* action. Rule B is redundant.

### Phase 6: Policy Optimization (`optimizer.py`)
- **Safety Guarantee**: Transformations must never change the action for any possible packet.
- **Optimization Passes**:
  - `ELIMINATE_EXACT_DUPLICATE`: Removes subsequent identical rules.
  - `ELIMINATE_SUBSUMED`: Removes redundant narrower rules already satisfied by earlier broad rules.
  - `ELIMINATE_DEAD_CONFLICT`: Removes unreachable conflicting rules while logging an audit trail.
- **Metrics**: Emits an audit report showing original count, optimized count, and exact reasons for each rule elimination.

### Phase 7: Code Generation & Safe Simulation (`code_generator.py`)
- **Target Language**: Python 3.
- **Target Structure**:
  - Produces an independent Python script containing `evaluate_packet(packet: dict) -> dict`.
  - Implements fast conditional branches and source matching helpers.
  - Includes default fallback handling.
- **Academic Simulation Guarantee**: Operates strictly on synthetic packet records represented as plain Python dictionaries. Never modifies host OS network configuration, sockets, or real firewall settings.

---

## 3. Data Structures Summary

| Phase | Input Data Structure | Output Data Structure |
|---|---|---|
| Lexer | `str` (Source Code) | `List[Token]` |
| Parser | `List[Token]` | `PolicyNode` (AST) |
| Semantic Analyzer | `PolicyNode` | Validated `PolicyNode` or `List[SemanticError]` |
| IR Generator | `PolicyNode` | `IntermediateProgram` (Quadruples & TAC) |
| Rule Analyzer | `PolicyNode` | `AnalysisReport` (`List[RuleAnomaly]`) |
| Optimizer | `PolicyNode` | `OptimizationResult` (Optimized `PolicyNode`) |
| Code Generator | `PolicyNode` | `str` (Python source code) / Simulation Table |
