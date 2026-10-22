# Compiler Architecture & Pipeline Design

This document describes the internal design of the **Domain-Specific Security Policy Compiler** (v2.0).

---

## 1. Pipeline

The compiler has a classic front end / middle end / back end structure. Each phase consumes the output of the previous one.

```
DSL source (.spol)
      |
[1] Lexical Analysis ............ lexer.py              -> tokens
[2] Syntax Analysis ............. parser.py             -> AST
[3] Semantic Analysis ........... semantic_analyzer.py  -> validated, normalized AST
------------------------------------------------------------------- front end
[4] Rule Anomaly Analysis ....... rule_analyzer.py      -> anomaly report
[5] Policy Optimization ......... optimizer.py          -> optimized AST
[6] IR Generation ............... intermediate_code.py  -> three-address code (quadruples)
    IR Peephole Optimization .... intermediate_code.py  -> optimized IR
------------------------------------------------------------------- middle end
[7] Code Generation ............. code_generator.py     -> standalone Python program
    IR Virtual Machine .......... ir_vm.py              -> executes the IR directly
    Translation Validation ...... verifier.py           -> original == IR == generated?
------------------------------------------------------------------- back end
```

Shared support modules:

- `runtime.py`: the one definition of source matching. It is used by the reference interpreter and the IR VM, and it is copied verbatim into every generated program, so all three always agree.
- `policy_semantics.py`: set relations over rule match-spaces (`covers`, `overlaps`, `equivalent`) used by the analyzer and optimizer.

Optimization happens at two levels, as in real compilers: **high-level** (removing whole rules on the AST, phase 5) and **low-level** (simplifying instructions in the IR, phase 6).

---

## 2. Phases

### Phase 1: Lexical Analysis (`lexer.py`)
Character-level scanner producing `Token(type, value, line, column)`. It recognizes keywords (case-insensitive), identifiers, numbers, IPv4 addresses and CIDR blocks, skips whitespace and `#` comments, and raises `LexerError` with a position on bad input.

### Phase 2: Syntax Analysis (`parser.py`)
A **recursive-descent parser** for an **LL(1)** grammar (`docs/grammar.md`): each production is a method, and the next token alone decides which alternative to take. It builds `PolicyNode` / `RuleNode` and records the position of every field so later phases can point at the exact token. `DENY` and named sources are normalized here.

### Phase 3: Semantic Analysis (`semantic_analyzer.py`)
Context-sensitive checks a context-free grammar cannot express: unique rule names, supported protocols, port range, ICMP/port compatibility, IPv4/CIDR validity, valid actions. Errors are collected (not stop-at-first) and are fatal; warnings are not. `normalized_policy()` returns a canonical AST (`ICMP PORT 0` becomes `ANY`, CIDR host bits are cleared).

### Phase 4: Rule Anomaly Analysis (`rule_analyzer.py`)
Policy semantics: **first-match, default BLOCK**. Each rule denotes a set of packets; anomalies are relations between those sets (classification after Al-Shaer & Hamed, IEEE INFOCOM 2004):

| Relation (Ri before Rj) | Same action | Different action |
|---|---|---|
| Rj equivalent to Ri | Exact Duplicate (WARNING) | Direct Conflict (ERROR) |
| Ri covers Rj | Redundant Subsumed (INFO) | Shadowed Rule (ERROR) |
| Rj covers Ri | Redundant Preceding (INFO)* | Generalization (INFO) |
| partial overlap | (no anomaly) | Correlation (WARNING) |

\* only if no rule between them overlaps Ri with a different action.

Sources are compared semantically: `INTERNAL` is the RFC 1918 ranges, `EXTERNAL` their complement, an IP equals its `/32`. Unreachable rules are reported once and then excluded, so they do not generate follow-on noise.

### Phase 5: Policy Optimization (`optimizer.py`)
Rule-level dead-code elimination, run to a fixed point:

1. **Unreachable rules**: a rule covered by an earlier rule can never fire, whatever its action (duplicates, dead conflicts, subsumed and shadowed rules).
2. **Redundant preceding rules**: Ri is removed if a later Rj covers it with the same action and nothing in between overrides it.
3. **Default-redundant BLOCK rules** (only with `-O2`/`--aggressive`): a BLOCK rule no later ALLOW overlaps gives the same result as the default. This is off by default because explicit BLOCK rules document intent.

### Phase 6: Intermediate Code (`intermediate_code.py`)
The **optimized** AST is lowered to three-address code stored as quadruples `(op, arg1, arg2, result)`:

```
R1_BLOCK_SSH:
    t0 = (packet.protocol == 'TCP')
    t1 = (packet.port == 22)
    t2 = t0 AND t1
    t3 = MATCH_SOURCE(packet.source, 'UNKNOWN')
    t4 = t2 AND t3
    IF NOT t4 GOTO R2_ALLOW_HTTPS
    RETURN ACTION(BLOCK) [Rule: BLOCK_SSH]
R2_ALLOW_HTTPS:
    ...
DEFAULT_FALLBACK:
    RETURN ACTION(BLOCK) [Rule: DEFAULT_FALLBACK]
```

The **peephole optimizer** then applies:
1. Constant folding: a test against `ANY` becomes `t = TRUE`.
2. Copy/constant propagation: `t2 = t0 AND t1` with `t0 = TRUE` becomes a copy of `t1`.
3. Branch elimination: `IF NOT TRUE GOTO L` is never taken and is removed.
4. Dead code elimination: assignments to temporaries nobody reads are removed.
5. Unreachable code elimination: a reachability walk over the control-flow graph removes code after an unconditional return.

Temporaries are then renumbered densely.

### Phase 7: Code Generation (`code_generator.py`)
Translates the optimized IR **instruction by instruction** into Python. `IF_FALSE_GOTO` always targets the next label (a structured forward jump), so it becomes an `if` block; any other jump shape is rejected with `CodeGenError`. The generated file contains the runtime, `evaluate_packet(packet)` and a small command-line interface.

### IR Virtual Machine (`ir_vm.py`)
A program-counter interpreter for quadruples. The packet simulation runs on it, showing the IR is a complete executable program on its own.

### Translation Validation (`verifier.py`)
After every compilation, the verifier compares the **original** policy (reference interpreter), the **optimized IR** (VM) and the **generated Python** on one packet from every equivalence class. Rules only test protocol equality, port equality and source membership, so the classes are: each protocol mentioned plus one other; each port mentioned plus one unused port; and one address in every region of the Venn diagram of all CIDR blocks and RFC 1918 ranges, plus each label. For this DSL the check is therefore **exhaustive**, not a sample. A seeded fuzz test (`tests/test_fuzz.py`) additionally runs it on hundreds of random policies.

---

## 3. Data Structures

| Phase | Input | Output |
|---|---|---|
| Lexer | `str` | `List[Token]` |
| Parser | `List[Token]` | `PolicyNode` (AST) |
| Semantic Analyzer | `PolicyNode` | errors / warnings, normalized `PolicyNode` |
| Rule Analyzer | `PolicyNode` | `AnalysisReport` |
| Optimizer | `PolicyNode` | `OptimizationResult` (optimized `PolicyNode` + audit trail) |
| IR Generator | `PolicyNode` | `IntermediateProgram` (quadruples) |
| IR Optimizer | `IntermediateProgram` | `IntermediateProgram`, `IROptimizationReport` |
| Code Generator | `IntermediateProgram` | `str` (Python source) |
| IR VM | quadruples + packet | decision |
| Verifier | original AST, optimized IR, generated code | `VerificationResult` |

---

## 4. Limitations

- Reachability is checked pairwise: a rule covered only by the *union* of several earlier rules is not detected as unreachable (it is still compiled correctly).
- IPv4 only; no port ranges; no destination address; stateless (no connection tracking).
- The output is a simulation in Python, not real firewall configuration.
