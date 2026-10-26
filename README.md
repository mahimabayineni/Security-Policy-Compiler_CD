# Domain-Specific Security Policy Compiler for Automated Rule Analysis and Optimization

A Compiler Design project: a complete compiler for a small security-policy language. It lexes, parses and validates firewall-style rules, detects rule anomalies, optimizes the policy at two levels (rules and intermediate code), generates an executable Python program from the IR, and **verifies** that the compiled program behaves exactly like the source policy.

> **Academic project notice:** the compiler only evaluates synthetic packet records (Python dictionaries). It never configures a real firewall, opens sockets, or touches network settings.

---

## 1. Why this project

Real firewalls accumulate thousands of rules. Administrators add duplicates, contradictory rules, and rules that can never fire because an earlier, broader rule always wins. These mistakes waste resources and, worse, hide security holes. Treating the policy as a **program** lets us use compiler techniques (parsing, semantic analysis, dead-code elimination, IR optimization) to find and fix them automatically.

---

## 2. Features

- **Full compiler pipeline**: lexer, LL(1) recursive-descent parser, semantic analysis, rule analysis, AST optimization, three-address code, IR optimization, code generation.
- **Precise diagnostics**: every lexical, syntax and semantic error reports the line and column of the offending token; all semantic errors are collected in one pass.
- **Semantic rule analysis** (Al-Shaer & Hamed classification): exact duplicates, conflicts, shadowing, subsumption, redundant preceding rules, generalization and correlation. Sources are compared by meaning, not text: the analyzer knows `INTERNAL` covers `192.168.1.0/24` and that `10.0.0.1` equals `10.0.0.1/32`.
- **Two-level optimization**:
  - *Policy level* (AST): removes unreachable and redundant rules, with an audit trail explaining each removal.
  - *IR level* (peephole): constant folding, copy propagation, branch elimination, dead-code and unreachable-code elimination.
- **IR-driven back end**: Python code is generated instruction-by-instruction from the optimized quadruples; an **IR virtual machine** can also execute the IR directly.
- **Translation validation**: after every compilation, the original policy, the optimized IR and the generated Python are compared on one packet from *every* equivalence class, which is exhaustive for this language.
- **Usable on your own policies and packets**: evaluate packets from the command line or a JSON file; the generated program is a standalone tool.
- **No dependencies**: Python 3.8+ standard library only. 62 unit, regression and fuzz tests.

---

## 3. Pipeline

```
 .spol source
     |
 [1] Lexical Analysis      lexer.py              tokens with line:column
 [2] Syntax Analysis       parser.py             AST
 [3] Semantic Analysis     semantic_analyzer.py  validated + normalized AST
 [4] Rule Analysis         rule_analyzer.py      anomaly report
 [5] Policy Optimization   optimizer.py          optimized AST
 [6] IR Generation         intermediate_code.py  three-address code (quadruples)
     IR Optimization       intermediate_code.py  peephole-optimized IR
 [7] Code Generation       code_generator.py     standalone Python program
     Validation            verifier.py, ir_vm.py original == IR == generated?
```

Details: [`docs/compiler_architecture.md`](docs/compiler_architecture.md). Grammar and semantics: [`docs/grammar.md`](docs/grammar.md).

---

## 4. Directory structure

```
Security-Policy-Compiler_CD-main/
|-- src/
|   |-- lexer.py               Phase 1  scanner
|   |-- parser.py              Phase 2  recursive-descent parser, AST
|   |-- semantic_analyzer.py   Phase 3  semantic checks, normalization
|   |-- rule_analyzer.py       Phase 4  anomaly detection
|   |-- optimizer.py           Phase 5  rule-level optimization
|   |-- intermediate_code.py   Phase 6  TAC/quadruples + peephole optimizer
|   |-- code_generator.py      Phase 7  IR -> Python, reference interpreter
|   |-- ir_vm.py               IR virtual machine
|   |-- verifier.py            translation validation
|   |-- policy_semantics.py    set relations between rules (covers / overlaps)
|   |-- runtime.py             source matching shared by all back ends
|   `-- main.py                command-line driver
|-- examples/
|   |-- sample_policy.spol       clean policy
|   |-- duplicate_rules.spol     duplicates and subsumed rules
|   |-- conflicting_rules.spol   conflicts, correlation and shadowing
|   |-- advanced_anomalies.spol  semantic analysis showcase
|   |-- invalid_policy.spol      semantic errors
|   `-- packets.json             sample packets for --packets
|-- tests/                       unit, regression, pipeline and fuzz tests
`-- docs/
    |-- grammar.md
    `-- compiler_architecture.md
```

---

## 5. The policy language

```spol
RULE <name>
WHEN <TCP | UDP | ICMP | ANY> PORT <1-65535 | ANY>
IF SOURCE <ANY | UNKNOWN | INTERNAL | EXTERNAL | IPv4 address | CIDR block>
THEN <ALLOW | BLOCK | DENY>
```

- Rules are checked **top to bottom; the first match wins**. A packet that matches nothing is **blocked** (default deny).
- `INTERNAL` = the RFC 1918 private ranges (10/8, 172.16/12, 192.168/16); `EXTERNAL` = every other address; `UNKNOWN` matches only packets labelled `UNKNOWN`.
- ICMP has no ports, so ICMP rules use `PORT ANY` (or `PORT 0`, which means the same).
- `DENY` is a synonym for `BLOCK`. Keywords are case-insensitive. `#` starts a comment.

```spol
# Block untrusted SSH
RULE BLOCK_SSH
WHEN TCP PORT 22
IF SOURCE UNKNOWN
THEN BLOCK

# Lab machines may SSH in
RULE ALLOW_LAB_SSH
WHEN TCP PORT 22
IF SOURCE 10.10.5.0/24
THEN ALLOW
```

---

## 6. How to run

Requires Python 3.8 or newer. No installation step. Open a terminal in the project folder (the one containing `src/`). On Windows, use `py` if `python` is not recognized.

**Full demonstration (all phases):**
```
python src/main.py examples/sample_policy.spol
```

**One phase at a time:**
```
python src/main.py --tokens examples/sample_policy.spol
python src/main.py --ast examples/sample_policy.spol
python src/main.py --analysis examples/advanced_anomalies.spol
python src/main.py --optimize examples/duplicate_rules.spol
python src/main.py --ir examples/conflicting_rules.spol
python src/main.py examples/invalid_policy.spol        # error diagnostics
```

**Using it on your own policy:** write a `.spol` file, then test any packets against it:
```
python src/main.py --packet "TCP 22 10.10.5.7" --packet "TCP 22 UNKNOWN" my_policy.spol
python src/main.py --packets examples/packets.json examples/advanced_anomalies.spol
```
A packet is `PROTOCOL PORT SOURCE`, where SOURCE is an IPv4 address or a label (`UNKNOWN`, `INTERNAL`, `EXTERNAL`). A packets file is a JSON list of `{"protocol": ..., "port": ..., "source": ...}` objects.

**Generating the compiled program:**
```
python src/main.py -o output/my_policy.py my_policy.spol
python output/my_policy.py TCP 22 10.10.5.7               # one packet
python output/my_policy.py --packets examples/packets.json # many packets
python output/my_policy.py                                # demo packets
```

### Command-line options

| Option | Effect |
|---|---|
| `--tokens`, `--ast`, `--ir`, `--analysis`, `--optimize` | Show that phase in detail |
| `--sast` | Display Static Application Security Testing findings for generated Python code |
| `--simulate` | Run the demo packets |
| `--all` | Show every phase (default when no view option is given) |
| `--packet "PROTO PORT SRC"` | Evaluate a packet (repeatable) |
| `--packets FILE` | Evaluate packets from a JSON file |
| `-o FILE` | Write the generated Python program |
| `--no-optimize` | Disable optimization (O0) |
| `-O2`, `--aggressive` | Also remove BLOCK rules already implied by the default BLOCK |
| `--strict` | Fail when the analysis reports ERROR-level anomalies (conflicts, shadowing) |

The exit code is 0 on success and 1 on any error, so the compiler can be used in scripts.

---

## 7. Tests

```
python -m unittest discover -s tests -t .
```
(or `pytest` if installed). The suite covers every phase, a regression test for each bug fixed in v2.0, end-to-end compilation of all examples, the generated program's command line, and a seeded fuzz test that compiles hundreds of random policies and validates each one.

---

## 8. Example output (abridged)

```
[*] Phase 4: Rule Anomaly Analysis
[ERROR] Issue #3: Shadowed Rule
  Affects     : 'ALLOW_EXTERNAL_HTTPS' (Line 28)
  Prior Rule  : 'BLOCK_ALL_EXTERNAL' (Line 20) ANY PORT ANY SRC EXTERNAL -> BLOCK
  ...
[*] Phase 5: Policy Optimization
Original Rule Count  : 4
Optimized Rule Count : 2
  1. [ELIMINATE_DEAD_CONFLICT] Removed 'BLOCK_HTTP_ANY' (Line 14)
  2. [ELIMINATE_SHADOWED] Removed 'ALLOW_EXTERNAL_HTTPS' (Line 28)

[*] Phase 6: Intermediate Code (from the optimized AST)
IR quadruples: 19 -> 13 after peephole optimization
  - Constant folding (tests against ANY -> TRUE): 3
  - Copy/constant propagation (AND with TRUE): 3
  - Dead code elimination (unused temporaries): 4
R1_ALLOW_HTTP_ANY:
    t0 = (packet.protocol == 'TCP')
    t1 = (packet.port == 80)
    t2 = t0 AND t1
    IF NOT t2 GOTO R2_BLOCK_ALL_EXTERNAL
    RETURN ACTION(ALLOW) [Rule: ALLOW_HTTP_ANY]
...
[*] Translation Validation
    [PASS] Equivalence check (original AST vs optimized IR vs generated Python):
           128 packet classes, 0 mismatch(es).
```

---

## 9. Guide for review / viva

1. **Front end**: the lexer tracks line:column; the parser is recursive descent over an LL(1) grammar (one method per production, one-token lookahead, no backtracking).
2. **Semantic analysis**: checks a grammar cannot express (port ranges, unique names, ICMP has no ports). Errors are collected, not stop-at-first, and point at the exact token.
3. **Rule analysis vs optimization**: analysis *reports* problems (some intentional, like generalization); optimization *removes* only what provably changes nothing.
4. **Why removing a shadowed rule is safe**: under first-match semantics, every packet a shadowed rule matches is already caught by the earlier rule, so it can never fire.
5. **Two levels of optimization**: whole rules on the AST, then individual instructions in the IR. Example: `WHEN ANY PORT ANY` produces tests that constant folding turns into `TRUE` and dead-code elimination deletes.
6. **IR is the real interface**: the code generator and the VM both consume the optimized quadruples.
7. **Correctness**: translation validation compares original, IR and generated code on every packet equivalence class after each compilation, plus fuzz testing.

---

## 10. Limitations and future work

- Reachability is checked pairwise; a rule covered only by the *union* of earlier rules is not flagged (it is still compiled correctly).
- IPv4 only; no port ranges (`PORT 8000-8080`), no destination addresses, no stateful inspection.
- Future: port ranges, destination matching, union-based shadowing detection (e.g. with interval/BDD representations), and back ends for `iptables`/`nftables` or eBPF.

---

## 11. Reference

E. Al-Shaer and H. Hamed, "Firewall Policy Advisor for Anomaly Discovery and Rule Editing," *IFIP/IEEE IM*, 2003; "Discovery of Policy Anomalies in Distributed Firewalls," *IEEE INFOCOM*, 2004.

