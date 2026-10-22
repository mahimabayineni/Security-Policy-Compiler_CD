"""
Compiler Driver (main.py)

Pipeline (front end -> middle end -> back end):
  Phase 1: Lexical Analysis               lexer.py
  Phase 2: Syntax Analysis (AST)          parser.py
  Phase 3: Semantic Analysis              semantic_analyzer.py
  Phase 4: Rule Anomaly Analysis          rule_analyzer.py
  Phase 5: Policy Optimization (AST)      optimizer.py
  Phase 6: IR Generation + IR Optimization intermediate_code.py
  Phase 7: Code Generation (IR -> Python) code_generator.py
  Then   : Translation validation + packet simulation (verifier.py, ir_vm.py)

Usage:
  python src/main.py examples/sample_policy.spol
  python src/main.py -o output/policy.py examples/sample_policy.spol
  python src/main.py --packet "TCP 22 10.0.0.5" examples/sample_policy.spol
  python src/main.py --packets examples/packets.json examples/sample_policy.spol
"""

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.lexer import LexerError, format_tokens, tokenize
from src.parser import ParserError, PolicyNode, format_ast, parse
from src.semantic_analyzer import SemanticAnalysisError, SemanticAnalyzer, format_semantic_report
from src.rule_analyzer import analyze_rules
from src.optimizer import optimize_policy
from src.intermediate_code import generate_ir, optimize_ir
from src.code_generator import DEMO_PACKETS, format_simulation_table, generate_python_code
from src.ir_vm import execute_ir
from src.verifier import verify


class CompilationResult:
    """Everything the pipeline produced; useful for tests and tooling."""

    def __init__(self):
        self.tokens = None
        self.ast: Optional[PolicyNode] = None
        self.semantic_warnings = []
        self.normalized: Optional[PolicyNode] = None
        self.analysis = None
        self.optimization = None
        self.ir_raw = None
        self.ir = None
        self.ir_report = None
        self.code: Optional[str] = None
        self.verification = None


def compile_source(source_code: str, source_name: str = "<input>", optimize: bool = True,
                   aggressive: bool = False, run_verification: bool = True) -> CompilationResult:
    """Runs the full pipeline. Raises LexerError / ParserError / SemanticAnalysisError on failure."""
    res = CompilationResult()
    res.tokens = tokenize(source_code)
    res.ast = parse(res.tokens)

    sem = SemanticAnalyzer(res.ast)
    sem.analyze_or_raise()
    res.semantic_warnings = list(sem.warnings)
    res.normalized = sem.normalized_policy()

    res.analysis = analyze_rules(res.normalized)
    if optimize:
        res.optimization = optimize_policy(res.normalized, aggressive=aggressive)
        final_policy = res.optimization.optimized_policy
    else:
        final_policy = res.normalized

    res.ir_raw = generate_ir(final_policy)
    if optimize:
        res.ir, res.ir_report = optimize_ir(res.ir_raw)
    else:
        res.ir = res.ir_raw
    res.code = generate_python_code(res.ir, source_name=source_name, rule_count=len(final_policy.rules))
    if run_verification:
        res.verification = verify(res.normalized, res.ir.quadruples, res.code)
    return res


# ---------------------------------------------------------------------------
# Presentation
# ---------------------------------------------------------------------------
def print_banner(title: str) -> None:
    print("\n" + "=" * 70)
    print(f" {title}")
    print("=" * 70)


def parse_packet_arg(text: str) -> Dict[str, Any]:
    parts = text.replace(",", " ").split()
    if len(parts) != 3 or not parts[1].isdigit():
        raise ValueError(f"Bad --packet '{text}'. Expected \"PROTOCOL PORT SOURCE\", e.g. \"TCP 22 10.0.0.5\"")
    return {"protocol": parts[0].upper(), "port": int(parts[1]), "source": parts[2]}


def load_packets_file(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, list):
        raise ValueError("Packets file must contain a JSON list of {protocol, port, source} objects")
    for i, p in enumerate(data):
        if not isinstance(p, dict) or not {"protocol", "port", "source"} <= set(p):
            raise ValueError(f"Packet #{i + 1} must have 'protocol', 'port' and 'source' fields")
    return data


def compile_policy(source_code: str, file_path: str = "<input>", show_all: bool = True,
                   show_tokens: bool = False, show_ast: bool = False, show_ir: bool = False,
                   show_analysis: bool = False, do_optimize: bool = False, output_file: Optional[str] = None,
                   simulate: bool = False, packets: Optional[List[Dict[str, Any]]] = None,
                   optimize: bool = True, aggressive: bool = False, strict: bool = False) -> bool:
    """Compiles a policy, prints the requested phases and returns True on success."""
    print_banner(f"COMPILING: {file_path}")

    try:
        res = compile_source(source_code, file_path, optimize=optimize, aggressive=aggressive)
    except LexerError as e:
        print(f"[!] Phase 1 (Lexical Analysis) FAILED\n    {e}")
        return False
    except ParserError as e:
        print(f"[!] Phase 2 (Syntax Analysis) FAILED\n    {e}")
        return False
    except SemanticAnalysisError as e:
        print("[!] Phase 3 (Semantic Analysis) FAILED")
        print(format_semantic_report(e.errors))
        return False

    print(f"\n[*] Phase 1: Lexical Analysis -> {len(res.tokens)} tokens")
    if show_all or show_tokens:
        print(format_tokens(res.tokens))

    print(f"\n[*] Phase 2: Syntax Analysis -> AST with {len(res.ast.rules)} rule(s)")
    if show_all or show_ast:
        print(format_ast(res.ast))

    print("\n[*] Phase 3: Semantic Analysis")
    print(format_semantic_report([], res.semantic_warnings))

    print("\n[*] Phase 4: Rule Anomaly Analysis")
    if show_all or show_analysis:
        print(res.analysis.format_report())
    else:
        print(f"    {len(res.analysis.anomalies)} finding(s); use --analysis for details")

    print("\n[*] Phase 5: Policy Optimization")
    if res.optimization is None:
        print("    Skipped (--no-optimize)")
    elif show_all or do_optimize:
        print(res.optimization.format_report())
    else:
        print(f"    {res.optimization.original_count} -> {res.optimization.optimized_count} rules")

    print("\n[*] Phase 6: Intermediate Code (from the optimized AST)")
    if res.ir_report:
        print(res.ir_report.format_report())
    if show_all or show_ir:
        print(res.ir.format_tac())
        print()
        print(res.ir.format_quadruples())

    print("\n[*] Phase 7: Code Generation (optimized IR -> Python)")
    print(f"    {len(res.code.splitlines())} lines of standalone Python generated")
    if output_file:
        out_dir = os.path.dirname(output_file)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as fh:
            fh.write(res.code)
        print(f"    [+] Written to {output_file}  (run it: python {output_file} TCP 22 10.0.0.5)")

    print("\n[*] Translation Validation")
    print("    " + res.verification.format_report().replace("\n", "\n    "))

    if show_all or simulate or packets:
        sim_packets = packets or DEMO_PACKETS
        title = "your packets" if packets else "demo packets"
        print(f"\n[*] Packet Simulation ({title}, executed on the optimized IR)")
        results = [{"packet": p, **execute_ir(res.ir.quadruples, p)} for p in sim_packets]
        print(format_simulation_table(results))

    ok = res.verification.passed
    if strict and res.analysis.has_errors():
        print("\n[!] --strict: rule analysis reported ERROR-level anomalies")
        ok = False

    print_banner("COMPILATION COMPLETED SUCCESSFULLY" if ok else "COMPILATION FAILED")
    return ok


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Domain-Specific Security Policy Compiler (academic simulation only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python src/main.py examples/sample_policy.spol\n"
               "  python src/main.py --analysis examples/conflicting_rules.spol\n"
               "  python src/main.py --packet \"TCP 22 10.0.0.5\" examples/sample_policy.spol\n"
               "  python src/main.py -o output/policy.py examples/sample_policy.spol",
    )
    ap.add_argument("file", help="Policy source file (.spol)")
    ap.add_argument("--tokens", action="store_true", help="Show the token table")
    ap.add_argument("--ast", action="store_true", help="Show the AST")
    ap.add_argument("--ir", action="store_true", help="Show the TAC and quadruple table")
    ap.add_argument("--analysis", action="store_true", help="Show the anomaly report")
    ap.add_argument("--optimize", action="store_true", help="Show the optimization report")
    ap.add_argument("--simulate", action="store_true", help="Run the demo packet simulation")
    ap.add_argument("--all", action="store_true", help="Show every phase in detail (default when no view flag is given)")
    ap.add_argument("-o", "--output", help="Write the generated Python policy to this file")
    ap.add_argument("--packet", action="append", default=[], metavar="\"PROTO PORT SRC\"",
                    help="Evaluate a packet, e.g. --packet \"TCP 22 10.0.0.5\" (repeatable)")
    ap.add_argument("--packets", metavar="FILE", help="Evaluate packets from a JSON file")
    ap.add_argument("--no-optimize", action="store_true", help="Disable optimization (O0)")
    ap.add_argument("-O2", "--aggressive", action="store_true",
                    help="Also remove BLOCK rules made redundant by the default BLOCK")
    ap.add_argument("--strict", action="store_true", help="Fail if the analysis reports ERROR-level anomalies")
    args = ap.parse_args()

    if not os.path.exists(args.file):
        print(f"Error: input file '{args.file}' not found.")
        sys.exit(1)
    with open(args.file, "r", encoding="utf-8") as fh:
        source = fh.read()

    try:
        packets = [parse_packet_arg(p) for p in args.packet]
        if args.packets:
            packets += load_packets_file(args.packets)
    except (ValueError, OSError, json.JSONDecodeError) as e:
        print(f"Error: {e}")
        sys.exit(1)

    view_flags = any([args.tokens, args.ast, args.ir, args.analysis, args.optimize, args.simulate, packets])
    ok = compile_policy(
        source, file_path=args.file, show_all=args.all or not view_flags,
        show_tokens=args.tokens, show_ast=args.ast, show_ir=args.ir, show_analysis=args.analysis,
        do_optimize=args.optimize, output_file=args.output, simulate=args.simulate, packets=packets or None,
        optimize=not args.no_optimize, aggressive=args.aggressive, strict=args.strict,
    )
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
