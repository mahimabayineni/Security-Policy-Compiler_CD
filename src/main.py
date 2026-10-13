"""
Phase 8: Compiler Main Driver (main.py)

Orchestrates all 7 phases of the Security Policy Compiler pipeline:
  Phase 1: Lexical Analysis
  Phase 2: Syntax Analysis (AST Generation)
  Phase 3: Semantic Analysis
  Phase 4: Intermediate Code Generation (TAC & Quadruples)
  Phase 5: Policy Rule Analysis (Redundancy & Conflict Detection)
  Phase 6: Policy Optimization
  Phase 7: Code Generation & Safe Simulation

Usage:
  python src/main.py examples/sample_policy.spol
  python src/main.py --all examples/sample_policy.spol
  python src/main.py --optimize -o output/compiled_policy.py examples/sample_policy.spol
"""

import argparse
import os
import sys
from typing import Any, Dict, List, Optional

# Ensure project root is in Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.lexer import LexerError, format_tokens, tokenize
from src.parser import ParserError, format_ast, parse
from src.semantic_analyzer import (
    SemanticAnalysisError,
    SemanticAnalyzer,
    format_semantic_report,
)
from src.intermediate_code import generate_ir
from src.rule_analyzer import analyze_rules
from src.optimizer import optimize_policy
from src.code_generator import (
    evaluate_packet,
    format_simulation_table,
    generate_python_code,
    simulate_packets,
)


def print_banner(title: str) -> None:
    print("\n" + "=" * 70)
    print(f" {title}")
    print("=" * 70)


def compile_policy(
    source_code: str,
    file_path: str = "<input>",
    show_all: bool = True,
    show_tokens: bool = False,
    show_ast: bool = False,
    show_ir: bool = False,
    show_analysis: bool = False,
    do_optimize: bool = False,
    output_file: Optional[str] = None,
    run_sim: bool = False,
) -> bool:
    """
    Executes the compiler pipeline. Returns True on success, False on fatal error.
    """
    print_banner(f"COMPILING: {file_path}")

    # -------------------------------------------------------------
    # PHASE 1: LEXICAL ANALYSIS
    # -------------------------------------------------------------
    print("\n[*] Phase 1: Lexical Analysis...")
    try:
        tokens = tokenize(source_code)
        print(f"    [+] Success: {len(tokens)} tokens generated.")
        if show_all or show_tokens:
            print("\n" + format_tokens(tokens))
    except LexerError as e:
        print(f"\n[!] {e}")
        return False

    # -------------------------------------------------------------
    # PHASE 2: SYNTAX ANALYSIS (PARSER)
    # -------------------------------------------------------------
    print("\n[*] Phase 2: Syntax Analysis (Parser)...")
    try:
        ast = parse(tokens)
        print(f"    [+] Success: AST constructed with {len(ast.rules)} rule node(s).")
        if show_all or show_ast:
            print("\n" + format_ast(ast))
    except ParserError as e:
        print(f"\n[!] {e}")
        return False

    # -------------------------------------------------------------
    # PHASE 3: SEMANTIC ANALYSIS
    # -------------------------------------------------------------
    print("\n[*] Phase 3: Semantic Analysis...")
    semantic_analyzer = SemanticAnalyzer(ast)
    semantic_errors = semantic_analyzer.analyze()
    print(format_semantic_report(semantic_errors))

    if semantic_errors:
        print("\n[!] Compilation terminated due to fatal semantic error(s).")
        return False

    # -------------------------------------------------------------
    # PHASE 4: INTERMEDIATE CODE GENERATION (IR)
    # -------------------------------------------------------------
    print("\n[*] Phase 4: Intermediate Representation (IR)...")
    ir_prog = generate_ir(ast)
    print(f"    [+] Generated {len(ir_prog.quadruples)} IR Quadruples.")
    if show_all or show_ir:
        print("\n" + ir_prog.format_tac())
        print("\n" + ir_prog.format_quadruples())

    # -------------------------------------------------------------
    # PHASE 5: RULE ANALYSIS (CONFLICT & REDUNDANCY DETECTION)
    # -------------------------------------------------------------
    print("\n[*] Phase 5: Rule Analysis (First-Match Semantics)...")
    analysis_report = analyze_rules(ast)
    if show_all or show_analysis:
        print("\n" + analysis_report.format())
    else:
        print(f"    [+] Found {len(analysis_report.anomalies)} rule anomaly/conflict item(s).")

    # -------------------------------------------------------------
    # PHASE 6: POLICY OPTIMIZATION
    # -------------------------------------------------------------
    target_ast = ast
    if show_all or do_optimize:
        print("\n[*] Phase 6: Policy Optimization...")
        opt_res = optimize_policy(ast)
        print("\n" + opt_res.format())
        target_ast = opt_res.optimized_policy

    # -------------------------------------------------------------
    # PHASE 7: CODE GENERATION & SIMULATION
    # -------------------------------------------------------------
    print("\n[*] Phase 7: Code Generation (Target: Executable Python Policy)...")
    python_code = generate_python_code(target_ast)

    if output_file:
        out_dir = os.path.dirname(output_file)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(python_code)
        print(f"    [+] Generated Python policy written to: {output_file}")
    else:
        if show_all:
            print("\n" + "-" * 70)
            print("GENERATED PYTHON POLICY CODE (FIRST 35 LINES PREVIEW):")
            print("-" * 70)
            preview_lines = python_code.splitlines()[:35]
            print("\n".join(preview_lines))
            if len(python_code.splitlines()) > 35:
                print("... [remainder truncated in preview] ...")
            print("-" * 70)

    # Simulation demonstration
    if show_all or run_sim:
        print("\n[*] Safe Policy Simulation Demo (Testing Sample Packets):")
        sample_packets: List[Dict[str, Any]] = [
            {"protocol": "TCP", "port": 22, "source": "UNKNOWN"},
            {"protocol": "TCP", "port": 443, "source": "192.168.1.100"},
            {"protocol": "TCP", "port": 80, "source": "ANY"},
            {"protocol": "UDP", "port": 53, "source": "8.8.8.8"},
            {"protocol": "ICMP", "port": 0, "source": "INTERNAL"},
        ]
        results = simulate_packets(target_ast, sample_packets)
        print("\n" + format_simulation_table(results))

    print_banner("COMPILATION COMPLETED SUCCESSFULLY")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Domain-Specific Security Policy Compiler for Rule Analysis and Optimization"
    )
    parser.add_argument("file", help="Path to the security policy source file (.spol)")
    parser.add_argument("--tokens", action="store_true", help="Display token stream table")
    parser.add_argument("--ast", action="store_true", help="Display Abstract Syntax Tree")
    parser.add_argument("--ir", action="store_true", help="Display Intermediate Code (TAC & Quadruples)")
    parser.add_argument("--analysis", action="store_true", help="Display rule anomaly report")
    parser.add_argument("--optimize", action="store_true", help="Run policy optimization")
    parser.add_argument("-o", "--output", help="Output path for generated Python policy script")
    parser.add_argument("--simulate", action="store_true", help="Run simulation test on sample packets")
    parser.add_argument("--all", action="store_true", help="Display all compiler stages in detail")

    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"[!] Error: Policy file '{args.file}' not found.", file=sys.stderr)
        sys.exit(1)

    with open(args.file, "r", encoding="utf-8") as f:
        source_code = f.read()

    # If no specific granular flag is passed, default to showing the complete demonstration
    show_all = args.all or not (
        args.tokens or args.ast or args.ir or args.analysis or args.optimize or args.simulate
    )

    success = compile_policy(
        source_code=source_code,
        file_path=args.file,
        show_all=show_all,
        show_tokens=args.tokens,
        show_ast=args.ast,
        show_ir=args.ir,
        show_analysis=args.analysis,
        do_optimize=args.optimize or show_all,
        output_file=args.output,
        run_sim=args.simulate,
    )

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
