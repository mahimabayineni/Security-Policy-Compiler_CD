
import pytest

from src.sast_analyzer import analyze_python_source, format_sast_report


def test_detects_dynamic_execution():
    findings = analyze_python_source("result = eval(user_input)\n")

    assert len(findings) == 1
    assert findings[0].rule_id == "PY001"
    assert findings[0].severity == "HIGH"
    assert findings[0].line == 1


def test_detects_subprocess_shell_true():
    source = (
        "import subprocess\n"
        "subprocess.run(command, shell=True)\n"
    )

    findings = analyze_python_source(source)

    assert any(f.rule_id == "PY003" for f in findings)


def test_detects_os_system():
    findings = analyze_python_source("os.system(command)\n")

    assert any(f.rule_id == "PY002" for f in findings)


def test_detects_pickle_loads():
    findings = analyze_python_source("pickle.loads(data)\n")

    assert any(f.rule_id == "PY004" for f in findings)


def test_safe_code_has_no_findings():
    source = """
def evaluate_packet(packet):
    protocol = str(packet.get("protocol", "")).upper()
    return {"action": "BLOCK", "protocol": protocol}
"""

    assert analyze_python_source(source) == []


def test_invalid_python_is_reported_as_syntax_error():
    with pytest.raises(SyntaxError):
        analyze_python_source("def broken(:\n")


def test_report_contains_rule_and_recommendation():
    findings = analyze_python_source("eval(data)\n")
    report = format_sast_report(findings)

    assert "PY001" in report
    assert "Recommendation" in report


def test_scanner_does_not_execute_source():
    # The scanner must parse the text, not execute it.
    source = "raise RuntimeError('must not execute')\n"

    assert analyze_python_source(source) == []
