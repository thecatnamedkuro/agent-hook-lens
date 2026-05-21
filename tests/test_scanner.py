from pathlib import Path

from agent_hook_lens.cli import main
from agent_hook_lens.scanner import max_severity, scan_file

FIXTURES = Path(__file__).parent / "fixtures"


def test_risky_settings_find_critical_and_high():
    findings = scan_file(FIXTURES / "risky-settings.json")
    codes = {f.code for f in findings}
    assert "destructive-command" in codes
    assert "remote-code-exec" in codes
    assert "secret-looking-value" in codes
    assert max_severity(findings) == "critical"


def test_safe_settings_has_no_findings():
    assert scan_file(FIXTURES / "safe-settings.json") == []


def test_cli_fail_on_threshold():
    rc = main(["--format", "json", "--fail-on", "high", str(FIXTURES / "risky-settings.json")])
    assert rc == 1
