from pathlib import Path
from typing import Any, cast
import json

from agent_hook_lens.cli import main, render_sarif
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


def test_sarif_report_contains_rules_and_locations(capsys):
    findings = scan_file(FIXTURES / "risky-settings.json")
    report = render_sarif(findings)
    assert report["version"] == "2.1.0"
    runs = cast(list[dict[str, Any]], report["runs"])
    run = runs[0]
    driver = cast(dict[str, Any], cast(dict[str, Any], run["tool"])["driver"])
    rule_ids = {rule["id"] for rule in cast(list[dict[str, Any]], driver["rules"])}
    assert "destructive-command" in rule_ids
    results = cast(list[dict[str, Any]], run["results"])
    location = cast(dict[str, Any], cast(list[dict[str, Any]], results[0]["locations"])[0])
    physical = cast(dict[str, Any], location["physicalLocation"])
    artifact = cast(dict[str, Any], physical["artifactLocation"])
    assert str(artifact["uri"]).endswith("risky-settings.json")

    rc = main(["--format", "sarif", str(FIXTURES / "safe-settings.json")])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["runs"][0]["results"] == []
