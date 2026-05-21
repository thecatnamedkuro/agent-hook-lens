from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .scanner import SEVERITY_RANK, Finding, max_severity, scan_file


def render_text(findings: list[Finding]) -> str:
    if not findings:
        return "agent-hook-lens: no findings"
    lines = [f"agent-hook-lens: {len(findings)} finding(s), max severity: {max_severity(findings)}", ""]
    for finding in findings:
        lines.append(f"{finding.severity.upper():9} {finding.path}")
        lines.append(f"  {finding.message}: {finding.code}")
        lines.append(f"  file: {finding.file}")
        lines.append(f"  evidence: {finding.evidence}")
        lines.append("")
    return "\n".join(lines).rstrip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan AI coding-agent hook JSON settings for risky commands.")
    parser.add_argument("paths", nargs="+", help="JSON settings files to scan")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="output format")
    parser.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], default=None, help="exit non-zero when max severity is at least this level")
    args = parser.parse_args(argv)

    findings: list[Finding] = []
    for raw in args.paths:
        try:
            findings.extend(scan_file(Path(raw)))
        except Exception as exc:
            print(f"agent-hook-lens: {exc}", file=sys.stderr)
            return 2

    if args.format == "json":
        payload = {"finding_count": len(findings), "max_severity": max_severity(findings), "findings": [f.as_dict() for f in findings]}
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(render_text(findings))

    if args.fail_on and SEVERITY_RANK[max_severity(findings)] >= SEVERITY_RANK[args.fail_on]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
