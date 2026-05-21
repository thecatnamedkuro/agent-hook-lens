from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import json
import re
from typing import Any, Iterable

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str
    evidence: str
    file: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)

RULES: list[tuple[str, str, str, re.Pattern[str]]] = [
    ("critical", "destructive-command", "Destructive command pattern", re.compile(r"\b(rm\s+-[rfRF]*|git\s+reset\s+--hard|git\s+clean\s+-[xfd]|mkfs|dd\s+if=|chmod\s+-R\s+777)\b")),
    ("high", "remote-code-exec", "Shell pipeline downloads remote code and executes it", re.compile(r"\b(curl|wget)\b[^\n|;]*(\||&&)\s*(sh|bash|zsh|python|node)\b")),
    ("high", "private-key-marker", "Private-key material marker", re.compile(r"BEGIN\s+(RSA|OPENSSH|EC|DSA)?\s*PRIVATE\s+KEY")),
    ("high", "secret-looking-value", "Secret-looking token or environment variable", re.compile(r"(?i)\b[A-Z0-9_-]*(api[_-]?key|secret|token|password|bearer)[A-Z0-9_-]*\b\s*[:=]\s*['\"]?[^'\"\s]{8,}")),
    ("medium", "network-egress", "Hook performs network egress", re.compile(r"\b(curl|wget|nc|netcat|ssh|scp|rsync|ftp|telnet)\b")),
    ("medium", "broad-filesystem-access", "Broad or sensitive filesystem access", re.compile(r"(\s|['\"])(/|~|\$HOME|\.ssh|\.env|/etc/|/var/run/docker\.sock)(\s|/|['\"]|$)")),
    ("medium", "permission-bypass-word", "Permission bypass wording", re.compile(r"(?i)\b(dangerously|bypass|allow[_-]?all|disable[_-]?permission|skip[_-]?approval)\b")),
    ("low", "hidden-shell", "Inline shell or interpreter execution", re.compile(r"\b(bash|sh|zsh)\s+-c\b|\b(python|node|ruby|perl)\s+(-c|-e)\b")),
]

COMMAND_KEYS = {"command", "cmd", "script", "run", "shell", "args"}


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc}") from exc


def iter_interesting_strings(value: Any, prefix: str = "$") -> Iterable[tuple[str, str, bool]]:
    if isinstance(value, dict):
        for key, child in value.items():
            child_prefix = f"{prefix}.{key}"
            is_command_key = str(key).lower() in COMMAND_KEYS
            if isinstance(child, str):
                # Include the key name in the scanned text so patterns like
                # SERVICE_TOKEN=<value> are caught even when JSON separates key
                # and value. Keep command-like values unchanged to avoid noisy
                # evidence in normal reports.
                text = child if is_command_key else f"{key}={child}"
                yield child_prefix, text, is_command_key
            else:
                yield from iter_interesting_strings(child, child_prefix)
    elif isinstance(value, list):
        for idx, child in enumerate(value):
            child_prefix = f"{prefix}[{idx}]"
            if isinstance(child, str):
                yield child_prefix, child, False
            else:
                yield from iter_interesting_strings(child, child_prefix)


def scan_text(text: str, path: str, file: str, command_context: bool) -> list[Finding]:
    findings: list[Finding] = []
    for severity, code, message, pattern in RULES:
        if pattern.search(text):
            if code in {"network-egress", "hidden-shell", "remote-code-exec", "destructive-command"} and not command_context:
                # Still flag very dangerous strings anywhere, but avoid noisy reports for docs/labels.
                if code not in {"remote-code-exec", "destructive-command"}:
                    continue
            findings.append(Finding(severity, code, path, message, text[:240], file))
    return findings


def scan_file(path: Path) -> list[Finding]:
    data = load_json(path)
    findings: list[Finding] = []
    for json_path, text, is_command in iter_interesting_strings(data):
        commandish = is_command or ".hooks." in json_path or json_path.lower().endswith(".matcher")
        findings.extend(scan_text(text, json_path, str(path), commandish))
    return dedupe(findings)


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.file, finding.path, finding.code, finding.evidence)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return sorted(unique, key=lambda f: (-SEVERITY_RANK[f.severity], f.file, f.path, f.code))


def max_severity(findings: list[Finding]) -> str:
    if not findings:
        return "info"
    return max((f.severity for f in findings), key=lambda s: SEVERITY_RANK[s])
