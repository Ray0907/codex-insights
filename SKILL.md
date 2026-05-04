---
name: codex-insights
description: Use when analyzing Codex Desktop or Codex CLI usage, recent sessions, tool calls, token-heavy threads, failed commands, workflow habits, or when the user asks for Codex optimization hints similar to Claude Code usage analytics.
---

# Codex Insights

## Overview

Use this skill to produce a privacy-conscious weekly usage review from local Codex data. Prefer the bundled analyzer script over ad hoc parsing because Codex session JSONL files can contain full prompts, system instructions, and tool outputs.

## Quick Start

Run:

```bash
python3 ~/.codex/skills/codex-insights/scripts/analyze_codex_usage.py --days 7
```

For machine-readable output:

```bash
python3 ~/.codex/skills/codex-insights/scripts/analyze_codex_usage.py --days 7 --json
```

For a local HTML report:

```bash
python3 ~/.codex/skills/codex-insights/scripts/analyze_codex_usage.py --days 7 --html --output /tmp/codex-insights.html
```

Only include thread titles when the user explicitly wants more detail:

```bash
python3 ~/.codex/skills/codex-insights/scripts/analyze_codex_usage.py --days 7 --include-titles
```

## Workflow

1. Run the analyzer for the requested time window.
2. Read the report and identify the top 3 actionable changes.
3. Explain the recommendations in plain language, tying each one to the observed metric.
4. Do not paste raw session messages, system prompts, tool outputs, secrets, or long thread titles.

## What The Analyzer Reads

- `~/.codex/state_5.sqlite`: thread metadata, cwd, token counts, models, reasoning effort.
- `~/.codex/sessions/**/*.jsonl`: event counts, tool calls, command failures, web searches, token events.
- `~/.codex/logs_2.sqlite`: log levels and noisy targets.

It is read-only. It does not modify sessions, databases, logs, or project files.

## Output To Prefer

Summarize:

- Total active threads, workspaces, and token-heavy threads.
- Tool usage by count, especially `exec_command`, `apply_patch`, web search, browser, and agents.
- Command failure rate and repeated failing tools.
- Sessions with high back-and-forth or high token usage.
- Concrete workflow hints: split large tasks, plan before implementation, batch file reads, use targeted tests, reduce web searches, or avoid repeated failed commands.
- HTML reports when the user wants a shareable local artifact; keep them self-contained and aggregate-only.

## Privacy Rules

- Default to aggregate metrics.
- Treat thread titles as potentially sensitive because Codex can store the first user request as a title.
- Never quote raw message content unless the user explicitly asks and the quoted content is necessary.
- If the analyzer cannot read a file because of permissions or schema drift, report the gap and continue with available sources.
