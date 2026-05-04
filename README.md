# Codex Insights

Codex Insights is a privacy-conscious Codex skill for analyzing recent local Codex usage. It reads local Codex metadata and session event counts, then produces workflow insights, recommendations, JSON, Markdown, or a self-contained HTML report.

The analyzer is aggregate-first by default. It does not print raw prompts, tool outputs, system instructions, or full thread titles unless you explicitly opt in to titles.

## What It Shows

- Active threads, workspaces, models, reasoning effort, sandbox and approval modes.
- Token-heavy threads and daily token load.
- Tool usage, shell command types, failed command types, and escalation requests.
- Codex-only signals such as dynamic tools exposed to threads.
- Official Codex feature matches, mapping observed friction to docs-backed features such as subagents, automations, skills, AGENTS.md, `codex exec`, and the Codex SDK.

## Install

Clone this repository into your Codex skills folder:

```bash
mkdir -p ~/.codex/skills
git clone https://github.com/Ray0907/codex-insights.git ~/.codex/skills/codex-insights
```

Restart Codex if the skill does not appear immediately.

## Usage

Markdown report:

```bash
python3 ~/.codex/skills/codex-insights/scripts/analyze_codex_usage.py --days 7
```

JSON report:

```bash
python3 ~/.codex/skills/codex-insights/scripts/analyze_codex_usage.py --days 7 --json
```

HTML report:

```bash
python3 ~/.codex/skills/codex-insights/scripts/analyze_codex_usage.py --days 7 --html --output /tmp/codex-insights.html
```

See [example-report.html](example-report.html) for a sample of what the HTML output looks like (generated with mock data).

## Privacy

The analyzer reads:

- `~/.codex/state_5.sqlite`
- `~/.codex/sessions/**/*.jsonl`
- `~/.codex/logs_2.sqlite`

It opens SQLite databases read-only and parses session JSONL files locally. It does not modify Codex data or project files.

Thread titles can contain prompt text, so they are omitted by default. Use `--include-titles` only when you explicitly want that detail.

## Skill Layout

```text
SKILL.md
agents/openai.yaml
scripts/analyze_codex_usage.py
example-report.html
```

## License

MIT
