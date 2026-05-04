#!/usr/bin/env python3
"""Read-only Codex usage analyzer.

The script intentionally reports aggregate metrics by default. Session JSONL
files often contain prompts, tool outputs, and system instructions.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import glob
import html
import json
import os
import shlex
import sqlite3
import sys
from pathlib import Path
from typing import Any


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def ts_to_iso(value: int | None) -> str:
    if not value:
        return ""
    if value > 10_000_000_000:
        value = value // 1000
    return dt.datetime.fromtimestamp(value, tz=dt.timezone.utc).isoformat()


def short(text: str, limit: int = 96) -> str:
    text = " ".join((text or "").split())
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "..."


def command_name_from_shell(command_text: str) -> str:
    try:
        parts = shlex.split(command_text)
    except ValueError:
        return "(unknown)"
    for part in parts:
        if "=" in part and not part.startswith(("/", "./", "../")):
            key = part.split("=", 1)[0]
            if key.replace("_", "").isalnum():
                continue
        return Path(part).name
    return "(unknown)"


def connect_readonly(path: Path) -> sqlite3.Connection | None:
    if not path.exists():
        return None
    uri = f"file:{path}?mode=ro"
    return sqlite3.connect(uri, uri=True)


def query_threads(codex_home: Path, since_ms: int, include_titles: bool) -> list[dict[str, Any]]:
    db = connect_readonly(codex_home / "state_5.sqlite")
    if db is None:
        return []
    db.row_factory = sqlite3.Row
    try:
        rows = db.execute(
            """
            SELECT id, rollout_path, created_at_ms, updated_at_ms, cwd, title,
                   tokens_used, model, reasoning_effort, source, archived,
                   sandbox_policy, approval_mode, first_user_message
            FROM threads
            WHERE updated_at_ms >= ?
            ORDER BY updated_at_ms DESC
            """,
            (since_ms,),
        ).fetchall()
    except sqlite3.Error:
        return []
    finally:
        db.close()

    threads: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        if not include_titles:
            item["title"] = ""
        else:
            item["title"] = short(item.get("title") or "")
        threads.append(item)
    return threads


def query_logs(codex_home: Path, since_s: int) -> list[dict[str, Any]]:
    db = connect_readonly(codex_home / "logs_2.sqlite")
    if db is None:
        return []
    db.row_factory = sqlite3.Row
    try:
        rows = db.execute(
            """
            SELECT level, target, COUNT(*) AS count, SUM(estimated_bytes) AS bytes
            FROM logs
            WHERE ts >= ?
            GROUP BY level, target
            ORDER BY count DESC
            LIMIT 30
            """,
            (since_s,),
        ).fetchall()
    except sqlite3.Error:
        return []
    finally:
        db.close()
    return [dict(row) for row in rows]


def query_dynamic_tools(codex_home: Path, thread_ids: list[str]) -> list[tuple[str, int]]:
    if not thread_ids:
        return []
    db = connect_readonly(codex_home / "state_5.sqlite")
    if db is None:
        return []
    placeholders = ",".join("?" for _ in thread_ids)
    try:
        rows = db.execute(
            f"""
            SELECT COALESCE(namespace, '') AS namespace, name, COUNT(*) AS count
            FROM thread_dynamic_tools
            WHERE thread_id IN ({placeholders})
            GROUP BY namespace, name
            ORDER BY count DESC
            LIMIT 20
            """,
            thread_ids,
        ).fetchall()
    except sqlite3.Error:
        return []
    finally:
        db.close()

    tools: list[tuple[str, int]] = []
    for namespace, name, count in rows:
        label = f"{namespace}.{name}" if namespace else name
        tools.append((label, int(count or 0)))
    return tools


def discover_rollouts(codex_home: Path, threads: list[dict[str, Any]], since: dt.datetime) -> list[Path]:
    paths: list[Path] = []
    for thread in threads:
        rollout_path = thread.get("rollout_path")
        if rollout_path:
            path = Path(rollout_path)
            if path.exists():
                paths.append(path)

    if paths:
        return sorted(set(paths))

    pattern = str(codex_home / "sessions" / "**" / "*.jsonl")
    cutoff = since.timestamp()
    for name in glob.glob(pattern, recursive=True):
        path = Path(name)
        try:
            if path.stat().st_mtime >= cutoff:
                paths.append(path)
        except OSError:
            continue
    return sorted(set(paths))


def parse_session(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = {
        "path": str(path),
        "events": collections.Counter(),
        "payload_types": collections.Counter(),
        "tool_calls": collections.Counter(),
        "web_searches": 0,
        "exec_completed": 0,
        "exec_failed": 0,
        "exec_cmd_types": collections.Counter(),
        "failed_cmd_types": collections.Counter(),
        "user_messages": 0,
        "agent_messages": 0,
        "token_events": 0,
        "escalation_requests": 0,
        "last_total_tokens": 0,
        "last_input_tokens": 0,
        "last_output_tokens": 0,
    }

    try:
        lines = path.open("r", encoding="utf-8")
    except OSError:
        return data

    with lines:
        for line in lines:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            event_type = event.get("type") or ""
            payload = event.get("payload") or {}
            payload_type = payload.get("type") or ""
            data["events"][event_type] += 1
            if payload_type:
                data["payload_types"][payload_type] += 1

            if event_type == "response_item" and payload.get("type") == "function_call":
                name = payload.get("name") or "unknown"
                data["tool_calls"][name] += 1
                if name == "exec_command":
                    try:
                        arguments = json.loads(payload.get("arguments") or "{}")
                    except json.JSONDecodeError:
                        arguments = {}
                    if arguments.get("sandbox_permissions") == "require_escalated":
                        data["escalation_requests"] += 1

            if event_type == "response_item" and payload.get("type") == "web_search_call":
                data["web_searches"] += 1

            if event_type == "event_msg" and payload_type == "exec_command_end":
                data["exec_completed"] += 1
                status = payload.get("status")
                exit_code = payload.get("exit_code")
                cmd_type = "(unknown)"
                parsed_cmd = payload.get("parsed_cmd") or []
                if parsed_cmd and isinstance(parsed_cmd, list):
                    first = parsed_cmd[0] or {}
                    cmd_type = first.get("type") or first.get("name") or cmd_type
                if cmd_type in ("(unknown)", "unknown"):
                    command = payload.get("command") or []
                    if command:
                        if len(command) >= 3 and Path(str(command[0])).name in ("zsh", "bash", "sh") and command[1] in ("-lc", "-c"):
                            cmd_type = command_name_from_shell(str(command[2]))
                        else:
                            cmd_type = Path(str(command[0])).name
                data["exec_cmd_types"][cmd_type] += 1
                if status == "failed" or (exit_code not in (None, 0)):
                    data["exec_failed"] += 1
                    data["failed_cmd_types"][cmd_type] += 1

            if event_type == "event_msg" and payload_type == "user_message":
                data["user_messages"] += 1
            if event_type == "event_msg" and payload_type == "agent_message":
                data["agent_messages"] += 1
            if event_type == "event_msg" and payload_type == "token_count":
                info = payload.get("info") or {}
                total = info.get("total_token_usage") or {}
                data["token_events"] += 1
                data["last_total_tokens"] = int(total.get("total_tokens") or data["last_total_tokens"] or 0)
                data["last_input_tokens"] = int(total.get("input_tokens") or data["last_input_tokens"] or 0)
                data["last_output_tokens"] = int(total.get("output_tokens") or data["last_output_tokens"] or 0)

    return data


def summarize(args: argparse.Namespace) -> dict[str, Any]:
    codex_home = Path(args.codex_home).expanduser()
    since = utc_now() - dt.timedelta(days=args.days)
    since_ms = int(since.timestamp() * 1000)
    since_s = int(since.timestamp())

    threads = query_threads(codex_home, since_ms, args.include_titles)
    rollouts = discover_rollouts(codex_home, threads, since)
    sessions = [parse_session(path) for path in rollouts]
    logs = query_logs(codex_home, since_s)

    cwd_counts = collections.Counter(t.get("cwd") or "(unknown)" for t in threads)
    model_counts = collections.Counter(t.get("model") or "(unknown)" for t in threads)
    reasoning_counts = collections.Counter(t.get("reasoning_effort") or "(unknown)" for t in threads)
    source_counts = collections.Counter(t.get("source") or "(unknown)" for t in threads)
    approval_counts = collections.Counter(t.get("approval_mode") or "(unknown)" for t in threads)
    sandbox_counts = collections.Counter()
    network_counts = collections.Counter()
    tool_counts: collections.Counter[str] = collections.Counter()
    exec_cmd_type_counts: collections.Counter[str] = collections.Counter()
    failed_cmd_type_counts: collections.Counter[str] = collections.Counter()

    totals = {
        "threads": len(threads),
        "sessions_parsed": len(sessions),
        "tokens_used": sum(int(t.get("tokens_used") or 0) for t in threads),
        "user_messages": sum(s["user_messages"] for s in sessions),
        "agent_messages": sum(s["agent_messages"] for s in sessions),
        "web_searches": sum(s["web_searches"] for s in sessions),
        "exec_completed": sum(s["exec_completed"] for s in sessions),
        "exec_failed": sum(s["exec_failed"] for s in sessions),
        "escalation_requests": sum(s["escalation_requests"] for s in sessions),
    }

    for thread in threads:
        sandbox_policy = thread.get("sandbox_policy") or ""
        try:
            sandbox = json.loads(sandbox_policy)
        except json.JSONDecodeError:
            sandbox = {}
        sandbox_counts[sandbox.get("type") or "(unknown)"] += 1
        network_counts["network on" if sandbox.get("network_access") else "network off"] += 1

    for session in sessions:
        tool_counts.update(session["tool_calls"])
        exec_cmd_type_counts.update(session["exec_cmd_types"])
        failed_cmd_type_counts.update(session["failed_cmd_types"])

    exec_failure_rate = 0.0
    if totals["exec_completed"]:
        exec_failure_rate = totals["exec_failed"] / totals["exec_completed"]

    top_threads = sorted(
        threads,
        key=lambda item: int(item.get("tokens_used") or 0),
        reverse=True,
    )[:10]
    daily_activity = build_daily_activity(threads, args.days)
    work_areas = build_work_areas(threads)
    intent_counts = build_intent_counts(threads)
    dynamic_tools = query_dynamic_tools(codex_home, [str(t.get("id")) for t in threads if t.get("id")])

    recommendations = build_recommendations(
        totals=totals,
        tool_counts=tool_counts,
        exec_failure_rate=exec_failure_rate,
        top_threads=top_threads,
        cwd_counts=cwd_counts,
        logs=logs,
    )

    return {
        "window": {
            "days": args.days,
            "since": since.isoformat(),
            "codex_home": str(codex_home),
        },
        "totals": totals,
        "exec_failure_rate": round(exec_failure_rate, 3),
        "top_workspaces": cwd_counts.most_common(10),
        "models": model_counts.most_common(),
        "reasoning_effort": reasoning_counts.most_common(),
        "sources": source_counts.most_common(),
        "approval_modes": approval_counts.most_common(),
        "sandbox_modes": sandbox_counts.most_common(),
        "network_modes": network_counts.most_common(),
        "tools": tool_counts.most_common(20),
        "dynamic_tools": dynamic_tools,
        "exec_command_types": exec_cmd_type_counts.most_common(20),
        "failed_command_types": failed_cmd_type_counts.most_common(20),
        "top_threads": [
            {
                "id": item.get("id"),
                "title": item.get("title") or None,
                "cwd": item.get("cwd"),
                "tokens_used": item.get("tokens_used"),
                "updated_at": ts_to_iso(item.get("updated_at_ms")),
                "model": item.get("model"),
                "reasoning_effort": item.get("reasoning_effort"),
            }
            for item in top_threads
        ],
        "daily_activity": daily_activity,
        "work_areas": work_areas,
        "intent_counts": intent_counts,
        "noisy_logs": logs[:10],
        "recommendations": recommendations,
        "insights": build_insights(
            totals=totals,
            tool_counts=tool_counts,
            exec_failure_rate=exec_failure_rate,
            top_threads=top_threads,
            cwd_counts=cwd_counts,
        ),
    }


def thread_text(thread: dict[str, Any]) -> str:
    return " ".join(
        str(thread.get(key) or "")
        for key in ("cwd", "title", "first_user_message")
    ).lower()


def classify_work_area(thread: dict[str, Any]) -> tuple[str, str]:
    text = thread_text(thread)
    if any(word in text for word in ("nuxt", "vue", "client_nuxt", "koc", "secudocx", "pug")):
        return (
            "Nuxt/Vue application work",
            "Frontend and full-stack app work: schema changes, API routes, UI patterns, and project-specific conventions.",
        )
    if any(word in text for word in ("oss", "stars", "mole", "macpulse", "first principle", "runcat")):
        return (
            "OSS product strategy",
            "Product ideation around developer utilities, first-principles positioning, and star-worthy open-source ideas.",
        )
    if any(word in text for word in ("codex", "session", "skill", "insights", "usage", "claude")):
        return (
            "Agent tooling and skills",
            "Building reusable agent workflows, local usage analysis, skills, and report generation.",
        )
    if any(word in text for word in ("jmeter", "report", "load", "metrics", "analysis")):
        return (
            "Performance and report analysis",
            "Analysis-heavy work where Codex is used to interpret reports, metrics, or system behavior.",
        )
    if any(word in text for word in ("schema", "migration", "mysql", "api", "sql")):
        return (
            "Database and API implementation",
            "Precise implementation tasks around schema, migrations, models, and API endpoints.",
        )
    return (
        "General coding sessions",
        "Mixed implementation, review, and investigation sessions that do not fall into a dominant category.",
    )


def build_work_areas(threads: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: collections.Counter[str] = collections.Counter()
    tokens: collections.Counter[str] = collections.Counter()
    descriptions: dict[str, str] = {}
    for thread in threads:
        name, description = classify_work_area(thread)
        counts[name] += 1
        tokens[name] += int(thread.get("tokens_used") or 0)
        descriptions[name] = description
    return [
        {
            "name": name,
            "sessions": count,
            "tokens": tokens[name],
            "description": descriptions[name],
        }
        for name, count in counts.most_common(6)
    ]


def build_intent_counts(threads: list[dict[str, Any]]) -> list[tuple[str, int]]:
    counts: collections.Counter[str] = collections.Counter()
    for thread in threads:
        text = thread_text(thread)
        if any(word in text for word in ("fix", "bug", "error", "failed", "failure", "debug")):
            counts["Bug Fix / Debugging"] += 1
        elif any(word in text for word in ("review", "plan", "feedback")):
            counts["Review / Planning"] += 1
        elif any(word in text for word in ("oss", "idea", "first principle", "stars", "可以做")):
            counts["Product Ideation"] += 1
        elif any(word in text for word in ("create", "implement", "add", "build", "schema", "api")):
            counts["Implementation"] += 1
        elif any(word in text for word in ("analyze", "report", "analysis")):
            counts["Analysis"] += 1
        else:
            counts["General Question"] += 1
    return counts.most_common(8)


def build_daily_activity(threads: list[dict[str, Any]], days: int) -> list[dict[str, Any]]:
    today = utc_now().date()
    start = today - dt.timedelta(days=days - 1)
    buckets = {
        (start + dt.timedelta(days=offset)).isoformat(): {"date": (start + dt.timedelta(days=offset)).isoformat(), "threads": 0, "tokens": 0}
        for offset in range(days)
    }
    for thread in threads:
        updated_at = thread.get("updated_at_ms")
        if not updated_at:
            continue
        if updated_at > 10_000_000_000:
            updated_at = updated_at // 1000
        date = dt.datetime.fromtimestamp(updated_at, tz=dt.timezone.utc).date().isoformat()
        if date in buckets:
            buckets[date]["threads"] += 1
            buckets[date]["tokens"] += int(thread.get("tokens_used") or 0)
    return list(buckets.values())


def build_insights(
    *,
    totals: dict[str, Any],
    tool_counts: collections.Counter[str],
    exec_failure_rate: float,
    top_threads: list[dict[str, Any]],
    cwd_counts: collections.Counter[str],
) -> list[dict[str, str]]:
    insights: list[dict[str, str]] = []

    if top_threads:
        top_tokens = int(top_threads[0].get("tokens_used") or 0)
        if top_tokens > 500_000:
            insights.append(
                {
                    "type": "Friction",
                    "title": "Long-thread drift",
                    "evidence": f"Largest thread used {top_tokens:,} tokens.",
                    "action": "Split research, planning, and implementation into separate threads after a durable summary.",
                }
            )

    exec_calls = tool_counts.get("exec_command", 0)
    patch_calls = tool_counts.get("apply_patch", 0)
    if exec_calls >= 20 and patch_calls == 0:
        insights.append(
            {
                "type": "Pattern",
                "title": "Exploration without artifact",
                "evidence": f"{exec_calls:,} shell tool calls and no patch tool calls in parsed response items.",
                "action": "End research sessions with a saved plan, issue body, README section, or generated report.",
            }
        )

    if exec_failure_rate >= 0.1 and totals["exec_completed"] >= 10:
        insights.append(
            {
                "type": "Friction",
                "title": "Command retries are costing turns",
                "evidence": f"Shell failure rate is {exec_failure_rate:.0%}.",
                "action": "Inspect the first failure and fix the environment or command shape before retrying variants.",
            }
        )

    if totals["web_searches"] >= 8:
        insights.append(
            {
                "type": "Research",
                "title": "Research should become durable",
                "evidence": f"{totals['web_searches']:,} web searches in this window.",
                "action": "Promote repeated findings into local notes or a skill reference so future threads start warmer.",
            }
        )

    if len(cwd_counts) >= 4:
        insights.append(
            {
                "type": "Context",
                "title": "Workspace spread",
                "evidence": f"Activity spans {len(cwd_counts)} workspaces.",
                "action": "Keep each repo/client task in its own thread and avoid mixing ideation with code changes.",
            }
        )

    if not insights:
        insights.append(
            {
                "type": "Healthy",
                "title": "No major session smell",
                "evidence": "The window has no dominant token, tool, or command-failure issue.",
                "action": "Keep using targeted verification and summarize before switching tasks.",
            }
        )

    return insights[:5]


def build_recommendations(
    *,
    totals: dict[str, Any],
    tool_counts: collections.Counter[str],
    exec_failure_rate: float,
    top_threads: list[dict[str, Any]],
    cwd_counts: collections.Counter[str],
    logs: list[dict[str, Any]],
) -> list[str]:
    recs: list[str] = []

    if top_threads and int(top_threads[0].get("tokens_used") or 0) > 500_000:
        recs.append(
            "Split very large threads earlier. One or more threads crossed 500k tokens; use a written plan, smaller tasks, or a fresh thread before implementation detail accumulates."
        )

    if exec_failure_rate >= 0.2 and totals["exec_completed"] >= 10:
        recs.append(
            "Reduce repeated command failures. The shell failure rate is high; inspect the first failure, then adjust the command or environment before retrying variants."
        )

    if tool_counts.get("exec_command", 0) >= 20 and tool_counts.get("apply_patch", 0) == 0:
        recs.append(
            "Convert exploration into edits sooner when the task is implementation-oriented. Many shell reads with no patch often means the scope needs a short plan checkpoint."
        )

    if tool_counts.get("exec_command", 0) >= 30:
        recs.append(
            "Batch independent file reads. Use parallel reads for `rg`, `sed`, `ls`, and schema inspection to lower turn count and keep context organized."
        )

    if totals["web_searches"] >= 8:
        recs.append(
            "Cache research conclusions in a note or plan. Heavy web search use is fine for current facts, but repeated searches should become durable source links and decisions."
        )

    if len(cwd_counts) >= 4:
        recs.append(
            "Group work by workspace. Many active cwd values in the same window can make session recall noisy; keep each repo or client task in its own thread."
        )

    warn_logs = sum(int(row.get("count") or 0) for row in logs if row.get("level") == "WARN")
    if warn_logs >= 20:
        recs.append(
            "Review recurring Codex warnings. The log database shows repeated WARN entries; noisy plugin or skill loading warnings can slow down startup and clutter diagnosis."
        )

    if not recs:
        recs.append(
            "Usage looks balanced for this window. Keep using read-only inspection before edits and run targeted verification before declaring work complete."
        )

    return recs[:6]


def render_markdown(report: dict[str, Any]) -> str:
    totals = report["totals"]
    lines = [
        "# Codex Usage Hints",
        "",
        f"Window: last {report['window']['days']} days since {report['window']['since']}",
        "",
        "## Summary",
        "",
        f"- Threads: {totals['threads']}",
        f"- Sessions parsed: {totals['sessions_parsed']}",
        f"- Tokens used: {totals['tokens_used']:,}",
        f"- User messages: {totals['user_messages']}",
        f"- Agent messages: {totals['agent_messages']}",
        f"- Web searches: {totals['web_searches']}",
        f"- Shell commands: {totals['exec_completed']} ({totals['exec_failed']} failed, {report['exec_failure_rate']:.0%})",
        "",
        "## Tool Use",
        "",
    ]

    if report["tools"]:
        for name, count in report["tools"]:
            lines.append(f"- {name}: {count}")
    else:
        lines.append("- No tool calls found in parsed sessions.")

    lines.extend(["", "## Top Workspaces", ""])
    for cwd, count in report["top_workspaces"]:
        lines.append(f"- {cwd}: {count} thread(s)")

    lines.extend(["", "## Token-Heavy Threads", ""])
    for item in report["top_threads"][:5]:
        label = item["id"]
        if item.get("title"):
            label = f"{label} - {item['title']}"
        lines.append(f"- {label}: {int(item.get('tokens_used') or 0):,} tokens, cwd={item.get('cwd')}")

    lines.extend(["", "## Recommendations", ""])
    for rec in report["recommendations"]:
        lines.append(f"- {rec}")

    return "\n".join(lines)


def build_report_story(report: dict[str, Any]) -> dict[str, Any]:
    totals = report["totals"]
    failure_pct = report["exec_failure_rate"] * 100
    thread_count = int(totals["threads"] or 0)
    token_total = int(totals["tokens_used"] or 0)
    command_total = int(totals["exec_completed"] or 0)
    top_work = report["work_areas"][0] if report["work_areas"] else {"name": "mixed Codex work", "sessions": 0, "tokens": 0}
    top_tool = report["tools"][0] if report["tools"] else ("tools", 0)
    top_command = report["exec_command_types"][0] if report["exec_command_types"] else ("commands", 0)
    top_failed = report["failed_command_types"][0] if report["failed_command_types"] else ("none", 0)
    top_source = report["sources"][0] if report["sources"] else ("unknown", 0)
    top_approval = report["approval_modes"][0] if report["approval_modes"] else ("unknown", 0)
    top_reasoning = report["reasoning_effort"][0] if report["reasoning_effort"] else ("unknown", 0)
    largest_thread = int(report["top_threads"][0]["tokens_used"]) if report["top_threads"] else 0
    dynamic_tool_count = sum(count for _, count in report["dynamic_tools"])
    high_effort_threads = sum(count for name, count in report["reasoning_effort"] if name == "high")
    workspace_count = len(report["top_workspaces"])
    active_days = sum(1 for day in report["daily_activity"] if int(day.get("tokens") or 0) > 0)

    working_parts = [
        f"Codex was used for {top_work['name'].lower()} across {top_work['sessions']} session(s).",
        f"The dominant tool path was {top_tool[0]} ({top_tool[1]:,} calls), which means the workflow is grounded in local inspection rather than unverified guessing.",
    ]
    if command_total:
        working_parts.append(f"Command failure rate is {failure_pct:.0f}% across {command_total:,} completed shell commands.")
    if dynamic_tool_count:
        working_parts.append(f"Dynamic tools were exposed {dynamic_tool_count:,} times, so the environment is giving Codex app-specific capabilities Claude-style reports usually do not surface.")

    hindering_parts = []
    if largest_thread > 500_000:
        hindering_parts.append(f"The largest thread reached {largest_thread:,} tokens, which is the clearest session-drift signal.")
    if token_total > 5_000_000:
        hindering_parts.append(f"Total token load is {token_total:,}, concentrated over {active_days} active day(s).")
    if top_tool[0] == "exec_command" and top_tool[1] > 100:
        hindering_parts.append(f"{top_tool[1]:,} exec_command calls indicate heavy exploration that should become artifacts sooner.")
    if workspace_count >= 4:
        hindering_parts.append(f"Activity spans {workspace_count} workspaces, increasing context switching and thread recall noise.")
    if not hindering_parts:
        hindering_parts.append("No single dominant friction metric stands out in this window.")

    quick_wins = []
    if largest_thread > 500_000:
        quick_wins.append("Split threads once research turns into implementation, and carry forward a short summary.")
    if top_tool[1] > 100:
        quick_wins.append("End exploration-heavy sessions with a saved plan, report, or skill update.")
    if top_failed[1] > 0:
        quick_wins.append(f"Review the first failing {top_failed[0]} command before retrying variants.")
    if high_effort_threads == thread_count and thread_count:
        quick_wins.append("Use lower reasoning effort for routine inspection or formatting-only work.")
    if not quick_wins:
        quick_wins.append("Keep the current verify-before-final workflow and targeted command usage.")

    ambitious = (
        "Codex can turn these signals into an automated loop: detect drift, write a summary, spawn a fresh implementation thread, "
        "run verification, and add a reusable skill or repo instruction when the same friction repeats."
    )

    wins = [
        {
            "title": "Local evidence loop",
            "body": f"The workflow produced {command_total:,} command events, browser checks, screenshots, and validation instead of relying only on prose.",
        },
        {
            "title": "Codex-native observability",
            "body": f"The report uses source, approval mode, sandbox, dynamic tools, and parsed command types; those are Codex-specific signals, not just copied Claude report sections.",
        },
        {
            "title": "Reusable workflow creation",
            "body": "A repeated question became a local skill with markdown, JSON, and HTML outputs plus privacy-preserving defaults.",
        },
    ]

    frictions = [
        {
            "title": "Long-thread drift",
            "body": f"Largest thread: {largest_thread:,} tokens. Split before planning and implementation collapse into the same context.",
        },
        {
            "title": "Exploration pressure",
            "body": f"Top tool: {top_tool[0]} ({top_tool[1]:,}). Top command type: {top_command[0]} ({top_command[1]:,}). Turn repeated inspection into a checklist or script.",
        },
        {
            "title": "Command failure hotspots",
            "body": f"Most common failed command type: {top_failed[0]} ({top_failed[1]:,}). Treat repeated failures as an environment issue, not a retry target.",
        },
    ]

    codex_signals = [
        {
            "title": "Model and reasoning budget",
            "body": f"Top reasoning effort is {top_reasoning[0]} across {top_reasoning[1]} thread(s). Use this to decide where lower effort is enough.",
        },
        {
            "title": "Sandbox and approval posture",
            "body": f"Top approval mode is {top_approval[0]} ({top_approval[1]} thread(s)); escalation requests in parsed sessions: {totals['escalation_requests']:,}.",
        },
        {
            "title": "Surface and tool availability",
            "body": f"Top source is {top_source[0]} ({top_source[1]} thread(s)); dynamic tools exposed across active threads: {dynamic_tool_count:,}.",
        },
        {
            "title": "Command semantics",
            "body": f"Parsed command intent shows {top_command[0]} as the top command type and {top_failed[0]} as the top failed type.",
        },
    ]

    features = [
        {
            "title": "Codex skills",
            "why": "Repeated workflows now show up as measurable friction. Promote them into skills when they recur.",
            "prompt": "Create a Codex skill for this repeated workflow. Include trigger description, exact commands, safety rules, validation steps, and one example invocation.",
        },
        {
            "title": "Reasoning-effort budget",
            "why": f"This window uses {top_reasoning[0]} effort heavily. Reserve high effort for architecture, debugging, and review.",
            "prompt": "Before starting, choose reasoning effort based on task risk: low for formatting/lookup, medium for routine edits, high for architecture or debugging.",
        },
        {
            "title": "Approval-aware planning",
            "why": f"Approval mode is visible in Codex thread metadata; plans should account for sandbox/network limits before commands fail.",
            "prompt": "Before running commands, summarize sandbox, network, and approval constraints, then choose commands that fit those constraints.",
        },
    ]

    patterns = [
        {
            "title": "Root-cause lock",
            "why": "Best for bugs and production failures where command retries start piling up.",
            "prompt": "Before editing any file, write: symptom, likely cause with evidence, minimal test/change. If evidence is missing, inspect first.",
        },
        {
            "title": "Research-to-artifact",
            "why": "Best for product/OSS exploration threads that otherwise become long and hard to reuse.",
            "prompt": "End this research thread by writing a durable artifact: README pitch, docs/research note, or implementation plan with review gates.",
        },
        {
            "title": "Command-failure review",
            "why": f"Failed command type data shows where retries concentrate, currently led by {top_failed[0]}.",
            "prompt": "When a command fails twice, stop retrying. Explain the error class, likely environment cause, and one safer next command.",
        },
    ]

    official_matches = [
        {
            "feature": "Persisted /goal workflows",
            "source": "Codex changelog, 2026-04-30",
            "url": "https://developers.openai.com/codex/changelog",
            "matches": f"Your largest thread reached {largest_thread:,} tokens, which means long-running goals need resumable checkpoints.",
            "try": "Use /goal for multi-step work that spans research, planning, implementation, verification, and cleanup instead of keeping everything in one free-form thread.",
        },
        {
            "feature": "Subagents",
            "source": "Codex docs: Subagents",
            "url": "https://developers.openai.com/codex/concepts/subagents",
            "matches": f"{top_tool[1]:,} {top_tool[0]} calls show noisy exploration pressure in the main thread.",
            "try": "When there are 2+ independent read-heavy questions, explicitly ask Codex to spawn subagents and return only distilled findings.",
        },
        {
            "feature": "Automations + Skills",
            "source": "Codex app docs: Automations",
            "url": "https://developers.openai.com/codex/app/automations",
            "matches": "This report is a recurring diagnostic workflow, and repeated friction should not require a manual prompt every week.",
            "try": "Schedule Codex Insights weekly, then ask it to propose one new skill or AGENTS.md rule from the top recurring friction.",
        },
        {
            "feature": "AGENTS.md instruction layering",
            "source": "Codex docs: AGENTS.md",
            "url": "https://developers.openai.com/codex/guides/agents-md",
            "matches": f"Activity spans {workspace_count} workspaces; repeated repo rules are likely being restated across threads.",
            "try": "Move stable preferences into global ~/.codex/AGENTS.md and keep repo-specific verification, safety, and style rules in each repository AGENTS.md.",
        },
        {
            "feature": "codex exec JSONL and explicit sandbox flags",
            "source": "Codex docs: Non-interactive mode",
            "url": "https://developers.openai.com/codex/noninteractive",
            "matches": f"Approval mode and sandbox state are visible, and this window had {totals['escalation_requests']:,} escalation request(s).",
            "try": "For repeatable reports or CI triage, run codex exec with explicit --sandbox and --json so command output becomes measurable instead of conversational.",
        },
        {
            "feature": "Codex SDK",
            "source": "Codex docs: SDK",
            "url": "https://developers.openai.com/codex/sdk",
            "matches": "A Codex insights product eventually needs programmatic control, not only a local HTML artifact.",
            "try": "Use the SDK when you want Codex Insights to open or resume threads, run analysis, and feed results into your own dashboard or workflow.",
        },
    ]

    return {
        "glance": {
            "working": " ".join(working_parts),
            "hindering": " ".join(hindering_parts),
            "quick_wins": " ".join(quick_wins),
            "ambitious": ambitious,
        },
        "wins": wins,
        "frictions": frictions,
        "codex_signals": codex_signals,
        "official_matches": official_matches,
        "features": features,
        "patterns": patterns,
        "method": (
            "Deterministic insight builder: SQLite thread metadata + session JSONL event counters + parsed shell command names. "
            "It maps official OpenAI Codex features from the docs/changelog to observed friction, and does not quote raw prompts or tool outputs by default."
        ),
    }


def render_html(report: dict[str, Any]) -> str:
    totals = report["totals"]
    failure_pct = report["exec_failure_rate"] * 100
    story = build_report_story(report)
    health_score = calculate_health_score(report)
    generated_at = utc_now().isoformat(timespec="seconds")
    generated_display = generated_at.replace("T", " ").replace("+00:00", " UTC")
    score_label = "Strong" if health_score >= 82 else "Needs attention" if health_score >= 62 else "At risk"
    score_class = "good" if health_score >= 82 else "warn" if health_score >= 62 else "bad"
    max_tool_count = max([count for _, count in report["tools"]] or [1])
    max_workspace_count = max([count for _, count in report["top_workspaces"]] or [1])

    def esc(value: Any) -> str:
        return html.escape(str(value or ""), quote=True)

    def metric(label: str, value: str, note: str = "", tone: str = "") -> str:
        note_html = f"<span>{esc(note)}</span>" if note else ""
        class_name = f"metric {tone}".strip()
        return f"""
        <article class="{esc(class_name)}">
          <p class="metric-label">{esc(label)}</p>
          <strong>{esc(value)}</strong>
          {note_html}
        </article>
        """

    def table(headers: list[str], rows: list[list[Any]]) -> str:
        head = "".join(f"<th>{esc(header)}</th>" for header in headers)
        body = []
        for row in rows:
            body.append("<tr>" + "".join(f"<td>{esc(cell)}</td>" for cell in row) + "</tr>")
        if not body:
            body.append(f"<tr><td colspan=\"{len(headers)}\">No data.</td></tr>")
        return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>"

    def bar_row(label: Any, value: int, max_value: int, detail: str = "") -> str:
        width = 0 if max_value <= 0 else max(3, min(100, round((value / max_value) * 100)))
        detail_html = f"<span>{esc(detail)}</span>" if detail else ""
        return f"""
        <div class="bar-row">
          <div class="bar-label">
            <strong>{esc(label)}</strong>
            {detail_html}
          </div>
          <div class="bar-track" aria-hidden="true"><div style="width: {width}%"></div></div>
          <b>{value:,}</b>
        </div>
        """

    def health_item(label: str, value: str, detail: str) -> str:
        return f"""
        <div class="health-item">
          <span>{esc(label)}</span>
          <strong>{esc(value)}</strong>
          <p>{esc(detail)}</p>
        </div>
        """

    def activity_column(day: dict[str, Any], max_tokens: int) -> str:
        tokens = int(day.get("tokens") or 0)
        threads = int(day.get("threads") or 0)
        height = 2 if max_tokens <= 0 else max(8, min(100, round((tokens / max_tokens) * 100)))
        label = str(day.get("date") or "")[5:]
        return f"""
        <div class="activity-col" title="{esc(label)}: {tokens:,} tokens, {threads} thread(s)">
          <div class="activity-bar"><div style="height: {height}%"></div></div>
          <span>{esc(label)}</span>
        </div>
        """

    def insight_card(item: dict[str, str]) -> str:
        return f"""
        <article class="insight-card">
          <span>{esc(item.get("type"))}</span>
          <h3>{esc(item.get("title"))}</h3>
          <p>{esc(item.get("evidence"))}</p>
          <strong>{esc(item.get("action"))}</strong>
        </article>
        """

    tool_rows = [[name, count] for name, count in report["tools"]]
    workspace_rows = [[cwd, count] for cwd, count in report["top_workspaces"]]
    thread_rows = [
        [
            (item.get("title") or item.get("id") or "") if item.get("title") else item.get("id"),
            f"{int(item.get('tokens_used') or 0):,}",
            item.get("cwd") or "",
            item.get("reasoning_effort") or "",
        ]
        for item in report["top_threads"][:8]
    ]
    recommendation_items = "\n".join(
        f"""
        <li>
          <span>{index:02d}</span>
          <p>{esc(rec)}</p>
        </li>
        """
        for index, rec in enumerate(report["recommendations"], start=1)
    )
    tool_bars = "\n".join(bar_row(name, count, max_tool_count) for name, count in report["tools"][:8])
    workspace_bars = "\n".join(
        bar_row(cwd, count, max_workspace_count, "active thread count")
        for cwd, count in report["top_workspaces"][:6]
    )
    max_daily_tokens = max([int(day.get("tokens") or 0) for day in report["daily_activity"]] or [1])
    activity_bars = "\n".join(activity_column(day, max_daily_tokens) for day in report["daily_activity"])
    insight_cards = "\n".join(insight_card(item) for item in report["insights"])
    model_text = ", ".join(f"{name} ({count})" for name, count in report["models"][:3]) or "No model data"
    effort_text = ", ".join(f"{name} ({count})" for name, count in report["reasoning_effort"][:3]) or "No effort data"

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Codex /insights</title>
  <style>
    :root {{
      color-scheme: light dark;
      --bg: #f8fafc;
      --panel: #ffffff;
      --panel-soft: #f1f5f9;
      --ink: #0f172a;
      --text: #1e293b;
      --muted: #64748b;
      --border: #e2e8f0;
      --border-strong: #cbd5e1;
      --primary: #2563eb;
      --primary-2: #0f766e;
      --accent: #f97316;
      --good: #0f766e;
      --warn: #b45309;
      --bad: #b91c1c;
      --shadow: 0 22px 60px rgba(15, 23, 42, .08);
    }}
    @media (prefers-color-scheme: dark) {{
      :root {{
        --bg: #0b1120;
        --panel: #111827;
        --panel-soft: #172033;
        --ink: #f8fafc;
        --text: #dbe4ef;
        --muted: #94a3b8;
        --border: #243244;
        --border-strong: #334155;
        --primary: #60a5fa;
        --primary-2: #2dd4bf;
        --accent: #fb923c;
        --shadow: 0 28px 70px rgba(0, 0, 0, .35);
      }}
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background:
        radial-gradient(circle at top left, rgba(37, 99, 235, .14), transparent 34rem),
        linear-gradient(180deg, var(--bg), var(--bg));
      color: var(--text);
      font: 15px/1.5 ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    main {{
      max-width: 1180px;
      margin: 0 auto;
      padding: 34px 24px 56px;
    }}
    header {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) 260px;
      gap: 24px;
      align-items: stretch;
      margin-bottom: 16px;
    }}
    h1, h2 {{ margin: 0; letter-spacing: 0; }}
    h1 {{
      color: var(--ink);
      font-size: 42px;
      line-height: 1.04;
      max-width: 760px;
    }}
    h2 {{
      color: var(--ink);
      font-size: 17px;
      margin-bottom: 14px;
    }}
    .hero, .score, .metric, section {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 8px;
      box-shadow: var(--shadow);
    }}
    .hero {{
      padding: 28px;
      position: relative;
      overflow: hidden;
    }}
    .hero:before {{
      content: "";
      position: absolute;
      inset: 0 auto 0 0;
      width: 6px;
      background: linear-gradient(180deg, var(--primary), var(--primary-2), var(--accent));
    }}
    .eyebrow {{
      color: var(--primary-2);
      font-size: 12px;
      font-weight: 700;
      letter-spacing: .12em;
      text-transform: uppercase;
      margin: 0 0 12px;
    }}
    .subtle {{ color: var(--muted); margin: 12px 0 0; max-width: 740px; }}
    .privacy {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      margin-top: 18px;
      padding: 7px 10px;
      border: 1px solid var(--border);
      border-radius: 999px;
      color: var(--muted);
      background: var(--panel-soft);
      font-size: 13px;
    }}
    .privacy:before {{
      content: "";
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: var(--good);
    }}
    .score {{
      padding: 22px;
      text-align: center;
      display: grid;
      align-content: center;
      gap: 12px;
    }}
    .score-ring {{
      width: 140px;
      height: 140px;
      margin: 0 auto;
      display: grid;
      place-items: center;
      border-radius: 50%;
      background:
        radial-gradient(circle at center, var(--panel) 0 55%, transparent 56%),
        conic-gradient(var(--primary) {health_score}%, var(--border) 0);
    }}
    .score strong {{ display: block; color: var(--ink); font-size: 42px; line-height: 1; }}
    .score span {{ color: var(--muted); }}
    .score .{score_class} {{ color: var(--primary-2); font-weight: 700; }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
      margin: 24px 0;
    }}
    .metric {{
      padding: 18px;
      min-height: 126px;
      box-shadow: none;
    }}
    .metric-label {{
      margin: 0 0 10px;
      color: var(--muted);
      font-size: 13px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: .06em;
    }}
    .metric strong {{ display: block; color: var(--ink); font-size: 27px; line-height: 1.1; }}
    .metric span {{ display: block; margin-top: 8px; color: var(--muted); font-size: 13px; }}
    .metric.warning strong {{ color: var(--warn); }}
    .metric.good strong {{ color: var(--good); }}
    .dashboard {{
      display: grid;
      grid-template-columns: minmax(0, 1.15fr) minmax(320px, .85fr);
      gap: 16px;
      align-items: start;
    }}
    section {{ padding: 20px; margin-top: 16px; overflow: auto; box-shadow: none; }}
    .panel-grid {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
    }}
    .insight-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }}
    .insight-card {{
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px;
      background: var(--panel-soft);
    }}
    .insight-card span {{
      color: var(--primary-2);
      font-size: 11px;
      font-weight: 800;
      letter-spacing: .08em;
      text-transform: uppercase;
    }}
    .insight-card h3 {{
      margin: 7px 0 6px;
      color: var(--ink);
      font-size: 17px;
      line-height: 1.25;
    }}
    .insight-card p {{
      margin: 0 0 10px;
      color: var(--muted);
      font-size: 13px;
    }}
    .insight-card strong {{
      display: block;
      color: var(--text);
      font-size: 14px;
      line-height: 1.45;
    }}
    .health-item {{
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px;
      background: var(--panel-soft);
    }}
    .health-item span {{ color: var(--muted); font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: .06em; }}
    .health-item strong {{ display: block; margin-top: 6px; color: var(--ink); font-size: 18px; }}
    .health-item p {{ margin: 6px 0 0; color: var(--muted); font-size: 13px; }}
    .recommendations {{
      list-style: none;
      padding: 0;
      margin: 0;
      display: grid;
      gap: 10px;
    }}
    .recommendations li {{
      display: grid;
      grid-template-columns: 42px 1fr;
      gap: 12px;
      align-items: start;
      padding: 12px;
      background: var(--panel-soft);
      border: 1px solid var(--border);
      border-radius: 8px;
    }}
    .recommendations span {{
      display: grid;
      place-items: center;
      width: 32px;
      height: 32px;
      border-radius: 50%;
      background: rgba(37, 99, 235, .12);
      color: var(--primary);
      font-weight: 800;
      font-size: 12px;
    }}
    .recommendations p {{ margin: 0; }}
    .bar-list {{ display: grid; gap: 12px; }}
    .bar-row {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(120px, .42fr) 54px;
      gap: 12px;
      align-items: center;
    }}
    .bar-label strong {{
      display: block;
      color: var(--ink);
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }}
    .bar-label span {{ display: block; color: var(--muted); font-size: 12px; }}
    .bar-track {{
      height: 9px;
      border-radius: 999px;
      overflow: hidden;
      background: var(--panel-soft);
      border: 1px solid var(--border);
    }}
    .bar-track div {{
      height: 100%;
      border-radius: inherit;
      background: linear-gradient(90deg, var(--primary), var(--primary-2));
    }}
    .bar-row b {{ color: var(--ink); text-align: right; font-variant-numeric: tabular-nums; }}
    .activity {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(42px, 1fr));
      gap: 10px;
      align-items: end;
      min-height: 160px;
    }}
    .activity-col {{
      display: grid;
      gap: 8px;
      align-items: end;
      min-width: 0;
    }}
    .activity-bar {{
      height: 112px;
      display: flex;
      align-items: end;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: var(--panel-soft);
      overflow: hidden;
    }}
    .activity-bar div {{
      width: 100%;
      min-height: 3px;
      background: linear-gradient(180deg, var(--primary), var(--primary-2));
    }}
    .activity-col span {{
      color: var(--muted);
      font-size: 11px;
      text-align: center;
      white-space: nowrap;
    }}
    table {{ width: 100%; border-collapse: collapse; table-layout: fixed; }}
    th, td {{ padding: 10px 8px; border-bottom: 1px solid var(--border); text-align: left; vertical-align: top; }}
    th {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }}
    td:nth-child(2), th:nth-child(2) {{ text-align: right; }}
    td {{ color: var(--text); overflow-wrap: anywhere; }}
    .small-note {{ color: var(--muted); font-size: 13px; margin: -6px 0 14px; }}
    @media (max-width: 820px) {{
      header {{ grid-template-columns: 1fr; }}
      .dashboard {{ grid-template-columns: 1fr; }}
      .panel-grid {{ grid-template-columns: 1fr; }}
      .insight-grid {{ grid-template-columns: 1fr; }}
      .grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
    }}
    @media (max-width: 520px) {{
      main {{ padding: 28px 14px 40px; }}
      .grid {{ grid-template-columns: 1fr; }}
      h1 {{ font-size: 28px; }}
      .bar-row {{ grid-template-columns: 1fr 72px; }}
      .bar-track {{ grid-column: 1 / -1; grid-row: 2; }}
    }}
    @media (prefers-reduced-motion: reduce) {{
      *, *:before, *:after {{ scroll-behavior: auto !important; transition: none !important; }}
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <div class="hero">
        <p class="eyebrow">Local Codex analytics</p>
        <h1>Codex /insights</h1>
        <p class="subtle">A privacy-first diagnosis of recent Codex sessions: activity, token load, tool mix, command friction, recurring patterns, and the next workflow changes worth making.</p>
        <p class="privacy">Aggregate only. No raw prompts, system instructions, or tool outputs included.</p>
      </div>
      <div class="score">
        <div class="score-ring">
          <div>
            <strong>{health_score}</strong>
            <span>/ 100</span>
          </div>
        </div>
        <span>Health Score</span>
        <span class="{score_class}">{esc(score_label)}</span>
      </div>
    </header>

    <div class="grid">
      {metric("Threads", f"{totals['threads']:,}", f"{totals['sessions_parsed']} sessions parsed")}
      {metric("Tokens", f"{totals['tokens_used']:,}", "state database total", "warning" if totals["tokens_used"] > 5_000_000 else "")}
      {metric("Shell Failure Rate", f"{failure_pct:.0f}%", f"{totals['exec_failed']} of {totals['exec_completed']} commands", "good" if failure_pct < 10 else "warning")}
      {metric("Web Searches", f"{totals['web_searches']:,}", "recent session events")}
    </div>

    <div class="dashboard">
      <div>
        <section>
          <h2>Doctor's Read</h2>
          <div class="panel-grid">
            {health_item("Model mix", model_text, "Models used in the active window.")}
            {health_item("Reasoning effort", effort_text, "Useful for spotting overpowered routine work.")}
            {health_item("Generated", generated_display, "Local report generated from read-only sources.")}
          </div>
        </section>

        <section>
          <h2>Insights</h2>
          <div class="insight-grid">{insight_cards}</div>
        </section>

        <section>
          <h2>Activity</h2>
          <p class="small-note">Daily token load from recently updated Codex threads.</p>
          <div class="activity">{activity_bars}</div>
        </section>

        <section>
          <h2>Actions</h2>
          <ul class="recommendations">{recommendation_items}</ul>
        </section>

        <section>
          <h2>Token-Heavy Threads</h2>
          <p class="small-note">Titles are hidden unless the report was generated with --include-titles.</p>
          {table(["Thread", "Tokens", "Workspace", "Effort"], thread_rows)}
        </section>
      </div>

      <div>
        <section>
          <h2>Tool Mix</h2>
          <div class="bar-list">{tool_bars or "<p class=\"small-note\">No tool calls found.</p>"}</div>
        </section>

        <section>
          <h2>Workspace Load</h2>
          <div class="bar-list">{workspace_bars or "<p class=\"small-note\">No workspace data found.</p>"}</div>
        </section>

        <section>
          <h2>Raw Tables</h2>
          {table(["Tool", "Calls"], tool_rows)}
          <div style="height: 16px"></div>
          {table(["Workspace", "Threads"], workspace_rows)}
        </section>
      </div>
    </div>
  </main>
</body>
</html>
"""


def render_html(report: dict[str, Any]) -> str:
    totals = report["totals"]
    since = report["window"]["since"][:10]
    today = utc_now().date().isoformat()
    days = report["window"]["days"]
    failure_pct = report["exec_failure_rate"] * 100
    story = build_report_story(report)

    def esc(value: Any) -> str:
        return html.escape(str(value or ""), quote=True)

    def stat(value: str, label: str) -> str:
        return f"<div class=\"stat\"><div class=\"stat-value\">{esc(value)}</div><div class=\"stat-label\">{esc(label)}</div></div>"

    def bar_block(title: str, rows: list[tuple[Any, int]]) -> str:
        max_value = max([int(value) for _, value in rows] or [1])
        body = []
        for label, value in rows:
            pct = max(3, round((int(value) / max_value) * 100)) if max_value else 0
            body.append(
                f"<div class=\"bar-row\"><div class=\"bar-label\">{esc(label)}</div>"
                f"<div class=\"bar-track\"><div class=\"bar-fill\" style=\"width:{pct}%\"></div></div>"
                f"<div class=\"bar-value\">{int(value):,}</div></div>"
            )
        return f"<div class=\"chart-card\"><div class=\"chart-title\">{esc(title)}</div>{''.join(body)}</div>"

    def work_area(area: dict[str, Any]) -> str:
        return f"""
        <div class="project-area">
          <div class="area-header">
            <div class="area-name">{esc(area["name"])}</div>
            <div class="area-count">~{int(area["sessions"]):,} sessions</div>
          </div>
          <div class="area-desc">{esc(area["description"])}</div>
        </div>
        """

    def insight_card(title: str, body: str, kind: str = "big-win") -> str:
        return f"<div class=\"{kind}\"><div class=\"{kind}-title\">{esc(title)}</div><div class=\"{kind}-desc\">{esc(body)}</div></div>"

    def feature_card(title: str, why: str, prompt: str) -> str:
        return f"""
        <div class="feature-card">
          <div class="feature-title">{esc(title)}</div>
          <div class="feature-why">{esc(why)}</div>
          <div class="example-code-row">
            <code class="example-code">{esc(prompt)}</code>
            <button class="copy-btn" data-copy="{esc(prompt)}">Copy</button>
          </div>
        </div>
        """

    def official_match_card(item: dict[str, str]) -> str:
        return f"""
        <div class="official-card">
          <div class="official-meta">{esc(item["source"])}</div>
          <div class="official-title">{esc(item["feature"])}</div>
          <div class="official-match"><strong>Why it matters:</strong> {esc(item["matches"])}</div>
          <div class="official-try"><strong>Try next:</strong> {esc(item["try"])}</div>
          <a class="source-link" href="{esc(item["url"])}">Open official docs</a>
        </div>
        """

    work_areas_html = "\n".join(work_area(area) for area in report["work_areas"])
    intent_chart = bar_block("WHAT YOU WANTED", [(name, count) for name, count in report["intent_counts"]])
    tool_chart = bar_block("TOP TOOLS USED", [(name, count) for name, count in report["tools"][:6]])
    workspace_chart = bar_block("WORKSPACES", [(name, count) for name, count in report["top_workspaces"][:6]])
    activity_chart = bar_block("DAILY TOKEN LOAD", [(item["date"][5:], int(item["tokens"])) for item in report["daily_activity"]])
    source_chart = bar_block("CODEX SURFACES", [(name, count) for name, count in report["sources"]])
    approval_chart = bar_block("APPROVAL MODES", [(name, count) for name, count in report["approval_modes"]])
    reasoning_chart = bar_block("REASONING EFFORT", [(name, count) for name, count in report["reasoning_effort"]])
    dynamic_tool_chart = bar_block("DYNAMIC TOOLS EXPOSED", [(name, count) for name, count in report["dynamic_tools"][:8]])
    command_type_chart = bar_block("COMMAND INTENT TYPES", [(name, count) for name, count in report["exec_command_types"][:8]])
    failed_command_chart = bar_block("FAILED COMMAND TYPES", [(name, count) for name, count in report["failed_command_types"][:8]])

    main_work = report["work_areas"][0]["name"] if report["work_areas"] else "mixed coding work"
    top_tool = report["tools"][0][0] if report["tools"] else "tools"
    top_tool_count = report["tools"][0][1] if report["tools"] else 0
    largest_thread = int(report["top_threads"][0]["tokens_used"]) if report["top_threads"] else 0
    top_source = report["sources"][0][0] if report["sources"] else "unknown"
    top_approval = report["approval_modes"][0][0] if report["approval_modes"] else "unknown"
    top_reasoning = report["reasoning_effort"][0][0] if report["reasoning_effort"] else "unknown"
    dynamic_tool_count = sum(count for _, count in report["dynamic_tools"])
    failed_type = report["failed_command_types"][0][0] if report["failed_command_types"] else "none"

    codex_signals = [insight_card(item["title"], item["body"], "codex-signal") for item in story["codex_signals"]]
    wins = [insight_card(item["title"], item["body"]) for item in story["wins"]]
    frictions = [insight_card(item["title"], item["body"], "friction-category") for item in story["frictions"]]
    official_matches = [official_match_card(item) for item in story["official_matches"]]
    features = [feature_card(item["title"], item["why"], item["prompt"]) for item in story["features"]]
    patterns = [feature_card(item["title"], item["why"], item["prompt"]) for item in story["patterns"]]

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Codex Insights</title>
  <style>
    * {{ box-sizing: border-box; }}
    body {{ font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f8fafc; color: #334155; line-height: 1.65; padding: 48px 24px; margin: 0; }}
    .container {{ max-width: 820px; margin: 0 auto; }}
    h1 {{ font-size: 34px; font-weight: 750; color: #0f172a; margin: 0 0 8px; letter-spacing: 0; }}
    h2 {{ font-size: 24px; color: #0f172a; margin: 44px 0 16px; letter-spacing: 0; }}
    h3 {{ font-size: 17px; color: #0f172a; margin: 26px 0 12px; }}
    .subtitle {{ color: #64748b; font-size: 15px; margin-bottom: 28px; }}
    .at-a-glance {{ background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%); border: 1px solid #f59e0b; border-radius: 12px; padding: 20px 24px; margin-bottom: 28px; }}
    .glance-section {{ margin: 0 0 14px; }}
    .glance-section:last-child {{ margin-bottom: 0; }}
    .glance-section strong {{ color: #78350f; }}
    .nav-toc {{ display: flex; flex-wrap: wrap; gap: 8px; margin: 24px 0 32px; padding: 16px; background: white; border-radius: 8px; border: 1px solid #e2e8f0; }}
    .nav-toc a {{ color: #2563eb; text-decoration: none; font-size: 14px; padding: 6px 10px; border-radius: 6px; }}
    .nav-toc a:hover {{ background: #eff6ff; }}
    .stats-row {{ display: flex; gap: 24px; margin-bottom: 40px; padding: 20px 0; border-top: 1px solid #e2e8f0; border-bottom: 1px solid #e2e8f0; flex-wrap: wrap; }}
    .stat {{ text-align: center; min-width: 105px; }}
    .stat-value {{ font-size: 25px; font-weight: 750; color: #0f172a; }}
    .stat-label {{ font-size: 12px; color: #64748b; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }}
    .project-areas, .big-wins, .friction-categories, .features-section, .patterns-section, .official-section {{ display: grid; gap: 14px; }}
    .project-area, .chart-card {{ background: white; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; }}
    .area-header {{ display: flex; justify-content: space-between; gap: 12px; margin-bottom: 6px; }}
    .area-name {{ font-weight: 700; color: #0f172a; }}
    .area-count {{ color: #64748b; font-size: 14px; white-space: nowrap; }}
    .area-desc {{ color: #475569; }}
    .narrative p {{ margin: 0 0 16px; }}
    .key-insight {{ border-left: 4px solid #2563eb; background: #eff6ff; padding: 14px 16px; border-radius: 0 8px 8px 0; margin: 18px 0; }}
    .charts-row {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin: 18px 0; }}
    .chart-title {{ font-size: 12px; color: #64748b; font-weight: 800; letter-spacing: .08em; margin-bottom: 12px; }}
    .bar-row {{ display: grid; grid-template-columns: minmax(0, 1fr) 120px 54px; gap: 10px; align-items: center; margin-bottom: 7px; }}
    .bar-label {{ color: #334155; font-size: 14px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
    .bar-track {{ height: 8px; background: #e2e8f0; border-radius: 99px; overflow: hidden; }}
    .bar-fill {{ height: 100%; background: #3b82f6; border-radius: inherit; }}
    .bar-value {{ font-size: 13px; color: #475569; text-align: right; font-variant-numeric: tabular-nums; }}
    .big-win {{ background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 8px; padding: 16px; }}
    .codex-signal {{ background: #eef2ff; border: 1px solid #c7d2fe; border-radius: 8px; padding: 16px; }}
    .big-win-title, .friction-category-title, .feature-title, .codex-signal-title {{ color: #0f172a; font-weight: 750; margin-bottom: 6px; }}
    .big-win-desc, .friction-category-desc, .feature-why, .codex-signal-desc {{ color: #475569; }}
    .friction-category {{ background: #fef2f2; border: 1px solid #fca5a5; border-radius: 8px; padding: 16px; }}
    .feature-card {{ background: #f0fdf4; border: 1px solid #86efac; border-radius: 8px; padding: 16px; }}
    .official-card {{ background: #fff7ed; border: 1px solid #fed7aa; border-radius: 8px; padding: 16px; }}
    .official-meta {{ color: #9a3412; font-size: 12px; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; margin-bottom: 6px; }}
    .official-title {{ color: #0f172a; font-weight: 750; margin-bottom: 8px; }}
    .official-match, .official-try {{ color: #475569; margin-top: 6px; }}
    .source-link {{ display: inline-block; margin-top: 10px; color: #2563eb; font-weight: 700; text-decoration: none; }}
    .source-link:hover {{ text-decoration: underline; }}
    .example-code-row {{ display: grid; grid-template-columns: 1fr auto; gap: 10px; margin-top: 12px; align-items: start; }}
    code.example-code {{ display: block; white-space: pre-wrap; background: #0f172a; color: #e2e8f0; border-radius: 6px; padding: 12px; font-size: 12px; line-height: 1.45; }}
    .copy-btn {{ border: 1px solid #cbd5e1; background: white; color: #2563eb; padding: 8px 10px; border-radius: 6px; cursor: pointer; font-weight: 700; }}
    .copy-btn:hover {{ background: #eff6ff; }}
    .section-intro {{ color: #64748b; margin-bottom: 16px; }}
    @media (max-width: 760px) {{ body {{ padding: 28px 14px; }} .charts-row {{ grid-template-columns: 1fr; }} .bar-row {{ grid-template-columns: 1fr 80px; }} .bar-track {{ grid-column: 1 / -1; grid-row: 2; }} .example-code-row {{ grid-template-columns: 1fr; }} }}
  </style>
</head>
<body>
  <main class="container">
    <h1>Codex Insights</h1>
    <p class="subtitle">{totals['user_messages']:,} user messages across {totals['threads']:,} active threads | {since} to {today} | aggregate-only local report</p>

    <section class="at-a-glance">
      <div class="glance-section"><strong>What's working:</strong> {esc(story["glance"]["working"])}</div>
      <div class="glance-section"><strong>What's hindering you:</strong> {esc(story["glance"]["hindering"])}</div>
      <div class="glance-section"><strong>Quick wins to try:</strong> {esc(story["glance"]["quick_wins"])}</div>
      <div class="glance-section"><strong>Ambitious workflows:</strong> {esc(story["glance"]["ambitious"])}</div>
      <div class="glance-section"><strong>Insight method:</strong> {esc(story["method"])}</div>
    </section>

    <nav class="nav-toc">
      <a href="#section-work">What You Work On</a>
      <a href="#section-codex-only">Codex-only Signals</a>
      <a href="#section-official">Official Feature Matches</a>
      <a href="#section-usage">How You Use Codex</a>
      <a href="#section-wins">Impressive Things</a>
      <a href="#section-friction">Where Things Go Wrong</a>
      <a href="#section-features">Features to Try</a>
      <a href="#section-patterns">New Usage Patterns</a>
      <a href="#section-horizon">On the Horizon</a>
    </nav>

    <div class="stats-row">
      {stat(f"{totals['threads']:,}", "THREADS")}
      {stat(f"{totals['tokens_used']:,}", "TOKENS")}
      {stat(f"{totals['exec_completed']:,}", "COMMANDS")}
      {stat(f"{failure_pct:.0f}%", "FAIL RATE")}
    </div>

    <h2 id="section-work">What You Work On</h2>
    <div class="project-areas">{work_areas_html}</div>
    <div class="charts-row">{intent_chart}{tool_chart}</div>

    <h2 id="section-codex-only">Codex-only Signals</h2>
    <p class="section-intro">These are signals this local Codex data can expose more directly than the Claude report: model/reasoning budget, sandbox and approval mode, active surface, dynamic tool availability, and parsed command semantics.</p>
    <div class="big-wins">{''.join(codex_signals)}</div>
    <div class="charts-row">{source_chart}{approval_chart}</div>
    <div class="charts-row">{reasoning_chart}{dynamic_tool_chart}</div>
    <div class="charts-row">{command_type_chart}{failed_command_chart}</div>

    <h2 id="section-official">Official Feature Matches</h2>
    <p class="section-intro">These recommendations map this week's measured friction to current OpenAI Codex docs and changelog items.</p>
    <div class="official-section">{''.join(official_matches)}</div>

    <h2 id="section-usage">How You Use Codex</h2>
    <div class="narrative">
      <p>You use Codex in a <strong>rapid investigation and correction loop</strong>: ask a compact question, let the agent inspect, then steer when the approach drifts. The tool profile is dominated by shell inspection, which is useful for grounding but expensive when the thread stays open too long.</p>
      <p>Your strongest pattern is turning repeated problems into reusable process. This session itself moved from an idea to a local skill, script, HTML report, browser verification, and a Claude-like insights format.</p>
      <div class="key-insight"><strong>Key pattern:</strong> Codex is most useful for you when it produces a durable artifact at the end of exploration: a skill, report, plan, or verified patch.</div>
    </div>
    <div class="charts-row">{workspace_chart}{activity_chart}</div>

    <h2 id="section-wins">Impressive Things You Did</h2>
    <p class="section-intro">The report is inferred from local Codex metadata and event patterns, not raw prompt excerpts.</p>
    <div class="big-wins">{''.join(wins)}</div>

    <h2 id="section-friction">Where Things Go Wrong</h2>
    <p class="section-intro">These are the session smells most likely to waste time or context.</p>
    <div class="friction-categories">{''.join(frictions)}</div>

    <h2 id="section-features">Existing Codex Features to Try</h2>
    <p class="section-intro">Copy these into Codex when you want the workflow to be explicit.</p>
    <div class="features-section">{''.join(features)}</div>

    <h2 id="section-patterns">New Ways to Use Codex</h2>
    <p class="section-intro">These mirror the Claude report's pasteable playbooks, adapted for Codex.</p>
    <div class="patterns-section">{''.join(patterns)}</div>

    <h2 id="section-horizon">On the Horizon</h2>
    <p>Codex can evolve from answering within a thread to running a full verification loop: plan, delegate, implement, test, screenshot, collect evidence, and only then summarize. The strongest next product is not just `/insights`; it is `/insights` feeding directly into new skills, repo instructions, and automated review gates.</p>
    {feature_card("Codex Insights as a recurring workflow", "Run this report weekly, compare drift, and turn repeated friction into skills or AGENTS.md rules.", "Run Codex Insights for the last 7 days, summarize the top 3 recurring frictions, and propose one new skill or repo instruction that would prevent them.")}
  </main>
  <script>
    document.querySelectorAll('.copy-btn').forEach((button) => {{
      button.addEventListener('click', async () => {{
        await navigator.clipboard.writeText(button.dataset.copy || '');
        button.textContent = 'Copied';
        setTimeout(() => button.textContent = 'Copy', 1200);
      }});
    }});
  </script>
</body>
</html>
"""


def calculate_health_score(report: dict[str, Any]) -> int:
    totals = report["totals"]
    score = 100

    if report["top_threads"] and int(report["top_threads"][0].get("tokens_used") or 0) > 500_000:
        score -= 16
    if int(totals["tokens_used"]) > 5_000_000:
        score -= 12
    if report["exec_failure_rate"] >= 0.2:
        score -= 14
    elif report["exec_failure_rate"] >= 0.1:
        score -= 7
    if totals["web_searches"] >= 15:
        score -= 6
    if len(report["top_workspaces"]) >= 5:
        score -= 6

    return max(0, min(100, score))


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze recent local Codex usage without printing raw session content.")
    parser.add_argument("--days", type=int, default=7, help="Lookback window in days.")
    parser.add_argument("--codex-home", default=os.environ.get("CODEX_HOME", "~/.codex"), help="Codex home directory.")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of Markdown.")
    parser.add_argument("--html", action="store_true", help="Emit a self-contained HTML report.")
    parser.add_argument("--output", help="Write report to this path instead of stdout.")
    parser.add_argument("--include-titles", action="store_true", help="Include shortened thread titles. Titles may contain prompt text.")
    args = parser.parse_args()

    if args.days <= 0:
        print("--days must be positive", file=sys.stderr)
        return 2

    report = summarize(args)
    report["story"] = build_report_story(report)
    if args.json:
        output = json.dumps(report, indent=2, ensure_ascii=False)
    elif args.html:
        output = render_html(report)
    else:
        output = render_markdown(report)

    if args.output:
        Path(args.output).expanduser().write_text(output, encoding="utf-8")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
