"""Evaluates a tool call against the rules and returns the strictest verdict."""

from __future__ import annotations

import os
from typing import Any

from . import rules
from .rules import ASK, DENY, Context, Verdict
from .shell import UnparsableCommand, parse

ALLOW = "allow"
SHELL_TOOLS = {"Bash", "PowerShell"}
FILE_TOOLS = {"Read": "file_path", "Edit": "file_path", "Write": "file_path", "NotebookEdit": "notebook_path",
              "Grep": "path", "Glob": "path"}
_RANK = {ALLOW: 0, ASK: 1, DENY: 2}


def strictest(verdicts: list[Verdict]) -> Verdict | None:
    return max(verdicts, key=lambda v: _RANK[v.decision], default=None)


def context_from_env(cwd: str) -> Context:
    branches = os.environ.get("GUARDRAILS_PROTECTED_BRANCHES", "main,master")
    patterns = os.environ.get("GUARDRAILS_SECRET_PATTERNS", "")
    return Context(
        cwd=cwd,
        protected_branches=frozenset(b.strip() for b in branches.split(",") if b.strip()),
        extra_secret_patterns=tuple(p.strip() for p in patterns.split(",") if p.strip()),
    )


def evaluate_command(command: str, ctx: Context) -> Verdict | None:
    try:
        commands = parse(command)
    except UnparsableCommand as exc:
        return Verdict(ASK, "unparsable", f"The command could not be analyzed ({exc}).")
    verdicts = [v for cmd in commands for rule in rules.SEGMENT_RULES if (v := rule(cmd, ctx))]
    verdicts += [v for rule in rules.RAW_RULES if (v := rule(command, ctx))]
    return strictest(verdicts)


def evaluate_tool_call(tool_name: str, tool_input: dict[str, Any], ctx: Context) -> Verdict | None:
    if tool_name in SHELL_TOOLS:
        return evaluate_command(str(tool_input.get("command", "")), ctx)
    key = FILE_TOOLS.get(tool_name)
    if key and rules.is_secret_path(str(tool_input.get(key, "") or ""), ctx):
        return Verdict(DENY, "credential-read", f"`{tool_input.get(key)}` looks like a credential file.")
    return None
