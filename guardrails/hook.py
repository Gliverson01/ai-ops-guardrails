"""Claude Code PreToolUse hook.

Reads the tool call as JSON on stdin and, when a rule matches, prints a permission decision:
  {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny"|"ask", ...}}
Prints nothing (exit 0) when no rule matches, so the normal permission flow continues.

Fails closed: if the hook itself breaks, it asks the human instead of letting the call through.
"""

from __future__ import annotations

import json
import os
import sys
import time

from .engine import context_from_env, evaluate_tool_call
from .rules import ASK


def _decision(decision: str, reason: str) -> str:
    return json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
        "permissionDecisionReason": f"[guardrails] {reason}",
    }})


def _audit(entry: dict) -> None:
    path = os.environ.get("GUARDRAILS_LOG")
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass


def main() -> int:
    try:
        event = json.load(sys.stdin)
        tool, tool_input = event.get("tool_name", ""), event.get("tool_input") or {}
        verdict = evaluate_tool_call(tool, tool_input, context_from_env(event.get("cwd") or os.getcwd()))
    except Exception as exc:  # noqa: BLE001 - any failure must not silently allow the call
        print(_decision(ASK, f"guardrails hook failed ({type(exc).__name__}); confirm manually."))
        return 0
    if verdict is None:
        return 0
    _audit({"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "session": event.get("session_id"), "tool": tool,
            "decision": verdict.decision, "rule": verdict.rule})
    print(_decision(verdict.decision, verdict.reason))
    return 0


if __name__ == "__main__":
    sys.exit(main())
