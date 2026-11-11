import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def run_hook(event: dict, env: dict | None = None) -> dict | None:
    proc = subprocess.run([sys.executable, "-m", "guardrails.hook"], input=json.dumps(event), capture_output=True,
                          text=True, cwd=ROOT, env=env, timeout=30)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout) if proc.stdout.strip() else None


def test_hook_denies_with_claude_code_format():
    out = run_hook({"tool_name": "Bash", "tool_input": {"command": "kubectl delete pod web-0"}, "cwd": str(ROOT)})
    decision = out["hookSpecificOutput"]
    assert decision["hookEventName"] == "PreToolUse"
    assert decision["permissionDecision"] == "deny"
    assert decision["permissionDecisionReason"].startswith("[guardrails]")


def test_hook_is_silent_when_allowed():
    assert run_hook({"tool_name": "Bash", "tool_input": {"command": "kubectl get pods"}, "cwd": str(ROOT)}) is None


def test_hook_fails_closed_on_bad_input():
    proc = subprocess.run([sys.executable, "-m", "guardrails.hook"], input="not json", capture_output=True,
                          text=True, cwd=ROOT, timeout=30)
    assert json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask"


@pytest.fixture
def repo_on(tmp_path):
    def make(branch: str) -> Path:
        subprocess.run(["git", "init", "-q", "-b", branch, str(tmp_path)], check=True)
        return tmp_path
    return make


def test_plain_push_from_main_is_denied(repo_on):
    from guardrails.engine import evaluate_command
    from guardrails.rules import Context
    repo = repo_on("main")
    verdict = evaluate_command("git push", Context(cwd=str(repo)))
    assert verdict and verdict.rule == "git-danger"


def test_plain_push_from_feature_branch_is_allowed(repo_on):
    from guardrails.engine import evaluate_command
    from guardrails.rules import Context
    repo = repo_on("feature/x")
    assert evaluate_command("git push -u origin", Context(cwd=str(repo))) is None
