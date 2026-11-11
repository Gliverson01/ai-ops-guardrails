# ai-ops-guardrails

[![ci](https://github.com/Gliverson01/ai-ops-guardrails/actions/workflows/ci.yml/badge.svg)](https://github.com/Gliverson01/ai-ops-guardrails/actions/workflows/ci.yml)

A [Claude Code](https://code.claude.com/docs/en/hooks) `PreToolUse` hook that lets an AI agent **investigate**
production infrastructure while keeping it from **changing** it. The agent can read logs, query metrics and inspect
the cluster; anything that writes to the cluster, a database, S3 or a protected branch, or that would print a
credential, is refused or sent to a human for approval.

I built the first version of this while running an AI-assisted L3 support workflow on a production Kubernetes
platform. This repository is a generic rewrite from scratch: no employer code, no internal names.

## Why

An agent with a shell is as powerful as the credentials on the machine. Most investigation work is read-only, but a
single `kubectl delete`, `deleteMany({})` or `git push --force` is enough to turn help into an incident, and a single
`cat .env` puts a secret into a transcript. Permission prompts help, but people approve prompts on autopilot. These
rules decide before the prompt appears.

## What it does

| Rule | Denied (refused, the agent is told why) | Asked (a human approves) |
|---|---|---|
| `kubernetes-write` | `kubectl apply/create/delete/edit/patch/scale/drain/...`, `rollout restart/undo`, `helm install/upgrade/uninstall/rollback` | `kubectl exec/cp/debug/attach` |
| `kubernetes-secret-read` | `kubectl get secret -o yaml/json/jsonpath`, `kubectl config view --raw` | |
| `credential-read` | reading `.env`, `*.pem`, `*.key`, SSH keys, `~/.aws/credentials`, `*.tfstate`... with `cat`, `grep`, `Get-Content`, the `Read`/`Grep` tools, etc. | `printenv`, `env`, `Get-ChildItem Env:` |
| `database-write` | `mongosh --eval` with insert/update/delete/drop/`$out`, SQL clients with `INSERT/UPDATE/DELETE/DROP/ALTER...`, Python using `pymongo` write methods | interactive `mongosh`, SQL script files |
| `cloud-write` | `aws s3 cp/sync` to `s3://`, `aws s3 mv/rm/rb/mb`, Python using `boto3` write calls | other mutating AWS CLI calls (`terminate-`, `delete-`, `put-`...) |
| `terraform-write` | `terraform/tofu apply/destroy/import/taint`, `state rm/mv/push` | |
| `git-danger` | force push, `+refspec`, `--mirror`, `--delete`, push to `main`/`master` (including a plain `git push` from those branches) | `reset --hard`, `clean -f`, `branch -D` |
| `kill-by-name` | `pkill`, `killall`, `taskkill /IM`, `Stop-Process -Name` | |

Reads stay allowed: `kubectl get/describe/logs/port-forward`, `kubectl get secrets` (names only), `aws s3 cp s3://...
./local`, `mongosh --eval 'db.x.find()'`, `SELECT` queries, `terraform plan`, pushes to feature branches.

## How it works

```
tool call (JSON on stdin)
  -> shell.parse()      split on ; && || | and newlines, unwrap sudo/env/timeout/watch/xargs,
                        recurse into bash -c, pwsh -Command, cmd /c, $(...), `...`, <(...)
  -> rules (per simple command, with real argument parsing: flags vs positionals)
  -> raw rules          scan the full text for Python heredocs using pymongo/boto3
  -> strictest verdict  deny > ask > nothing
  -> {"hookSpecificOutput": {"permissionDecision": "deny" | "ask", "permissionDecisionReason": "..."}}
```

Design choices:

- **Parse, don't grep.** `kubectl get pods -l app=delete` is allowed; `watch -n 5 kubectl delete pod x` and
  `kubectl get pods -o name | xargs kubectl delete` are not. Flags that take values are skipped when looking for the verb.
- **Fail closed.** Claude Code lets a tool call through when a hook crashes, so every failure path (bad JSON, a bug,
  unbalanced quotes) returns `ask` instead.
- **Silent when allowed.** No output means the normal permission flow continues; the hook never grants anything.
- **Windows too.** `C:\tools\kubectl.exe`, PowerShell cmdlets and the `PowerShell` tool are covered, and CI runs on
  Ubuntu and Windows.
- **Audit trail.** Set `GUARDRAILS_LOG=/path/guardrails.jsonl` to append one line per decision (no command text, so
  no secrets end up in the log).

## Install

```bash
pip install git+https://github.com/Gliverson01/ai-ops-guardrails
```

Then add the hook to `.claude/settings.json` (project) or `~/.claude/settings.json` (user). See
[`examples/settings.json`](examples/settings.json):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell|Read|Edit|Write|Grep|Glob",
        "hooks": [{ "type": "command", "command": "guardrails-hook", "timeout": 10 }]
      }
    ]
  }
}
```

Check a command by hand:

```bash
python -m guardrails "kubectl -n apps rollout restart deploy/web"
# deny [kubernetes-write] `kubectl rollout restart` changes the cluster. A human runs it.
```

### Configuration

| Variable | Default | Meaning |
|---|---|---|
| `GUARDRAILS_PROTECTED_BRANCHES` | `main,master` | Branches that only accept changes through pull requests |
| `GUARDRAILS_SECRET_PATTERNS` | (none) | Extra credential file patterns, e.g. `*.ini,config/prod-*.yaml` |
| `GUARDRAILS_LOG` | (off) | JSONL audit log path |

## Tests

```bash
pip install -e ".[dev]"
pytest -q
```

The suite is a table of commands that must be denied, asked or allowed (including the evasions above), plus
end-to-end tests that run the hook as Claude Code does and a real git repository for the protected-branch check.

## Limitations

This is a seatbelt, not a sandbox.

- An agent that writes a script to a file and then runs it, or that uses an alias, a custom binary or an API client
  the rules do not know, gets past a command-line filter. Least-privilege credentials (read-only database users,
  read-only cluster roles, scoped cloud roles) remain the primary control; these rules catch the honest mistakes and
  make the risky path visible.
- The parser is conservative: text that merely *mentions* a dangerous command inside a nested shell or a `$(...)`
  may be blocked. That is intended.
- Rules cover the tools I use in production: kubectl, Helm, AWS CLI, MongoDB, PostgreSQL/MySQL, Terraform, git. Adding
  one is a function in [`guardrails/rules.py`](guardrails/rules.py) plus rows in the test table.

## License

MIT
