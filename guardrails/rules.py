"""The rules. Each one looks at a single simple command (or at the raw text) and returns a verdict or None.

Verdicts:
  deny -> the tool call is refused and the agent is told why.
  ask  -> the human is asked to approve it.
"""

from __future__ import annotations

import fnmatch
import os
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

from .shell import SimpleCommand, program_name

DENY, ASK = "deny", "ask"


@dataclass(frozen=True)
class Verdict:
    decision: str  # "deny" or "ask"
    rule: str
    reason: str


@dataclass(frozen=True)
class Context:
    cwd: str
    protected_branches: frozenset[str] = frozenset({"main", "master"})
    extra_secret_patterns: tuple[str, ...] = ()


SegmentRule = Callable[[SimpleCommand, Context], Verdict | None]
RawRule = Callable[[str, Context], Verdict | None]


def first_positional(args: tuple[str, ...] | list[str], value_flags: set[str]) -> tuple[int | None, str | None]:
    """Index and value of the first argument that is not a flag (skipping flag values)."""
    i = 0
    while i < len(args):
        a = args[i]
        if a.startswith("-"):
            i += 2 if (a in value_flags and "=" not in a) else 1
            continue
        return i, a
    return None, None


def positionals(args: tuple[str, ...] | list[str], value_flags: set[str]) -> list[str]:
    out, i = [], 0
    while i < len(args):
        a = args[i]
        if a.startswith("-"):
            i += 2 if (a in value_flags and "=" not in a) else 1
            continue
        out.append(a)
        i += 1
    return out


# --------------------------------------------------------------------------------------------- Kubernetes

KUBECTL = {"kubectl", "oc"}
KUBE_VALUE_FLAGS = {
    "-n", "--namespace", "--context", "--kubeconfig", "--cluster", "--user", "-s", "--server",
    "--token", "--as", "--as-group", "--request-timeout", "-l", "--selector", "-o", "--output", "-f", "--filename",
    "-c", "--container",
}
KUBE_WRITE_VERBS = {
    "apply", "create", "delete", "edit", "patch", "replace", "scale", "autoscale", "set", "label", "annotate",
    "drain", "cordon", "uncordon", "taint", "expose", "run",
}
KUBE_ROLLOUT_WRITE = {"restart", "undo", "pause", "resume"}
HELM_WRITE_VERBS = {"install", "upgrade", "uninstall", "delete", "rollback"}


def kubernetes_write(cmd: SimpleCommand, ctx: Context) -> Verdict | None:
    if cmd.program == "helm":
        _, verb = first_positional(cmd.args, {"-n", "--namespace", "--kube-context", "--kubeconfig"})
        if verb in HELM_WRITE_VERBS:
            return Verdict(DENY, "kubernetes-write", f"`helm {verb}` changes the cluster. A human runs it.")
        return None
    if cmd.program not in KUBECTL:
        return None
    i, verb = first_positional(cmd.args, KUBE_VALUE_FLAGS)
    if verb in KUBE_WRITE_VERBS:
        return Verdict(DENY, "kubernetes-write", f"`kubectl {verb}` changes the cluster. A human runs it.")
    if verb == "rollout" and i is not None:
        _, sub = first_positional(cmd.args[i + 1:], KUBE_VALUE_FLAGS)
        if sub in KUBE_ROLLOUT_WRITE:
            return Verdict(DENY, "kubernetes-write", f"`kubectl rollout {sub}` changes the cluster. A human runs it.")
    if verb in ("exec", "cp", "debug", "attach"):
        return Verdict(ASK, "kubernetes-write", f"`kubectl {verb}` can change what runs inside a pod.")
    return None


def kubernetes_secret_read(cmd: SimpleCommand, ctx: Context) -> Verdict | None:
    if cmd.program not in KUBECTL:
        return None
    args = list(cmd.args)
    if "view-secret" in args or ("config" in args and "view" in args and "--raw" in args):
        return Verdict(DENY, "kubernetes-secret-read", "This prints credentials in clear text.")
    i, verb = first_positional(args, KUBE_VALUE_FLAGS)
    if verb != "get" or i is None:
        return None
    _, resource = first_positional(args[i + 1:], KUBE_VALUE_FLAGS)
    if not resource or not any(r.split("/")[0] in ("secret", "secrets") for r in resource.lower().split(",")):
        return None
    joined = " ".join(args)
    if re.search(r"(^|\s)(-o|--output)(=|\s)?(yaml|json|jsonpath|go-template|template|custom-columns)", joined):
        return Verdict(DENY, "kubernetes-secret-read", "Secret values would be printed. List names without `-o`.")
    return None


# --------------------------------------------------------------------------------------------- credentials

READERS = {
    "cat", "tac", "less", "more", "head", "tail", "bat", "nl", "type", "get-content", "gc", "strings", "xxd", "od",
    "hexdump", "grep", "egrep", "rg", "ag", "sed", "awk", "base64", "select-string", "sls", "cp", "scp", "rsync",
    "copy-item", "vim", "vi", "nano", "code", "notepad", "openssl",
}
SECRET_PATTERNS = (
    ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.kdbx", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    ".netrc", ".pgpass", "credentials", "*.tfstate", "*.tfvars", "secrets.y*ml", ".git-credentials",
)
SAFE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".pub")


def is_secret_path(path: str, ctx: Context) -> bool:
    name = program_name(path.strip("'\"")) if path else ""
    if not name or name.endswith(SAFE_SUFFIXES):
        return False
    return any(fnmatch.fnmatch(name, p.lower()) for p in SECRET_PATTERNS + ctx.extra_secret_patterns)


def credential_read(cmd: SimpleCommand, ctx: Context) -> Verdict | None:
    if cmd.program == "printenv" or (cmd.program in ("get-childitem", "gci", "dir", "ls") and
                                     any(a.lower().rstrip("\\/") in ("env:", "env:*") for a in cmd.args)):
        return Verdict(ASK, "credential-read", "Environment variables often hold tokens.")
    if cmd.program == "env" and not cmd.args:
        return Verdict(ASK, "credential-read", "Environment variables often hold tokens.")
    if cmd.program not in READERS:
        return None
    for a in cmd.args:
        if not a.startswith("-") and is_secret_path(a, ctx):
            return Verdict(DENY, "credential-read", f"`{a}` looks like a credential file. Read the non-secret fields "
                                                    "another way, or ask the human.")
    return None


# --------------------------------------------------------------------------------------------- databases

MONGO_WRITE = re.compile(
    r"\.(insert(One|Many)?|update(One|Many)?|replaceOne|delete(One|Many)|remove|drop(Database|Indexes|Index)?|"
    r"bulkWrite|findOneAnd(Update|Replace|Delete)|findAndModify|createIndex(es)?|renameCollection)\s*\(|\$(out|merge)\b"
)
SQL_WRITE = re.compile(r"\b(insert|update|delete|drop|truncate|alter|create|grant|revoke|merge|replace)\b", re.I)
SQL_CLIENTS = {"psql": {"-c", "--command"}, "mysql": {"-e", "--execute"}, "mariadb": {"-e", "--execute"},
               "sqlcmd": {"-q", "-Q"}, "clickhouse-client": {"-q", "--query"}}
SQL_FILE_FLAGS = {"psql": {"-f", "--file"}, "sqlcmd": {"-i"}}


def database_write(cmd: SimpleCommand, ctx: Context) -> Verdict | None:
    args = list(cmd.args)
    if cmd.program in ("mongosh", "mongo"):
        if "--eval" in args:
            script = args[args.index("--eval") + 1] if args.index("--eval") + 1 < len(args) else ""
            if MONGO_WRITE.search(script):
                return Verdict(DENY, "database-write", "This writes to MongoDB. Hand the command to a human.")
            return None
        if any(a.endswith(".js") for a in args):
            return Verdict(ASK, "database-write", "A MongoDB script file can write. Check it first.")
        return Verdict(ASK, "database-write", "An interactive MongoDB shell cannot be inspected in advance.")
    if cmd.program in SQL_CLIENTS:
        flags = SQL_CLIENTS[cmd.program]
        for i, a in enumerate(args):
            name, _, inline = a.partition("=")
            if a in flags and i + 1 < len(args):
                query = args[i + 1]
            elif inline and name in flags:
                query = inline
            else:
                query = None
            if query and SQL_WRITE.search(query):
                return Verdict(DENY, "database-write", "This SQL changes data or schema. Hand it to a human.")
        if set(args) & SQL_FILE_FLAGS.get(cmd.program, set()):
            return Verdict(ASK, "database-write", "A SQL file can change data. Check it first.")
    if cmd.program == "sqlite3" and len(args) >= 2 and SQL_WRITE.search(" ".join(args[1:])):
        return Verdict(DENY, "database-write", "This SQL changes data or schema. Hand it to a human.")
    return None


PYMONGO_WRITE = re.compile(
    r"\.(insert_one|insert_many|update_one|update_many|replace_one|delete_one|delete_many|drop|drop_collection|"
    r"drop_database|bulk_write|find_one_and_(update|replace|delete)|create_index|create_indexes|rename)\s*\("
)


def python_database_write(raw: str, ctx: Context) -> Verdict | None:
    if re.search(r"\b(python3?|py|ipython)\b", raw) and "pymongo" in raw and PYMONGO_WRITE.search(raw):
        return Verdict(DENY, "database-write", "This Python code writes to MongoDB. Hand it to a human.")
    return None


# --------------------------------------------------------------------------------------------- cloud

AWS_VALUE_FLAGS = {
    "--profile", "--region", "--endpoint-url", "--exclude", "--include", "--acl", "--storage-class", "--expires",
    "--content-type", "--cache-control", "--metadata", "--sse", "--sse-kms-key-id", "--grants", "--page-size",
    "--output", "--query", "--color", "--cli-read-timeout", "--cli-connect-timeout", "--bucket", "--key",
}
AWS_MUTATING = re.compile(r"^(delete|terminate|put|create|update|modify|stop|reboot|attach|detach|remove|revoke|"
                          r"authorize|disable|deregister|reset|restore|replace|run|start|send|invoke|copy|upload)-")


def aws_write(cmd: SimpleCommand, ctx: Context) -> Verdict | None:
    if cmd.program != "aws":
        return None
    pos = positionals(cmd.args, AWS_VALUE_FLAGS)
    if not pos:
        return None
    service, rest = pos[0], pos[1:]
    if service == "s3" and rest:
        verb, paths = rest[0], rest[1:]
        if verb in ("rm", "rb", "mb"):
            return Verdict(DENY, "cloud-write", f"`aws s3 {verb}` changes S3. A human runs it.")
        if verb == "mv" and any(p.startswith("s3://") for p in paths):
            return Verdict(DENY, "cloud-write", "`aws s3 mv` writes to (or deletes from) S3. A human runs it.")
        if verb in ("cp", "sync") and paths and paths[-1].startswith("s3://"):
            return Verdict(DENY, "cloud-write", f"`aws s3 {verb}` to an S3 destination writes to S3. A human runs it.")
        return None
    if rest and AWS_MUTATING.match(rest[0]):
        return Verdict(ASK, "cloud-write", f"`aws {service} {rest[0]}` changes AWS resources.")
    return None


BOTO3_WRITE = re.compile(
    r"\.(put_object|delete_object|delete_objects|upload_file|upload_fileobj|copy_object|copy|delete_bucket|"
    r"create_bucket|put_bucket_\w+|terminate_instances|delete_\w+)\s*\("
)


def python_cloud_write(raw: str, ctx: Context) -> Verdict | None:
    if re.search(r"\b(python3?|py|ipython)\b", raw) and "boto3" in raw and BOTO3_WRITE.search(raw):
        return Verdict(DENY, "cloud-write", "This Python code changes AWS resources. Hand it to a human.")
    return None


def terraform_write(cmd: SimpleCommand, ctx: Context) -> Verdict | None:
    if cmd.program not in ("terraform", "tofu", "terragrunt"):
        return None
    pos = positionals(cmd.args, {"-chdir", "-var", "-var-file", "-target"})
    if not pos:
        return None
    state_write = pos[0] == "state" and len(pos) > 1 and pos[1] in ("rm", "mv", "push", "replace-provider")
    if pos[0] in ("apply", "destroy", "import", "taint", "untaint") or state_write:
        return Verdict(DENY, "terraform-write", f"`{cmd.program} {' '.join(pos[:2])}` changes real infrastructure.")
    return None


# --------------------------------------------------------------------------------------------- git

def _current_branch(cwd: str, git_args: list[str]) -> str | None:
    path = cwd
    if "-C" in git_args and git_args.index("-C") + 1 < len(git_args):
        path = os.path.join(cwd, git_args[git_args.index("-C") + 1])
    try:
        out = subprocess.run(["git", "-C", path, "symbolic-ref", "--short", "HEAD"],
                             capture_output=True, text=True, timeout=5)
        if out.returncode != 0:
            return None
        return out.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def git_danger(cmd: SimpleCommand, ctx: Context) -> Verdict | None:
    if cmd.program != "git":
        return None
    args = list(cmd.args)
    i, sub = first_positional(args, {"-C", "-c", "--git-dir", "--work-tree"})
    if sub is None or i is None:
        return None
    rest = args[i + 1:]
    if sub == "push":
        if any(a in ("-f", "--force", "--force-with-lease") or a.startswith("--force") or
               (not a.startswith("-") and a.startswith("+")) for a in rest):
            return Verdict(DENY, "git-danger", "Force push rewrites shared history.")
        if "--mirror" in rest or "--delete" in rest or "-d" in rest:
            return Verdict(DENY, "git-danger", "This deletes or overwrites remote refs.")
        pos = positionals(rest, {"-o", "--push-option", "--repo"})
        refspecs = pos[1:]
        targets = [r.split(":")[-1].removeprefix("refs/heads/") for r in refspecs]
        if not refspecs:
            branch = _current_branch(ctx.cwd, args[:i])
            targets = [branch] if branch else []
        hit = [t for t in targets if t in ctx.protected_branches]
        if hit:
            return Verdict(DENY, "git-danger", f"Direct push to `{hit[0]}`. Push a branch and open a pull request.")
    if sub == "reset" and "--hard" in rest:
        return Verdict(ASK, "git-danger", "`git reset --hard` discards uncommitted work.")
    if sub == "clean" and any(a.startswith("-") and "f" in a for a in rest):
        return Verdict(ASK, "git-danger", "`git clean -f` deletes untracked files.")
    if sub == "branch" and "-D" in rest:
        return Verdict(ASK, "git-danger", "`git branch -D` deletes a branch that may not be merged.")
    return None


# --------------------------------------------------------------------------------------------- processes

def kill_by_name(cmd: SimpleCommand, ctx: Context) -> Verdict | None:
    lowered = [a.lower() for a in cmd.args]
    if cmd.program in ("pkill", "killall") or (cmd.program == "taskkill" and "/im" in lowered) or \
            (cmd.program in ("stop-process", "spps", "kill") and "-name" in lowered):
        return Verdict(DENY, "kill-by-name", "Killing by name can hit processes this session did not start. "
                                             "Kill the PID you started.")
    return None


SEGMENT_RULES: list[SegmentRule] = [
    kubernetes_write, kubernetes_secret_read, credential_read, database_write, aws_write, terraform_write,
    git_danger, kill_by_name,
]
RAW_RULES: list[RawRule] = [python_database_write, python_cloud_write]
