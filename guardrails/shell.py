"""Turns a shell command line into the list of simple commands it would run.

The goal is not to be a full shell parser. It is to see every program a command line can start,
including the ones hidden behind `&&`, pipes, `bash -c "..."`, `$(...)` or `sudo`, so the rules can
judge each one. When in doubt it errs on the side of finding more commands, never fewer.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

MAX_DEPTH = 4

# Programs that only run the next program on the line.
WRAPPERS = {"sudo", "doas", "nohup", "time", "nice", "ionice", "command", "exec", "stdbuf", "xargs", "watch"}
# Wrapper flags that consume the next token (e.g. `sudo -u postgres psql`, `watch -n 5 kubectl ...`).
WRAPPER_VALUE_FLAGS = {
    "sudo": {"-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-U"},
    "watch": {"-n", "--interval", "-d"},
    "nice": {"-n", "--adjustment"},
    "ionice": {"-c", "-n", "-p"},
    "xargs": {"-I", "-n", "-P", "-L", "-d", "-a", "-E", "-s"},
    "env": {"-u", "-C", "-S"},
}
# Wrappers that take one value before the program (e.g. `timeout 30 kubectl ...`).
WRAPPERS_WITH_VALUE = {"timeout"}
SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
POWERSHELLS = {"powershell", "pwsh"}
SEPARATOR_CHARS = set(";&|()")
WINDOWS_SEPARATOR = re.compile(r"\\(?=[A-Za-z0-9_.\-])")
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
SUBSTITUTIONS = [re.compile(r"\$\(([^()]*)\)"), re.compile(r"`([^`]*)`"), re.compile(r"<\(([^()]*)\)")]


class UnparsableCommand(ValueError):
    """The command could not be tokenized (for example, unbalanced quotes)."""


@dataclass(frozen=True)
class SimpleCommand:
    program: str          # normalized name: lower case, no path, no .exe
    args: tuple[str, ...]
    text: str             # the tokens joined back, for messages

    def __str__(self) -> str:
        return self.text


def program_name(token: str) -> str:
    name = re.split(r"[\\/]", token)[-1].lower()
    for ext in (".exe", ".cmd", ".bat", ".ps1"):
        if name.endswith(ext):
            name = name[: -len(ext)]
    return name


def _tokenize(command: str) -> list[str]:
    # A newline outside quotes separates commands, like `;`.
    text = command.replace("\r\n", "\n").replace("\n", " ; ")
    # Windows paths (C:\tools\kubectl.exe): a backslash before a path character is a separator, not an escape.
    text = WINDOWS_SEPARATOR.sub("/", text)
    lexer = shlex.shlex(text, posix=True, punctuation_chars=";&|()")
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        return list(lexer)
    except ValueError as exc:  # unbalanced quotes
        raise UnparsableCommand(str(exc)) from exc


def _segments(tokens: list[str]) -> list[list[str]]:
    segments, current = [], []
    for tok in tokens:
        if tok and set(tok) <= SEPARATOR_CHARS:
            if current:
                segments.append(current)
            current = []
        else:
            current.append(tok)
    if current:
        segments.append(current)
    return segments


def _strip_prefixes(tokens: list[str]) -> list[str]:
    """Drops `VAR=value`, `sudo -u x`, `timeout 30`, `env -i` and similar until the real program."""
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        name = program_name(tok)
        if ASSIGNMENT.match(tok):
            i += 1
        elif name in WRAPPERS or name == "env":
            i += 1
            value_flags = WRAPPER_VALUE_FLAGS.get(name, set())
            while i < len(tokens) and (tokens[i].startswith("-") or (name == "env" and ASSIGNMENT.match(tokens[i]))):
                i += 2 if tokens[i] in value_flags else 1
        elif name in WRAPPERS_WITH_VALUE:
            i += 1
            while i < len(tokens) and tokens[i].startswith("-"):
                i += 1
            i += 1  # the duration
        else:
            break
    return tokens[i:]


def _inner_script(program: str, args: list[str]) -> str | None:
    """The script passed to `bash -c`, `pwsh -Command` or `cmd /c`, if any."""
    lowered = [a.lower() for a in args]
    if program in SHELLS:
        for i, a in enumerate(args):
            if a.startswith("-") and not a.startswith("--") and "c" in a[1:] and i + 1 < len(args):
                return args[i + 1]
    if program in POWERSHELLS:
        for i, a in enumerate(lowered):
            if a in ("-c", "-command", "/c", "/command") and i + 1 < len(args):
                return " ".join(args[i + 1:])
    if program == "cmd":
        for i, a in enumerate(lowered):
            if a in ("/c", "/k") and i + 1 < len(args):
                return " ".join(args[i + 1:])
    return None


def parse(command: str, depth: int = 0) -> list[SimpleCommand]:
    """Every simple command the line can run, nested ones included."""
    if depth > MAX_DEPTH:
        raise UnparsableCommand("nesting too deep")
    found: list[SimpleCommand] = []
    for segment in _segments(_tokenize(command)):
        tokens = _strip_prefixes(segment)
        if not tokens:
            continue
        program, args = program_name(tokens[0]), tokens[1:]
        found.append(SimpleCommand(program, tuple(args), " ".join(tokens)))
        inner = _inner_script(program, args)
        if inner:
            found.extend(parse(inner, depth + 1))
    for pattern in SUBSTITUTIONS:
        for inner in pattern.findall(command):
            if inner.strip():
                found.extend(parse(inner, depth + 1))
    return found
