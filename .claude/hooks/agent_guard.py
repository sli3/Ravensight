#!/usr/bin/env python3
"""agent_guard.py — PreToolUse hook that applies Ravensight's per-agent rules.

Claude Code permission rules in settings.json apply to every agent alike. The
PreToolUse hook input, however, carries `agent_type`: the subagent's name when
the hook fires inside a subagent, or the main-thread agent's name when the
session runs as a named agent (the `agent` setting or `claude --agent`). This
script reads that field and blocks the calls each agent is not permitted to make.

Exit 0 with no output leaves the call to the normal permission rules, so the
global deny and ask rules in settings.json still apply on top of this guard.
Exit 2 blocks the call and shows the stderr message to the agent. Any
unexpected error also exits 2, so a broken guard fails closed.

Agents not named below (including a session with no named agent) are left to
the normal permission rules.
"""

import json
import os
import re
import sys
from pathlib import Path

PM = "pm"
PLAN_REVIEWER = "plan-reviewer"
CODE_WRITER = "code-writer"
DEEP_BUG_HUNTER = "deep-bug-hunter"
TEAM = (PLAN_REVIEWER, CODE_WRITER, DEEP_BUG_HUNTER)

FILE_TOOLS = ("Edit", "Write", "MultiEdit", "NotebookEdit")

ROADMAP = "docs/RAVENSIGHT_ROADMAP.md"
MEMO_DIR = ".session-memos/"

GRAFT_READ = (
    "graft map",
    "graft ask",
    "graft grep",
    "graft skeleton",
    "graft callers",
)

# Bash command prefixes each read-only or orchestrating agent may run. A
# command matches a prefix when it equals it or continues with a space.
BASH_ALLOW = {
    PM: GRAFT_READ + (
        "uv run pytest",
        "uv run python -m pytest",
        "uv run python -m py_compile",
        "uv run python -c",  # still prompts: "ask" rule in settings.json
        "uv run python main.py --help",
        "uv run python main.py -h",
        "uv run ruff check",
        "ls -t",
        "head",
        "cat",
        "git status",
        "git diff",
        "git --no-pager diff",
        "git log",
        "git --no-pager log",
        "git add",
        "git commit",  # still prompts: "ask" rule in settings.json
        "mkdir -p .session-memos",
        "date",
    ),
    PLAN_REVIEWER: GRAFT_READ,
    DEEP_BUG_HUNTER: GRAFT_READ + (
        "git diff",
        "git --no-pager diff",
        "git status",
        "uv run python -m py_compile",
        "uv run ruff check",
        "uv run pytest",
        "uv run python -m pytest",
        "uv run pyright",
    ),
}

# Files code-writer must never edit, matched by file name at any depth.
CODE_WRITER_DENY_NAMES = {
    "config.toml",
    "AGENTS.md",
    "CLAUDE.md",
    "ROADMAP.md",
    "RAVENSIGHT_ROADMAP.md",
    ".mcp.json",
}
# Top-level directories code-writer must never edit.
CODE_WRITER_DENY_DIRS = {".claude"}
# The same protected names, spotted anywhere in a code-writer Bash command.
CODE_WRITER_BASH_DENY = re.compile(
    r"AGENTS\.md|CLAUDE\.md|ROADMAP\.md|\.mcp\.json"
    r"|\.claude/"
)

# Shell constructs that could write files or run hidden commands.
UNSAFE_SHELL = re.compile(r"[<>`]|\$\(")
HARMLESS_REDIRECTS = re.compile(r"\s2>&1|\s2>/dev/null")
COMMAND_SEPARATORS = re.compile(r"&&|\|\||[;|&\n]")


def block(reason: str) -> None:
    """Block the tool call and tell the agent why."""
    print(f"agent_guard: {reason}", file=sys.stderr)
    sys.exit(2)


def project_relative(raw_path: str, project_dir: Path) -> str | None:
    """Return the path relative to the project root, or None if outside it."""
    path = Path(raw_path)
    if not path.is_absolute():
        path = project_dir / path
    try:
        return path.resolve().relative_to(project_dir.resolve()).as_posix()
    except ValueError:
        return None


def code_writer_may_edit(rel: str) -> bool:
    """Return True if code-writer may edit this project-relative path."""
    parts = rel.split("/")
    name = parts[-1]
    if parts[0] in CODE_WRITER_DENY_DIRS or name in CODE_WRITER_DENY_NAMES:
        return False
    if name == ".env" or (name.startswith(".env.") and name != ".env.example"):
        return False
    return True


def roadmap_edit_in_table(tool_input: dict, project_dir: Path) -> str | None:
    """Return a reason to block a pm roadmap Edit, or None if it stays in the table."""
    text = (project_dir / ROADMAP).read_text(encoding="utf-8")
    header = text.find("\n## Feature Status\n")
    if header == -1:
        return "cannot find the '## Feature Status' heading in the roadmap"
    start = header + len("\n## Feature Status\n")
    end = text.find("\n---\n", start)
    if end == -1:
        return "cannot find the '---' line that ends the Feature Status section"
    old = tool_input.get("old_string", "")
    new = tool_input.get("new_string", "")
    if not old:
        return "roadmap edits need a non-empty old_string inside the Feature Status table"
    in_table = text[start:end].count(old)
    if in_table == 0 or in_table != text.count(old):
        return "this edit reaches outside the Feature Status table of the roadmap"
    if re.search(r"^(#{1,6} |---\s*$)", new, re.MULTILINE):
        return "a roadmap edit may not add headings or '---' lines"
    return None


def check_file_tool(agent: str, tool: str, tool_input: dict, project_dir: Path) -> None:
    """Apply the per-agent edit rules to Edit, Write, MultiEdit and NotebookEdit."""
    raw = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
    rel = project_relative(raw, project_dir)

    if agent in (PLAN_REVIEWER, DEEP_BUG_HUNTER):
        block(f"{agent} is read-only and may not use {tool}")

    if agent == CODE_WRITER:
        if rel is not None and not code_writer_may_edit(rel):
            block(f"code-writer may not edit {rel} (protected file; flag it to Prin)")
        return

    if agent == PM:
        if rel is None:
            block("pm may only write inside .session-memos/ and the roadmap's Feature Status table")
        if rel.startswith(MEMO_DIR) and tool in ("Edit", "Write"):
            if tool == "Write" and (project_dir / rel).exists():
                block(f"{rel} already exists; never overwrite a session memo")
            return
        if rel == ROADMAP:
            if tool != "Edit":
                block("pm may change the roadmap only with Edit, inside the Feature Status table")
            reason = roadmap_edit_in_table(tool_input, project_dir)
            if reason:
                block(reason)
            return
        block(f"pm may not edit {rel}; only .session-memos/ and the roadmap's Feature Status table")


def check_bash(agent: str, command: str) -> None:
    """Apply the per-agent Bash rules."""
    if agent == CODE_WRITER:
        if CODE_WRITER_BASH_DENY.search(command):
            block("code-writer may not name protected governance files in Bash; use Read to read them")
        for segment in COMMAND_SEPARATORS.split(command):
            if segment.strip().startswith("git commit"):
                block("code-writer may not run git commit; that belongs to the git-workflow skill")
        return

    allowed = BASH_ALLOW.get(agent)
    if allowed is None:
        return
    cleaned = HARMLESS_REDIRECTS.sub("", command)
    if UNSAFE_SHELL.search(cleaned):
        block(f"{agent} may not use redirection or command substitution in Bash")
    for segment in COMMAND_SEPARATORS.split(cleaned):
        segment = segment.strip()
        if not segment:
            continue
        if not any(segment == p or segment.startswith(p + " ") for p in allowed):
            block(f"{agent} may not run '{segment}' (not on its Bash allowlist)")


def check_agent(agent: str, tool_input: dict) -> None:
    """Restrict which subagents can be spawned, and with which model."""
    if agent in TEAM:
        block(f"{agent} may not spawn subagents")
    if agent == PM:
        subagent = tool_input.get("subagent_type", "")
        if subagent not in TEAM:
            block(
                f"pm may spawn only {', '.join(TEAM)}, not '{subagent or 'default'}'; "
                "never substitute a built-in agent such as general-purpose"
            )
        model = tool_input.get("model")
        if model and not (subagent == DEEP_BUG_HUNTER and model == "opus"):
            block("a model override is allowed only as opus on the deep-bug-hunter Mode 2 escalation")


def main() -> None:
    """Read the hook input from stdin and apply the rules for its agent."""
    data = json.load(sys.stdin)
    agent = data.get("agent_type") or ""
    if agent != PM and agent not in TEAM:
        return
    tool = data.get("tool_name", "")
    tool_input = data.get("tool_input") or {}
    project_dir = Path(os.environ.get("CLAUDE_PROJECT_DIR") or data.get("cwd") or ".")

    if tool in FILE_TOOLS:
        check_file_tool(agent, tool, tool_input, project_dir)
    elif tool == "Bash":
        check_bash(agent, tool_input.get("command", ""))
    elif tool == "Agent":
        check_agent(agent, tool_input)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as err:  # fail closed: a broken guard must not let calls through
        block(f"guard error, call blocked: {err!r}")
