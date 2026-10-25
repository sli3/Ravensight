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
from urllib.parse import urlsplit

PM = "pm"
PLAN_REVIEWER = "plan-reviewer"
CODE_WRITER = "code-writer"
DEEP_BUG_HUNTER = "deep-bug-hunter"
TEAM = (PLAN_REVIEWER, CODE_WRITER, DEEP_BUG_HUNTER)
# The Codex plugin's forwarding agent starts Codex with its own sandbox setting,
# which replaces .codex/config.toml, so it is blocked outright. pm runs Codex
# itself with `codex exec` instead. Both spellings of its name are guarded.
CODEX_AGENT_NAMES = ("codex:codex-rescue", "codex-rescue")
SPAWNABLE = TEAM

FILE_TOOLS = ("Edit", "Write", "MultiEdit", "NotebookEdit")

# Per-call model overrides pm may pass, by subagent. plan-reviewer and
# deep-bug-hunter always run on the model in their definition files.
ALLOWED_MODEL_OVERRIDES = {
    CODE_WRITER: ("haiku", "sonnet", "opus"),
}

ROADMAP = "docs/RAVENSIGHT_ROADMAP.md"
ARCHIVE = "docs/roadmap-archive.md"
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
        "git commit",
        "git switch",
        "git checkout -b",
        "git branch",  # branch -D still prompts: "ask" rule in settings.json
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
    "roadmap-archive.md",
    ".mcp.json",
}
# Top-level directories code-writer must never edit.
CODE_WRITER_DENY_DIRS = {".claude", ".codex"}
# The same protected names, spotted anywhere in a code-writer Bash command.
CODE_WRITER_BASH_DENY = re.compile(
    r"AGENTS\.md|CLAUDE\.md|ROADMAP\.md|roadmap-archive\.md|\.mcp\.json"
    r"|\.claude/|\.codex/"
)

# Claude in Chrome (browser) rules. Only pm may use the browser, only on local
# pages, and only to upload sample data. The hook matcher in settings.json must
# include mcp__claude-in-chrome__.* or these calls never reach this script.
BROWSER_PREFIX = "mcp__claude-in-chrome__"
BROWSER_LOCAL_HOSTS = ("127.0.0.1", "localhost")
BROWSER_PM_ALLOWED = frozenset({
    "tabs_context_mcp",
    "tabs_create_mcp",
    "tabs_close_mcp",
    "navigate",
    "computer",
    "read_page",
    "get_page_text",
    "find",
    "read_console_messages",
    "read_network_requests",
    "resize_window",
    "file_upload",
    "browser_batch",
})
# Not allowed: javascript_tool, form_input, upload_image, shortcuts_execute,
# gif_creator, and the browser-switching tools.
BROWSER_COMPUTER_ACTIONS = frozenset({
    "screenshot", "zoom", "scroll", "scroll_to", "hover", "wait",
    "left_click", "double_click", "triple_click", "type", "key",
})
# Shortcut chords (ctrl+l can retarget the address bar) and function keys.
BROWSER_BLOCKED_KEYS = re.compile(r"(?i)\b(ctrl|control|cmd|command|meta|alt|win|windows|super)\b|\+|\bf\d{1,2}\b")
# Sample data pm may upload into the viewer, relative to the project root.
# CONFIRM with Prin: set this to where the sample fixture really lives.
BROWSER_UPLOAD_DIR = "tests/fixtures/"

# Design reference: pm may read two files of Prin's own Claude Design artifact
# with the Artifact tool, and nothing else. Add "Artifact" to the hook matcher.
ARTIFACT_URL = "https://claude.ai/artifact/RmvHREuYhRdM7FcBufRJ5J"
ARTIFACT_PM_PATHS = ("project/Viewer.dc.html", "project/canvas.json", "project/Evidence.dc.html")

# Shell constructs that could write files or run hidden commands.
UNSAFE_SHELL = re.compile(r"[<>`]|\$\(")
HARMLESS_REDIRECTS = re.compile(r"\s2>&1|\s2>/dev/null")
COMMAND_SEPARATORS = re.compile(r"&&|\|\||[;|&\n]")
# Files holding live credentials. No guarded agent may name them in Bash.
SECRET_FILES = re.compile(r"config\.toml|\.env\b(?!\.example)")
# The only Codex commands pm may run: a writer task, a writer follow-up by
# session id, or a reviewer task on gpt-6-astra, each with an effort level and a
# one-line brief in double quotes. No other flag fits, so the sandbox in
# .codex/config.toml always applies.
CODEX_EXEC = re.compile(
    r'codex exec (?:resume [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12} '
    r'|-m gpt-6-astra )?-c model_reasoning_effort=(?:low|medium|high|xhigh) '
    r'"[^"\\$`;&|<>\n\r]+"'
)
# Any run of the codex command or the plugin's script, to stop other agents.
CODEX_COMMAND = re.compile(r"(?:^|[\s;&|(/\"'=])codex(?:\s|$)|codex-companion")


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
    return not (name == ".env" or (name.startswith(".env.") and name != ".env.example"))


def roadmap_edit_problem(tool_input: dict, project_dir: Path, rel: str) -> str | None:
    """Return a reason to block a pm roadmap or archive Edit, or None if it may go ahead.

    pm may edit the roadmap and its archive only with targeted Edit calls: a
    non-empty old_string that matches exactly once. The archive is insert-only:
    new_string must begin with old_string unchanged, so archived text is never
    altered. Whole-file Write is refused in check_file_tool. Which parts pm
    should touch, and when, is governed by pm.md (ROADMAP UPDATES), not by this
    guard.
    """
    old = tool_input.get("old_string", "")
    if not old:
        return f"{rel} edits need a non-empty old_string"
    text = (project_dir / rel).read_text(encoding="utf-8")
    if text.count(old) != 1:
        return f"old_string must match exactly one place in {rel}; widen it"
    if rel == ARCHIVE and not str(tool_input.get("new_string", "")).startswith(old):
        return "the archive is insert-only: new_string must begin with old_string unchanged"
    return None


def check_file_tool(agent: str, tool: str, tool_input: dict, project_dir: Path) -> None:
    """Apply the per-agent edit rules to Edit, Write, MultiEdit and NotebookEdit."""
    raw = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
    rel = project_relative(raw, project_dir)

    if agent in (PLAN_REVIEWER, DEEP_BUG_HUNTER) or agent in CODEX_AGENT_NAMES:
        block(f"{agent} is read-only and may not use {tool}")

    if agent == CODE_WRITER:
        if rel is not None and not code_writer_may_edit(rel):
            block(f"code-writer may not edit {rel} (protected file; flag it to Prin)")
        return

    if agent == PM:
        if rel is None:
            block("pm may only write inside .session-memos/, the roadmap and its archive")
        if rel.startswith(MEMO_DIR) and tool in ("Edit", "Write"):
            if tool == "Write" and (project_dir / rel).exists():
                block(f"{rel} already exists; never overwrite a session memo")
            return
        if rel in (ROADMAP, ARCHIVE):
            if tool != "Edit":
                block(f"pm may change {rel} only with targeted Edit calls, never a whole-file write")
            reason = roadmap_edit_problem(tool_input, project_dir, rel)
            if reason:
                block(reason)
            return
        block(f"pm may not edit {rel}; only .session-memos/, the roadmap and its archive")


def check_bash(agent: str, command: str) -> None:
    """Apply the per-agent Bash rules."""
    if SECRET_FILES.search(command):
        block(f"{agent} may not name config.toml or a .env file in Bash; they hold live credentials")
    if agent in CODEX_AGENT_NAMES:
        block("the Codex plugin agent is disabled: it skips Codex's sandbox; pm runs codex exec itself")
    if CODEX_COMMAND.search(command):
        if agent != PM:
            block(f"{agent} may not run Codex; only pm may, with codex exec")
        if not CODEX_EXEC.fullmatch(command.strip()):
            block(
                "pm may run Codex only as: codex exec [resume <session id> | -m gpt-6-astra] "
                '-c model_reasoning_effort=low|medium|high|xhigh "<one-line brief>", with no other '
                "flags, and no double quote, backslash, $, backticks, ; & | < > or line "
                "breaks in the brief"
            )
        return
    if agent == CODE_WRITER:
        if CODE_WRITER_BASH_DENY.search(command):
            block("code-writer may not name protected governance files in Bash; use Read to read them")
        for segment in COMMAND_SEPARATORS.split(command):
            if segment.strip().startswith("git commit"):
                block("code-writer may not run git commit; that belongs to the git-workflow skill")
            if segment.strip().startswith("graft build"):
                block("code-writer may not run graft build; Prin runs it")
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
    if agent in TEAM or agent in CODEX_AGENT_NAMES:
        block(f"{agent} may not spawn subagents")
    if agent == PM:
        subagent = tool_input.get("subagent_type", "")
        if subagent not in SPAWNABLE:
            block(
                f"pm may spawn only {', '.join(SPAWNABLE)}, not '{subagent or 'default'}'; "
                "never substitute a built-in agent such as general-purpose"
            )
        model = tool_input.get("model")
        allowed = ALLOWED_MODEL_OVERRIDES.get(subagent, ())
        if model and model not in allowed:
            block(
                f"model '{model}' is not allowed on {subagent}; allowed: "
                f"{', '.join(allowed) or 'none (omit the model parameter)'}"
            )


def local_url_problem(url: str) -> str | None:
    """Return a reason to refuse this navigate target, or None if it is allowed."""
    if url in ("back", "forward"):
        return None
    # The extension assumes https:// when no scheme is given, so require one.
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https"):
        return f"navigate needs an explicit http://127.0.0.1:<port>/ or http://localhost:<port>/ URL, not '{url}'"
    if parts.username or parts.password:
        return "navigate URLs may not carry credentials"
    if parts.hostname not in BROWSER_LOCAL_HOSTS:
        return f"pm may browse only 127.0.0.1 and localhost, not '{parts.hostname}'"
    return None


def browser_call_problem(tool: str, tool_input: dict, project_dir: Path) -> str | None:
    """Return a reason to refuse one pm browser call, or None if it is allowed."""
    if tool == "browser_batch":
        actions = tool_input.get("actions")
        if not isinstance(actions, list):
            return "browser_batch needs an actions list"
        for item in actions:
            if not isinstance(item, dict):
                return "browser_batch item is not an object"
            name = str(item.get("name", "")).removeprefix(BROWSER_PREFIX)
            if name == "browser_batch":
                return "browser_batch cannot be nested"
            reason = browser_call_problem(name, item.get("input") or {}, project_dir)
            if reason:
                return reason
        return None

    if tool not in BROWSER_PM_ALLOWED:
        return f"pm may not use browser tool '{tool}' (allowed: {', '.join(sorted(BROWSER_PM_ALLOWED))})"

    if tool == "navigate":
        return local_url_problem(str(tool_input.get("url", "")))

    if tool == "computer":
        action = tool_input.get("action", "")
        if action not in BROWSER_COMPUTER_ACTIONS:
            return f"pm may not use the browser action '{action}'"
        if tool_input.get("modifiers"):
            return "pm may not click with modifier keys"
        if action == "key" and BROWSER_BLOCKED_KEYS.search(str(tool_input.get("text", ""))):
            return "pm may not press shortcut or function keys in the browser"
        return None

    if tool == "file_upload":
        paths = tool_input.get("paths")
        if not isinstance(paths, list) or not paths:
            return "file_upload needs a paths list"
        for raw in paths:
            rel = project_relative(str(raw), project_dir)
            if rel is None or not rel.startswith(BROWSER_UPLOAD_DIR):
                return f"pm may upload only files under {BROWSER_UPLOAD_DIR} (sample data), not '{raw}'"
    return None


def check_browser(agent: str, tool: str, tool_input: dict, project_dir: Path) -> None:
    """Apply the Claude in Chrome rules: pm only, local pages only, sample data only."""
    short = tool.removeprefix(BROWSER_PREFIX)
    if agent != PM:
        block(f"{agent} may not use the browser; only pm may, and only on local pages")
    reason = browser_call_problem(short, tool_input, project_dir)
    if reason:
        block(reason)


def check_artifact(agent: str, tool_input: dict) -> None:
    """Let pm read only the design reference files; block every other Artifact use."""
    if agent != PM:
        block(f"{agent} may not use the Artifact tool; only pm may, to read the design reference")
    if tool_input.get("action") != "read":
        block("pm may only read artifacts (action 'read'), never publish, list or delete")
    if str(tool_input.get("url", "")).rstrip("/") != ARTIFACT_URL:
        block(f"pm may read only the design reference artifact {ARTIFACT_URL}")
    path = tool_input.get("path")
    paths = tool_input.get("paths")
    if paths or path not in ARTIFACT_PM_PATHS:
        block(f"pm may read only {' and '.join(ARTIFACT_PM_PATHS)} from the artifact")
    if tool_input.get("out_dir"):
        block("pm may not choose where an artifact file is saved; omit out_dir")
    # A validated design-reference read is approved here, so it needs no prompt.
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "allow",
        "permissionDecisionReason": "pm reads the design reference artifact (read-only)",
    }}))


def main() -> None:
    """Read the hook input from stdin and apply the rules for its agent."""
    data = json.load(sys.stdin)
    agent = data.get("agent_type") or ""
    tool = data.get("tool_name", "")
    tool_input = data.get("tool_input") or {}
    if agent != PM and agent not in TEAM and agent not in CODEX_AGENT_NAMES:
        # Any other session, including a plain `claude` session, may run Codex
        # only in pm's safe forms, so the project sandbox always applies.
        if tool == "Bash":
            command = str(tool_input.get("command", ""))
            if CODEX_COMMAND.search(command) and not CODEX_EXEC.fullmatch(command.strip()):
                block(
                    "Codex may run here only as: codex exec [resume <session id> | -m gpt-6-astra] "
                    '-c model_reasoning_effort=low|medium|high|xhigh "<one-line brief>"; '
                    "other flags, such as --cd, would skip the project sandbox"
                )
        return
    project_dir = Path(os.environ.get("CLAUDE_PROJECT_DIR") or data.get("cwd") or ".")

    if tool in FILE_TOOLS:
        check_file_tool(agent, tool, tool_input, project_dir)
    elif tool == "Bash":
        check_bash(agent, tool_input.get("command", ""))
    elif tool == "Agent":
        check_agent(agent, tool_input)
    elif tool == "Artifact":
        check_artifact(agent, tool_input)
    elif tool.startswith(BROWSER_PREFIX):
        check_browser(agent, tool, tool_input, project_dir)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    # Fail closed: a broken guard must not let calls through.
    except Exception as err:  # noqa: BLE001
        block(f"guard error, call blocked: {err!r}")