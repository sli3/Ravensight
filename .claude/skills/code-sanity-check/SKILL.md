---
name: code-sanity-check
description: Logic and syntax verification for Python code. Run when user says "sanity check", "check this", or "verify this file". Always run before committing any new or heavily modified file.
---

## Sanity Check Protocol

> **Session-type gate (AGENTS.md):** permitted only in Code sessions. If this is
> not a Code session, stop and say so.

### Steps

1. **Syntax**
   Run `uv run ruff check` on the file.
   Fall back to `uv run python -m py_compile` if ruff is unavailable.
```bash
   uv run ruff check [file.py] || uv run python -m py_compile [file.py]
```
   If syntax fails — stop immediately. Report the failure and do NOT continue
   to the next steps. Ask the user to fix the syntax error first.

2. **Logic**
   Check for:
   - Bare `except:` clauses (must catch specific exceptions)
   - Missing type hints on function signatures
   - `print()` used instead of `logging`
   - Hardcoded credentials, IPs, or paths that should come from config
   - `os.path` used instead of `pathlib.Path`

3. **Error Handling**
   Verify that:
   - API calls (Wazuh, LLM) have try/except around them
   - HTTP errors are checked (status codes, timeouts)
   - File I/O operations handle missing files gracefully

4. **Idempotency**
   Verify the module can be imported and run multiple times without side effects.
   Look for operations that would fail or corrupt state on a second run.

5. **Second-pass review**
   Invoke `@deep-bug-hunter` (the Agent tool, `subagent_type: deep-bug-hunter`)
   in Mode 1 (post-edit review) on the changed file or function:
   > "@deep-bug-hunter review the change to [file.py]"

   Wait for the reviewer output before continuing.
   Present the reviewer findings beneath the sanity check report.

6. **Approval gate**
   After presenting both the sanity check report and the reviewer output, ask:
   > "Sanity check and review complete — OK to proceed to git-workflow?
   > (Yes / No)"

   Do not trigger or suggest git-workflow until the user says Yes.
   If the user says No — stop and wait for instructions.

---

### Report Format
Sanity Check Report — [filename]
──────────────────────────────────
Syntax:         [Passed / Failed — reason]
Logic:          [Passed / Warnings — list]
Error Handling: [Passed / Concerns — list]
Idempotency:    [Passed / Concern — description]
Reviewer Output (@deep-bug-hunter):
──────────────────────────────────
[bullet points from @deep-bug-hunter]
Result: ✅ Ready for git-workflow / ⚠️ Issues found — review before proceeding

---

### Rules

- Never modify the file during a sanity check — report only
- Never skip the @deep-bug-hunter step if syntax passes
- Never proceed to git-workflow without explicit Yes from the user
- If syntax fails, stop at step 1 — do not run logic checks or reviewer
- Always run this before git-workflow on a Code session