---
name: deep-bug-analysis
description: Deep root cause analysis before bug fixing. Triggers on "deep bug hunt", "rca", "analyse this bug", "root cause", or "why is this failing". Always runs before bug-hunt-loop for non-trivial errors. Invokes @deep-bug-hunter for analysis, gates on user OK, then hands structured findings to bug-hunt-loop.
---

## Deep Bug Analysis Protocol

> **Session-type gate (AGENTS.md):** permitted only in Debug sessions. If this is
> not a Debug session, stop and say so.

### When to use this skill

Use instead of jumping straight to `bug-hunt-loop` when:
- The error is not immediately obvious from the traceback
- The bug involves state, ordering, or cross-module interactions
- A previous `bug-hunt-loop` iteration did not find the root cause
- The symptom and the actual fault are likely in different places

Do NOT use for trivial one-liner errors (syntax, typo, missing import) — use `bug-hunt-loop` directly.

---

### Steps

#### 1. Gather context

Before invoking `@deep-bug-hunter`, collect:
- The exact error message and stack trace
- The file(s) and function(s) involved
- Any recent changes (check latest session memo)

Ask the user if not provided:
> "Please paste the error output (stack trace + last 20 lines of log if available).
> Which file and function is the entry point?"

Wait for the answer before continuing.

---

#### 2. Invoke @deep-bug-hunter

Use the Agent tool with `subagent_type: deep-bug-hunter` (no `model` override).
Pass a structured brief using this format:

```
@deep-bug-hunter

**Error:**
[paste error message and stack trace]

**Entry point:**
`ravensight/[file.py]` → `[function_name()]`

**Files to investigate:**
- `ravensight/[file1.py]`
- `ravensight/[file2.py]`

**Context:**
[Any relevant runtime context — config values, data state, recent changes]

Produce a Root Cause Analysis using your standard output format.
```

Wait for `@deep-bug-hunter` to respond fully before continuing.

---

#### 3. Present RCA and gate

Display the full RCA report from `@deep-bug-hunter`, then ask:

> "Root cause analysis complete.
>
> **Confidence:** [extract from RCA]
> **Hypothesis:** [extract one-line summary from RCA]
>
> Does this look correct? Shall I pass these findings to bug-hunt-loop? (Yes / No / Revise)"

- **Yes** → proceed to step 4
- **No** → ask what is wrong; re-invoke `@deep-bug-hunter` with corrections (max 2 retries)
- **Revise** → ask what to change in the brief and re-invoke

Do not proceed to bug-hunt-loop without an explicit **Yes**.

---

#### 4. Hand off to bug-hunt-loop

Construct the bug-hunt-loop prompt using the RCA findings:

```
Run bug-hunt-loop on `ravensight/[file.py]`.

Root cause (from RCA):
[paste Hypothesis section]

Fix strategy:
[paste Fix Strategy section]

Constrained scope — only modify:
[paste Affected Paths section]

Do NOT touch:
[paste What NOT to touch section]

Confidence in root cause: [High / Medium / Low]
```

---

### Output summary

After the full cycle completes, report:

```
Deep Bug Analysis Summary
──────────────────────────────────
RCA confidence:    [High / Medium / Low]
Root cause:        [one line]
Files implicated:  [list]
bug-hunt-loop:     [Passed in N iterations / Failed — reason]
Result:            ✅ Fixed / ⚠️ Partial / ❌ Not resolved
```

---

### Rules

- Never skip the RCA gate — always wait for explicit Yes before running bug-hunt-loop
- Never let bug-hunt-loop modify files outside the Affected Paths from the RCA
- If `@deep-bug-hunter` returns Low confidence, surface this prominently before gating
- Maximum 2 RCA retries — if confidence is still Low, stop and escalate to the user
- UK English throughout