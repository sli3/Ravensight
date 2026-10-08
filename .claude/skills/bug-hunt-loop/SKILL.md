---
name: bug-hunt-loop
description: Run a file, capture errors, apply a targeted fix, and re-run. Loops up to 3 iterations. Triggers on "bug hunt", "hunt bugs", "fix and run", or "run bug hunt on [filename]". Shows a diff and states every change before applying. Writes bug-hunt-report.md on failure. Delegates the run/fix/re-run loop to @code-writer, which holds the bash and edit permissions this requires.
---

## Bug Hunt Loop

> **Session-type gate (AGENTS.md):** permitted only in Code and Debug sessions,
> and only after `deep-bug-analysis` has run, except for trivial one-liner errors
> (syntax, typo, missing import). If neither applies, stop and say so.

### Purpose

Run a file, observe failures, apply a targeted fix, and re-run — up to three times.
Every change is shown as a diff before it is applied. Nothing is edited silently.
On three consecutive failures, the loop stops and writes `bug-hunt-report.md` to the project root.

You do not run the file or edit it yourself — you delegate the whole loop to
`@code-writer` in a single task, then present its report.

---

### Pre-flight

Before doing anything, warn the user:
> "⚠️ This will edit the file directly. Make sure your recent changes are committed or stashed before I proceed. Shall I continue?"

Wait for explicit confirmation. Do not proceed without it.

---

### Delegating to @code-writer

On confirmation, hand `@code-writer` (the Agent tool, `subagent_type:
code-writer`) the following brief in full — it runs
the entire loop internally (detect → run → diagnose → diff → fix → re-run,
up to 3 iterations) and reports back once:

```
@code-writer

Run the bug-hunt-loop protocol on `[filename]`.

1. Detect language/runner from extension or shebang (bash / python3 / node /
   npx tsx / go run / ruby). If unrecognised, stop and report — do not guess.
2. Confirm the runner is installed before running. For .go files, confirm
   go.mod exists first. If either check fails, stop and report — do not
   attempt to install or create anything.
3. Run the file, capturing stdout, stderr, and exit code.
   - Exit 0, no error indicators → report "No errors detected on first run"
     and stop. Make no changes.
4. Otherwise, loop up to 3 iterations:
   a. Diagnose: exact error, file/line, one-sentence proposed fix.
   b. Show the change as a diff block before touching the file.
   c. Apply ONLY the diagnosed fix — nothing else. Do not reformat unrelated
      lines. Do not fix other issues you notice — list them separately in
      your final report instead.
   d. If this iteration's fix is identical to a previous iteration's, stop
      immediately and treat this as a final failure — do not repeat it.
   e. Re-run, capture output and exit code.
   f. Exit 0, no errors → report success and stop.
   g. Still failing and iterations remain → continue to iteration N+1.
   h. Still failing at iteration 3 → stop.
5. If unresolved after 3 iterations, write `bug-hunt-report.md` to the
   project root with: date, language, runner, result, each iteration's
   error/fix/diff/output-after-fix, final output, issues noticed but not
   fixed, and suggested next steps.
6. Report back: which outcome (success / unresolved), iterations used, and
   the diff(s) applied, or the bug-hunt-report.md path if unresolved.
```

---

### Presenting the result

- **Success** → relay `@code-writer`'s summary and the diff(s) applied.
- **Unresolved after 3 iterations** → relay the summary and state:
  > "Bug hunt failed after 3 iterations. Report saved to `bug-hunt-report.md`. No further edits will be made."
- **Stopped early** (unrecognised language, runner missing, go.mod missing, file not found) → relay `@code-writer`'s reason verbatim and stop.

---

### Rules

- **Hard cap of 3 iterations** — `@code-writer` must never attempt a 4th fix; this brief states that explicitly every time
- **Never edit silently** — the diff block and stated change must appear before every edit
- **One error per iteration** — fix only the diagnosed error, nothing else
- **Never repeat the same fix** — identical proposed change to a prior iteration ends the loop immediately
- **Pre-flight is mandatory** — never delegate to `@code-writer` without the user's explicit confirmation
- If the target file does not exist, or the runner isn't installed, or the file passes on the first run — `@code-writer` stops and reports; you relay this, you do not retry or work around it