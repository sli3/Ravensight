---
name: code-preflight
description: Pre-flight checklist for Code sessions ONLY. Triggers on "run preflight", "preflight check", or when the user explicitly says "Code session". NEVER triggers for Plan, Explore, or Review sessions. Do not run this skill unless the session type is explicitly Code.
---

## Code Pre-Flight Checklist

> **Session-type gate (AGENTS.md):** permitted only in Code sessions. If this is
> not a Code session, stop and say so.

You do not edit files yourself in this skill — once the plan is approved,
the change is delegated to `@code-writer`, which holds the only edit
permission in this project.

### Steps

1. **Read session memo:**
```bash
   ls -t .session-memos/*.md | head -1
```
   Summarise in one sentence what this Code session is supposed to do.

1b. **If this is a roadmap feature session**, read the relevant feature section from `docs/RAVENSIGHT_ROADMAP.md` before stating scope.

2. **Check previous mistakes** — look for `## Mistakes Made` in memo:
   - Read each mistake aloud
   - State how you will avoid repeating each one
   - If none, state that clearly

3. **State exact scope:**
   - Which file will be changed
   - Which function or section will be changed
   - What specific change will be made
   - What will NOT be changed

4. **Read only what is needed** — relevant function only, not entire file.

5. **Show the plan** — exact proposed change in a code block with inline comments.
   Do not delegate the edit yet.

6. **Wait for OK** — ask:
   > "Does this plan look correct? Shall I proceed?"

   Do not delegate to `@code-writer` until the user says yes.
   After showing the plan, output exactly this line and nothing else:
   `WAITING FOR OK — do not proceed until user explicitly types "OK"`

7. **Delegate the edit to `@code-writer`:**
   On explicit OK, hand `@code-writer` (the Agent tool, `subagent_type:
   code-writer`) the exact scope from Step 3 and the
   plan shown in Step 5 — do not let it broaden scope. Wait for it to report
   the change complete before continuing.

8. **Remind user of post-edit sequence:**
   > "After the edit is done: run `@deep-bug-hunter` on the changed function,
   > then `code-sanity-check`, then `git-workflow`."

---

### Checklist Output Format
Pre-Flight Check:
✅ Memo read — [one line summary]
✅ Previous mistakes reviewed — [none / list]
✅ Scope confirmed: [file1.py, file2.toml] (colon + explicit file list, no em dash)
✅ Plan shown — waiting for your OK
✅ Post-edit sequence noted — @deep-bug-hunter → sanity-check → git-workflow

---

### Rules

- Never skip this checklist in a Code session
- Never delegate the edit before user says OK
- If scope is unclear, ask — do not guess
- Always acknowledge previous mistakes before proceeding
- Never invoke `@deep-bug-hunter` yourself as part of this skill — remind the user to do it manually, as a separate step
- Never let `@code-writer` touch files outside the stated scope — if another file needs changing, STOP and report back to the user before proceeding
- Never create any file before the user says OK