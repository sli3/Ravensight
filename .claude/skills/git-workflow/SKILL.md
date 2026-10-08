---
name: git-workflow
description: Secure Git workflow with review gates and UK English commit standards. Triggers on "commit", "git commit", "push", or "save to git". Always run after code-sanity-check passes.
---

## Secure Git Workflow

> **Session-type gate (AGENTS.md):** permitted only in Code sessions. If this is
> not a Code session, stop and say so.

### Steps

1. **Stage Check**
   ```bash
   git status
   ```
   Report which files are staged, modified, or untracked.
   If unexpected files are staged, stop and ask the user to review.
   If any new files created this session appear as **Untracked**, 
   stage them along with modified files — do not leave new files uncommitted.

2. **Review Gate**
   ```bash
   git diff --cached
   ```
   Wait for explicit **"OK"** before proceeding.
   Do not continue if the user does not confirm.

3. **Commit Format**
   Use UK English in all commit messages.
   Format: `[category]: [description in past tense]`

   | Category | Use for |
   |----------|---------|
   | `feat` | New feature added |
   | `fix` | Bug corrected |
   | `refactor` | Code restructured, no behaviour change |
   | `docs` | Documentation updated |
   | `chore` | Build, config, or tooling changes |
   | `test` | Tests added or updated |

   **Examples:**
   ```
   feat: added Wazuh alert fetch with pagination
   fix: corrected baseline threshold comparison
   refactor: extracted report sections into separate functions
   docs: updated README with config table
   ```

4. **Push Gate**
   Ask explicitly:
   > "Shall I push to `main`? (Yes / No)"

   Never push without an explicit **"Yes"**.

   In Claude Code, `git push` is denied in `.claude/settings.json`. On "Yes",
   do not attempt the push or work around the deny: give Prin the exact
   `git push` command to run in their own terminal.

5. **Safety**
   Never use `--force` or `-f` under any circumstance.

---

### Rules

- Never skip the diff review gate
- Never push without explicit approval
- Never use `--force` or `-f`
- Always use UK English in commit messages
- One logical change per commit
