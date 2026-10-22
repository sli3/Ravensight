---
name: git-workflow
description: Secure Git workflow with UK English commit standards. Triggers on "commit", "git commit", "push", or "save to git". Always run after code-sanity-check passes.
---

## Secure Git Workflow

> **Session-type gate (AGENTS.md):** permitted only in Code sessions. If this is
> not a Code session, stop and say so.

Prin's request to commit is the approval to commit. Prin reviews the work
before pushing, and the push is always done by hand, so this workflow shows
the diff but does not pause for a second "OK".

### Steps

1. **Stage Check**
   ```bash
   git status
   ```
   Report which files are staged, modified, or untracked.
   If unexpected files are staged, stop and ask the user to review.
   If any new files created this session appear as **Untracked**, 
   stage them along with modified files — do not leave new files uncommitted.

2. **Diff Review**
   ```bash
   git diff --cached
   ```
   Show the diff in your reply, then carry on to the commit. Do not wait for
   an "OK".

   Stop and ask only if the diff contains something unexpected: a file that
   is not part of the agreed work, `config.toml`, a `.env` file, or anything
   that looks like a credential.

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

4. **Push (Prin does this by hand)**
   Never push, and do not ask whether to push. `git push` is denied in
   `.claude/settings.json`, so do not attempt it or work around the deny.
   After the commit, give Prin the exact `git push` command to run in their
   own terminal, naming the current branch.

5. **Safety**
   Never use `--force` or `-f` under any circumstance.

---

### Rules

- Always show the staged diff before committing
- Never push; give Prin the exact command to run
- Never use `--force` or `-f`
- Always use UK English in commit messages
- One logical change per commit
