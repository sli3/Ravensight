---
name: memory-sync
description: Store one short Hindsight entry about work that was committed outside a /build run (manual fixes, external review, hand commits). Triggers ONLY on "/memory-sync", "memory sync" or "sync memory". Never triggers automatically. Read-only apart from one hindsight_retain call.
---

## Memory Sync Protocol

Use this when commits landed without `pm` running the build, so the Hindsight
bank has no entry for them, or has an entry that is now out of date.

This skill is for `pm` only. Subagents are denied `hindsight_retain`.

### Hard limits

- Do not edit, create or delete any file. Do not run a build, tests or a live run.
- Exactly one `hindsight_retain` call. If that call fails, report the error and stop.
- Do not explain why a change was made unless the commit message or Prin's note
  says why. You were not present for this work. Never infer a reason from a diff.

### Steps

1. **Read the commits.**
   ```bash
   git status
   git --no-pager log -1 --stat --format="%h %ad %s%n%n%b" --date=short
   ```
   If Prin named a number of commits or a range, use it in place of `-1`
   (for example `-3`, or `abc1234..HEAD`). If the working tree is not clean,
   say so in your reply and carry on: only committed work is stored.

2. **Check for an entry this one replaces.** Call `hindsight_recall` once with a
   short query built from the commit subject. If an earlier entry covers the
   same work and is now out of date, the new entry's first line must end with
   "Supersedes the earlier entry for <that work>." If nothing relevant comes
   back, skip this.

3. **Build the entry.** Three to six short lines. Each line must make sense on
   its own, because recall returns lines in isolation.
   - Line 1: today's date (`date +"%Y-%m-%d"`), the commit hash, and the commit
     subject in a few words. State that Prin committed it by hand.
   - Lines from git: what changed, naming files and functions only. Take
     reasons only from the commit message body.
   - Lines from Prin's note, if one was given: store them word for word. Do not
     shorten, reword or add to them. Put "Prin's note:" at the start of each.
   - No note and no commit body: store the git facts only. Do not pad.

4. **Apply the storage rules to the lines you wrote yourself.**
   - No test counts, pass or fail results, or `file:line` references.
   - No credentials, tokens, API keys, contents of `config.toml` or any
     secrets file, and no personal data. If Prin's note contains any of
     these, do not store it: stop and tell Prin.
   - Never store a skipped or waived workflow step in a way that could read
     as permission to skip it again.

5. **Store and show.** Call `hindsight_retain` once. Then print, exactly as
   passed, the text you stored, so Prin can review it and delete a wrong
   entry from the Hindsight dashboard. If there was nothing worth storing,
   store nothing and print "Memory sync: none".

### Rules

- One entry per run
- Git facts and Prin's own words only
- Never guess a reason from a diff
- Always print the stored text
