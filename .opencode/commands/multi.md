---
description: >
  Run two or more agents in parallel on the same task and synthesise
  their results. Mention agents by @name in your message.
  Example: /multi @plan-reviewer @deep-bug-hunter assess the risk of
  switching baseline.py to async writes
agent: pm
subtask: false
---

You are coordinating a parallel agent run for the Ravensight project.

Spawn each @mentioned agent simultaneously as independent subagents, giving
each the same task described in this message. Do not start one and wait for
it to finish before starting the next — launch all of them at the same time.

This is an analysis run. Tell every subagent, including `@code-writer` if it is
mentioned, that it must not edit, create or delete any file during this run.

If the task depends on earlier sessions, call `hindsight_recall` once before
spawning, and include the relevant lines in every subagent's prompt under
`Recalled context (unverified)`.

Tell every subagent to locate code with graft first (its `graft_*` MCP tools
or the `graft` CLI: ask with source spans, skeleton, callers) and to open files
only at the cited spans.

If a mentioned agent cannot be invoked, report which one and why. Never
substitute a different agent, such as the built-in `general` agent.

Wait until all subagents have reported back, then synthesise their findings
into a single coherent response. Highlight where agents agreed, where they
disagreed, and which recommendation to act on.

Do not write or modify any files until synthesis is complete and Prin has
confirmed the direction.