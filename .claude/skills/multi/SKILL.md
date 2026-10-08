---
name: multi
description: >
  Run two or more agents in parallel on the same task and synthesise
  their results. Mention agents by @name in your message.
  Example: /multi @plan-reviewer @deep-bug-hunter assess the risk of
  switching baseline.py to async writes
argument-hint: "@agent [@agent ...] <task>"
disable-model-invocation: true
---

This command runs in the main conversation as `pm`, the project's default agent
(set by `agent` in `.claude/settings.json`). If you are not running as `pm`,
stop and tell Prin to start the session with `claude --agent pm`.

You are coordinating a parallel agent run for the Ravensight project.

Spawn each @mentioned agent simultaneously as independent subagents, giving
each the same task described in this message. Do not start one and wait for
it to finish before starting the next — launch all of them at the same time,
with one Agent tool call per agent in a single message, `subagent_type` set to
the agent's exact name.

This is an analysis run. Tell every subagent, including `@code-writer` if it is
mentioned, that it must not edit, create or delete any file during this run.

<!-- Hindsight disabled for the Claude Code trial -->

Tell every subagent to locate code with graft first (its `mcp__graft__*` MCP
tools or the `graft` CLI: ask with source spans, skeleton, callers) and to open
files only at the cited spans.

If a mentioned agent cannot be invoked, report which one and why. Never
substitute a built-in agent such as `general-purpose`.

Wait until all subagents have reported back, then synthesise their findings
into a single coherent response. Highlight where agents agreed, where they
disagreed, and which recommendation to act on.

Do not write or modify any files until synthesis is complete and Prin has
confirmed the direction.

Task and mentioned agents:

$ARGUMENTS
