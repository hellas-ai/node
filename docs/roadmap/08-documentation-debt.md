# 08 — Documentation and history

## The staked fraud game has no documentation

Roughly 37 commits of two-edge staked payment protocol — `Channel`,
`MakerVoucher`, `JobAcceptanceContext`, the bond, the slash routing, the
challenge margins — and **nothing outside `workflows/` describes it**.
Verified: no committed `.md` mentions it.

`workflows/` is git-ignored, so from the repository's point of view this
protocol is undocumented. Everything a reader has is module docs, which
are good but explain *decisions* rather than *the game*.

This is the largest documentation gap in the tree and it covers the
most subtle code.

## A false claim in a dated root document

`2026-07-18_ATTESTATION_PLAN.md:146` states something about
blake3/ContentId that the Xet migration made untrue.

Unresolved question: are the dated root documents living references that
should be corrected, or historical records that should be left alone and
superseded? Decide once, apply to all of them.

## History

`11a7765` has a commit message about TLS trust roots and a diff
containing eight files of a subagent's in-progress `Reach` work. Cause:
`git add -A` while an agent was editing the same worktree. Clippy is red
at that commit.

Not rewritten at the time because the agent was still running. Either
straighten it or leave it with a note — but decide, rather than letting
it be found later.

**Process fix, worth more than the cleanup:** give subagents isolated
worktrees, or stage explicit paths. Never `git add -A` with an agent
running.

## Nothing has been pushed

`origin` has not been updated all session. That is George's call, but it
should be a decision rather than an oversight.
