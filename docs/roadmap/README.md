# Open work — content materialization and the quote path

Written 2026-08-08, after the session that built `hellas-store`. Each
file is one landable slice: what is wrong, the evidence, what "done"
means, and what could go wrong doing it.

## The honest caveat, first

This list is what is *known* open. Every investigation during the
session that produced it found something real that was not on the list
beforehand — a remote fetch primitive in the quote path, a BF16
capability that always fails, two CLI features that never built alone,
a TLS trust split, a test of mine that could not fail, two extra quote
doors. The count went **up** under scrutiny every time.

So treat "eight slices" as a floor. The rate is falling — the last pass
found doors rather than architecture — but the state we want is the one
where looking stops producing new items, and we are not there.

## Order

| # | Slice | Why this order |
| --- | --- | --- |
| ~~[01](01-store-gate-convergence.md)~~ | ~~Store and gate answer one question~~ | **Landed.** Adopting a cache makes its models quotable |
| ~~[04](04-fastresume-in-the-node.md)~~ | ~~A node uses what `adopt` learned~~ | **Landed** with 01 — same subsystem, same tests |
| [02](02-catgrad-cutover.md) | catgrad stops fetching | Small now 01 has landed; closes the last uncontrolled fetch |
| [06](06-security-cleanup.md) | Three unrelated small defects | One is a capability that always fails |
| [05](05-manifest-memo.md) | Stop rebuilding the manifest per quote | Independent, cheap |
| [03](03-peer-fetch.md) | Peer-to-peer fetch | Needs a wire protocol; genuinely its own thing |
| [07](07-conformance-gaps.md) | Untested protocol corners | Fold into whatever touches them |
| [08](08-documentation-debt.md) | Docs and history | Fold in, or do when tired |

[09-open-decisions.md](09-open-decisions.md) is not a slice. It is the
questions that need George, not code.
