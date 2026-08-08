# 09 — Questions that need a decision, not code

## The seal

Three separate times this session the plan was "then we'll get back to
the seal", and we never did. It is the largest undesigned thing in the
tree.

What is known: `SealVerifier` hard-rejects every seal unless the
`preverified-seals` dev feature is on, in which case a `FraudArtifact`
in a trusted cache stands in for a real proof. The binding is checked
(this artifact slashes exactly one bond, one job, these parties); the
*wrongness* argument is stubbed. `SealPublicInputs` now carries the
network, so a seal born today is network-scoped.

The bisection → atomic-op argument is its own design and has not been
started.

## Should a CPU provider serve the network at all?

See [06a](06-security-cleanup.md). Currently it advertises BF16 and
every such job fails. The fix depends on the answer: refuse the
capability, or refuse the role.

## Is the gateway ever exposed to untrusted callers?

See [06c](06-security-cleanup.md). Determines whether it needs the same
locality gate as the quote path.

## `hellas-testnet-1` has deliberately public credentials

Committee reproducible from validator seed 200, funded accounts from
secret scalars 3 and 4. Documented in its README, and the same
arrangement devnet uses. Fine for a testnet nobody trusts; needs a real
committee with private key material before it means anything. That
material does not belong in this repository.

## Dated root documents: living or historical?

See [08](08-documentation-debt.md).

## Four HTTP stacks

reqwest 0.13, reqwest 0.12 (only under `--features otel`, via
`opentelemetry-otlp`), ureq 3.3, ureq 2.12 (via catgrad-llm and
hf-hub 0.4.3).

The two-versus-one question is settled and written up in
`crates/store/README.md`: one client is not purchasable because `iroh`
pins reqwest and `hf-hub` pins ureq. But **four** is more than the two
that are forced. The duplicate *versions* are worth a look — that is a
different question from the duplicate *clients*, and nobody has asked
it.

## Push to origin

Not done all session. See [08](08-documentation-debt.md).
