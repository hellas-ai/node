# Testing Baseline

Last refreshed: May 14, 2026.

This repository uses tests, linting, coverage, mutation testing, model checking,
and ITF replay as complementary confidence signals. None of these is proof by
itself; the useful property is that they fail for different classes of mistakes.

## Commands

Run these before merging behavior changes:

```sh
cargo fmt --all --check
cargo test --all-features
cargo clippy --all-features --all-targets -- -D warnings
npm run quint:test
npm run quint:verify
```

Run mutation testing when changing security-critical code, consensus encoding,
fee/reserve accounting, verification routing, or parser behavior:

```sh
cargo mutants --all-features --test-tool nextest --jobs 8
```

Run coverage when evaluating whether a change has enough direct test pressure:

```sh
cargo llvm-cov --all-features --workspace --ignore-filename-regex '/nix/store/'
```

If `cargo-llvm-cov` cannot find `llvm-tools-preview`, run inside the Nix
development shell or set `LLVM_COV` and `LLVM_PROFDATA` to the active Rust
toolchain's bundled binaries.

Regenerate committed ITF replay fixtures when changing `models/l1.qnt`,
`models/l1_fees.qnt`, or the Rust replay schema:

```sh
npm run quint:fixtures
cargo test --all-features itf
```

## Current Baselines

Rust test suite:

```text
cargo test --all-features
101 Rust tests + 2 doctests passed
```

Coverage:

```text
cargo llvm-cov --all-features --workspace --ignore-filename-regex '/nix/store/'

Regions:   94.12%
Functions: 93.87%
Lines:     95.56%
```

Mutation testing:

```text
cargo mutants --all-features --test-tool nextest --jobs 8

663 mutants tested in 3m
9 missed
306 caught
342 unviable
6 timeouts
```

Quint models:

```text
npm run quint:test
all model tests passed

npm run quint:verify
all configured invariant checks completed with no violation found
```

ITF replay:

```text
cargo test --all-features itf
committed l1 and l1_fees traces replayed against the Rust kernel
```

## Remaining Mutation Survivors

The current missed mutants are accepted as baseline noise unless nearby code
changes make them meaningful.

Equivalent or near-equivalent boundary mutations:

```text
src/canonical.rs: List<T, N>::decode len > N changed to len >= N
src/list.rs: List<T, N>::take len > N changed to len >= N
src/view.rs: View::pack_coins sort comparator > changed to >=
src/view.rs: View::pack_edges sort comparator > changed to >=
```

These do not expose a security difference under the current invariants:
`List::take` saturates at capacity, `List::decode` already has exact-capacity
coverage, and view entries are keyed by unique object ids in well-formed stores.

Equivalent bit-composition mutations:

```text
src/webauthn.rs: user-presence/user-verification mask | changed to ^
src/webauthn.rs: base64url_32 byte-composition | changed to ^
```

The bit ranges are non-overlapping, so `|` and `^` produce the same value for
these specific expressions.

Equivalent truncated-literal mutation:

```text
src/webauthn.rs: consume_literal length check < changed to <=
```

This still rejects malformed boolean literals used by `crossOrigin`; the
mutated path does not admit a malformed assertion.

Timeouts:

```text
src/view.rs: insertion-sort index mutations
src/webauthn.rs: parser cursor increment mutations
```

These are non-terminating mutants rather than accepted behavior. Treat new
timeouts in fee, authorization, open/close validation, or canonical hashing as
regressions until reviewed.

## Regression Policy

New surviving mutants are high priority when they touch:

- canonical encodings or hash inputs;
- fee, reserve, timeout, or payout accounting;
- open/close validity rules;
- signature, WebAuthn, or seal-verifier routing;
- terms hash binding;
- rollback and batch atomicity;
- model/ITF replay logic.

Do not chase the raw mutation percentage blindly. Prefer removing code surface,
tightening invariants, or adding direct protocol-property tests over writing
tests that only pin incidental implementation details.
