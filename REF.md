# Formal Verification and Stateful Testing Strategy

This repository contains reference materials and patterns for implementing Model-Based Testing (MBT) and stateful fuzzing, aimed at massively reducing Rust boilerplate and ensuring robust correctness. The strategies below derive from tools actively used in the Cosmos ecosystem (e.g., Tendermint/Malachite).

## 1. Model-Based Testing with Quint and ITF Traces

Instead of writing manual, linear unit tests in Rust to test complex protocol logic, we can treat the **Quint specification** as the single source of truth.

### The Workflow:
1. **Model Edge Cases:** Write all complex state transition logic and edge cases in Quint (`.qnt`).
2. **Generate Traces:** Use Quint's Apalache integration to exhaustively generate all valid execution traces and export them as `Informal Trace Format (ITF)` JSON files (`.itf.json`).
3. **Generic Rust Runner:** Write exactly *one* generic Rust test runner that iterates over these `.itf.json` files and blindly executes the trace on your Rust logic. 

### Implementation Reference (from Malachite)
The `itf` Rust crate (often under `quint-connect` or similar wrappers) allows you to define an `itf::Runner`. 

*Check `ref/malachite/code/crates/test/mbt/src/tests/consensus.rs` and `runner.rs` for their exact setup.*

**Basic pattern:**
```rust
use itf::Runner as ItfRunner;

pub struct StateMachineRunner {
    // context, mapping from abstract variables to concrete Rust addresses, etc.
}

impl ItfRunner for StateMachineRunner {
    type ActualState = MyRustState;
    type ExpectedState = MyQuintState; // Serialized via serde
    type Result = Option<Output>;
    type Error = ();

    fn init(&mut self, expected: &Self::ExpectedState) -> Result<Self::ActualState, Self::Error> {
        // Map expected Quint initial state to your initial Rust state
        Ok(MyRustState::new(...))
    }

    fn step(
        &mut self,
        actual: &mut Self::ActualState,
        expected: &Self::ExpectedState,
    ) -> Result<Self::Result, Self::Error> {
        // Read the "expected.input" from the trace
        // Apply it to "actual" Rust state
        // Return the output so it can be checked against expected assertions
    }
}
```

By doing this, whenever a new channel resolution path or state edge case is needed, you just update the `.qnt` spec, generate a new trace, and the Rust tests automatically pass or fail without writing a single line of Rust test code.

## 2. Stateful Fuzzing with `proptest-state-machine`

For local, synchronous data structures and core kernel logic (like allocations, open/close ops), manual scenarios are too rigid.

### The Strategy:
Use `proptest-state-machine`. You define:
1. **Transitions:** An enum of possible operations (`Tx::Open`, `Tx::Close`).
2. **Reference Model:** A dead-simple Rust struct that represents expected state (e.g., simple integers for balance, avoiding complex crypto).

`proptest` will generate thousands of random operation interleavings. If it finds a sequence that causes your real `Tx` kernel to panic or deviate from the simple model, it shrinks it down to the exact minimal failing sequence.

## 3. Stateright Explicit Exploration (Optional)

If the kernel scales into distributed scenarios, you can implement Stateright's `Model` trait (bypassing the heavier `Actor` model) directly on the `Tx` state. This lets you use Stateright's `Explorer` web UI to manually click through a visual tree of state transitions, which is exceptional for debugging.

---

### Reference Directory
*   `ref/malachite/`: Contains Informal Systems' Rust implementation of Tendermint BFT.
    *   `ref/malachite/code/crates/test/mbt/`: Shows exactly how they map Quint `.itf.json` traces into Rust tests.
    *   `ref/malachite/specs/consensus/quint/`: Shows their Quint formal models.