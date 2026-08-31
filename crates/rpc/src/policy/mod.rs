//! Execution authorization: `ExecutePolicy` and its glob matcher.
//!
//! Pure, dependency-free policy evaluation — no protocol or transport
//! knowledge. Consumers pass a policy string and a candidate, and get an
//! allow/deny decision.

mod execute;
mod glob;

pub use execute::ExecutePolicy;
