#![no_std]
#![forbid(unsafe_code)]
//! Deterministic settlement kernel for Hellas.
//!
//! # Verifier Boundary
//!
//! The kernel implements no cryptography. Signature and dispute-seal
//! verification go through a [`Verifier`] passed by the caller, typically a
//! preverified-cache lookup populated off the apply critical path. Tests wire
//! their own forgeable verifier; production wires real cryptography. The
//! kernel does not see the difference.
//!
//! # Warning: Fake Crypto
//!
//! The `fake-crypto` feature enables the degenerate [`Proof::basic`] witness
//! for modelling and tests. It must not be used in production. Without that
//! feature, basic proofs do not verify regardless of the verifier supplied.
//!
//! State objects and events are not directly constructible outside the crate.
//!
//! ```compile_fail
//! use hellas_kernel::{Coin, Key};
//!
//! let owner = Key::from_bytes([0; Key::LENGTH]);
//! let _coin = Coin::new(owner, 1);
//! ```
//!
//! ```compile_fail
//! use hellas_kernel::State;
//!
//! let _state = State::new(());
//! ```
//!
//! ```compile_fail
//! use hellas_kernel::{CoinId, EdgeId, Event, EventKind, List, MAX_EDGE_INPUTS};
//!
//! let id = CoinId::from_bytes([0; CoinId::LENGTH]);
//! let edge = EdgeId::from_bytes([0; EdgeId::LENGTH]);
//! let _event = Event {
//!     kind: EventKind::EdgeOpened {
//!         inputs: List::all([id; MAX_EDGE_INPUTS]),
//!         output: edge,
//!     },
//! };
//! ```

#[cfg(all(feature = "fake-crypto", not(debug_assertions), not(doc)))]
compile_error!(
    "hellas-kernel fake-crypto is for modelling only; do not build optimized artifacts with forgeable placeholder verification"
);

mod block;
mod context;
pub(crate) mod domain;
mod error;
mod event;
mod list;
mod object;
mod op;
mod primitive;
mod state;
mod store;
mod terms;
mod verifier;
mod view;

pub use block::Block;
pub use context::{BlockHash, BlockHeight, Context, Cost, Fees};
pub use error::{
    ApplyError, BatchError, InsertError, InvalidOpenReason, InvalidProofReason,
    InvalidResolveReason, KernelResult,
};
pub use event::{Diff, Event, EventKind};
pub use list::List;
pub use object::{Coin, Edge, Genesis, Parties};
pub use op::{
    Access, Agreement, Funding, MAX_EDGE_INPUTS, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, Op, Open,
    Payout, Proof, Resolve, ResolveKind, Seal,
};
pub use primitive::{CoinId, EdgeId, Key, Party, ProtocolCode, ResolveHash, Sig, TermsHash};
pub use state::State;
pub use store::{Store, Tx};
pub use terms::Terms;
pub use verifier::Verifier;
pub use view::{Snapshot, View};
