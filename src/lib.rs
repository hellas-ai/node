#![no_std]
#![forbid(unsafe_code)]
//! Deterministic settlement kernel for Hellas.
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

mod block;
mod context;
mod error;
mod event;
mod list;
mod object;
mod op;
mod primitive;
mod state;
mod store;
mod terms;
mod view;

pub use block::Block;
pub use context::{BlockHash, BlockHeight, Context, Cost, Fees};
pub use error::{ApplyError, BatchError, InsertError, KernelResult};
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
pub use view::{Snapshot, View};
