#![no_std]
#![forbid(unsafe_code)]
//! Deterministic settlement kernel for Hellas.
//!
//! # Abstract model
//!
//! Every kernel module has a counterpart under `models/`. Reading the abstract
//! Quint module first is often the fastest way to understand a Rust module's
//! shape.
//!
//! | Concern              | Rust                       | Quint                                |
//! |----------------------|----------------------------|--------------------------------------|
//! | Apply driver         | [`State`]                       | `models/l1.qnt`                      |
//! | Tx vocabulary + step | [`Tx`]                          | `models/l1.qnt` (`step` action)      |
//! | Proof witnesses      | [`Proof`]                       | `models/verifier.qnt`                |
//! | Verification policy  | [`SigVerifier`]/[`SealVerifier`]| `models/verifier.qnt`                |
//! | Live objects         | [`Coin`] / [`Edge`] / ids       | `models/types.qnt`                   |
//! | Block context        | [`Context`]                     | `models/l1.qnt` (`height` var)       |
//! | Established rules    | [`Diff`], [`View`]              | `models/rules/invariants.qnt`        |
//! | Assumed dependencies | [`Store`], verifier traits      | `models/deps/assumptions.qnt`        |
//!
//! # Verifier boundary
//!
//! The transition core delegates cryptography to caller-wired traits:
//! [`SigVerifier`] decides cooperative-close signatures and open
//! authorizations, [`SealVerifier`] decides dispute seals. [`Proof::Timeout`]
//! needs neither — its admissibility is purely structural and the kernel
//! checks it inline. Test verifiers accept the deterministic placeholders
//! documented on [`Sig::placeholder`] and [`Seal::placeholder`]; production
//! verifiers wire real cryptography. Optional feature-gated helpers provide
//! concrete native/`WebAuthn` verification without changing the apply path.
//! `OpenAuth` is only a witness format: it proves consent from the same
//! party key used for coin ownership, terms, and payouts.
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
mod canonical;
pub(crate) mod consts;
mod context;
mod error;
mod event;
mod list;
mod object;
mod primitive;
#[cfg(feature = "secp256k1")]
mod secp256k1;
mod state;
mod store;
mod terms;
mod tx;
mod verifier;
mod view;
#[cfg(feature = "webauthn")]
mod webauthn;

pub use block::Block;
pub use canonical::{BufferWriter, Decode, DecodeError, Encode, Writer};
pub use consts::{MAX_EDGE_INPUTS, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, MAX_WEBAUTHN_DATA_LENGTH};
pub use context::{BlockHash, BlockHeight, Context, Cost, Fees};
pub use error::{
    ApplyError, BatchError, InsertError, InvalidCloseReason, InvalidOpenReason, InvalidProofReason,
    KernelResult,
};
pub use event::{Diff, Event, EventKind};
pub use list::List;
pub use object::{Coin, Edge, Genesis, Parties};
pub use primitive::{CoinId, EdgeId, Key, Party, PayloadHash, ProtocolCode, Sig, TermsHash};
#[cfg(feature = "secp256k1")]
pub use secp256k1::Secp256k1Verifier;
pub use state::State;
pub use store::{Batch, Store};
pub use terms::Terms;
pub use tx::{
    CloseKind, Funding, OpenAuth, Payout, Proof, Seal, Tx, WebAuthnAssertion, WebAuthnData,
};
pub use verifier::{SealPublicInputs, SealVerifier, SigVerifier};
pub use view::{Snapshot, View};
#[cfg(feature = "webauthn")]
pub use webauthn::{WebAuthnError, p256_key, verify_webauthn_assertion};
